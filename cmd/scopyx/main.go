// Command scopyx is the web-egress enforcement point.
//
// It is not a browser. It sits between an agent and whatever fetching backend
// the operator already uses, decides each destination against the policy plane
// before anything leaves, re-decides every redirect hop, bounds what comes
// back, and writes one tamper-evident record.
//
// This file is configuration and wiring only. Every rule it appears to enforce
// is enforced in `internal/decide`, `internal/fetch` and `internal/mcp`, which
// is what lets those be tested without a network. What lives HERE is the set of
// defaults, and a default is a decision: see the constants below, each of which
// is finite on purpose.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/backend"
	"github.com/TAIPANBOX/scopyx/internal/decide"
	"github.com/TAIPANBOX/scopyx/internal/fetch"
	"github.com/TAIPANBOX/scopyx/internal/mcp"
	"github.com/TAIPANBOX/scopyx/internal/pin"
	"github.com/TAIPANBOX/scopyx/internal/policy"
	"github.com/TAIPANBOX/scopyx/internal/record"
	"github.com/TAIPANBOX/scopyx/internal/robots"
)

// version is stamped by the build.
var version = "dev"

// The defaults. Every one is finite, and invariant 8 is the reason.
//
// The per-hour cap especially: a backend that is free today can be priced
// tomorrow, and an uncapped deployment then starts spending without anybody
// deciding to. There is no unlimited mode without SCOPYX_MAX_FETCHES_PER_HOUR
// being set deliberately, and setting it to 0 says so in the log at startup.
const (
	defaultAddr            = "127.0.0.1:4300"
	defaultMaxBodyBytes    = 32 << 20
	defaultMaxRedirects    = 10
	defaultFetchesPerHour  = 500
	defaultBackendTimeout  = 30 * time.Second
	defaultPolicyTimeout   = 3 * time.Second
	defaultShutdownTimeout = 10 * time.Second
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("scopyx stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	mcp.Version = version

	addr := env("SCOPYX_ADDR", defaultAddr)
	keys := mcp.ParseKeys(os.Getenv("SCOPYX_KEYS"))

	// Before anything binds. A non-loopback bind with no credential is an
	// unauthenticated fetch proxy on somebody's network, and the failure is
	// silent: it works perfectly for whoever finds it.
	if why := mcp.RefuseOpenBind(addr, keys, mcp.TruthyEnv(os.Getenv("SCOPYX_ALLOW_OPEN_BIND"))); why != "" {
		return errors.New(why)
	}

	pdpURL := os.Getenv("SCOPYX_WARDRYX")
	if pdpURL == "" {
		// Refused rather than defaulted. A default policy plane address would
		// be a plane that answers nothing, and this component fails closed, so
		// every fetch would be refused with a reason pointing at the network
		// rather than at the missing configuration.
		return errors.New("SCOPYX_WARDRYX is unset, and this plane will not start without a policy " +
			"plane to ask: it fails closed, so an unconfigured one would refuse every fetch with a " +
			"message about the network instead of about the configuration. " +
			"Set SCOPYX_WARDRYX=http://wardryx:8080")
	}
	pdp := policy.New(pdpURL, os.Getenv("SCOPYX_WARDRYX_KEY"), defaultPolicyTimeout)

	// ONE pinned client, shared by everything that reaches the open web.
	//
	// Shared on purpose. Two clients would be two dialers, and a dialer that
	// resolves a name for itself is the hole this closes: `internal/fetch`
	// checks addresses, and anything below it that looks the name up again is
	// deciding about one host and connecting to another.
	//
	// The policy client is deliberately NOT on this transport. wardryx is an
	// internal service that no fetch decision covers, so a pinned dialer would
	// refuse to reach it and this plane would fail closed against its own
	// control plane. Different direction, different rules.
	pinned := pin.Client(defaultBackendTimeout)

	back, err := chooseBackend(pinned)
	if err != nil {
		return err
	}

	journal, err := record.Open(os.Getenv("SCOPYX_EVENTS"), os.Getenv("SCOPYX_RETAIN") == "payload")
	if err != nil {
		return err
	}
	defer func() {
		if err := journal.Close(); err != nil {
			log.Error("the journal did not close cleanly", "error", err)
		}
	}()

	// The site's own preference. On by default, because invariant 9 says this
	// plane governs evasion and never supplies it, and ignoring a site's
	// stated wishes is the cheapest kind of supplying it.
	//
	// `report` is the default and NOT the crawler posture: an unreadable
	// robots.txt allows and says it could not be read, because letting a
	// site's 500 stop an operator's own governed work hands any origin a way
	// to deny service to the agents fetching it. `strict` is there for an
	// operator who wants the crawler behaviour.
	var robotsMode robots.Mode
	switch v := env("SCOPYX_ROBOTS", "report"); v {
	case "report":
		robotsMode = robots.ModeReport
	case "strict":
		robotsMode = robots.ModeStrict
	case "off":
		robotsMode = robots.ModeOff
	default:
		return fmt.Errorf("SCOPYX_ROBOTS=%q is not one this build knows. "+
			"report (the default: an unreadable robots.txt allows, and the result says so), "+
			"strict (an unreadable robots.txt refuses), or off", v)
	}

	perHour := envInt("SCOPYX_MAX_FETCHES_PER_HOUR", defaultFetchesPerHour)
	g := &governed{
		log:     log,
		backend: back,
		pdp:     pdp,
		journal: journal,
		limits: decide.Limits{
			MaxRedirects: int(envInt("SCOPYX_MAX_REDIRECTS", defaultMaxRedirects)),
			MaxBodyBytes: envInt("SCOPYX_MAX_BYTES", defaultMaxBodyBytes),
		},
		cap:      newHourlyCap(perHour),
		resolver: systemResolver{},
		// The SAME pinned transport the backend uses, and this is what closed
		// the hole invariant 9 carried as debt for a day.
		//
		// A robots.txt fetch is a fetch. Given its own client it would resolve
		// the host a second time, independently of the lookup the decision was
		// made on, and a name that answered publicly for the decision and
		// privately a microsecond later would be reached without the address
		// checks seeing it. `internal/pin` makes the dialer refuse any host the
		// context does not carry, so this client cannot reach anywhere
		// `internal/fetch` has not already resolved and decided about.
		robots: robots.New(robotsMode, 0, pinned),
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           &mcp.Server{Keys: keys, Fetcher: g, RunID: runID()},
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Info("scopyx listening",
		"version", version, "addr", addr, "backend", back.Name(),
		"enforcement", string(back.Enforcement()),
		"policy_plane", pdpURL,
		"credentials_required", keys.Configured(),
		"journal", journalState(os.Getenv("SCOPYX_EVENTS")),
		"robots", env("SCOPYX_ROBOTS", "report"),
		"fetches_per_hour", capState(perHour))

	// Said out loud rather than left in a config file nobody re-reads. An
	// uncapped deployment is a decision, and a decision nobody is reminded of
	// is one nobody revisits.
	if perHour <= 0 {
		log.Warn("this deployment has NO per-hour fetch cap. " +
			"The default backend is free today and unpriced at general availability; " +
			"every other backend is metered from the first fetch.")
	}

	errc := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case <-stop:
	}

	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
	defer cancel()
	if skipped, failed := journal.Counts(); skipped > 0 || failed > 0 {
		// Reported at exit rather than kept private. Each number means "this
		// journal is not the whole story", and a reader who cannot see it has
		// no way to know.
		log.Warn("the record is incomplete", "skipped_no_agent_id", skipped, "write_failures", failed)
	}
	return srv.Shutdown(ctx)
}

// chooseBackend reads SCOPYX_BACKEND.
//
// The default is the one that needs no vendor, no account and no token, so a
// deployment is governed on the day it is installed.
func chooseBackend(hc *http.Client) (backend.Backend, error) {
	switch name := env("SCOPYX_BACKEND", "passthrough"); name {
	case "passthrough":
		p := backend.NewPassthrough(
			envInt("SCOPYX_MAX_BYTES", defaultMaxBodyBytes), defaultBackendTimeout)
		p.HTTP = hc
		return p, nil
	case "external":
		endpoint := os.Getenv("SCOPYX_EXTERNAL_ENDPOINT")
		if endpoint == "" {
			return nil, errors.New("SCOPYX_BACKEND=external needs SCOPYX_EXTERNAL_ENDPOINT, " +
				"the URL of the fetching service you already run")
		}
		// NOT pinned, and the reason is worth reading. `external` calls a
		// service the operator already runs, at an address of their choosing;
		// no fetch decision covers THAT host, so a pinned dialer would refuse
		// it. What the vendor then reaches is outside this process entirely,
		// which is exactly why this backend reports `navigation_only`.
		return backend.NewExternal(
			env("SCOPYX_EXTERNAL_LABEL", "service"),
			endpoint,
			os.Getenv("SCOPYX_EXTERNAL_KEY"),
			defaultBackendTimeout), nil
	default:
		return nil, fmt.Errorf("SCOPYX_BACKEND=%q is not a backend this build has. "+
			"Known: passthrough (the default, no vendor), external (your own fetching service)", name)
	}
}

// governed is the Fetcher the MCP surface calls.
//
// It holds no rule of its own. Every refusal comes from `internal/fetch`, and
// this exists to assemble the per-fetch memo, apply the spend cap and write the
// record.
type governed struct {
	log     *slog.Logger
	backend backend.Backend
	pdp     *policy.Client
	journal *record.Journal
	limits  decide.Limits
	cap     *hourlyCap

	robots *robots.Cache

	// resolver is a field rather than a call to the system one, and the reason
	// is that the end-to-end test could not otherwise exist: every httptest
	// server is on loopback, and `decide` refuses loopback, correctly. A test
	// that had to avoid the address checks to run would be testing a pipeline
	// with its most important refusal removed.
	resolver fetch.Resolver
}

func (g *governed) Fetch(ctx context.Context, c mcp.Call) (mcp.Answer, error) {
	if !g.cap.take() {
		// Recorded as a block, because from the agent's side it is one and a
		// trail that showed nothing here would make a throttled hour look like
		// a quiet one.
		g.journal.Blocked(c.AgentID, c.RunID, c.URL, "deny_rate", "the per-hour fetch cap for this deployment is spent")
		return mcp.Answer{}, fmt.Errorf(
			"deny_rate: this deployment's per-hour fetch cap is spent. It exists so a backend that " +
				"becomes metered cannot start spending without anybody deciding to")
	}

	// One memo per fetch, thrown away with it. Never shared between fetches or
	// between agents: a remembered verdict is a decision somebody else got.
	memo := policy.NewMemo(g.pdp, c.AgentID, c.RunID, c.Tool)

	res, err := fetch.Do(ctx, fetch.Deps{
		Backend:  g.backend,
		Resolver: g.resolver,
		Memo:     memo,
		Limits:   g.limits,
		Robots:   g.robots,
	}, backend.Request{URL: c.URL, Extract: c.Extract, WaitFor: c.WaitFor})

	if err != nil {
		if r, ok := fetch.AsRefusal(err); ok {
			g.journal.Blocked(c.AgentID, c.RunID, c.URL, r.Verdict().String(), r.Decision.Reason)
			// Logged without the URL. Invariant 10: a URL is personal data and
			// nothing above debug logs a full one.
			g.log.Info("refused", "verdict", r.Verdict().String(), "agent", c.AgentID)
		}
		return mcp.Answer{}, err
	}

	g.journal.Fetch(c.AgentID, c.RunID, res.FinalURL,
		res.Fidelity.Backend, string(res.Fidelity.Enforcement), res.Fidelity.ContentBytes)
	return mcp.Answer{Body: res.Body, FinalURL: res.FinalURL, Fidelity: res.Fidelity}, nil
}

// systemResolver is the real one.
//
// It returns EVERY address a name answers with, never the first. A name that
// answers with a public address and a private one is DNS rebinding spelled out
// in a single response, and `decide.Destination` refuses on any of them.
type systemResolver struct{}

func (systemResolver) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// hourlyCap is invariant 8.
//
// A fixed window rather than a sliding one, deliberately: the point is a
// ceiling on spend per hour, not smooth pacing, and a fixed window is something
// an operator can reason about from a log line. Zero or less means uncapped,
// which startup says out loud.
type hourlyCap struct {
	mu       sync.Mutex
	limit    int64
	used     int64
	windowAt time.Time
}

func newHourlyCap(limit int64) *hourlyCap {
	return &hourlyCap{limit: limit, windowAt: time.Now()}
}

func (h *hourlyCap) take() bool {
	if h.limit <= 0 {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if time.Since(h.windowAt) >= time.Hour {
		h.windowAt = time.Now()
		h.used = 0
	}
	if h.used >= h.limit {
		return false
	}
	h.used++
	return true
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// envInt refuses a malformed value rather than falling back to the default.
//
// Falling back would mean an operator who typed `SCOPYX_MAX_BYTES=32MB` gets
// the default and no indication, which is a bound they believe they set.
func envInt(name string, fallback int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("%s=%q is not a whole number. It is a bound, and a bound that "+
			"silently became the default is one you believe you set.", name, v))
	}
	return n
}

func journalState(path string) string {
	if path == "" {
		return "disabled (set SCOPYX_EVENTS to a path to record what this plane did)"
	}
	return path
}

func capState(perHour int64) string {
	if perHour <= 0 {
		return "UNCAPPED"
	}
	return strconv.FormatInt(perHour, 10)
}

// runID labels this process's fetches. One per process, because a run is a
// thing an operator restarts.
func runID() string {
	return "scopyx-" + strconv.FormatInt(time.Now().UTC().Unix(), 10)
}
