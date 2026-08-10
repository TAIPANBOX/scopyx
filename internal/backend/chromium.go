package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/browserproxy"
	"github.com/TAIPANBOX/scopyx/internal/cdp"
	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// Chromium renders a page in a browser this plane drives.
//
// # WHY THIS IS THE ONLY BACKEND THAT CAN SAY per_request AND MEAN IT
//
// `passthrough-http` is per_request because it makes exactly one request, which
// is true and vacuous: there are no subresources to police because none are
// fetched. `external` is honestly navigation_only, because the vendor loads the
// page's images, fonts and scripts with nothing in between.
//
// A page is a document plus forty other requests, and until this backend
// existed no part of the estate decided any of them. This one does, and it is
// arranged so the guarantee does not rest on anybody else's cooperation.
//
// # TWO MECHANISMS, AND THEY ARE NOT REDUNDANT
//
//  1. The browser is launched with no route to the network except a proxy this
//     process owns, and that proxy refuses any destination the plane did not
//     decide. This is the FLOOR. It cannot be talked out of by a browser flag,
//     a service worker or a version change, because it is a socket that is not
//     opened.
//
//  2. CDP `Fetch` interception decides each request by its full URL, including
//     inside TLS, and produces the counts. This is the ACCOUNTANT. It sees more
//     than the proxy can and is trusted for less: it is Chrome telling us what
//     Chrome is doing.
//
// Where the two disagree the connection wins, because the connection is what
// carries bytes. Every counted request came through the floor.
//
// # WHAT IT DELIBERATELY DOES NOT DO
//
// No TLS interception. Minting certificates for other people's sites would put
// a private CA on the operator's box and build the capability this plane exists
// to bound. The consequence is stated rather than hidden: for https the proxy
// sees a host and not a path, and the per-URL decision comes from mechanism 2.
//
// No profile, no cookie jar, no cache, and a fresh user-data directory per
// fetch, deleted after. Invariant 4, and here it is not theoretical: a warm
// browser is the obvious optimisation, it would pass every test, and it would
// silently join two tenants' pages in one storage partition.
type Chromium struct {
	// Exe is the browser binary. Empty means look for one.
	Exe string

	// MaxBodyBytes bounds the extracted document.
	MaxBodyBytes int64

	// Timeout bounds one whole fetch, browser launch included.
	Timeout time.Duration

	// Resolve turns a name into addresses. Required: this backend refuses to
	// resolve anything itself, so that every address it reaches is one the same
	// resolver produced for the decision.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)

	// Allow decides one destination, by full URL. Required.
	//
	// Supplied by `internal/fetch` rather than reached for here, because a
	// backend that could decide is a backend that could decide differently
	// from the plane above it, which is invariant 1.
	Allow func(ctx context.Context, rawURL string, addrs []netip.Addr) decide.Decision

	// Dial opens a socket to an already-checked address. Nil is ordinary.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// NoSandbox turns off the browser's own renderer sandbox. Off by default,
	// and never set to work around an error. See chromeArgs.
	NoSandbox bool
}

// ErrNoBrowser is a chromium backend with no browser to drive.
var ErrNoBrowser = errors.New("no chromium or chrome found")

// NewChromium builds one, and refuses to exist without a browser.
//
// Refused at construction rather than at the first fetch on purpose: a plane
// that starts happily and fails every fetch reports a problem about the network
// to somebody whose actual problem is that they never installed a browser.
func NewChromium(exe string, maxBodyBytes int64, timeout time.Duration) (*Chromium, error) {
	if exe == "" {
		found, ok := cdp.Find()
		if !ok {
			if found != "" {
				return nil, fmt.Errorf("%w: SCOPYX_CHROMIUM=%s is not a file. This backend drives "+
					"a browser the operator installs; nothing is downloaded", ErrNoBrowser, found)
			}
			return nil, fmt.Errorf("%w: looked for %s on PATH. This backend drives a browser you "+
				"install, and nothing is bundled or downloaded, so the image stays small and "+
				"nothing arrives on your machine that you did not choose. Install one, or set "+
				"SCOPYX_CHROMIUM, or use SCOPYX_BACKEND=passthrough",
				ErrNoBrowser, strings.Join(cdp.Candidates, ", "))
		}
		exe = found
	}
	if maxBodyBytes <= 0 {
		maxBodyBytes = 32 << 20
	}
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	return &Chromium{Exe: exe, MaxBodyBytes: maxBodyBytes, Timeout: timeout}, nil
}

func (c *Chromium) Name() string { return "chromium" }

// Enforcement is per_request, and this is the first backend for which that is
// a measurement rather than a definition. See the type comment.
func (c *Chromium) Enforcement() decide.Enforcement { return decide.EnforcementPerRequest }

// Fetch renders one page.
func (c *Chromium) Fetch(ctx context.Context, req Request) (Result, error) {
	if c.Resolve == nil || c.Allow == nil {
		return Result{}, errors.New("scopyx: the chromium backend was built without a resolver or " +
			"a decider, and it will not fetch: deciding for itself is the one thing a backend " +
			"must not do")
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	// The floor. Started before the browser so there is no window in which the
	// browser exists and its only exit does not.
	px := &browserproxy.Proxy{
		Decide:  browserproxy.DeciderFunc(c.decideHost),
		Dial:    c.Dial,
		Timeout: c.Timeout,
	}
	proxyAddr, err := px.Start()
	if err != nil {
		return Result{}, fmt.Errorf("scopyx: the egress proxy did not start: %w", err)
	}
	defer px.Close()

	profile, err := os.MkdirTemp("", "scopyx-profile-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(profile)

	conn, err := cdp.Launch(ctx, c.Exe, chromeArgs(profile, proxyAddr, c.NoSandbox)...)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()

	res, err := c.drive(ctx, conn, px, req)
	if err != nil {
		// The browser's own words, when it had any. "the browser closed the
		// connection" describes the symptom and hides the sentence that says
		// why, and the why is usually one line: a missing shared library, a
		// sandbox that cannot initialise in a container, a profile it cannot
		// write.
		if said := conn.Stderr(); said != "" {
			return res, fmt.Errorf("%w. The browser said: %s.%s",
				err, lastLines(said, 3), sandboxAdvice(said))
		}
	}
	return res, err
}

// chromeArgs is the launch, and every flag here is load-bearing.
func chromeArgs(profile, proxyAddr string, noSandbox bool) []string {
	args := []string{
		"--headless=new",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-gpu",
		// Fresh per fetch and removed after: invariant 4, no profile, no
		// cookie jar, no cache and no storage partition shared with anything.
		"--user-data-dir=" + profile,
		// The only way out. --proxy-server alone is not enough: Chrome bypasses
		// a proxy for localhost by default, and the bypass list below removes
		// even that, so there is no destination it reaches directly.
		"--proxy-server=http://" + proxyAddr,
		"--proxy-bypass-list=<-loopback>",
		// Chrome resolves names for itself, and the proxy is what stops that
		// mattering: with a proxy configured, Chrome sends the NAME in CONNECT
		// and the proxy resolves and pins. This flag removes the remaining
		// path, the one Chrome uses for its own prediction and prefetch.
		"--disable-features=NetworkPrediction,PreconnectToSearch",
		// Nothing of Google's is contacted on this plane's behalf.
		"--disable-background-networking",
		"--disable-sync",
		"--disable-component-update",
		"--disable-domain-reliability",
		"--metrics-recording-only",
		"--no-pings",
		"--mute-audio",
		"--window-size=1280,900",
	}
	if noSandbox {
		// NEVER implicit, and never a repair for an error message.
		//
		// This turns off the browser's own renderer sandbox, which is the thing
		// standing between a hostile page and the process rendering it. That
		// page is attacker-controlled by definition: this plane exists because
		// agents read pages that tell them what to do next.
		//
		// It is here because a container commonly cannot give Chrome the user
		// namespaces its sandbox needs, and an operator who has read what it
		// costs may still decide the isolation they want is the container. The
		// same shape as SCOPYX_ALLOW_OPEN_BIND: a deliberate weakening, named,
		// opt-in, and said out loud at every boot.
		args = append(args, "--no-sandbox")
	}
	return args
}

// sandboxAdvice turns the browser's own complaint into the two ways out.
//
// Named separately because the tempting fix for "running as root without
// --no-sandbox is not supported" is to add the flag, and the better fix is
// usually not to run as root.
func sandboxAdvice(said string) string {
	if !strings.Contains(said, "--no-sandbox") && !strings.Contains(said, "sandbox") {
		return ""
	}
	return " This is the browser's sandbox, not scopyx. Run the container as a " +
		"non-root user with the namespaces Chrome needs, which keeps the sandbox, or set " +
		"SCOPYX_CHROMIUM_NO_SANDBOX=1, which turns it off and is a decision rather than a fix."
}

// decideHost is what the proxy asks. It resolves and defers to Allow.
func (c *Chromium) decideHost(ctx context.Context, scheme, host string) ([]netip.Addr, decide.Decision) {
	addrs, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, decide.Decision{
			Verdict: decide.DenyAddress,
			Reason:  "the host could not be resolved: " + err.Error(),
		}
	}
	return addrs, c.Allow(ctx, browserproxy.URLOf(scheme, host), addrs)
}

type fetchPaused struct {
	RequestID string `json:"requestId"`
	Request   struct {
		URL string `json:"url"`
	} `json:"request"`
	ResponseStatusCode int    `json:"responseStatusCode"`
	ResourceType       string `json:"resourceType"`

	ResponseHeaders []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"responseHeaders"`
}

// location reads the redirect target out of a paused response.
func (p fetchPaused) location() string {
	for _, h := range p.ResponseHeaders {
		if strings.EqualFold(h.Name, "location") {
			return h.Value
		}
	}
	return ""
}

func (c *Chromium) drive(ctx context.Context, conn *cdp.Conn, px *browserproxy.Proxy, req Request) (Result, error) {
	var target struct {
		TargetID string `json:"targetId"`
	}
	if err := conn.Call(ctx, "", "Target.createTarget",
		map[string]any{"url": "about:blank"}, &target); err != nil {
		return Result{}, err
	}
	var att struct {
		SessionID string `json:"sessionId"`
	}
	if err := conn.Call(ctx, "", "Target.attachToTarget",
		map[string]any{"targetId": target.TargetID, "flatten": true}, &att); err != nil {
		return Result{}, err
	}
	sid := att.SessionID

	var (
		mu     sync.Mutex
		seen   []Subresource
		navHop string
		loaded = make(chan struct{}, 1)
		hopped = make(chan struct{}, 1)
	)
	signal := func(ch chan struct{}) {
		select {
		case ch <- struct{}{}:
		default:
		}
	}

	conn.Handle(func(m cdp.Message) {
		switch m.Method {
		case "Page.loadEventFired":
			signal(loaded)
		case "Fetch.requestPaused":
			var p fetchPaused
			if json.Unmarshal(m.Params, &p) != nil {
				return
			}

			// Two stages arrive on this one event and they mean different
			// things. A non-zero status is the RESPONSE stage, which exists
			// here for exactly one reason: a redirect on the navigation.
			//
			// Chrome would follow it, in the network stack, without asking
			// anybody. That is the oldest allowlist bypass there is, and it is
			// invisible to a check that reads only the URL the caller passed.
			// So the hop is aborted here and reported UP, where
			// `internal/fetch` resolves and decides it like any other
			// destination.
			if p.ResponseStatusCode != 0 {
				if p.ResourceType == "Document" &&
					p.ResponseStatusCode >= 300 && p.ResponseStatusCode < 400 {
					if loc := p.location(); loc != "" {
						mu.Lock()
						navHop = loc
						mu.Unlock()
						_ = conn.Send(m.SessionID, "Fetch.failRequest",
							map[string]any{"requestId": p.RequestID, "errorReason": "Aborted"})
						signal(hopped)
						return
					}
				}
				_ = conn.Send(m.SessionID, "Fetch.continueResponse",
					map[string]any{"requestId": p.RequestID})
				return
			}

			u, err := url.Parse(p.Request.URL)
			if err != nil {
				_ = conn.Send(m.SessionID, "Fetch.failRequest",
					map[string]any{"requestId": p.RequestID, "errorReason": "Aborted"})
				return
			}

			addrs, err := c.Resolve(ctx, u.Hostname())
			var d decide.Decision
			if err != nil {
				d = decide.Decision{Verdict: decide.DenyAddress, Reason: err.Error()}
			} else {
				d = c.Allow(ctx, p.Request.URL, addrs)
			}

			mu.Lock()
			seen = append(seen, Subresource{URL: p.Request.URL, Blocked: !d.Verdict.Allowed()})
			mu.Unlock()

			if !d.Verdict.Allowed() {
				_ = conn.Send(m.SessionID, "Fetch.failRequest",
					map[string]any{"requestId": p.RequestID, "errorReason": "BlockedByClient"})
				return
			}
			_ = conn.Send(m.SessionID, "Fetch.continueRequest",
				map[string]any{"requestId": p.RequestID})
		}
	})

	if err := conn.Call(ctx, sid, "Page.enable", nil, nil); err != nil {
		return Result{}, err
	}
	// Both stages. The request stage is where every destination is decided;
	// the response stage is only for catching a redirect on the navigation
	// before Chrome's own network stack follows it.
	if err := conn.Call(ctx, sid, "Fetch.enable", map[string]any{"patterns": []map[string]any{
		{"urlPattern": "*", "requestStage": "Request"},
		{"urlPattern": "*", "requestStage": "Response"},
	}}, nil); err != nil {
		return Result{}, err
	}

	var nav struct {
		ErrorText string `json:"errorText"`
	}
	if err := conn.Call(ctx, sid, "Page.navigate", map[string]any{"url": req.URL}, &nav); err != nil {
		return Result{}, err
	}

	select {
	case <-loaded:
	case <-hopped:
	case <-ctx.Done():
		// Not an error on its own. A page that never fires load still has a
		// document, and returning nothing here would throw away a real answer
		// because of a slow advert. What must not happen is reporting it as
		// complete, which the truncation value below is for.
	}

	// Copied under the lock, and this is not defensive tidiness: the handler
	// runs on the goroutine reading the browser's pipe, and events keep
	// arriving while this one evaluates the document. Reading `seen` directly
	// here is a data race, which `-race` found in CI and a laptop did not.
	snapshot := func() (string, []Subresource) {
		mu.Lock()
		defer mu.Unlock()
		return navHop, append([]Subresource(nil), seen...)
	}

	hop, counted := snapshot()
	if hop != "" {
		return Result{RedirectTo: hop, FinalURL: req.URL, Subresources: mergeCounts(counted, px)}, nil
	}

	var eval struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	expr := "document.documentElement ? document.documentElement.outerHTML : ''"
	if req.Extract == "text" {
		expr = "document.body ? document.body.innerText : ''"
	}
	if err := conn.Call(ctx, sid, "Runtime.evaluate",
		map[string]any{"expression": expr, "returnByValue": true}, &eval); err != nil {
		return Result{}, err
	}

	body := []byte(eval.Result.Value)
	trunc := decide.Truncation("")
	if int64(len(body)) > c.MaxBodyBytes {
		body = body[:c.MaxBodyBytes]
		trunc = decide.TruncatedByBytes
	}

	var final struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	_ = conn.Call(ctx, sid, "Runtime.evaluate",
		map[string]any{"expression": "location.href", "returnByValue": true}, &final)
	finalURL := final.Result.Value
	if finalURL == "" || finalURL == "about:blank" {
		finalURL = req.URL
	}

	// Taken again rather than reused: the evaluate calls above are round trips
	// to the browser, and a page's own scripts keep fetching during them.
	_, counted = snapshot()

	return Result{
		FinalURL:     finalURL,
		Body:         body,
		HTTPStatus:   200,
		Subresources: mergeCounts(counted, px),
		TruncatedBy:  trunc,
	}, nil
}

// mergeCounts reports what the ACCOUNTANT saw, plus anything the FLOOR refused
// that the accountant never heard about.
//
// The second half is the interesting one and it is the reason this is not just
// `seen`. A request that never reached CDP interception, because a service
// worker made it or because this build of Chrome routes it elsewhere, still
// hits the proxy, and a count that ignored those would quietly under-report
// exactly the requests the accountant is worst at seeing.
//
// Never nil: this backend CAN report subresources, so an empty list truthfully
// says the page asked for nothing beyond its own document.
func mergeCounts(seen []Subresource, px *browserproxy.Proxy) []Subresource {
	out := make([]Subresource, 0, len(seen))
	out = append(out, seen...)

	byHost := map[string]bool{}
	for _, s := range seen {
		if u, err := url.Parse(s.URL); err == nil {
			byHost[u.Scheme+"://"+u.Host] = true
		}
	}
	for _, s := range px.Requests() {
		if !s.Blocked {
			// An allowed connection carries requests the accountant already
			// counted; counting it again would double every subresource.
			continue
		}
		if byHost[strings.TrimSuffix(s.URL, "/")] {
			continue
		}
		out = append(out, Subresource{URL: s.URL, Status: s.Status, Blocked: s.Blocked, Failed: s.Failed})
	}
	return out
}

// lastLines keeps the tail, which is where a browser puts its reason.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
