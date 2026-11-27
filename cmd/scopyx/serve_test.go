package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/scopyx/internal/mcp"
	"github.com/TAIPANBOX/scopyx/internal/record"
)

// Startup and shutdown of the process itself: what an operator's environment
// turns into, what is refused before anything binds, and what is said on the
// way out. Until serve took its listener and its stop signal as arguments none
// of this could run in a test, and every line of it is configuration an
// operator relies on without reading.

// syncBuffer is a log sink the server goroutine and the test can share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// client bounds every request a case makes, so a listener nobody serves
// fails the case instead of hanging the package.
var client = &http.Client{Timeout: 2 * time.Second}

// cleanEnv clears every variable serve reads, so the runner's own environment
// (CI sets the chromium ones) cannot decide a case.
func cleanEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SCOPYX_ADDR", "SCOPYX_KEYS", "SCOPYX_ALLOW_OPEN_BIND", "SCOPYX_WARDRYX",
		"SCOPYX_WARDRYX_KEY", "SCOPYX_BACKEND", "SCOPYX_EVENTS", "SCOPYX_RETAIN",
		"SCOPYX_ROBOTS", "SCOPYX_MAX_FETCHES_PER_HOUR", "SCOPYX_MAX_REDIRECTS",
		"SCOPYX_MAX_BYTES", "SCOPYX_ACCEPT_KEY_IN_META", "SCOPYX_EXTERNAL_ENDPOINT",
	} {
		t.Setenv(k, "")
	}
}

// fakePolicyPlane answers allow to everything and counts nothing: the cases
// here are about wiring, and the decisions are tested elsewhere.
func fakePolicyPlane(t *testing.T) string {
	t.Helper()
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"decision": "allow", "policy_version": "v1", "reason": "fixture policy",
		})
	}))
	t.Cleanup(pdp.Close)
	return pdp.URL
}

// running is one serve call in progress.
type running struct {
	url    string
	asked  string // the address serve asked to bind
	log    *syncBuffer
	cancel context.CancelFunc
	done   chan struct{} // closed when serve has returned, err then holds what it returned
	err    error
}

// startServe runs serve on a loopback listener the test owns, and records the
// address serve asked for so the configuration's effect is visible.
func startServe(t *testing.T) *running {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &running{log: &syncBuffer{}, done: make(chan struct{}), url: "http://" + ln.Addr().String()}
	var mu sync.Mutex
	listen := func(network, address string) (net.Listener, error) {
		mu.Lock()
		r.asked = address
		mu.Unlock()
		return ln, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	log := slog.New(slog.NewTextHandler(r.log, nil))
	go func() { r.err = serve(ctx, log, listen); close(r.done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
		}
	})
	waitForAnswer(t, r.url)
	mu.Lock()
	defer mu.Unlock()
	return r
}

func waitForAnswer(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Post(url, "application/json",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("nothing answered on the listener serve was given, at %s", url)
}

// stop cancels serve and returns what it returned.
func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	select {
	case <-r.done:
		return r.err
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after it was told to stop")
		return nil
	}
}

func (r *running) fetch(t *testing.T, key, url string) map[string]any {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url",
		"arguments":{"url":"` + url + `"}}}`
	req, _ := http.NewRequest(http.MethodPost, r.url, strings.NewReader(body))
	if key != "" {
		req.Header.Set(mcp.ClientKeyHeader, key)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// The process binds where SCOPYX_ADDR says (the loopback default when unset),
// answers the MCP surface there, says at startup what it is enforcing with,
// and returns cleanly when told to stop rather than waiting for a signal.
func TestTheServiceAnswersOnItsListenerAndStopsWhenAsked(t *testing.T) {
	cleanEnv(t)
	t.Setenv("SCOPYX_WARDRYX", fakePolicyPlane(t))

	r := startServe(t)

	if r.asked != defaultAddr {
		t.Errorf("serve asked to bind %q, want the loopback default %q", r.asked, defaultAddr)
	}
	resp, err := client.Post(r.url, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "fetch_url") {
		t.Errorf("the listener must serve the MCP surface, tools/list said %s", b)
	}

	if err := r.stop(t); err != nil {
		t.Errorf("a requested stop must return nil, got %v", err)
	}
	logged := r.log.String()
	for _, want := range []string{"scopyx listening", "backend=passthrough-http",
		"fetches_per_hour=500", "shutting down"} {
		if !strings.Contains(logged, want) {
			t.Errorf("startup and shutdown must log %q, got:\n%s", want, logged)
		}
	}
	if strings.Contains(logged, "NO per-hour fetch cap") {
		t.Errorf("a capped deployment must not be warned about as uncapped:\n%s", logged)
	}
}

// SCOPYX_ADDR reaches the bind. A deployment that set it and got the default
// would be listening somewhere nobody configured.
func TestTheConfiguredAddressIsTheOneBound(t *testing.T) {
	cleanEnv(t)
	t.Setenv("SCOPYX_WARDRYX", fakePolicyPlane(t))
	t.Setenv("SCOPYX_ADDR", "127.0.0.1:4999")

	r := startServe(t)
	if r.asked != "127.0.0.1:4999" {
		t.Errorf("serve asked to bind %q, want the configured 127.0.0.1:4999", r.asked)
	}
}

// The whole pipeline as main assembles it: a credential names the agent, the
// real resolver and address rules refuse a loopback destination, and the
// journal SCOPYX_EVENTS names holds the refusal under that agent.
func TestAFetchThroughTheRunningServiceIsDecidedAndRecordedUnderTheCallersAgent(t *testing.T) {
	cleanEnv(t)
	t.Setenv("SCOPYX_WARDRYX", fakePolicyPlane(t))
	t.Setenv("SCOPYX_KEYS", "k1=agent://acme.example/support-bot")
	journal := filepath.Join(t.TempDir(), "events.ndjson")
	t.Setenv("SCOPYX_EVENTS", journal)

	r := startServe(t)
	out := r.fetch(t, "k1", "http://127.0.0.1:1/private")
	res, _ := out["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("a loopback destination must be refused, got %v", out)
	}
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}

	evs, err := event.ReadFile(journal)
	if err != nil {
		t.Fatalf("reading the journal SCOPYX_EVENTS named: %v", err)
	}
	if len(evs) != 1 || evs[0].Type != record.TypeBlocked {
		t.Fatalf("want one web_blocked event, got %+v", evs)
	}
	if evs[0].AgentID != "agent://acme.example/support-bot" {
		t.Errorf("the record must name the agent the key belongs to, got %q", evs[0].AgentID)
	}
	if v, _ := evs[0].Data["verdict"].(string); v != "deny_address" {
		t.Errorf("verdict = %q, want deny_address from the real address rules", v)
	}
}

// A refusal for a caller with no agent identity cannot be journalled, and the
// process says so on the way out rather than leaving a record that looks whole.
func TestAnIncompleteRecordIsReportedAtShutdown(t *testing.T) {
	cleanEnv(t)
	t.Setenv("SCOPYX_WARDRYX", fakePolicyPlane(t))
	t.Setenv("SCOPYX_EVENTS", filepath.Join(t.TempDir(), "events.ndjson"))

	r := startServe(t)
	out := r.fetch(t, "", "http://127.0.0.1:1/private")
	if res, _ := out["result"].(map[string]any); res["isError"] != true {
		t.Fatalf("a loopback destination must be refused, got %v", out)
	}
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	logged := r.log.String()
	if !strings.Contains(logged, "the record is incomplete") || !strings.Contains(logged, "skipped_no_agent_id=1") {
		t.Errorf("shutdown must report the skipped record, got:\n%s", logged)
	}
}

// Invariant 8: an uncapped deployment is a decision, and startup says so.
func TestAnUncappedDeploymentIsWarnedAboutAtStartup(t *testing.T) {
	cleanEnv(t)
	t.Setenv("SCOPYX_WARDRYX", fakePolicyPlane(t))
	t.Setenv("SCOPYX_MAX_FETCHES_PER_HOUR", "0")

	r := startServe(t)
	_ = r.stop(t)
	logged := r.log.String()
	if !strings.Contains(logged, "NO per-hour fetch cap") || !strings.Contains(logged, "fetches_per_hour=UNCAPPED") {
		t.Errorf("an uncapped deployment must be said out loud, got:\n%s", logged)
	}
}

// Reading a credential from params._meta moves where the door reads, so
// turning it on is announced.
func TestReadingTheKeyFromMetaIsAnnouncedWhenTurnedOn(t *testing.T) {
	cleanEnv(t)
	t.Setenv("SCOPYX_WARDRYX", fakePolicyPlane(t))
	t.Setenv("SCOPYX_ACCEPT_KEY_IN_META", "1")

	r := startServe(t)
	_ = r.stop(t)
	if logged := r.log.String(); !strings.Contains(logged, mcp.MetaKeyName) {
		t.Errorf("startup must name the _meta entry it now reads, got:\n%s", logged)
	}
}

// Every configuration refusal happens before anything binds: an operator who
// got one of these has nothing listening, half-configured, on their network.
func TestAConfigurationThatCannotRunIsRefusedBeforeAnythingBinds(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"no policy plane", map[string]string{}, "SCOPYX_WARDRYX"},
		{"open bind with no credential", map[string]string{
			"SCOPYX_WARDRYX": "http://pdp.invalid", "SCOPYX_ADDR": "0.0.0.0:4300"}, "SCOPYX_KEYS"},
		{"unknown robots mode", map[string]string{
			"SCOPYX_WARDRYX": "http://pdp.invalid", "SCOPYX_ROBOTS": "sometimes"}, "SCOPYX_ROBOTS"},
		{"a backend that cannot be built", map[string]string{
			"SCOPYX_WARDRYX": "http://pdp.invalid", "SCOPYX_BACKEND": "external"}, "SCOPYX_EXTERNAL_ENDPOINT"},
		{"a journal that cannot be opened", map[string]string{
			"SCOPYX_WARDRYX": "http://pdp.invalid", "SCOPYX_EVENTS": filepath.Join(notADir, "events.ndjson")}, "journal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			bound := false
			listen := func(string, string) (net.Listener, error) {
				bound = true
				return nil, errors.New("must not be reached")
			}
			done := make(chan error, 1)
			go func() {
				done <- serve(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), listen)
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("want a refusal naming %q, got %v", tc.want, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("serve kept running on a configuration it should have refused")
			}
			if bound {
				t.Error("serve bound a listener before refusing the configuration")
			}
		})
	}
}

// A bind that fails stops startup with the reason, rather than leaving a
// process that looks up and answers nothing.
func TestABindThatFailsStopsStartupWithItsReason(t *testing.T) {
	cleanEnv(t)
	t.Setenv("SCOPYX_WARDRYX", fakePolicyPlane(t))
	listen := func(string, string) (net.Listener, error) {
		return nil, errors.New("address already in use")
	}
	done := make(chan error, 1)
	go func() { done <- serve(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), listen) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "address already in use") {
			t.Errorf("want the bind error, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve kept running after its listener failed")
	}
}

// A listener that dies under a running server ends the process with the error,
// rather than leaving it waiting for a stop that will never matter.
func TestAListenerThatFailsWhileServingEndsTheProcessWithTheError(t *testing.T) {
	cleanEnv(t)
	t.Setenv("SCOPYX_WARDRYX", fakePolicyPlane(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close() // Accept now fails at once, and not with ErrServerClosed
	listen := func(string, string) (net.Listener, error) { return ln, nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), listen) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a dead listener must end serve with an error, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve kept waiting after its listener failed")
	}
}
