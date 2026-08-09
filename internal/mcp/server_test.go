package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// recordingFetcher answers, and remembers exactly what the server handed it.
//
// What it remembers is the assertion in most of this file: a test that only
// looked at the response could not tell a field that was refused from one that
// was quietly dropped and then used.
type recordingFetcher struct {
	last Call
	err  error
}

func (f *recordingFetcher) Fetch(_ context.Context, c Call) (Answer, error) {
	f.last = c
	if f.err != nil {
		return Answer{}, f.err
	}
	return Answer{
		Body:     []byte("the page"),
		FinalURL: c.URL,
		Fidelity: decide.Fidelity{Backend: "fixture", Enforcement: decide.EnforcementPerRequest},
	}, nil
}

func serve(t *testing.T, keys string, f Fetcher) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(&Server{Keys: ParseKeys(keys), Fetcher: f, RunID: "run-1"})
	t.Cleanup(srv.Close)
	return srv
}

func rpc(t *testing.T, srv *httptest.Server, key, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set(ClientKeyHeader, key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// Invariant 3, enforced rather than declared.
//
// `additionalProperties: false` in the published schema means nothing on its
// own: a schema that declares a closed shape beside a server that ignores extra
// fields is the "declared but unheld" control this estate keeps finding. The
// field must be REFUSED, and the fetcher must never have seen the call.
func TestAHeaderArgumentIsRefusedAndTheFetchNeverHappens(t *testing.T) {
	f := &recordingFetcher{}
	srv := serve(t, "k1=agent://acme.example/bot", f)

	for _, field := range []string{"headers", "cookie", "authorization", "proxy", "user_agent"} {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url",
			"arguments":{"url":"https://example.com/","` + field + `":{"X-Secret":"hunter2"}}}}`
		_, out := rpc(t, srv, "k1", body)

		e, ok := out["error"].(map[string]any)
		if !ok {
			t.Errorf("%s: the call was not refused, got %v", field, out)
			continue
		}
		if msg, _ := e["message"].(string); !strings.Contains(msg, field) {
			t.Errorf("%s: the refusal must name the field, got %q", field, msg)
		}
		if f.last.URL != "" {
			t.Fatalf("%s: the fetcher was reached anyway, with %+v", field, f.last)
		}
	}
}

// The other half of the same rule. A field the caller believes was sent is
// worse than one that was refused, because the caller acts on the belief.
func TestAnUnknownArgumentIsNamedRatherThanSilentlyDropped(t *testing.T) {
	srv := serve(t, "k1=agent://acme.example/bot", &recordingFetcher{})
	_, out := rpc(t, srv, "k1",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url",
		 "arguments":{"url":"https://example.com/","follow_redirects":false}}}`)

	e, ok := out["error"].(map[string]any)
	if !ok {
		t.Fatalf("an unknown argument must be refused, got %v", out)
	}
	msg, _ := e["message"].(string)
	if !strings.Contains(msg, "follow_redirects") {
		t.Errorf("the message must name what was refused, got %q", msg)
	}
}

// Invariant 6. Identity comes from an authenticated caller and never from a
// claim, so a body that names an agent must not be able to name one.
func TestTheAgentIdentityComesFromTheCredentialAndNotFromTheBody(t *testing.T) {
	f := &recordingFetcher{}
	srv := serve(t, "k1=agent://acme.example/the-real-one", f)

	_, _ = rpc(t, srv, "k1",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url",
		 "arguments":{"url":"https://example.com/"}}}`)

	if f.last.AgentID != "agent://acme.example/the-real-one" {
		t.Errorf("AgentID = %q, want the identity the credential carries", f.last.AgentID)
	}
}

// A credential that names nobody still authenticates, and every fetch through
// it reaches the policy plane with no subject, which fails closed downstream.
// Substituting anything here would be inventing an identity.
func TestACredentialThatNamesNobodyYieldsNoIdentityRatherThanAFabricatedOne(t *testing.T) {
	f := &recordingFetcher{}
	srv := serve(t, "bare-key", f)

	_, _ = rpc(t, srv, "bare-key",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url",
		 "arguments":{"url":"https://example.com/"}}}`)

	if f.last.URL == "" {
		t.Fatal("the call should have reached the fetcher; the door accepted the credential")
	}
	if f.last.AgentID != "" {
		t.Errorf("AgentID = %q, want empty: nothing may be substituted for an identity", f.last.AgentID)
	}
}

// The door is before the parser, so an unauthenticated caller cannot reach the
// tool dispatch at all.
func TestAnUnknownCredentialIsRefusedBeforeAnythingIsParsed(t *testing.T) {
	f := &recordingFetcher{}
	srv := serve(t, "k1=agent://acme.example/bot", f)

	status, _ := rpc(t, srv, "wrong", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	if f.last.URL != "" {
		t.Error("the fetcher was reached by an unauthenticated caller")
	}
}

// A refusal is a tool RESULT, not a transport error. A client that gets a
// protocol error concludes the server is broken and retries; one that gets a
// result explaining the refusal can tell the agent why.
func TestARefusalComesBackAsAToolResultTheAgentCanRead(t *testing.T) {
	f := &recordingFetcher{err: errors.New("deny_policy: evil.example is not in the domains this agent may reach")}
	srv := serve(t, "k1=agent://acme.example/bot", f)

	_, out := rpc(t, srv, "k1",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url",
		 "arguments":{"url":"https://evil.example/"}}}`)

	if _, isProtocolError := out["error"]; isProtocolError {
		t.Fatalf("a refusal must not be a protocol error, got %v", out["error"])
	}
	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", out)
	}
	if res["isError"] != true {
		t.Error("the result must be marked as an error the agent can act on")
	}
	text := firstText(t, res)
	if !strings.Contains(text, "not in the domains") {
		t.Errorf("the agent must be told WHY, got %q", text)
	}
}

// Invariant 5. A field the caller has to ask for is a field nobody asks for, so
// the fidelity block travels with every answer.
func TestEveryAnswerCarriesTheFidelityBlockWithoutBeingAskedFor(t *testing.T) {
	srv := serve(t, "k1=agent://acme.example/bot", &recordingFetcher{})
	_, out := rpc(t, srv, "k1",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"browse",
		 "arguments":{"url":"https://example.com/"}}}`)

	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", out)
	}
	sc, ok := res["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("no structuredContent: %v", res)
	}
	fid, ok := sc["fidelity"].(map[string]any)
	if !ok {
		t.Fatalf("no fidelity block: %v", sc)
	}
	if fid["backend"] != "fixture" {
		t.Errorf("backend = %v, want the one that answered", fid["backend"])
	}
	if _, ok := fid["subresources_requested"]; !ok {
		t.Error("the counts must be present even when null, or a reader cannot tell unknown from zero")
	}
}

// tools/list publishes the closed shape, which is what an MCP client reads
// before it ever calls anything.
func TestToolsListPublishesTheClosedSchema(t *testing.T) {
	srv := serve(t, "k1=agent://acme.example/bot", &recordingFetcher{})
	_, out := rpc(t, srv, "k1", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	res, _ := out["result"].(map[string]any)
	tools, ok := res["tools"].([]any)
	if !ok || len(tools) != 2 {
		t.Fatalf("want two tools, got %v", res)
	}
	for _, raw := range tools {
		tool := raw.(map[string]any)
		schema := tool["inputSchema"].(map[string]any)
		if schema["additionalProperties"] != false {
			t.Errorf("%v publishes an open schema", tool["name"])
		}
	}
}

// An enum the schema declares is enforced, for the same reason
// additionalProperties is: a value outside it would otherwise reach a backend
// as something nobody validated.
func TestAValueOutsideADeclaredEnumIsRefused(t *testing.T) {
	f := &recordingFetcher{}
	srv := serve(t, "k1=agent://acme.example/bot", f)
	_, out := rpc(t, srv, "k1",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"browse",
		 "arguments":{"url":"https://example.com/","extract":"pdf"}}}`)

	if _, ok := out["error"]; !ok {
		t.Fatalf("an undeclared enum value must be refused, got %v", out)
	}
	if f.last.URL != "" {
		t.Error("the fetcher was reached with an unvalidated value")
	}
}

func TestAMissingRequiredArgumentIsRefused(t *testing.T) {
	srv := serve(t, "k1=agent://acme.example/bot", &recordingFetcher{})
	_, out := rpc(t, srv, "k1",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url","arguments":{}}}`)
	if _, ok := out["error"]; !ok {
		t.Fatalf("a missing url must be refused, got %v", out)
	}
}

func firstText(t *testing.T, res map[string]any) string {
	t.Helper()
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("no content in %v", res)
	}
	first, _ := content[0].(map[string]any)
	s, _ := first["text"].(string)
	return s
}
