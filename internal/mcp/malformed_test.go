package mcp

import (
	"net/http"
	"strings"
	"testing"
)

// Requests that are not a well-formed call. Each gets the JSON-RPC error a
// client can act on, and none of them reaches the fetcher: a parser that
// guessed at what a broken request meant is a parser that fetches something
// nobody asked for.
func TestAMalformedRequestGetsItsJSONRPCErrorAndNeverReachesAFetch(t *testing.T) {
	cases := []struct {
		name string
		body string
		code float64
		says string
	}{
		{"not JSON", `this is not json`, codeParse, "could not be parsed"},
		{"wrong protocol version", `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`, codeInvalidRequest, `"jsonrpc" must be "2.0"`},
		{"unknown method", `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, codeMethodNotFound, "unknown method resources/list"},
		{"params not an object", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":5}`, codeInvalidParams, "params could not be read"},
		{"unknown tool", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell",
			"arguments":{"url":"https://example.com/"}}}`, codeMethodNotFound, "unknown tool shell"},
		{"arguments not an object", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"browse",
			"arguments":["https://example.com/"]}}`, codeInvalidParams, "arguments could not be read"},
		{"a url that is not a string", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"browse",
			"arguments":{"url":42}}}`, codeInvalidParams, `requires "url"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &recordingFetcher{}
			srv := serve(t, "k1=agent://acme.example/bot", f)

			_, out := rpc(t, srv, "k1", tc.body)
			e, _ := out["error"].(map[string]any)
			if e == nil {
				t.Fatalf("want a JSON-RPC error, got %v", out)
			}
			if e["code"] != tc.code {
				t.Errorf("code = %v, want %v", e["code"], tc.code)
			}
			if msg, _ := e["message"].(string); !strings.Contains(msg, tc.says) {
				t.Errorf("message = %q, want it to say %q", msg, tc.says)
			}
			if f.last.URL != "" || f.last.Tool != "" {
				t.Errorf("a malformed request reached the fetcher: %+v", f.last)
			}
		})
	}
}

// Anything but POST is turned away before the door and the parser.
func TestOnlyPostIsAnswered(t *testing.T) {
	f := &recordingFetcher{}
	srv := serve(t, "k1", f)
	resp, err := http.Get(srv.URL + "?method=tools/call")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET got %d, want 405", resp.StatusCode)
	}
	if f.last.Tool != "" {
		t.Error("a GET reached the fetcher")
	}
}

// An optional enum argument sent empty is read as absent and the call goes
// through with the default, rather than refused as a value outside the enum.
func TestAnEmptyOptionalEnumIsReadAsAbsent(t *testing.T) {
	f := &recordingFetcher{}
	srv := serve(t, "k1", f)
	_, out := rpc(t, srv, "k1", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"browse",
		"arguments":{"url":"https://example.com/","extract":""}}}`)
	if out["error"] != nil {
		t.Fatalf("an empty optional enum was refused: %v", out)
	}
	if f.last.URL != "https://example.com/" || f.last.Extract != "" {
		t.Errorf("the fetcher got %+v, want the url and no extract", f.last)
	}
}

// A credential list entry with no key creates no credential, and a key the
// door does not accept has no identity, whatever the list says.
func TestAnEntryWithNoKeyIsNoCredentialAndAnUnknownKeyHasNoIdentity(t *testing.T) {
	k := ParseKeys("k1=agent://acme.example/bot, =agent://acme.example/admin")
	if k.Allow("") {
		t.Error("an entry with no key must not admit an empty credential")
	}
	if id := k.Identity(""); id != "" {
		t.Errorf("an empty credential was given the identity %q", id)
	}
	if id := k.Identity("k9"); id != "" {
		t.Errorf("an unknown credential was given the identity %q", id)
	}
	if id := k.Identity("k1"); id != "agent://acme.example/bot" {
		t.Errorf("k1's identity = %q", id)
	}
}
