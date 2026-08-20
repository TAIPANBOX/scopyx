package backend

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// What this backend sends to the operator's own fetching service, and what it
// does with each answer that service can give. None of it had been read back.
//
// This backend is the one that reaches outside the process, so its request
// shape is a contract with somebody else's software, and its error text is the
// whole of what an operator sees when that software misbehaves.

func TestItPostsTheRequestShapeTheOperatorsServiceWasPromised(t *testing.T) {
	t.Parallel()

	var gotMethod, gotContentType, gotAuth string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"final_url":"https://example.com/after","content":"hi","status":200}`))
	}))
	defer server.Close()

	e := NewExternal("acme", server.URL, "secret-key", 5*time.Second)
	res, err := e.Fetch(context.Background(), Request{
		URL: "https://example.com/", Extract: "text", WaitFor: "#main",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type %q", gotContentType)
	}
	if gotAuth != "Bearer secret-key" {
		t.Errorf("authorization %q, want the bearer the operator configured", gotAuth)
	}

	var sent map[string]any
	if err := json.Unmarshal(gotBody, &sent); err != nil {
		t.Fatalf("the body must be JSON: %v (%s)", err, gotBody)
	}
	for k, want := range map[string]any{
		"url": "https://example.com/", "extract": "text", "wait_for": "#main",
	} {
		if sent[k] != want {
			t.Errorf("field %q: sent %v, want %v", k, sent[k], want)
		}
	}

	if res.FinalURL != "https://example.com/after" {
		t.Errorf("final url %q", res.FinalURL)
	}
	if string(res.Body) != "hi" {
		t.Errorf("body %q", res.Body)
	}
	if res.HTTPStatus != 200 {
		t.Errorf("status %d", res.HTTPStatus)
	}

	// Nil, not empty. This service does not report what the page asked for, and
	// an empty slice would say it asked for nothing. Those are different
	// statements and the record carries whichever one this puts there.
	if res.Subresources != nil {
		t.Errorf("subresources must be nil when the service does not report them, got %#v", res.Subresources)
	}
}

func TestNoKeyMeansNoAuthorizationHeaderRatherThanAnEmptyBearer(t *testing.T) {
	t.Parallel()

	// An empty `Authorization: Bearer ` is a header a service may reject or,
	// worse, accept as an anonymous principal. Absent is the honest form.
	var sawAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawAuth = r.Header["Authorization"]
		_, _ = w.Write([]byte(`{"content":"","status":200}`))
	}))
	defer server.Close()

	e := NewExternal("acme", server.URL, "", 5*time.Second)
	if _, err := e.Fetch(context.Background(), Request{URL: "https://example.com/"}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if sawAuth {
		t.Error("no key configured must mean no Authorization header at all")
	}
}

func TestAnAnswerWithNoFinalURLKeepsTheURLThatWasAskedFor(t *testing.T) {
	t.Parallel()

	// An empty final_url would otherwise put an empty string in the record,
	// and a record that cannot say which URL it is about is not a record.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"content":"body","status":200}`))
	}))
	defer server.Close()

	e := NewExternal("acme", server.URL, "", 5*time.Second)
	res, err := e.Fetch(context.Background(), Request{URL: "https://example.com/asked"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.FinalURL != "https://example.com/asked" {
		t.Errorf("final url %q, want the URL that was requested", res.FinalURL)
	}
}

func TestAServiceThatRefusesIsReportedWithItsStatusAndItsOwnWords(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("quota exhausted for this tenant"))
	}))
	defer server.Close()

	e := NewExternal("acme", server.URL, "", 5*time.Second)
	_, err := e.Fetch(context.Background(), Request{URL: "https://example.com/"})
	if err == nil {
		t.Fatal("a non-200 must be an error, not an empty result")
	}
	msg := err.Error()
	for _, want := range []string{"403", "quota exhausted", "acme"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error must carry %q so an operator can act on it, got: %s", want, msg)
		}
	}
}

func TestAnAnswerThatIsNotJSONIsAnErrorRatherThanAnEmptyPage(t *testing.T) {
	t.Parallel()

	// The same shape as everywhere else in this estate: 200 plus a sign-in
	// page. An empty result here would be recorded as a page that legitimately
	// had no content.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Sign in</body></html>"))
	}))
	defer server.Close()

	e := NewExternal("acme", server.URL, "", 5*time.Second)
	if _, err := e.Fetch(context.Background(), Request{URL: "https://example.com/"}); err == nil {
		t.Fatal("a non-JSON answer must be an error")
	}
}

func TestAnUnreachableServiceNamesItselfAndLeaksNoKey(t *testing.T) {
	t.Parallel()

	const key = "secret-key-do-not-log"
	e := NewExternal("acme", "http://127.0.0.1:1/fetch", key, 2*time.Second)
	_, err := e.Fetch(context.Background(), Request{URL: "https://example.com/"})
	if err == nil {
		t.Fatal("an unreachable service must be an error")
	}
	if !strings.Contains(err.Error(), "acme") {
		t.Errorf("the error must name which backend failed, got: %v", err)
	}
	if strings.Contains(err.Error(), key) {
		t.Errorf("the configured key reached an error message: %v", err)
	}
}
