package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	metaKey   = "k1"
	metaAgent = "agent://acme.example/reader"
	metaKeys  = metaKey + "=" + metaAgent + ",k2=agent://acme.example/other"
)

func serveMeta(t *testing.T, on bool, f Fetcher) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(&Server{Keys: ParseKeys(metaKeys), Fetcher: f, RunID: "run-1", AcceptKeyInMeta: on})
	t.Cleanup(srv.Close)
	return srv
}

// post answers with the status, because the door speaks in statuses and the
// dispatch in JSON-RPC, and which of the two answered is most of these tests.
func post(t *testing.T, srv *httptest.Server, header, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if header != "" {
		req.Header.Set(ClientKeyHeader, header)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, out.String()
}

// call is one tools/call carrying `key` in _meta.
func call(key string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url",`+
		`"arguments":{"url":"https://example.com/"},"_meta":{"scopyx/key":%q}}}`, key)
}

func TestACredentialInMetaAdmitsTheCallAndNamesItsAgent(t *testing.T) {
	f := &recordingFetcher{}
	status, body := post(t, serveMeta(t, true, f), "", call(metaKey))
	if status != http.StatusOK || !strings.Contains(body, "the page") {
		t.Fatalf("status %d: %s", status, body)
	}
	if f.last.AgentID != metaAgent {
		t.Errorf("the key names %q and the fetch was attributed to %q", metaAgent, f.last.AgentID)
	}
	if f.last.URL != "https://example.com/" {
		t.Errorf("the call arrived as %+v", f.last)
	}
}

func TestWithTheFlagOffTheEntryIsNotACredential(t *testing.T) {
	f := &recordingFetcher{}
	status, _ := post(t, serveMeta(t, false, f), "", call(metaKey))
	if status != http.StatusUnauthorized {
		t.Fatalf("status %d: the door is the header unless an operator says otherwise", status)
	}
	if f.last.URL != "" {
		t.Errorf("a refused call reached the fetcher: %+v", f.last)
	}
}

func TestWithTheFlagOffTheDoorStillRefusesBeforeTheBody(t *testing.T) {
	status, body := post(t, serveMeta(t, false, &recordingFetcher{}), "", "not json at all")
	if status != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", status, body)
	}
}

func TestAWrongKeyInMetaIsRefused(t *testing.T) {
	// The second is a handle the broker had no secret for, which arrives as text.
	for _, key := range []string{"not-a-key", "{{secret:scopyx_key}}", ""} {
		f := &recordingFetcher{}
		status, _ := post(t, serveMeta(t, true, f), "", call(key))
		if status != http.StatusUnauthorized {
			t.Errorf("key %q: status %d", key, status)
		}
		if f.last.URL != "" {
			t.Errorf("key %q reached the fetcher: %+v", key, f.last)
		}
	}
}

func TestTheHeaderWinsWhenBothAreSent(t *testing.T) {
	f := &recordingFetcher{}
	status, _ := post(t, serveMeta(t, true, f), "k2", call(metaKey))
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if f.last.AgentID != "agent://acme.example/other" {
		t.Errorf("attributed to %q, and the header's key names another agent", f.last.AgentID)
	}

	f = &recordingFetcher{}
	status, _ = post(t, serveMeta(t, true, f), "wrong", call(metaKey))
	if status != http.StatusUnauthorized {
		t.Fatalf("status %d: a bad header is not rescued by the body", status)
	}
	if f.last.URL != "" {
		t.Errorf("refused and still fetched: %+v", f.last)
	}
}

// This server dispatches on the method alone, so a missing id is no way past the
// door: reading it as a notification would be.
func TestACallWithNoIDStillNeedsACredential(t *testing.T) {
	f := &recordingFetcher{}
	status, _ := post(t, serveMeta(t, true, f), "",
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://example.com/"}}}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("status %d", status)
	}
	if f.last.URL != "" {
		t.Errorf("fetched with no credential: %+v", f.last)
	}
}

func TestTheHandshakeAndTheListingNeedNoCredentialBehindTheBroker(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	} {
		on, _ := post(t, serveMeta(t, true, &recordingFetcher{}), "", body)
		if on == http.StatusUnauthorized {
			t.Errorf("%s: refused with the flag on", body)
		}
		off, _ := post(t, serveMeta(t, false, &recordingFetcher{}), "", body)
		if off != http.StatusUnauthorized {
			t.Errorf("%s: answered %d with the flag off", body, off)
		}
	}
}

func TestAnythingElseWithNoCredentialIsRefused(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`,
		`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}{"jsonrpc":"2.0","id":2,"method":"tools/call"}`,
		`not json at all`,
		``,
	} {
		f := &recordingFetcher{}
		status, _ := post(t, serveMeta(t, true, f), "", body)
		if status != http.StatusUnauthorized {
			t.Errorf("%q: status %d", body, status)
		}
		if f.last.URL != "" {
			t.Errorf("%q reached the fetcher", body)
		}
	}
}

func TestABodyOverTheBoundCarriesNoCredential(t *testing.T) {
	padding := strings.Repeat("x", maxRequestBytes)
	body := strings.Replace(call(metaKey), "fetch_url", padding, 1)
	f := &recordingFetcher{}
	status, _ := post(t, serveMeta(t, true, f), "", body)
	if status != http.StatusUnauthorized {
		t.Fatalf("status %d", status)
	}
	if f.last.URL != "" {
		t.Errorf("fetched: %+v", f.last)
	}
}

func TestTheEntryIsRemovedAndTheRestOfTheMessageStays(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"browse",` +
		`"arguments":{"url":"https://example.com/"},"_meta":{"scopyx/key":"k1","progressToken":"p"}}}`
	key, stripped, ok := extractMetaKey([]byte(in))
	if !ok || key != "k1" {
		t.Fatalf("key %q ok %v", key, ok)
	}
	if strings.Contains(string(stripped), "scopyx/key") || strings.Contains(string(stripped), `"k1"`) {
		t.Errorf("the entry survived: %s", stripped)
	}
	var got rpcRequest
	if err := json.Unmarshal(stripped, &got); err != nil {
		t.Fatal(err)
	}
	if got.Method != "tools/call" || string(got.ID) != "7" {
		t.Errorf("the envelope moved: %s", stripped)
	}
	for _, want := range []string{`"name":"browse"`, `"url":"https://example.com/"`, `"progressToken":"p"`} {
		if !strings.Contains(string(got.Params), want) {
			t.Errorf("%s is gone from %s", want, got.Params)
		}
	}

	// The only entry in `_meta` takes `_meta` with it.
	_, stripped, _ = extractMetaKey([]byte(call("k1")))
	if strings.Contains(string(stripped), "_meta") {
		t.Errorf("an empty _meta was left behind: %s", stripped)
	}
}

// The dispatch reads r.Body after the door, so the door leaving the entry there is
// the difference between "stops at the door" and "nothing happens to read it yet".
func TestTheDoorLeavesTheRequestWithNoEntryInIt(t *testing.T) {
	for _, header := range []string{"", "k2"} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(call(metaKey)))
		w := httptest.NewRecorder()
		doorFromBody(w, r, header)
		left, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(left), "scopyx/key") || strings.Contains(string(left), metaKey) {
			t.Errorf("header %q: the entry is still in the body: %s", header, left)
		}
		if !strings.Contains(string(left), "fetch_url") {
			t.Errorf("header %q: the call went with it: %s", header, left)
		}
	}
}

func TestAnythingThatIsNotTheEntryIsLeftExactlyAsItCame(t *testing.T) {
	for _, in := range []string{
		`not json`,
		``,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"scopyx/key":"k1"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"browse"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":"not an object"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"other":"x"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"scopyx/key":5}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1,2]}`,
	} {
		key, stripped, ok := extractMetaKey([]byte(in))
		if ok || key != "" || string(stripped) != in {
			t.Errorf("%q: key %q ok %v stripped %q", in, key, ok, stripped)
		}
	}
}

// What a fetch is handed, whole: the key is the one value nothing past the door
// may hold, and a Call that grew a place for it would pass every test above.
func TestNothingPastTheDoorHoldsTheKey(t *testing.T) {
	const secret = "a-long-and-recognisable-key"
	srv := httptest.NewServer(&Server{
		Keys:            ParseKeys(secret + "=" + metaAgent),
		Fetcher:         &recordingFetcher{},
		RunID:           "run-1",
		AcceptKeyInMeta: true,
	})
	t.Cleanup(srv.Close)
	f := srv.Config.Handler.(*Server).Fetcher.(*recordingFetcher)

	status, body := post(t, srv, "", call(secret))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	if strings.Contains(fmt.Sprintf("%+v", f.last), secret) {
		t.Errorf("the fetch was handed the key: %+v", f.last)
	}
	if strings.Contains(body, secret) {
		t.Errorf("the answer carries the key: %s", body)
	}
}

// 200 seeded bodies from the bytes the door cares about. None carries a key this
// door knows, so none may reach a fetch, whatever it parses as.
func TestHostileBodiesNeverPanicAndNeverReachAFetch(t *testing.T) {
	pieces := []string{
		`{`, `}`, `"method"`, `:`, `,`, `"tools/call"`, `"tools/list"`, `"initialize"`, `"params"`,
		`"_meta"`, `"scopyx/key"`, `"wrong"`, `null`, `[`, `]`, `"id"`, `1`, `"jsonrpc"`, `"2.0"`,
	}
	state := uint64(0x5c0_9e11_d00_2026)
	next := func(n uint64) uint64 {
		state = state*6364136223846793005 + 1442695040888963407
		return (state >> 33) % n
	}
	f := &recordingFetcher{}
	srv := serveMeta(t, true, f)
	for i := 0; i < 200; i++ {
		var b strings.Builder
		for j := uint64(0); j < 3+next(20); j++ {
			b.WriteString(pieces[next(uint64(len(pieces)))])
		}
		post(t, srv, "", b.String())
		if f.last.URL != "" {
			t.Fatalf("case %d reached a fetch: %s", i, b.String())
		}
	}
}
