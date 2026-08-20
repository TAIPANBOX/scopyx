package decide

import (
	"net/netip"
	"strings"
	"testing"
)

// Subresource is invariant 1 at its narrowest point: a page is not one
// destination. It is a document plus fonts, images, scripts and XHR, each
// potentially a different host, and exfiltration through a subresource URL is
// the oldest trick there is.
//
// This is where a partial enforcement looks exactly like a complete one. The
// document was decided, the page rendered, the record has a row. The row just
// does not mention the img tag that carried the data out.

func TestASubresourceIsRefusedForTheSameReasonsADocumentIs(t *testing.T) {
	public := addrs(t, "93.184.216.34")

	cases := []struct {
		name    string
		raw     string
		res     []netip.Addr
		allow   []string
		verdict Verdict
		why     string
	}{
		{
			"a scheme that is not the web",
			"file:///etc/shadow", nil, nil, DenyScheme,
			"a file: subresource reads the host's disk through the renderer",
		},
		{
			"data URLs are not fetched either",
			"data:text/html;base64,PHNjcmlwdD4=", nil, nil, DenyScheme,
			"nothing here decides what a data URL contains",
		},
		{
			"a URL that will not parse",
			"ht!tp://%%%", nil, nil, DenyScheme,
			"an unparseable subresource is refused rather than guessed at",
		},
		{
			"an internal name",
			"http://api.internal/keys", public, nil, DenyHost,
			"a subresource is the easiest way to reach inside the deployment",
		},
		{
			"a name that resolves to the metadata endpoint",
			"https://harmless.example.com/pixel.gif",
			addrs(t, "169.254.169.254"), nil, DenyAddress,
			"the name says nothing; the address is the whole question",
		},
		{
			"one bad address among several",
			"https://harmless.example.com/pixel.gif",
			addrs(t, "93.184.216.34", "10.0.0.1"), nil, DenyAddress,
			"a host with several A records is refused if ANY of them is refused, " +
				"or the fetch picks whichever it likes and the check meant nothing",
		},
		{
			"a host outside the policy's domains",
			"https://somewhere-else.example/x.js", public,
			[]string{"good.example.com"}, DenyPolicy,
			"the allow-set is the operator's rule and applies to subresources too",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Subresource(c.raw, c.res, c.allow)
			if d.Verdict != c.verdict {
				t.Fatalf("Subresource(%q) = %s (%q), want %s. %s",
					c.raw, d.Verdict, d.Reason, c.verdict, c.why)
			}
			if strings.TrimSpace(d.Reason) == "" {
				t.Fatalf("refused with no reason, which is a row in the record " +
					"that says a subresource was blocked and not why")
			}
		})
	}
}

// An empty allow-set means the policy declared no domain restriction. It must
// NOT mean "allow nothing", which would break every page, and it must not
// weaken the address rules either.
func TestAnEmptyAllowSetIsNoRestrictionAndNotADenyAll(t *testing.T) {
	public := addrs(t, "93.184.216.34")

	for _, allow := range [][]string{nil, {}} {
		d := Subresource("https://cdn.example.com/app.js", public, allow)
		if d.Verdict != Allow {
			t.Fatalf("an empty allow-set refused an ordinary subresource: %s (%q). "+
				"nil and empty are opposite meanings here and this is the one "+
				"that means no restriction", d.Verdict, d.Reason)
		}
	}

	// And the address rules still apply with no allow-set at all.
	d := Subresource("https://cdn.example.com/app.js", addrs(t, "127.0.0.1"), nil)
	if d.Verdict != DenyAddress {
		t.Fatalf("with no allow-set, a loopback subresource was %s: the domain "+
			"rules being absent must not take the address rules with them",
			d.Verdict)
	}
}

// domainAllowed through its public door. The distinction it exists for is that
// a bare entry matches exactly and a dotted one matches below: suffix matching
// without it lets example.com match notexample.com, which is somebody else's
// domain that happens to end in the right letters.
func TestTheAllowSetMatchesExactlyUnlessItSaysOtherwise(t *testing.T) {
	public := addrs(t, "93.184.216.34")

	cases := []struct {
		host  string
		allow []string
		want  Verdict
		why   string
	}{
		{"example.com", []string{"example.com"}, Allow, "an exact entry matches the host"},
		{"notexample.com", []string{"example.com"}, DenyPolicy,
			"somebody else's domain that ends in the right letters"},
		{"cdn.example.com", []string{"example.com"}, DenyPolicy,
			"a bare entry is exact, so a subdomain is not covered by it"},
		{"cdn.example.com", []string{".example.com"}, Allow,
			"a leading dot means this domain and anything under it"},
		{"example.com", []string{".example.com"}, Allow,
			"and the dotted form covers the domain itself as well"},
		{"notexample.com", []string{".example.com"}, DenyPolicy,
			"the dotted form still must not match a different domain"},
		{"EXAMPLE.COM", []string{"example.com"}, Allow, "hosts are case-insensitive"},
		{"example.com.", []string{"example.com"}, Allow,
			"the fully qualified form is the same name"},
		{"example.com", []string{"  example.com  "}, Allow,
			"an entry with whitespace is the operator's typing, not a different domain"},
		{"example.com", []string{"", "example.com"}, Allow,
			"an empty entry is skipped rather than matching everything"},
		{"anything.at.all", []string{""}, DenyPolicy,
			"an allow-set of one empty string must not become allow-all"},
	}
	for _, c := range cases {
		t.Run(c.host+"_"+strings.Join(c.allow, ","), func(t *testing.T) {
			d := Subresource("https://"+strings.TrimSuffix(c.host, ".")+"/x", public, c.allow)
			// The trailing-dot case has to go through the raw URL to be real.
			if strings.HasSuffix(c.host, ".") {
				d = Subresource("https://"+c.host+"/x", public, c.allow)
			}
			if d.Verdict != c.want {
				t.Fatalf("host %q against %v = %s (%q), want %s. %s",
					c.host, c.allow, d.Verdict, d.Reason, c.want, c.why)
			}
		})
	}
}
