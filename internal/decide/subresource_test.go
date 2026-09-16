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
		policy  PolicyAnswer
		verdict Verdict
		why     string
	}{
		{
			"a scheme that is not the web",
			"file:///etc/shadow", nil, PolicyAnswer{Allowed: true}, DenyScheme,
			"a file: subresource reads the host's disk through the renderer",
		},
		{
			"data URLs are not fetched either",
			"data:text/html;base64,PHNjcmlwdD4=", nil, PolicyAnswer{Allowed: true}, DenyScheme,
			"nothing here decides what a data URL contains",
		},
		{
			"a URL that will not parse",
			"ht!tp://%%%", nil, PolicyAnswer{Allowed: true}, DenyScheme,
			"an unparseable subresource is refused rather than guessed at",
		},
		{
			"an internal name",
			"http://api.internal/keys", public, PolicyAnswer{Allowed: true}, DenyHost,
			"a subresource is the easiest way to reach inside the deployment",
		},
		{
			"a name that resolves to the metadata endpoint",
			"https://harmless.example.com/pixel.gif",
			addrs(t, "169.254.169.254"), PolicyAnswer{Allowed: true}, DenyAddress,
			"the name says nothing; the address is the whole question",
		},
		{
			"one bad address among several",
			"https://harmless.example.com/pixel.gif",
			addrs(t, "93.184.216.34", "10.0.0.1"), PolicyAnswer{Allowed: true}, DenyAddress,
			"a host with several A records is refused if ANY of them is refused, " +
				"or the fetch picks whichever it likes and the check meant nothing",
		},
		{
			"a host the policy plane refuses",
			"https://somewhere-else.example/x.js", public,
			PolicyAnswer{Allowed: false, Reason: "outside the policy"}, DenyPolicy,
			"the policy is the operator's rule and applies to subresources too",
		},
		{
			"a host the policy plane could not be asked about",
			"https://somewhere-else.example/x.js", public,
			PolicyAnswer{Unreachable: true, Reason: "the plane is down"}, DenyPolicyUnreachable,
			"nobody to ask is a refusal, and it is named as one",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Subresource(c.raw, c.res, c.policy)
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

// The address rules are read before the policy answer, and an allow does not
// reach past them: a subresource naming the metadata endpoint is refused even
// when the policy plane, which was never written to contemplate it, says yes.
func TestAPolicyAllowDoesNotReachPastTheAddressRulesForASubresource(t *testing.T) {
	d := Subresource("https://cdn.example.com/app.js", addrs(t, "127.0.0.1"), PolicyAnswer{Allowed: true})
	if d.Verdict != DenyAddress {
		t.Fatalf("a loopback subresource with a policy allow was %s: the address rules "+
			"come first and the policy cannot lift them", d.Verdict)
	}
}
