package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// CLAUDE.md invariant 3, held by the schema itself: a field that does not
// exist cannot be sent. This is the test the gate script mirrors.
func TestNoToolAcceptsAHeaderCookieOrCredential(t *testing.T) {
	for _, tool := range Tools() {
		for name := range tool.InputSchema.Properties {
			lower := strings.ToLower(name)
			for _, bad := range ForbiddenFields() {
				if lower == strings.ToLower(bad) {
					t.Errorf("tool %q accepts %q: a free-form header or credential field is a "+
						"laundering channel past the broker's DLP, and is how a plane that "+
						"refuses authenticated sessions acquires them one header at a time",
						tool.Name, name)
				}
			}
		}
	}
}

// Refusing an unknown field is not the same as ignoring one, and the
// difference matters to the caller: ignoring it leaves them believing their
// header was sent.
func TestEveryToolRefusesUnknownArgumentsRatherThanIgnoringThem(t *testing.T) {
	for _, tool := range Tools() {
		if tool.InputSchema.AdditionalProperties {
			t.Errorf("tool %q allows additional properties, so an unknown argument is silently "+
				"dropped and the caller believes it was sent", tool.Name)
		}
	}
}

// The names are not free choices: they are already in tokenfuse's default
// taint sources map, so an operator who turns the firewall on gets correct
// labelling with no configuration. Any other name lands in `unclassified`.
func TestTheToolNamesAreTheOnesTheTaintMapAlreadyKnows(t *testing.T) {
	want := map[string]bool{"browse": false, "fetch_url": false}
	for _, tool := range Tools() {
		if _, ok := want[tool.Name]; !ok {
			t.Errorf("unexpected tool %q: a name outside the taint map lands in `unclassified`", tool.Name)
			continue
		}
		want[tool.Name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tool %q is missing", name)
		}
	}
}

func TestEveryToolRequiresAUrlAndNothingElse(t *testing.T) {
	for _, tool := range Tools() {
		if len(tool.InputSchema.Required) != 1 || tool.InputSchema.Required[0] != "url" {
			t.Errorf("tool %q requires %v, want exactly [url]", tool.Name, tool.InputSchema.Required)
		}
	}
}

func TestTheSchemaSurvivesJsonRoundTrip(t *testing.T) {
	raw, err := json.Marshal(Tools())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"additionalProperties":false`) {
		t.Error("additionalProperties:false must reach the wire; it is the refusal, not a comment")
	}
	var back []Tool
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != len(Tools()) {
		t.Fatalf("got %d tools back, want %d", len(back), len(Tools()))
	}
}

// ------------------------------------------------------------------- the door

func TestAnOpenBindWithNoCredentialsRefusesToStart(t *testing.T) {
	msg := RefuseOpenBind("0.0.0.0:4300", ParseKeys(""), false)
	if msg == "" {
		t.Fatal("a non-loopback bind with no credentials must refuse to start")
	}
	for _, want := range []string{"0.0.0.0:4300", "SCOPYX_KEYS", "SCOPYX_ALLOW_OPEN_BIND"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must name %q so the operator can act on it: %s", want, msg)
		}
	}
}

// Loopback must not get harder for the common local case.
func TestALoopbackBindIsNeverRefused(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:4300", "127.0.0.2:4300", "localhost:4300", "[::1]:4300", "LOCALHOST:4300",
	} {
		if msg := RefuseOpenBind(addr, ParseKeys(""), false); msg != "" {
			t.Errorf("%s is loopback and must start: %s", addr, msg)
		}
	}
}

// 127.0.0.2 is the case a string match against "127.0.0.1" gets wrong, which
// is why the standard library answers this and not a comparison.
func TestLoopbackIsTheStandardLibrarysAnswerNotAStringMatch(t *testing.T) {
	if !IsLoopback("127.0.0.2:4300") {
		t.Error("the whole of 127.0.0.0/8 is loopback, not just 127.0.0.1")
	}
	if IsLoopback("10.0.0.1:4300") {
		t.Error("10.0.0.1 is not loopback")
	}
}

func TestConfiguredCredentialsAllowAWideBind(t *testing.T) {
	if msg := RefuseOpenBind("0.0.0.0:4300", ParseKeys("k1"), false); msg != "" {
		t.Errorf("a wide bind WITH credentials is a posture an operator may choose: %s", msg)
	}
}

func TestTheOperatorCanOptOutOfTheRefusal(t *testing.T) {
	if msg := RefuseOpenBind("0.0.0.0:4300", ParseKeys(""), true); msg != "" {
		t.Errorf("the opt-out must work: %s", msg)
	}
}

// A security opt-out that turns itself on when told "no" is the worst possible
// spelling, and any-non-empty-string is the obvious reading that does it.
func TestOnlyOneAndTrueTurnTheOptOutOn(t *testing.T) {
	for _, on := range []string{"1", "true", "TRUE", " true "} {
		if !TruthyEnv(on) {
			t.Errorf("%q must read as on", on)
		}
	}
	for _, off := range []string{"", "0", "no", "false", "yes", "please", "off"} {
		if TruthyEnv(off) {
			t.Errorf("%q must NOT read as on", off)
		}
	}
}

func TestAnUnconfiguredDoorAuthenticatesNobodyAndAConfiguredOneRefuses(t *testing.T) {
	open := ParseKeys("")
	if !open.Allow("") || !open.Allow("anything") {
		t.Error("an unconfigured door authenticates nobody, which is the loopback default")
	}
	closed := ParseKeys("k1, k2 ,")
	if !closed.Allow("k1") || !closed.Allow("k2") {
		t.Error("a configured credential must be accepted")
	}
	if closed.Allow("k3") {
		t.Error("an unknown credential must be refused")
	}
	if closed.Allow("") {
		t.Error("an empty credential must be refused; a blank entry in the list must not create one")
	}
}
