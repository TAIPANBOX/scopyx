package main

import (
	"net/http"
	"strings"
	"testing"
)

// Startup: which backend an operator gets, and what they are told when the
// configuration cannot produce one. None of this had ever been read back.
//
// It matters more here than the line count suggests. `SCOPYX_BACKEND` decides
// what enforcement every subsequent record claims, so a silent fallback to the
// wrong backend would not fail, it would produce records that overstate what
// this plane did.

func TestTheDefaultBackendIsPassthroughAndSaysSo(t *testing.T) {
	t.Setenv("SCOPYX_BACKEND", "")

	b, err := chooseBackend(&http.Client{})
	if err != nil {
		t.Fatalf("the default must produce a backend: %v", err)
	}
	if got := b.Name(); got != "passthrough-http" {
		t.Errorf("default backend is %q, want passthrough-http", got)
	}
}

func TestEachNamedBackendIsTheOneAskedFor(t *testing.T) {
	t.Setenv("SCOPYX_BACKEND", "external")
	t.Setenv("SCOPYX_EXTERNAL_ENDPOINT", "https://fetch.example")
	t.Setenv("SCOPYX_EXTERNAL_LABEL", "acme")

	b, err := chooseBackend(&http.Client{})
	if err != nil {
		t.Fatalf("external with an endpoint must build: %v", err)
	}
	if got := b.Name(); !strings.Contains(got, "acme") {
		t.Errorf("the label an operator set must reach the record, got %q", got)
	}
}

func TestExternalWithoutAnEndpointIsRefusedAtStartupAndNamesTheVariable(t *testing.T) {
	t.Setenv("SCOPYX_BACKEND", "external")
	t.Setenv("SCOPYX_EXTERNAL_ENDPOINT", "")

	_, err := chooseBackend(&http.Client{})
	if err == nil {
		t.Fatal("external with no endpoint must be refused at startup, not at the first fetch")
	}
	if !strings.Contains(err.Error(), "SCOPYX_EXTERNAL_ENDPOINT") {
		t.Errorf("the error must name the variable to set, got: %v", err)
	}
}

func TestAnUnknownBackendIsRefusedAndListsTheOnesThatExist(t *testing.T) {
	t.Setenv("SCOPYX_BACKEND", "playwright")

	_, err := chooseBackend(&http.Client{})
	if err == nil {
		t.Fatal("an unknown backend must be refused rather than silently defaulted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "playwright") {
		t.Errorf("the error must quote what was asked for, got: %s", msg)
	}
	for _, known := range []string{"passthrough", "external", "chromium"} {
		if !strings.Contains(msg, known) {
			t.Errorf("the error must list %q as a backend that exists, got: %s", known, msg)
		}
	}
}

// The three lines an operator reads at startup to know what this process will
// and will not do. Each one is a sentence somebody acts on.

func TestStartupSaysHowToTurnRecordingOnWhenItIsOff(t *testing.T) {
	off := journalState("")
	if !strings.Contains(off, "SCOPYX_EVENTS") {
		t.Errorf("with no journal the line must name the variable that enables it, got: %q", off)
	}
	if got := journalState("/var/log/scopyx.ndjson"); got != "/var/log/scopyx.ndjson" {
		t.Errorf("with a journal the line must be the path itself, got: %q", got)
	}
}

func TestAnAbsentSpendCeilingIsPrintedAsUncappedRatherThanAsZero(t *testing.T) {
	// "0" reads as "none allowed". The opposite is true, and an operator
	// scanning startup output has one word to go on.
	for _, limit := range []int64{0, -1} {
		if got := capState(limit); got != "UNCAPPED" {
			t.Errorf("capState(%d) = %q, want UNCAPPED", limit, got)
		}
	}
	if got := capState(500); got != "500" {
		t.Errorf("capState(500) = %q, want the number itself", got)
	}
}

func TestTheRunLabelIsPresentAndIdentifiesThisPlane(t *testing.T) {
	// It labels every fetch record this process writes, so a reader can tell
	// one run's records from another's.
	id := runID()
	if !strings.HasPrefix(id, "scopyx-") {
		t.Errorf("run id %q does not identify the plane that wrote it", id)
	}
	if len(id) <= len("scopyx-") {
		t.Errorf("run id %q carries nothing to tell one run from another", id)
	}
}

func TestAnEnvironmentValueOverridesTheFallbackAndAnEmptyOneDoesNot(t *testing.T) {
	t.Setenv("SCOPYX_TEST_ONLY_VALUE", "from-env")
	if got := env("SCOPYX_TEST_ONLY_VALUE", "fallback"); got != "from-env" {
		t.Errorf("got %q, want the environment value", got)
	}
	t.Setenv("SCOPYX_TEST_ONLY_VALUE", "")
	if got := env("SCOPYX_TEST_ONLY_VALUE", "fallback"); got != "fallback" {
		t.Errorf("an empty value must fall back, got %q", got)
	}
}
