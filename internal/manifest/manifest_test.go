// The declaration in components.json is only worth reading if this repository
// proves it, and proves it by RUNNING rather than by describing.
//
// estate-gates cannot do this. It has no Go toolchain, and building twenty-two
// repositories in its CI is a matrix it does not have. This repository already
// runs its suite on every push, so the marginal cost of a few process starts is
// seconds.
//
// What is proved here is exactly the `checked` bucket and nothing else. The
// `declared` bucket is not asserted against anything, on purpose: a test that
// pretended to verify a sentence about purpose would be the failure this whole
// design exists to avoid.
package manifest

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// os/exec copies a process's output on its own goroutine, so reading what it has
// written while the process is still running is a data race and `-race` says so.
// The matrix below deliberately leaves processes running, because "it started"
// is half of what is being proved.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type envVar struct {
	Required bool   `json:"required"`
	Default  string `json:"default"`
}

type openBind struct {
	ExitCode          int    `json:"exit_code"`
	EscapedByAKey     string `json:"escaped_by_a_key"`
	EscapedBySayingSo string `json:"escaped_by_saying_so"`
}

type component struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	Checked struct {
		Package                 string            `json:"package"`
		ListenDefault           string            `json:"listen_default"`
		HealthPath              string            `json:"health_path"`
		Env                     map[string]envVar `json:"env"`
		MissingRequiredExitCode int               `json:"missing_required_exit_code"`
		RefusesAnOpenBind       openBind          `json:"refuses_an_open_bind_without_a_credential"`
	} `json:"checked"`
}

type manifest struct {
	Schema     string      `json:"schema"`
	Repo       string      `json:"repo"`
	Components []component `json:"components"`
}

func root(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func load(t *testing.T) (manifest, string) {
	t.Helper()
	r := root(t)
	b, err := os.ReadFile(filepath.Join(r, "components.json"))
	if err != nil {
		t.Fatalf("reading components.json: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parsing components.json: %v", err)
	}
	if len(m.Components) == 0 {
		t.Fatal("components.json declares no component, so every test here measured nothing")
	}
	return m, r
}

func service(t *testing.T, m manifest) component {
	t.Helper()
	for _, c := range m.Components {
		if c.Class == "service" {
			return c
		}
	}
	t.Fatal("components.json declares no service, so the running half measured nothing")
	return component{}
}

func build(t *testing.T, r, pkg string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "scopyx")
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	cmd.Dir = r
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", pkg, err, out)
	}
	return bin
}

// A free port, so a developer already running scopyx does not make this fail for
// a reason that is not a finding.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("splitting %q: %v", l.Addr().String(), err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("releasing the reserved port: %v", err)
	}
	return port
}

// Starts it and answers one question: did it stay up, or did it exit and with
// what. "Stayed up" is a claim in three of the four rows below, so it needs to
// be a result rather than an absence of one.
func startAndSee(t *testing.T, bin string, env []string) (stayedUp bool, code int, out string) {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = env
	var buf syncBuffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting it: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return false, exit.ExitCode(), buf.String()
		}
		if err == nil {
			return false, 0, buf.String()
		}
		t.Fatalf("waiting for it: %v", err)
	case <-time.After(2 * time.Second):
	}
	_ = cmd.Process.Kill()
	<-done
	return true, 0, buf.String()
}

// THE ONE THAT CLOSES THE HOLE. A binary this repository builds and does not
// declare is invisible from outside by construction, which is what estate-gates
// invariant 18 says about its own `runs` field.
func TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)

	list := exec.Command("go", "list", "-f", "{{if eq .Name \"main\"}}{{.ImportPath}}{{end}}", "./...")
	// Without this the command runs in THIS package's directory and `./...`
	// means this package alone. It then finds no main package, and the test
	// passes while measuring nothing.
	list.Dir = r
	out, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	built := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			built[line] = true
		}
	}
	if len(built) == 0 {
		t.Fatal("go list found no main package in this repository, so this measured nothing")
	}
	declared := map[string]bool{}
	for _, c := range m.Components {
		if c.Checked.Package == "" {
			t.Errorf("component %q declares no package", c.Name)
			continue
		}
		declared[c.Checked.Package] = true
	}
	for p := range built {
		if !declared[p] {
			t.Errorf("this repository builds %s and components.json does not declare it.\n"+
				"A component nobody declares is one no deployment can be asked to install.", p)
		}
	}
	for p := range declared {
		if !built[p] {
			t.Errorf("components.json declares %s and this repository does not build it", p)
		}
	}
}

// Every SCOPYX_ name in non-test source, against every one declared. It reads
// STRING LITERALS rather than following os.Getenv, because main.go reads most of
// these through a local `env(name, fallback)` helper and a reader that followed
// call sites would report a set that is quietly short.
func TestEveryEnvironmentVariableThisRepositoryReadsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)

	name := regexp.MustCompile(`SCOPYX_[A-Z0-9_]+`)
	inSource := map[string]bool{}
	err := filepath.Walk(r, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range name.FindAllString(string(b), -1) {
			if !strings.HasSuffix(n, "_") {
				inSource[n] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if len(inSource) == 0 {
		t.Fatal("no SCOPYX_ name found in any non-test .go file, so this measured nothing")
	}

	declared := map[string]bool{}
	for _, c := range m.Components {
		for k := range c.Checked.Env {
			declared[k] = true
		}
	}
	var missing, extra []string
	for n := range inSource {
		if !declared[n] {
			missing = append(missing, n)
		}
	}
	for n := range declared {
		if !inSource[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	for _, n := range missing {
		t.Errorf("the code reads %s and components.json does not declare it", n)
	}
	for _, n := range extra {
		t.Errorf("components.json declares %s and no non-test source reads it", n)
	}
}

// The declared listen default is the constant the binary falls back to.
func TestTheDeclaredListenDefaultIsTheOneTheCodeUses(t *testing.T) {
	m, r := load(t)
	b, err := os.ReadFile(filepath.Join(r, "cmd", "scopyx", "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	found := regexp.MustCompile(`defaultAddr\s*=\s*"([^"]*)"`).FindStringSubmatch(string(b))
	if found == nil {
		t.Fatal("main.go no longer defines defaultAddr, so this measured nothing")
	}
	if got := service(t, m).Checked.ListenDefault; got != found[1] {
		t.Errorf("components.json says the default listen address is %q; main.go says %q",
			got, found[1])
	}
}

// AND THE HALF NO CENTRAL FILE COULD EVER DO: start it four ways.
//
// A non-loopback bind with no credential is an unauthenticated fetch proxy on
// somebody's network, and the failure is silent: it works perfectly for whoever
// finds it. So this is a matrix, and the three rows that MUST START are as
// important as the one that must refuse. A test that only proved the refusal
// would pass just as well on a component that refuses always, which would be a
// different and broken thing.
func TestItRefusesAnOpenBindWithNoCredentialAndOnlyThat(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	m, r := load(t)
	c := service(t, m)
	ob := c.Checked.RefusesAnOpenBind
	if ob.ExitCode == 0 || ob.EscapedByAKey == "" || ob.EscapedBySayingSo == "" {
		t.Fatal("components.json does not record the open-bind refusal in full, so this measured nothing")
	}
	// The policy plane it refuses without. It never has to answer: every row
	// here is decided before a fetch is attempted.
	pdp := "SCOPYX_WARDRYX=http://127.0.0.1:1/unreachable"
	bin := build(t, r, c.Checked.Package)

	for _, row := range []struct {
		name      string
		addr      string
		extra     []string
		mustStart bool
	}{
		{"loopback with no credential", "127.0.0.1:", nil, true},
		{"open bind with no credential", "0.0.0.0:", nil, false},
		{"open bind, said so", "0.0.0.0:", []string{ob.EscapedBySayingSo + "=1"}, true},
		{"open bind with a key", "0.0.0.0:", []string{ob.EscapedByAKey + "=k1:acme:admin"}, true},
	} {
		env := append([]string{pdp, "SCOPYX_ADDR=" + row.addr + freePort(t)}, row.extra...)
		up, code, out := startAndSee(t, bin, env)
		switch {
		case row.mustStart && !up:
			t.Errorf("%s: it exited %d and components.json says only an open bind with no "+
				"credential is refused\n%s", row.name, code, out)
		case !row.mustStart && up:
			t.Errorf("%s: it started. That is an unauthenticated fetch proxy on whatever "+
				"network this box is on, and the manifest claims it refuses.", row.name)
		case !row.mustStart && code != ob.ExitCode:
			t.Errorf("%s: it refused with exit %d; components.json says %d",
				row.name, code, ob.ExitCode)
		}
	}
}

// The one unconditionally required variable of seventeen, and the code says why
// in its own words: it fails closed, so an unconfigured one would refuse every
// fetch with a message about the network instead of about the configuration.
func TestItRefusesWithoutEachRequiredVariable(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	m, r := load(t)
	c := service(t, m)
	want := c.Checked.MissingRequiredExitCode
	if want == 0 {
		t.Fatal("components.json declares no missing-required exit code, so this measured nothing")
	}

	var required []string
	for k, v := range c.Checked.Env {
		if v.Required {
			required = append(required, k)
		}
	}
	sort.Strings(required)
	if len(required) == 0 {
		t.Fatal("no variable is declared required, so this measured nothing")
	}

	bin := build(t, r, c.Checked.Package)
	working := map[string]string{
		"SCOPYX_WARDRYX": "http://127.0.0.1:1/unreachable",
		"SCOPYX_ADDR":    "127.0.0.1:" + freePort(t),
	}
	for _, missing := range required {
		var env []string
		for k, v := range working {
			if k != missing {
				env = append(env, k+"="+v)
			}
		}
		up, code, out := startAndSee(t, bin, env)
		if up {
			t.Errorf("without %s it started; components.json says it refuses", missing)
			continue
		}
		if code != want {
			t.Errorf("without %s it exited %d; components.json says %d\n%s",
				missing, code, want, out)
		}
		// The refusal has to name the variable, or an operator reads a stack
		// trace and guesses.
		if !strings.Contains(out, missing) {
			t.Errorf("without %s it refused without naming it:\n%s", missing, out)
		}
	}

	// And the converse, which is the half a refusal test usually forgets: with
	// every required variable present it must NOT refuse, or "required" would
	// be indistinguishable from "broken".
	var full []string
	for k, v := range working {
		full = append(full, k+"="+v)
	}
	if up, code, out := startAndSee(t, bin, full); !up {
		t.Errorf("with every required variable set it still exited %d\n%s", code, out)
	}
}
