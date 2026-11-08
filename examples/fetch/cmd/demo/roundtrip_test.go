// The demo baseline round-trips through the gateway's OpenAPI policy
// commands without change.

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	policydoc "github.com/Alex-Zechariah-02/apiward/policy"
)

// TestBaselineRoundTrip exports each API of the demo baseline as OpenAPI with
// the gateway's policy commands and imports it back onto the same baseline;
// the canonical policy must not change and the import must map everything.
func TestBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	gateway := filepath.Join(dir, "gateway.exe")
	build := exec.Command("go", "build", "-C", filepath.Join("..", "..", "..", ".."), "-o", gateway, "./cmd/gateway")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the gateway: %v\n%s", err, out)
	}
	base := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(base, indented(baselinePolicy()), 0600); err != nil {
		t.Fatal(err)
	}
	want := canonical(t, base)
	baseline, err := policydoc.Decode(indented(baselinePolicy()))
	if err != nil {
		t.Fatal(err)
	}
	for i, api := range baseline.APIs {
		file := func(name string) string { return filepath.Join(dir, fmt.Sprintf("%d-%s", i, name)) }
		// An export exits 2 when it rewrote operations to fit OpenAPI.
		policyCommand(t, gateway, []int{0, 2}, "export-openapi", "--policy", base, "--api", api.ID, "--out", file("spec.json"), "--report", file("export.json"))
		policyCommand(t, gateway, []int{0}, "import-openapi", "--spec", file("spec.json"), "--api", api.ID, "--upstream", api.Upstream,
			"--base", base, "--with-permits", "--out", file("policy.json"), "--report", file("import.json"))
		if got := canonical(t, file("policy.json")); !bytes.Equal(got, want) {
			t.Fatalf("%s: round trip changed the baseline:\n%s", api.ID, got)
		}
	}
}

// policyCommand runs one gateway policy command, which must exit with one of
// codes: for an import, 0 means every operation was mapped.
func policyCommand(t *testing.T, gateway string, codes []int, args ...string) {
	t.Helper()
	cmd := exec.Command(gateway, append([]string{"policy"}, args...)...)
	out, err := cmd.CombinedOutput()
	if cmd.ProcessState == nil || !slices.Contains(codes, cmd.ProcessState.ExitCode()) {
		t.Fatalf("%s: %v\n%s", args[0], err, out)
	}
}

// canonical returns the canonical encoding of the policy file at name.
func canonical(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policydoc.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := policydoc.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
