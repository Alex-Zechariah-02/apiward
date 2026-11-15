// Routing of the command line: migrate subcommands reach the migration tool, "migrate --config" the store upgrade.

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stderrOf runs the command line and returns its exit status and stderr.
func stderrOf(t *testing.T, args ...string) (int, string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	t.Cleanup(func() {
		os.Stderr = saved
		writer.Close()
		reader.Close()
	})
	os.Stderr = writer
	code := run(args)
	os.Stderr = saved
	writer.Close()
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return code, string(output)
}

func TestRouting(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	cases := []struct {
		args          []string
		want, notWant string
	}{
		{[]string{"migrate", "--config", missing}, "missing.json", "is required"},
		{[]string{"policy", "export-openapi"}, "--policy is required\nusage: apiward policy export-openapi", ""},
		{[]string{"policy", "validate", "--policy", writeInvalid(t)}, "policy refused", "is valid"},
	}
	for _, c := range cases {
		code, stderr := stderrOf(t, c.args...)
		if code != 1 || !strings.Contains(stderr, c.want) || c.notWant != "" && strings.Contains(stderr, c.notWant) {
			t.Errorf("%v: exit %d, stderr %q", c.args, code, stderr)
		}
	}
	valid := filepath.Join("..", "..", "internal", "openapi", "testdata", "policy-shop.json")
	if code, stderr := stderrOf(t, "policy", "validate", "--policy", valid); code != 0 || !strings.Contains(stderr, "the policy is valid") {
		t.Errorf("valid policy: exit %d, stderr %q", code, stderr)
	}
}

// writeInvalid writes a policy the gateway refuses: it holds a member the
// policy grammar does not define.
func writeInvalid(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("..", "..", "internal", "openapi", "testdata", "policy-shop.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(path, []byte(strings.Replace(string(source), `"schema_version"`, `"schema_version": 1, "unused"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
