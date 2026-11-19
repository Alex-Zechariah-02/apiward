// What the import reports instead of dropping silently: JSON beside other
// media types, roles read without --with-permits, unknown members, applied
// settings and a changed upstream; and what it refuses per operation: two
// spellings of one header, a non-string header, a path outside the forward
// prefix.

package openapi

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// imported runs the import of a JSON description and fails on an error.
func imported(t *testing.T, spec string, options Options) *Report {
	t.Helper()
	_, report, err := Import([]byte(spec), JSON, options)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func refusedCode(report *Report, path string) string {
	for _, r := range report.Refused {
		if r.Path == path {
			return r.Code
		}
	}
	return ""
}

func TestImportReportsInsteadOfDropping(t *testing.T) {
	spec := `{"openapi": "3.1.0", "info": {"title": "t", "version": "1"},
		"x-apiward-forward": {"strip_prefix": "/orders"},
		"paths": {
			"/orders": {"post": {"operationId": "create", "x-apiward-roles": ["customer"], "requestbody": {},
				"requestBody": {"required": true, "content": {
					"application/json": {"schema": {"type": "object"}},
					"multipart/form-data": {"schema": {"type": "object"}}}}}},
			"/orders/list": {"GET": {"operationId": "shouted"}}
		}}`
	options := testOptions()
	options.Base.APIs[0].Upstream = "stock-svc"
	report := imported(t, spec, options)
	if len(report.Mapped) != 1 {
		t.Fatalf("mapped %+v, refused %+v", report.Mapped, report.Refused)
	}
	var fields []string
	for _, c := range report.Changed {
		fields = append(fields, c.Field)
	}
	if !slices.Contains(fields, "body.media_type") || !slices.Contains(fields, "x-apiward-roles") {
		t.Errorf("changed %+v", report.Changed)
	}
	if !slices.Contains(report.Ignored, "requestbody") || !slices.Contains(report.Ignored, "GET") {
		t.Errorf("ignored %v", report.Ignored)
	}
	if refusedCode(report, "/orders/list") != CodeMethod {
		t.Errorf("refused %+v", report.Refused)
	}
	if !slices.Equal(report.AppliedSettings, []string{"forward"}) || !slices.Contains(report.ReplacedSettings, "upstream") {
		t.Errorf("applied %v, replaced %v", report.AppliedSettings, report.ReplacedSettings)
	}
}

func TestImportRefusesPerOperation(t *testing.T) {
	spec := `{"openapi": "3.1.0", "info": {"title": "t", "version": "1"},
		"x-apiward-forward": {"strip_prefix": "/orders"},
		"paths": {
			"/orders/twice": {"get": {"operationId": "twice", "parameters": [
				{"name": "X-Probe", "in": "header", "schema": {"type": "string"}},
				{"name": "x-probe", "in": "header", "schema": {"type": "string"}}]}},
			"/orders/count": {"get": {"operationId": "count", "parameters": [
				{"name": "X-Count", "in": "header", "schema": {"type": "integer"}}]}},
			"/orders/form": {"post": {"operationId": "form", "requestBody": {"content": {"text/plain": {}}}}},
			"/outside": {"get": {"operationId": "outside"}},
			"/orders/fine": {"get": {"operationId": "fine"}}
		}}`
	report := imported(t, spec, testOptions())
	for path, code := range map[string]string{"/orders/twice": CodeKeyword, "/orders/count": CodeKeyword,
		"/orders/form": CodeMediaType, "/outside": CodeCompiler} {
		if got := refusedCode(report, path); got != code {
			t.Errorf("%s: refused %q, want %q", path, got, code)
		}
	}
	if len(report.Mapped) != 1 || report.Mapped[0].Path != "/orders/fine" {
		t.Errorf("mapped %+v", report.Mapped)
	}
	for _, r := range report.Refused {
		if r.Path == "/orders/count" && !strings.Contains(r.Message, "X-Count") {
			t.Errorf("the refusal does not name the parameter: %q", r.Message)
		}
	}
}

// With both outputs already present, the refusal always names the policy
// output: the files are created in a fixed order.
func TestWriteOrder(t *testing.T) {
	dir := t.TempDir()
	out, report := filepath.Join(dir, "out.json"), filepath.Join(dir, "report.json")
	for _, path := range []string{out, report} {
		if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for range 20 {
		err := write(out, map[string]any{}, report, map[string]any{})
		if err == nil || !strings.Contains(err.Error(), out) {
			t.Fatalf("error %v, want one naming %s", err, out)
		}
	}
	if kept, _ := os.ReadFile(report); !bytes.Equal(kept, []byte("keep")) {
		t.Fatal("an existing file changed")
	}
}
