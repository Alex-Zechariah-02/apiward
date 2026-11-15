// Import report members: permits added, settings replaced, operations that
// need permissions, roles on public operations and the default limits named
// in a refusal; the export's refusal answers.

package openapi

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestImportReportsGrants(t *testing.T) {
	options := testOptions()
	options.WithPermits = true
	options.Base.APIs[0].AllowAddresses = []string{"10.0.0.0/8"}
	spec := `{"openapi":"3.1.0","info":{"title":"t","version":"2.4"},"components":{"securitySchemes":{"b":{"type":"http","scheme":"bearer"}}},"paths":{
		"/orders":{"post":{"operationId":"create","security":[{"b":[]}],"x-apiward-roles":["clerk"]},
			"get":{"operationId":"list","security":[{"b":[]}],"x-apiward-roles":[]}},
		"/health":{"get":{"operationId":"health","security":[],"x-apiward-roles":["clerk"]}}}}`
	_, report, err := Import([]byte(spec), JSON, options)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(report.AddedPermits, []Permit{{Role: "clerk", Operation: "orders.create"}}) {
		t.Errorf("added permits %v", report.AddedPermits)
	}
	// An empty role list admits nobody, as no list does.
	if !slices.Equal(report.NeedsPermissions, []string{"orders.list"}) {
		t.Errorf("needs permissions %v", report.NeedsPermissions)
	}
	if !slices.Equal(report.ReplacedSettings, []string{"allow_addresses"}) {
		t.Errorf("replaced settings %v", report.ReplacedSettings)
	}
	if report.DescriptionVersion != "2.4" {
		t.Errorf("description version %q", report.DescriptionVersion)
	}
	// Roles on a public operation refuse that operation only, by its path.
	if len(report.Refused) != 1 || report.Refused[0].Path != "/health" || report.Refused[0].Code != CodeExtension {
		t.Errorf("refused %+v", report.Refused)
	}
}

// A result over a default capacity limit names the limits the import checks
// against, as the deployment's own may be higher.
func TestImportNamesDefaultLimits(t *testing.T) {
	var paths []string
	for n := range 300 {
		paths = append(paths, fmt.Sprintf(`"/p%d":{"get":{"operationId":"p%d"}}`, n, n))
	}
	spec := `{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{` + strings.Join(paths, ",") + `}}`
	_, _, err := Import([]byte(spec), JSON, testOptions())
	if err == nil || !strings.Contains(err.Error(), "default capacity limits") || !strings.Contains(err.Error(), "256 operations") {
		t.Fatalf("error %v", err)
	}
}

// Every exported operation lists the gateway's own refusals; the body limit
// is stated in words as well as in x-apiward-max-bytes.
func TestExportResponses(t *testing.T) {
	doc, _, _ := exported(t, policyFixture(t, "policy-shop.json"), ExportOptions{API: "shop"}, JSON)
	paths, _ := doc["paths"].(map[string]any)
	bodies := 0
	for path, item := range paths {
		for method, raw := range item.(map[string]any) {
			op, _ := raw.(map[string]any)
			responses, _ := op["responses"].(map[string]any)
			want := []string{"default", "400", "403", "429", "503"}
			if security, _ := op["security"].([]any); len(security) > 0 {
				want = append(want, "401")
			}
			if body, present := op["requestBody"].(map[string]any); present {
				bodies++
				want = append(want, "413", "415")
				if text, _ := body["description"].(string); !strings.Contains(text, fmt.Sprint(op["x-apiward-max-bytes"])) {
					t.Errorf("%s %s body description %q", method, path, text)
				}
			}
			for _, code := range want {
				if responses[code] == nil {
					t.Errorf("%s %s has no %s response", method, path, code)
				}
			}
			if len(responses) != len(want) {
				t.Errorf("%s %s responses %v, want %v", method, path, responses, want)
			}
		}
	}
	if bodies == 0 {
		t.Fatal("the fixture exports no request body")
	}
}
