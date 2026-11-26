// Disabling an administrator: the operator command stops its password at
// once, and a reset stops the old password before the new secret is used.

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func TestOperatorDisablesAdministrator(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	_, departed := addAdmin(e, gatewaytest.Binaries.Plain, "ops", "read,manage_policy")
	_, forgotten := addAdmin(e, gatewaytest.Binaries.Plain, "lead", "read")
	e.Stop()
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "disable", "--admin", "ops"); code != 0 {
		t.Fatalf("disable ops: exit %d\n%s", code, out)
	}
	out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "enrol", "--admin", "lead", "--permissions", "read")
	if code != 0 {
		t.Fatalf("reset lead: exit %d\n%s", code, out)
	}
	e.Start(gatewaytest.Binaries.Plain)
	if _, code := e.Login("ops", departed); code == http.StatusCreated {
		t.Error("the disabled administrator still signs in with its password")
	}
	if _, code := e.Login("lead", forgotten); code == http.StatusCreated {
		t.Error("the reset administrator still signs in with its old password")
	}
	status, body, _ := e.HarnessCall(http.MethodGet, "/admin/administrators", "")
	var list struct {
		Items []struct{ Name, Status string } `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &list) != nil {
		t.Fatalf("administrators: %d %s", status, body)
	}
	for _, a := range list.Items {
		if (a.Name == "ops" || a.Name == "lead") && a.Status == "active" {
			t.Errorf("%s is still active after the operator's command", a.Name)
		}
	}
	if code, body := enrol(e, "lead", gatewaytest.EnrolmentSecret(t, out), testPassword()); code != http.StatusCreated {
		t.Errorf("the new enrolment after the reset: %d %s", code, body)
	}
}
