// Build information in the status reply and the version command.

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The status reply names the build and every compiled-in control, sorted by
// phase and then ID.
func TestStatusBuild(t *testing.T) {
	e := newEnv(t)
	seed(t, e.database, e.protectedPolicy(), seedOptions{})
	c, _ := e.own(e.controllerConfig())
	reply := httptest.NewRecorder()
	testAdmin(c).handleStatus(reply, httptest.NewRequest(http.MethodGet, "/admin/status", nil), caller{})
	var status struct{ Build buildInfo }
	if reply.Code != http.StatusOK || json.Unmarshal(reply.Body.Bytes(), &status) != nil {
		t.Fatalf("status: %d %s", reply.Code, reply.Body)
	}
	var listed []string
	for _, m := range status.Build.Modules {
		listed = append(listed, m.ID+":"+m.Phase)
	}
	if got := strings.Join(listed, " "); got != "jwt:identity rbac:authorise rate:traffic body:validate validation:validate" ||
		status.Build.Version == "" || !strings.HasPrefix(status.Build.Go, "go") {
		t.Fatalf("build: %+v", status.Build)
	}
}

// version prints the same facts, reads no configuration and takes no options.
func TestVersionCommand(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = write
	code := Main([]string{"version"})
	os.Stdout = stdout
	write.Close()
	out, _ := io.ReadAll(read)
	if code != 0 || string(out) != currentBuild().text() || !strings.Contains(string(out), "\nmodule jwt identity ") {
		t.Fatalf("version: exit %d, output %q", code, out)
	}
	if code := Main([]string{"version", "--config", "x"}); code != exitFailed {
		t.Fatalf("version with an option: exit %d", code)
	}
}
