// Build information in the status reply and the version command.

package gateway

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/admin"
)

// version prints the same facts, reads no configuration and takes no options.
func TestVersionCommand(t *testing.T) {
	t.Parallel()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	t.Cleanup(func() {
		os.Stdout = stdout
		write.Close()
		read.Close()
	})
	os.Stdout = write
	code := Main([]string{"version"})
	os.Stdout = stdout
	write.Close()
	out, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || string(out) != admin.VersionText() || !strings.Contains(string(out), "\nmodule jwt identity ") {
		t.Fatalf("version: exit %d, output %q", code, out)
	}
	if code := Main([]string{"version", "--config", "x"}); code != exitFailed {
		t.Fatalf("version with an option: exit %d", code)
	}
}
