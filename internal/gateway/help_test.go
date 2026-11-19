// Asking for help is not a failure: the usage is printed and the command
// exits 0.

package gateway

import "testing"

func TestHelpExitsZero(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		if code := Main([]string{arg}); code != 0 {
			t.Errorf("%s: exit %d, want 0", arg, code)
		}
	}
}
