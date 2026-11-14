// Fuzzing of the settings file an operator writes. Fuzzing this package runs
// its TestMain, which builds the test binaries, in every fuzz worker: remove
// the apiward-bin* folders it leaves in the temporary folder afterwards.

package gateway

import (
	"testing"
)

// FuzzSettings checks that no settings document makes decoding or checking
// panic.
func FuzzSettings(f *testing.F) {
	for _, seed := range []string{
		`{"version":1,"gateway":{"database":"state.db","audit_log":"audit.log","admin_listen":"127.0.0.1:9440","jwt":{"issuer":"i","audience":"g","keys":[{"kid":"a","public_key_file":"k.pem"}]}},"data":{"listen":"127.0.0.2:9480"}}`,
		`{"version":1,"version":1}`, `{"apps":{}}`, `{"version":2}`, `[]`, `{"version":1} x`, `{"Version":1}`,
		`{"version":1,"gateway":{"audit_max_bytes":-1,"audit_max_files":0}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		settings, err := decodeNativeFile(data)
		if err != nil {
			return
		}
		_, _ = settings.check()
	})
}
