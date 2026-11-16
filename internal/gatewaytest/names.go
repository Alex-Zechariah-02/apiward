// The Admin API's names, limits and stored credential format as its clients
// and the test harness see them: the tests assert these values, so a change
// to any of them in the Admin API fails here first.

package gatewaytest

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Each value is the Admin API's own, so the tests fail if the two ever disagree.
const (
	AdminCookie  = "__Host-gateway-admin"
	AdminCSRF    = "X-CSRF-Token"
	NameLimit    = 5  // failed sign-ins per name before it is throttled
	WindowLimit  = 50 // failed sign-ins from one address per window before it is throttled
	HistoryKinds = 16 // kinds one history filter may name
	// PasswordPrefix starts every stored password: argon2id, 19 MiB, 2 passes,
	// 1 thread.
	// The Admin API refuses a stored hash that carries any other prefix.
	PasswordPrefix = "$argon2id$v=19$m=19456,t=2,p=1$"
)

// RevisionTag is the entity tag of a confirmed policy revision.
func RevisionTag(revision int64) string { return fmt.Sprintf(`"r%d"`, revision) }

// HarnessHash is HarnessPassword stored as the Admin API stores a password.
var HarnessHash = sync.OnceValue(func() string {
	salt := make([]byte, 16)
	rand.Read(salt)
	// The lengths and work below are the only ones the Admin API's verifier accepts.
	key := argon2.IDKey([]byte(HarnessPassword), salt, 2, 19*1024, 1, 32)
	return PasswordPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
})
