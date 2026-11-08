// The Admin API's names, limits and stored credential format as its clients
// and the test harness see them: the tests assert these values, so a change
// to any of them in the Admin API fails here first.

package gateway

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	adminCookie  = "__Host-gateway-admin"
	adminCSRF    = "X-CSRF-Token"
	nameLimit    = 5  // failed sign-ins per name before it is throttled
	windowLimit  = 50 // failed sign-ins per window before all are throttled
	historyKinds = 16 // kinds one history filter may name
	// passwordPrefix starts every stored password: argon2id, 19 MiB, 2 passes,
	// 1 thread.
	passwordPrefix = "$argon2id$v=19$m=19456,t=2,p=1$"
)

// revisionTag is the entity tag of a confirmed policy revision.
func revisionTag(revision int64) string { return fmt.Sprintf(`"r%d"`, revision) }

// harnessHash is harnessPassword stored as the Admin API stores a password.
var harnessHash = sync.OnceValue(func() string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key := argon2.IDKey([]byte(harnessPassword), salt, 2, 19*1024, 1, 32)
	return passwordPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
})
