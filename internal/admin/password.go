// Administrator password hashing and checks.

package admin

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"golang.org/x/crypto/argon2"
)

// Password hashing uses argon2id with the OWASP minimum configuration. Only
// hashes with exactly these parameters are accepted, so a stored value can
// never make the gateway compute an attacker-chosen cost.
const (
	argonMemory    = 19 * 1024 // KiB
	argonTime      = 2
	argonThreads   = 1
	argonSaltBytes = 16
	argonKeyBytes  = 32
	// NIST SP 800-63B-4 requires at least 15 characters for a password used
	// alone; 256 bytes allows long passphrases and bounds the hashing input.
	minPasswordBytes = 15
	maxPasswordBytes = 256
)

var argonPrefix = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$", argon2.Version, argonMemory, argonTime, argonThreads)

// passwordsText is every password of minPasswordBytes to maxPasswordBytes in
// the SecLists "Pwdb top 1,000,000" list (MIT), one per line, most common
// first: NIST SP 800-63B requires refusing commonly used passwords, and OWASP
// ASVS 6.2.4 asks for at least the top 3,000 that fit the length rule.
//
//go:embed passwords.txt
var passwordsText string

// commonPasswords is passwordsText in lower case, sorted for binary search.
var commonPasswords = sync.OnceValue(func() []string {
	list := strings.Split(strings.ToLower(strings.TrimSpace(passwordsText)), "\n")
	slices.Sort(list)
	return slices.Compact(list)
})

// validPassword applies the password rule: 15 to 256 bytes of UTF-8, and not
// a common password in any letter case.
func validPassword(password string) bool {
	if len(password) < minPasswordBytes || len(password) > maxPasswordBytes || !utf8.ValidString(password) {
		return false
	}
	_, common := slices.BinarySearch(commonPasswords(), strings.ToLower(password))
	return !common
}

func hashPassword(password string) string {
	salt := make([]byte, argonSaltBytes)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyBytes)
	encoding := base64.RawStdEncoding
	return argonPrefix + encoding.EncodeToString(salt) + "$" + encoding.EncodeToString(key)
}

func verifyPassword(encoded, password string) bool {
	rest, ok := strings.CutPrefix(encoded, argonPrefix)
	if !ok {
		return false
	}
	saltText, keyText, ok := strings.Cut(rest, "$")
	if !ok {
		return false
	}
	salt, saltErr := base64.RawStdEncoding.DecodeString(saltText)
	key, keyErr := base64.RawStdEncoding.DecodeString(keyText)
	if saltErr != nil || keyErr != nil || len(salt) != argonSaltBytes || len(key) != argonKeyBytes {
		return false
	}
	computed := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyBytes)
	return subtle.ConstantTimeCompare(computed, key) == 1
}

// dummyHash is verified against when the named administrator does not exist,
// so the response time does not reveal which names exist.
var dummyHash = sync.OnceValue(func() string { return hashPassword(session.NewToken()) })
