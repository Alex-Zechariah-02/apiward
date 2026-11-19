// The audit verify command: it reads the gateway's published key set and
// checks an audit log's hash chain and signed checkpoints, files oldest
// first, then prints the report as JSON; the exit status says whether
// anything was found altered.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/go-jose/go-jose/v4"
)

const auditUsage = "usage: apiward audit verify --jwks <key set file> <audit file>... (oldest first; rotated files sort by name)"

// maxKeySet bounds the key set file; a published set holds a few keys.
const maxKeySet = 1 << 20

// auditCommand runs "audit verify" and returns the exit status: 0 when the
// chain and every checkpoint verify, 1 otherwise or on any error.
func auditCommand(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	jwks := set.String("jwks", "", "key set file")
	if len(args) == 0 || args[0] != "verify" || set.Parse(args[1:]) != nil || *jwks == "" || set.NArg() == 0 {
		fmt.Fprintln(stderr, auditUsage)
		return 1
	}
	keys, err := readKeySet(*jwks)
	if err != nil {
		fmt.Fprintln(stderr, "apiward: key set:", err)
		return 1
	}
	report, err := audit.VerifyChain(set.Args(), keys)
	if err != nil {
		fmt.Fprintln(stderr, "apiward:", err)
		return 1
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "apiward:", err)
		return 1
	}
	fmt.Fprintln(stdout, string(data))
	if !report.Valid() {
		return 1
	}
	return 0
}

// readKeySet reads a JSON Web Key Set of public Ed25519 and P-256 keys, each
// with a distinct key ID, as the gateway publishes it.
func readKeySet(path string) (map[string]crypto.PublicKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxKeySet+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeySet {
		return nil, fmt.Errorf("larger than %d bytes", maxKeySet)
	}
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(data, &keySet); err != nil {
		return nil, err
	}
	keys := map[string]crypto.PublicKey{}
	for _, key := range keySet.Keys {
		if _, taken := keys[key.KeyID]; key.KeyID == "" || taken {
			return nil, errors.New("every key needs its own kid")
		}
		if !key.IsPublic() {
			return nil, fmt.Errorf("key %s is not a public key", key.KeyID)
		}
		switch public := key.Key.(type) {
		case ed25519.PublicKey:
			keys[key.KeyID] = public
		case *ecdsa.PublicKey:
			if public.Curve != elliptic.P256() {
				return nil, fmt.Errorf("key %s is not on P-256", key.KeyID)
			}
			keys[key.KeyID] = public
		default:
			return nil, fmt.Errorf("key %s is neither Ed25519 nor P-256", key.KeyID)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no keys")
	}
	return keys, nil
}
