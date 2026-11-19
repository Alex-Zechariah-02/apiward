// The chain: an untouched log verifies, with its checkpoints signed; an
// altered, removed or inserted record is found.

package audit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestChainFindsTampering(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(message []byte) (string, []byte, error) { return "k1", ed25519.Sign(private, message), nil }
	path := filepath.Join(t.TempDir(), "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 2 << 10, MaxFiles: 64, Append: true, Signer: signer})
	for range 20 {
		if err := a.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: "r", Subject: "cust-001"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	files := append(rotated(t, path), path)
	keys := map[string]crypto.PublicKey{"k1": public}
	report, err := VerifyChain(files, keys)
	if err != nil || !report.Valid() || report.Chains == 0 || report.Checkpoints == 0 || report.Unchained != 0 {
		t.Fatalf("untouched log: %+v %v", report, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, altered := range map[string][]byte{
		"altered":  bytes.Replace(data, []byte("cust-001"), []byte("cust-002"), 1),
		"removed":  bytes.Replace(data, data[:bytes.IndexByte(data, '\n')+1], nil, 1),
		"inserted": append([]byte(`{"event_id":"x","kind":"request.admitted"}`+"\n"), data...),
	} {
		if bytes.Equal(altered, data) {
			t.Fatalf("%s: the fixture did not change the file", name)
		}
		if err := os.WriteFile(path, altered, 0o600); err != nil {
			t.Fatal(err)
		}
		if report, err := VerifyChain(files, keys); err != nil || report.Valid() {
			t.Errorf("%s record not found: %+v %v", name, report, err)
		}
	}
}
