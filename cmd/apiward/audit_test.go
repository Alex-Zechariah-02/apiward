// The audit verify command: an untouched log verifies against the published
// key set and exits 0; an altered file, or an unusable key set, exits 1.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/go-jose/go-jose/v4"
)

func TestAuditVerify(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	signer := func(message []byte) (string, []byte, error) { return "k1", ed25519.Sign(private, message), nil }
	// Small files rotate, and each rotation writes a signed checkpoint.
	log := audit.OpenAudit(path, audit.Settings{MaxBytes: 2 << 10, MaxFiles: 64, Append: true, Signer: signer})
	for range 20 {
		if err := log.Commit(context.Background(), audit.Event{Kind: "request.admitted", RequestID: "r", Subject: "cust-001"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotated, err := audit.RotatedFiles(path, "")
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, file := range rotated {
		files = append(files, filepath.Join(dir, file.Name))
	}
	files = append(files, path)
	keySet, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: public, KeyID: "k1"}}})
	if err != nil {
		t.Fatal(err)
	}
	jwks := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(jwks, keySet, 0o600); err != nil {
		t.Fatal(err)
	}
	verify := func(keys string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := auditCommand(append([]string{"verify", "--jwks", keys}, files...), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	code, out, errs := verify(jwks)
	var report audit.ChainReport
	if code != 0 || json.Unmarshal([]byte(out), &report) != nil || report.Checkpoints == 0 {
		t.Fatalf("untouched log: exit %d, %s %s", code, out, errs)
	}
	secretKeys := filepath.Join(dir, "private.json")
	secretSet, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: private, KeyID: "k1"}}})
	if err := os.WriteFile(secretKeys, secretSet, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := verify(secretKeys); code != 1 || !strings.Contains(errs, "not a public key") {
		t.Fatalf("private key set: exit %d, %s", code, errs)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	altered := bytes.Replace(data, []byte("cust-001"), []byte("cust-002"), 1)
	if bytes.Equal(altered, data) {
		t.Fatal("fixture did not alter a record")
	}
	if err := os.WriteFile(files[0], altered, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := verify(jwks); code != 1 || !strings.Contains(out, "altered") {
		t.Fatalf("altered log: exit %d, %s", code, out)
	}
	young := filepath.Join(dir, "young.log")
	youngSnap := filepath.Join(dir, "young-unclosed.log")
	short := audit.OpenAudit(young, audit.Settings{MaxBytes: 1 << 20, MaxFiles: 4, Append: true, Signer: signer})
	if err := short.Commit(context.Background(), audit.Event{Kind: "request.admitted", RequestID: "r-short", Subject: "cust-001"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(young)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(youngSnap, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := short.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := auditCommand([]string{"verify", "--jwks", jwks, youngSnap}, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "no verifiable checkpoint") {
		t.Fatalf("unclosed young log without checkpoint: exit %d, %s %s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := auditCommand([]string{"verify", "--jwks", jwks, young}, &stdout, &stderr); code != 0 {
		t.Fatalf("cleanly stopped young log: exit %d, %s %s", code, stdout.String(), stderr.String())
	}
}
