// Tests for mid-run checkpoint anchoring in VerifyChain when the earliest
// files of a run are not given (for example after oldest-first eviction).

package audit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func anchoredFiles(t *testing.T, report ChainReport) []string {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Anchored []string `json:"anchored_files"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"anchored_files":[`)) {
		t.Fatalf("expected non-null JSON array for anchored_files, got %s", data)
	}
	return out.Anchored
}

func writeRotatedAudit(t *testing.T, signer Signer) (string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 2 << 10, MaxFiles: 64, Append: true, Signer: signer})
	for range 40 {
		if err := a.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: "r", Subject: "cust-001"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	files := append(rotated(t, path), path)
	if len(files) < 3 {
		t.Fatalf("expected at least 3 files, got %d", len(files))
	}
	return path, files
}

func TestVerifyAnchorsAtCheckpointAfterEviction(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(message []byte) (string, []byte, error) {
		return "k1", ed25519.Sign(private, message), nil
	}
	_, files := writeRotatedAudit(t, signer)
	keys := map[string]crypto.PublicKey{"k1": public}

	whole, err := VerifyChain(files, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !whole.Valid() || len(anchoredFiles(t, whole)) != 0 {
		t.Fatalf("full verify: valid=%v anchored=%v problems=%v", whole.Valid(), anchoredFiles(t, whole), whole.Problems)
	}

	report, err := VerifyChain(files[1:], keys)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid() || len(report.Problems) != 0 || len(report.Missing) != 0 {
		t.Fatalf("tail verify failed: valid=%v problems=%v missing=%v", report.Valid(), report.Problems, report.Missing)
	}
	if report.Chains == 0 || report.Checkpoints == 0 {
		t.Fatalf("expected chains and checkpoints > 0, got chains=%d checkpoints=%d", report.Chains, report.Checkpoints)
	}
	if got := anchoredFiles(t, report); !slices.Equal(got, []string{files[1]}) {
		t.Fatalf("anchored_files = %v, want [%s]", got, files[1])
	}
}

func TestVerifyWithoutCheckpointReportsOnce(t *testing.T) {
	_, files := writeRotatedAudit(t, nil)

	report, err := VerifyChain(files[1:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid() {
		t.Fatal("expected invalid report without checkpoint")
	}
	if len(report.Problems) != 1 {
		t.Fatalf("expected 1 problem, got %d: %v", len(report.Problems), report.Problems)
	}
	if !strings.Contains(report.Problems[0], files[1]) || !strings.Contains(report.Problems[0], "starts here without a verifiable checkpoint; earlier records of this run cannot be checked") {
		t.Fatalf("unexpected problem: %q", report.Problems[0])
	}
	if got := anchoredFiles(t, report); len(got) != 0 {
		t.Fatalf("expected empty anchored_files, got %v", got)
	}
}

func TestVerifyRejectsForgedAnchor(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(message []byte) (string, []byte, error) {
		return "k1", ed25519.Sign(private, message), nil
	}
	_, files := writeRotatedAudit(t, signer)

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		keys map[string]crypto.PublicKey
	}{
		{"missing_key", map[string]crypto.PublicKey{"k2": otherPub}},
		{"wrong_key", map[string]crypto.PublicKey{"k1": otherPub}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := VerifyChain(files[1:], tc.keys)
			if err != nil {
				t.Fatal(err)
			}
			if report.Valid() {
				t.Fatal("expected invalid report")
			}
			if len(report.Problems) == 0 {
				t.Fatal("expected problems")
			}
			if !strings.Contains(report.Problems[0], "starts here without a verifiable checkpoint") {
				t.Fatalf("unexpected first problem: %q", report.Problems[0])
			}
			if slices.ContainsFunc(report.Problems, func(p string) bool {
				return strings.Contains(p, "altered, added or removed")
			}) {
				t.Fatalf("unexpected chain errors after unanchored start: %v", report.Problems)
			}
			if got := anchoredFiles(t, report); len(got) != 0 {
				t.Fatalf("expected empty anchored_files, got %v", got)
			}
		})
	}
}

func TestVerifyFindsAlterationAfterAnchor(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(message []byte) (string, []byte, error) {
		return "k1", ed25519.Sign(private, message), nil
	}
	_, files := writeRotatedAudit(t, signer)

	raw, err := os.ReadFile(files[2])
	if err != nil {
		t.Fatal(err)
	}
	altered := bytes.Replace(raw, []byte("cust-001"), []byte("cust-999"), 1)
	if bytes.Equal(raw, altered) {
		t.Fatal("expected target string in rotated file")
	}
	if err := os.WriteFile(files[2], altered, 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := VerifyChain(files[1:], map[string]crypto.PublicKey{"k1": public})
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid() {
		t.Fatal("expected invalid report after alteration")
	}
	if got := anchoredFiles(t, report); !slices.Equal(got, []string{files[1]}) {
		t.Fatalf("anchored_files = %v, want [%s]", got, files[1])
	}
	if !slices.ContainsFunc(report.Problems, func(p string) bool {
		return strings.Contains(p, "altered, added or removed")
	}) {
		t.Fatalf("expected alteration problem, got %v", report.Problems)
	}
}
