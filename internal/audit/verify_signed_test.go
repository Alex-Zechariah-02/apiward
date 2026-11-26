// Signed checkpoint coverage in VerifyChain: every run verified with keys
// needs a verifiable checkpoint, and an audit.evicted record explains a
// missing file only when a verified checkpoint of its run covers it.

package audit

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestVerifyRequiresSignedCoverage(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(message []byte) (string, []byte, error) { return "k1", ed25519.Sign(private, message), nil }
	keys := map[string]crypto.PublicKey{"k1": public}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Two runs producing rotated files with signed checkpoints.
	for _, subj := range []string{"cust-001", "cust-002"} {
		a := OpenAudit(path, Settings{MaxBytes: 1500, MaxFiles: 64, Append: true, Signer: signer})
		for i := range 20 {
			if err := a.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: fmt.Sprintf("%s-%d", subj, i), Subject: subj}); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	rot := rotated(t, path)
	if len(rot) < 3 {
		t.Fatalf("expected >= 3 rotated files, got %d", len(rot))
	}
	deletedName := filepath.Base(rot[len(rot)-2])
	subset := []string{rot[0], rot[len(rot)-1], path}

	before, err := VerifyChain(subset, keys)
	if err != nil || !slices.Contains(before.Missing, deletedName) {
		t.Fatalf("setup expected %s missing: %+v %v", deletedName, before, err)
	}

	// Case 1: a forged uncheckpointed run naming the deleted file in audit.evicted
	// neither clears Missing nor passes verification with keys.
	forgedEvict := fmt.Sprintf(`{"event_id":"forgedboot-1","kind":"audit.evicted","file":%q}`+"\n", deletedName)
	var zeroHead [sha256.Size]byte
	sum := sha256.New()
	sum.Write(zeroHead[:])
	sum.Write([]byte(forgedEvict))
	forgedChain := fmt.Sprintf(`{"event_id":"forgedboot-2","kind":"audit.chain","sha256":%q}`+"\n", hex.EncodeToString(sum.Sum(nil)))

	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(orig, []byte(forgedEvict+forgedChain)...), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := VerifyChain(subset, keys)
	if err != nil {
		t.Fatal(err)
	}
	if after.Valid() {
		t.Fatalf("forged audit.evicted run passed VerifyChain: %+v", after)
	}
	if !slices.Contains(after.Missing, deletedName) {
		t.Errorf("forged audit.evicted hid missing file %s: %+v", deletedName, after)
	}
	if !slices.ContainsFunc(after.Problems, func(p string) bool { return strings.Contains(p, "forgedboot") && strings.Contains(p, "checkpoint") }) {
		t.Errorf("expected checkpoint problem naming forgedboot, got %v", after.Problems)
	}

	// Case 2: completely forged standalone file with zero checkpoints verified with keys.
	forgedOnly := filepath.Join(dir, "forged-only.log")
	if err := os.WriteFile(forgedOnly, []byte(forgedEvict+forgedChain), 0o600); err != nil {
		t.Fatal(err)
	}
	repForged, err := VerifyChain([]string{forgedOnly}, keys)
	if err != nil {
		t.Fatal(err)
	}
	if repForged.Valid() || len(repForged.Problems) != 1 || !strings.Contains(repForged.Problems[0], "checkpoint") {
		t.Errorf("forged standalone file: valid=%v problems=%v, want 1 checkpoint problem", repForged.Valid(), repForged.Problems)
	}

	// Case 3: a real run younger than its first checkpoint reports one problem with keys.
	youngPath := filepath.Join(dir, "young.log")
	young := OpenAudit(youngPath, Settings{MaxBytes: 1 << 20, MaxFiles: 4, Append: true, Signer: signer})
	if err := young.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: "r-young", Subject: "cust-001"}); err != nil {
		t.Fatal(err)
	}
	if err := young.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	repYoung, err := VerifyChain([]string{youngPath}, keys)
	if err != nil {
		t.Fatal(err)
	}
	if repYoung.Valid() || len(repYoung.Problems) != 1 || !strings.Contains(repYoung.Problems[0], "checkpoint") {
		t.Errorf("young run before first checkpoint: valid=%v problems=%v, want 1 checkpoint problem", repYoung.Valid(), repYoung.Problems)
	}
}

func TestVerifyAcceptsSignedEviction(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(message []byte) (string, []byte, error) { return "k1", ed25519.Sign(private, message), nil }
	keys := map[string]crypto.PublicKey{"k1": public}
	path := filepath.Join(t.TempDir(), "audit.log")

	// Run 1 and Run 2 produce rotated files with signed checkpoints.
	for _, subj := range []string{"cust-001", "cust-002"} {
		a := OpenAudit(path, Settings{MaxBytes: 1500, MaxFiles: 64, Append: true, Signer: signer})
		for i := range 20 {
			if err := a.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: fmt.Sprintf("%s-%d", subj, i), Subject: subj}); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	rot12 := rotated(t, path)
	if len(rot12) < 4 {
		t.Fatalf("expected >= 4 rotated files, got %d", len(rot12))
	}
	// Omit rot12[len-2] (whose successor rot12[len-1] is in Run 2 and anchors cleanly).
	evictedName := filepath.Base(rot12[len(rot12)-2])

	// Run 3: record audit.evicted for evictedName, then write enough records to
	// rotate so a signed checkpoint of Run 3 covers that eviction record.
	a3 := OpenAudit(path, Settings{MaxBytes: 1500, MaxFiles: 64, Append: true, Signer: signer})
	if err := a3.Commit(context.Background(), Event{Kind: "audit.evicted", File: evictedName}); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		if err := a3.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: fmt.Sprintf("r3-%d", i), Subject: "cust-003"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a3.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	allRot := rotated(t, path)
	subset := append([]string{rot12[0], rot12[1], rot12[len(rot12)-1]}, allRot[len(rot12):]...)
	subset = append(subset, path)

	report, err := VerifyChain(subset, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid() || len(report.Missing) != 0 {
		t.Fatalf("signed eviction did not explain %s: %+v", evictedName, report)
	}

	// An audit.evicted written after Run 3's last checkpoint does not explain a missing file.
	otherMissing := filepath.Base(rot12[len(rot12)-1])
	subset2 := append([]string{rot12[0], rot12[1]}, allRot[len(rot12):]...)
	subset2 = append(subset2, path)
	a4 := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 64, Append: true, Signer: signer})
	if err := a4.Commit(context.Background(), Event{Kind: "audit.evicted", File: otherMissing}); err != nil {
		t.Fatal(err)
	}
	if err := a4.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	repUncovered, err := VerifyChain(subset2, keys)
	if err != nil {
		t.Fatal(err)
	}
	if repUncovered.Valid() || !slices.Contains(repUncovered.Missing, otherMissing) {
		t.Fatalf("uncovered audit.evicted hid %s or passed: %+v", otherMissing, repUncovered)
	}
}
