// Signed checkpoint coverage in VerifyChain: every run verified with keys
// needs a verifiable checkpoint, a clean stop writes one before audit.closed,
// and an audit.evicted record explains a missing file only when a verified
// checkpoint of its run covers it.

package audit

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testCheckpointKeys(t *testing.T) (Signer, map[string]crypto.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(message []byte) (string, []byte, error) { return "k1", ed25519.Sign(private, message), nil }
	return signer, map[string]crypto.PublicKey{"k1": public}
}

func writeTwoSignedRuns(t *testing.T, path string, signer Signer) []string {
	t.Helper()
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
	return rotated(t, path)
}

func snapshotFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRequiresSignedCoverage(t *testing.T) {
	signer, keys := testCheckpointKeys(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	rot := writeTwoSignedRuns(t, path, signer)
	if len(rot) < 3 {
		t.Fatalf("expected >= 3 rotated files, got %d", len(rot))
	}
	deletedName := filepath.Base(rot[len(rot)-2])
	subset := []string{rot[0], rot[len(rot)-1], path}

	before, err := VerifyChain(subset, keys)
	if err != nil || !slices.Contains(before.Missing, deletedName) {
		t.Fatalf("setup expected %s missing: %+v %v", deletedName, before, err)
	}

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

	// A run that ends without a clean stop before its first periodic checkpoint
	// still reports the missing-checkpoint problem.
	youngPath := filepath.Join(dir, "young.log")
	youngSnap := filepath.Join(dir, "young-unclosed.log")
	young := OpenAudit(youngPath, Settings{MaxBytes: 1 << 20, MaxFiles: 4, Append: true, Signer: signer})
	if err := young.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: "r-young", Subject: "cust-001"}); err != nil {
		t.Fatal(err)
	}
	snapshotFile(t, youngPath, youngSnap)
	if err := young.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	repYoung, err := VerifyChain([]string{youngSnap}, keys)
	if err != nil {
		t.Fatal(err)
	}
	if repYoung.Valid() || len(repYoung.Problems) != 1 || !strings.Contains(repYoung.Problems[0], "checkpoint") {
		t.Errorf("unclosed young run: valid=%v problems=%v, want 1 checkpoint problem", repYoung.Valid(), repYoung.Problems)
	}
}

func TestVerifyAcceptsSignedEviction(t *testing.T) {
	signer, keys := testCheckpointKeys(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	rot12 := writeTwoSignedRuns(t, path, signer)
	if len(rot12) < 4 {
		t.Fatalf("expected >= 4 rotated files, got %d", len(rot12))
	}
	evictedName := filepath.Base(rot12[len(rot12)-2])

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

	// An audit.evicted in a run that ends without a checkpoint does not explain a missing file.
	otherMissing := filepath.Base(rot12[len(rot12)-1])
	snapPath := filepath.Join(dir, "unclosed-evict.log")
	a4 := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 64, Append: true, Signer: signer})
	if err := a4.Commit(context.Background(), Event{Kind: "audit.evicted", File: otherMissing}); err != nil {
		t.Fatal(err)
	}
	snapshotFile(t, path, snapPath)
	if err := a4.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	subset2 := append([]string{rot12[0], rot12[1]}, allRot[len(rot12):]...)
	subset2 = append(subset2, snapPath)
	repUncovered, err := VerifyChain(subset2, keys)
	if err != nil {
		t.Fatal(err)
	}
	if repUncovered.Valid() || !slices.Contains(repUncovered.Missing, otherMissing) {
		t.Fatalf("uncovered audit.evicted hid %s or passed: %+v", otherMissing, repUncovered)
	}
}

// A checkpoint signs the chain head before it, not the records after that
// head, so an eviction placed there and cut off from its chain record
// explains nothing.
func TestVerifyIgnoresUnchainedEviction(t *testing.T) {
	signer, keys := testCheckpointKeys(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	rot := writeTwoSignedRuns(t, path, signer)
	if len(rot) < 3 {
		t.Fatalf("expected >= 3 rotated files, got %d", len(rot))
	}
	deleted := filepath.Base(rot[len(rot)-2])
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(Content(data)), "\n")
	var forged []string
	for _, line := range lines {
		if strings.Contains(line, `"kind":"audit.checkpoint"`) {
			var r chainLine
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatal(err)
			}
			boot, _, _ := strings.Cut(r.ID, "-")
			forged = append(forged, fmt.Sprintf(`{"event_id":"%s-forged","kind":"audit.evicted","file":%q}`+"\n", boot, deleted), line)
			break
		}
		forged = append(forged, line)
	}
	if err := os.WriteFile(path, []byte(strings.Join(forged, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := VerifyChain([]string{rot[0], rot[1], rot[len(rot)-1], path}, keys)
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid() || !slices.Contains(report.Missing, deleted) {
		t.Fatalf("an eviction no chain record covers hid %s: %+v", deleted, report)
	}
}

// A clean stop writes a signed checkpoint before audit.closed, so a short
// cleanly stopped run verifies with keys and an eviction written after the
// last periodic checkpoint and before a clean stop explains its file.
func TestVerifyCleanStopCheckpoint(t *testing.T) {
	signer, keys := testCheckpointKeys(t)
	dir := t.TempDir()

	shortPath := filepath.Join(dir, "short.log")
	short := OpenAudit(shortPath, Settings{MaxBytes: 1 << 20, MaxFiles: 4, Append: true, Signer: signer})
	if err := short.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: "r-short", Subject: "cust-001"}); err != nil {
		t.Fatal(err)
	}
	if err := short.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	repShort, err := VerifyChain([]string{shortPath}, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !repShort.Valid() || repShort.Checkpoints != 1 {
		t.Errorf("cleanly stopped one-record run: valid=%v checkpoints=%d problems=%v", repShort.Valid(), repShort.Checkpoints, repShort.Problems)
	}

	evictPath := filepath.Join(dir, "evict.log")
	rot := writeTwoSignedRuns(t, evictPath, signer)
	if len(rot) < 4 {
		t.Fatalf("expected >= 4 rotated files, got %d", len(rot))
	}
	evictedName := filepath.Base(rot[len(rot)-2])
	tail := OpenAudit(evictPath, Settings{MaxBytes: 1 << 20, MaxFiles: 64, Append: true, Signer: signer})
	if err := tail.Commit(context.Background(), Event{Kind: "audit.evicted", File: evictedName}); err != nil {
		t.Fatal(err)
	}
	if err := tail.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	subset := []string{rot[0], rot[1], rot[len(rot)-1], evictPath}
	repEvict, err := VerifyChain(subset, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !repEvict.Valid() || len(repEvict.Missing) != 0 {
		t.Errorf("eviction before clean stop did not explain %s: %+v", evictedName, repEvict)
	}
}
