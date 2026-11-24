// Verifying the chain: the files read in order, each batch's bytes hashed
// onto the head of its run, every audit.chain record compared and every
// audit.checkpoint signature checked with the gateway's public keys. A run
// starts at each start of the gateway (its boot ID); records written after
// a run's last chain record (an unclean stop) are reported as unchained, not
// as tampered. Compressed files are read through gzip and their content
// checked against the SHA-256 in their header; a file named by the next
// file's audit.rotated record that was neither given nor evicted (an
// audit.evicted record names it) is reported missing.

package audit

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// ChainReport is what VerifyChain found.
type ChainReport struct {
	Records     int      `json:"records"`
	Chains      int      `json:"chain_records"`
	Checkpoints int      `json:"checkpoints"`
	Unchained   int      `json:"unchained_records"`
	Anchored    []string `json:"anchored_files"`
	Problems    []string `json:"problems"`
	Missing     []string `json:"missing_files"`
}

// Valid reports whether nothing was found altered or missing.
func (r ChainReport) Valid() bool { return len(r.Problems) == 0 && len(r.Missing) == 0 }

// chainLine is what verification reads of one record.
type chainLine struct {
	ID        string `json:"event_id"`
	Kind      string `json:"kind"`
	Digest    string `json:"sha256"`
	Target    string `json:"target"`
	Signature string `json:"signature"`
	File      string `json:"file"`
}

// verifier is the state carried from line to line, across files.
type verifier struct {
	keys       map[string]crypto.PublicKey
	report     ChainReport
	file       string
	boot       string
	head       [sha256.Size]byte
	pending    []byte
	lines      int // records in pending
	needAnchor bool
	anchorSeen bool
	// evicted names the files audit.evicted records name; before the file
	// each given file's first audit.rotated record names.
	evicted map[string]bool
	before  []string
}

// VerifyChain checks the files, oldest first, with the checkpoint keys by
// key ID (Ed25519 or ECDSA P-256 public keys).
func VerifyChain(paths []string, keys map[string]crypto.PublicKey) (ChainReport, error) {
	v := &verifier{
		keys:    keys,
		report:  ChainReport{Anchored: []string{}, Problems: []string{}, Missing: []string{}},
		evicted: map[string]bool{},
	}
	given := map[string]bool{}
	for _, path := range paths {
		given[strings.TrimSuffix(filepath.Base(path), packedSuffix)] = true
		v.file = path
		data, err := v.content(path)
		if err != nil {
			return v.report, err
		}
		reader := bufio.NewReaderSize(bytes.NewReader(data), MaxRecordBytes)
		for n := 1; ; n++ {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				v.line(line, fmt.Sprintf("%s:%d", path, n), n == 1)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return v.report, err
			}
		}
	}
	if v.needAnchor {
		v.reportUnanchored()
	}
	v.report.Unchained += v.lines
	// The first file's predecessor is not checked: a subset may be given.
	for i, name := range v.before {
		if i > 0 && name != "" && !given[name] && !v.evicted[name] {
			v.report.Missing = append(v.report.Missing, name)
		}
	}
	return v.report, nil
}

// content reads a file's records: a compressed file whole through gzip,
// with a changed or damaged one reported and read as empty.
func (v *verifier) content(path string) ([]byte, error) {
	if !strings.HasSuffix(path, packedSuffix) {
		data, err := os.ReadFile(path)
		return Content(data), err
	}
	header, err := ReadPacked(path)
	if err != nil {
		v.report.Problems = append(v.report.Problems, path+": "+err.Error())
		return nil, nil
	}
	reader, err := OpenRecords(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	// Bounded by the size the header states, so a changed file cannot
	// expand without limit; a longer content fails the digest check.
	data, err := io.ReadAll(io.LimitReader(reader, header.Bytes+1))
	sum := sha256.Sum256(data)
	switch {
	case err != nil:
		v.report.Problems = append(v.report.Problems, path+": the compressed file is damaged: "+err.Error())
		return nil, nil
	case hex.EncodeToString(sum[:]) != header.Digest:
		v.report.Problems = append(v.report.Problems, path+": the content does not match the SHA-256 in its header")
	}
	return data, nil
}

// line takes one record with its newline; where names it in problems, and
// head marks a file's first record.
func (v *verifier) line(line []byte, where string, head bool) {
	v.report.Records++
	var r chainLine
	parsed := json.Unmarshal(bytes.TrimSpace(line), &r) == nil
	if head {
		before := ""
		if parsed && r.Kind == "audit.rotated" {
			before = r.File
		}
		v.before = append(v.before, before)
	}
	if parsed && r.Kind == "audit.evicted" {
		v.evicted[r.File] = true
	}
	if parsed {
		if boot, _, found := strings.Cut(r.ID, "-"); found && boot != v.boot {
			if v.needAnchor {
				v.reportUnanchored()
			}
			// A new run: what the last one left unchained is not its.
			v.report.Unchained += v.lines
			v.boot, v.head, v.pending, v.lines = boot, [sha256.Size]byte{}, nil, 0
			v.needAnchor = head && r.Kind == "audit.rotated"
			v.anchorSeen = false
		}
	}
	if parsed && r.Kind == "audit.chain" {
		if v.needAnchor {
			v.reportUnanchored()
			v.head, _ = parseDigest(r.Digest)
			v.pending, v.lines = v.pending[:0], 0
			v.report.Chains++
			return
		}
		sum := sha256.New()
		sum.Write(v.head[:])
		sum.Write(v.pending)
		var head [sha256.Size]byte
		copy(head[:], sum.Sum(nil))
		if hex.EncodeToString(head[:]) != r.Digest {
			v.report.Problems = append(v.report.Problems, where+": the records before this chain record were altered, added or removed")
		}
		v.head, v.pending, v.lines = head, v.pending[:0], 0
		v.report.Chains++
		return
	}
	if parsed && r.Kind == "audit.checkpoint" {
		if v.needAnchor {
			v.anchor(r)
		} else {
			v.checkpoint(r, where)
		}
	}
	v.pending = append(v.pending, line...)
	v.lines++
}

// anchor verifies the first checkpoint of a mid-run rotated file by signature
// only so later chain records of the run can be checked from its digest.
func (v *verifier) anchor(r chainLine) {
	v.report.Checkpoints++
	if v.anchorSeen {
		return
	}
	v.anchorSeen = true
	head, ok := parseDigest(r.Digest)
	if !ok {
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(r.Signature)
	key := v.keys[r.Target]
	if key == nil || err != nil || !checkpointSigned(key, checkpointMessage(v.boot, r.Digest), signature) {
		return
	}
	v.head = head
	v.needAnchor = false
	v.report.Anchored = append(v.report.Anchored, v.file)
}

func (v *verifier) reportUnanchored() {
	v.report.Problems = append(v.report.Problems, fmt.Sprintf("%s: run %s starts here without a verifiable checkpoint; earlier records of this run cannot be checked", v.file, v.boot))
	v.needAnchor = false
	v.anchorSeen = false
}

func parseDigest(text string) ([sha256.Size]byte, bool) {
	var out [sha256.Size]byte
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != sha256.Size {
		return out, false
	}
	copy(out[:], raw)
	return out, true
}

// checkpoint checks a checkpoint names the head so far and is signed by its key.
func (v *verifier) checkpoint(r chainLine, where string) {
	v.report.Checkpoints++
	signature, err := base64.RawURLEncoding.DecodeString(r.Signature)
	key := v.keys[r.Target]
	switch {
	case r.Digest != hex.EncodeToString(v.head[:]):
		v.report.Problems = append(v.report.Problems, where+": the checkpoint does not name the chain head before it")
	case key == nil:
		v.report.Problems = append(v.report.Problems, where+": the checkpoint's key "+r.Target+" is not among the keys given")
	case err != nil || !checkpointSigned(key, checkpointMessage(v.boot, r.Digest), signature):
		v.report.Problems = append(v.report.Problems, where+": the checkpoint's signature does not verify")
	}
}

// checkpointSigned verifies a raw signature: Ed25519 over the message, or
// ES256 (P-256, two 32-byte integers) over its SHA-256.
func checkpointSigned(key crypto.PublicKey, message, signature []byte) bool {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, message, signature)
	case *ecdsa.PublicKey:
		if len(signature) != 64 {
			return false
		}
		digest := sha256.Sum256(message)
		return ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	}
	return false
}
