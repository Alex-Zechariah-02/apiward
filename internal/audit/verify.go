// Verifying the chain: the files read in order, each batch's bytes hashed
// onto the head of its run, every audit.chain record compared and every
// audit.checkpoint signature checked with the gateway's public keys. A run
// starts at each start of the gateway (its boot ID); records written after
// a run's last chain record (an unclean stop) are reported as unchained, not
// as tampered.

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
	"strings"
)

// ChainReport is what VerifyChain found.
type ChainReport struct {
	Records     int      `json:"records"`
	Chains      int      `json:"chain_records"`
	Checkpoints int      `json:"checkpoints"`
	Unchained   int      `json:"unchained_records"`
	Problems    []string `json:"problems"`
}

// Valid reports whether nothing was found altered.
func (r ChainReport) Valid() bool { return len(r.Problems) == 0 }

// chainLine is what verification reads of one record.
type chainLine struct {
	ID        string `json:"event_id"`
	Kind      string `json:"kind"`
	Digest    string `json:"sha256"`
	Target    string `json:"target"`
	Signature string `json:"signature"`
}

// verifier is the state carried from line to line, across files.
type verifier struct {
	keys    map[string]crypto.PublicKey
	report  ChainReport
	boot    string
	head    [sha256.Size]byte
	pending []byte
	lines   int // records in pending
}

// VerifyChain checks the files, oldest first, with the checkpoint keys by
// key ID (Ed25519 or ECDSA P-256 public keys).
func VerifyChain(paths []string, keys map[string]crypto.PublicKey) (ChainReport, error) {
	v := &verifier{keys: keys, report: ChainReport{Problems: []string{}}}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return v.report, err
		}
		reader := bufio.NewReaderSize(bytes.NewReader(Content(data)), MaxRecordBytes)
		for n := 1; ; n++ {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				v.line(line, fmt.Sprintf("%s:%d", path, n))
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return v.report, err
			}
		}
	}
	v.report.Unchained += v.lines
	return v.report, nil
}

// line takes one record with its newline; where names it in problems.
func (v *verifier) line(line []byte, where string) {
	v.report.Records++
	var r chainLine
	parsed := json.Unmarshal(bytes.TrimSpace(line), &r) == nil
	if parsed {
		if boot, _, found := strings.Cut(r.ID, "-"); found && boot != v.boot {
			// A new run: what the last one left unchained is not its.
			v.report.Unchained += v.lines
			v.boot, v.head, v.pending, v.lines = boot, [sha256.Size]byte{}, nil, 0
		}
	}
	if parsed && r.Kind == "audit.chain" {
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
		v.checkpoint(r, where)
	}
	v.pending = append(v.pending, line...)
	v.lines++
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
