// Checkpoint and anchor verification for VerifyChain: signature checks,
// mid-run anchoring and per-run signed coverage accounting.

package audit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

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
	v.markVerified()
	v.report.Anchored = append(v.report.Anchored, v.origin)
}

func (v *verifier) markVerified() {
	v.runVerified = true
	for _, name := range v.runEvicted {
		v.evicted[name] = true
	}
	v.runEvicted = nil
}

func (v *verifier) finishRun() {
	if v.needAnchor {
		v.reportUnanchored()
	}
	if len(v.keys) > 0 && v.runRecords && !v.runVerified && !v.runUnanchored {
		name := v.boot
		if name == "" {
			name = "unknown"
		}
		v.report.Problems = append(v.report.Problems, fmt.Sprintf("%s: run %s has no verifiable checkpoint; its records are not signed by any given key", v.origin, name))
	}
	v.runRecords, v.runVerified, v.runUnanchored, v.runEvicted = false, false, false, nil
}

func (v *verifier) reportUnanchored() {
	v.report.Problems = append(v.report.Problems, fmt.Sprintf("%s: run %s starts here without a verifiable checkpoint; earlier records of this run cannot be checked", v.origin, v.boot))
	v.needAnchor = false
	v.anchorSeen = false
	v.runUnanchored = true
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
	default:
		v.markVerified()
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
