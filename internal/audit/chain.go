// The tamper-evident chain. Each written batch extends a SHA-256 chain,
// h(n) = SHA-256(h(n-1) || the batch's bytes), and ends with an audit.chain
// record carrying h(n); the chain starts again at zero at each start of the
// gateway. Once a minute and at each rotation an audit.checkpoint record
// carries the head signed with the gateway's identity key, so a copy of a
// checkpoint kept off the host bounds what anyone could later rewrite (AWS
// CloudTrail digest files, RFC 5848 signed syslog). Someone with root on the
// host holds the key and can rewrite and re-sign the tail; only checkpoints
// copied off the host bound that.

package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// CheckpointInterval is how often a signed checkpoint is written.
const CheckpointInterval = time.Minute

// Signer signs a checkpoint's message and names its key; nil writes no
// checkpoints (an identity assertion turned off), the chain still runs.
type Signer func(message []byte) (kid string, signature []byte, err error)

// checkpointMessage is what a checkpoint signs: the boot ID and the head.
func checkpointMessage(boot, head string) []byte {
	return []byte("apiward audit checkpoint\n" + boot + "\n" + head + "\n")
}

// chain appends the batch's audit.chain record to buffer, which holds only
// this batch, and returns it with the new head; the caller keeps the head
// only once the batch is synced.
func (a *AuditLog) chain(buffer []byte, head [sha256.Size]byte) ([]byte, [sha256.Size]byte) {
	sum := sha256.New()
	sum.Write(head[:])
	sum.Write(buffer)
	copy(head[:], sum.Sum(nil))
	return a.appendEvent(buffer, a.stamp(Event{Kind: "audit.chain", Digest: hex.EncodeToString(head[:])})), head
}

// checkpoint returns the signed checkpoint of head, or false without a
// signer or when signing failed (logged by the caller's next checkpoint).
func (a *AuditLog) checkpoint(head [sha256.Size]byte) (Event, bool) {
	if a.signer == nil {
		return Event{}, false
	}
	digest := hex.EncodeToString(head[:])
	kid, signature, err := a.signer(checkpointMessage(a.boot, digest))
	if err != nil {
		return Event{}, false
	}
	return a.stamp(Event{Kind: "audit.checkpoint", Digest: digest, Target: kid, Signature: base64.RawURLEncoding.EncodeToString(signature)}), true
}

// ChainHead is the chain head after the last batch written, as hex, or ""
// before the first; an operator copies it off the host to bound rewrites.
func (a *AuditLog) ChainHead() string {
	if head := a.published.Load(); head != nil {
		return hex.EncodeToString(head[:])
	}
	return ""
}
