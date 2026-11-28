// The tamper-evident chain. Each written batch extends a SHA-256 chain,
// h(n) = SHA-256(h(n-1) || the batch's bytes), and ends with an audit.chain
// record carrying h(n); the chain starts again at zero at each start of the
// gateway. Once a minute, at each rotation and at a clean stop an
// audit.checkpoint record carries the head signed with the gateway's identity
// key, so a copy of a checkpoint kept off the host bounds what anyone could
// later rewrite (AWS CloudTrail digest files, RFC 5848 signed syslog). Someone
// with root on the host holds the key and can rewrite and re-sign the tail;
// only checkpoints copied off the host bound that.

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

// Checkpoint is the last synced signed checkpoint, returned by GET /admin/status
// for off-host anchoring.
type Checkpoint struct {
	Boot      string    `json:"boot"`
	SHA256    string    `json:"sha256"`
	Kid       string    `json:"kid"`
	Signature string    `json:"signature"`
	Time      time.Time `json:"time"`
}

// ChainBatches is the number of audit.chain records written and synced since start.
func (a *AuditLog) ChainBatches() uint64 { return a.chainBatches.Load() }

// Checkpoint returns the last synced signed checkpoint, or nil before the first
// checkpoint or when signing is disabled.
func (a *AuditLog) Checkpoint() *Checkpoint {
	cp := a.lastCheckpoint.Load()
	if cp == nil {
		return nil
	}
	snapshot := *cp
	return &snapshot
}
