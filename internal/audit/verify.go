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
	"compress/gzip"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
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
	keys          map[string]crypto.PublicKey
	report        ChainReport
	file          string
	origin        string // the file where the current run starts
	boot          string
	head          [sha256.Size]byte
	pending       []byte
	lines         int
	needAnchor    bool
	anchorSeen    bool
	runRecords    bool
	runVerified   bool
	runUnanchored bool
	runEvicted    []string // audit.evicted files no chain record covers yet
	runChained    []string // audit.evicted files chained but not yet signed
	// evicted names the files audit.evicted records name (with keys given,
	// only once a verified checkpoint signs a chain head covering them);
	// before names each file's predecessor from its first audit.rotated
	// record.
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
	v.finishRun()
	v.report.Unchained += v.lines
	// The first file's predecessor is not checked: a subset may be given.
	for i, name := range v.before {
		if i > 0 && name != "" && !given[name] && !v.evicted[name] {
			v.report.Missing = append(v.report.Missing, name)
		}
	}
	return v.report, nil
}

// content reads a file's records: a plain one of at most MaxAuditBytes, a
// compressed one whole through gzip, with a changed or damaged one reported
// and read as empty. Anything but a regular file is refused unopened.
func (v *verifier) content(path string) ([]byte, error) {
	if !strings.HasSuffix(path, packedSuffix) {
		data, err := filecheck.Read(path, MaxAuditBytes, nil)
		return Content(data), err
	}
	file, _, err := filecheck.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	zr, err := gzip.NewReader(file)
	if err != nil {
		v.report.Problems = append(v.report.Problems, path+": "+err.Error())
		return nil, nil
	}
	defer zr.Close()
	header, err := readPackedHeader(filepath.Base(path), zr)
	if err != nil {
		v.report.Problems = append(v.report.Problems, path+": "+err.Error())
		return nil, nil
	}
	// Bounded by the size the header states, so a changed file cannot
	// expand without limit; a longer content fails the digest check.
	data, err := io.ReadAll(io.LimitReader(zr, header.Bytes+1))
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
	if parsed {
		if boot, _, found := strings.Cut(r.ID, "-"); found && boot != v.boot {
			v.finishRun()
			// A new run: what the last one left unchained is not its.
			v.report.Unchained += v.lines
			v.boot, v.head, v.pending, v.lines = boot, [sha256.Size]byte{}, nil, 0
			v.needAnchor = head && r.Kind == "audit.rotated"
			v.origin = v.file
			v.anchorSeen = false
		}
	}
	if !v.runRecords {
		v.runRecords = true
		if v.origin == "" {
			v.origin = v.file
		}
	}
	if parsed && r.Kind == "audit.evicted" {
		if len(v.keys) == 0 {
			v.evicted[r.File] = true
		} else {
			v.runEvicted = append(v.runEvicted, r.File)
		}
	}
	if parsed && r.Kind == "audit.chain" {
		if v.needAnchor {
			v.reportUnanchored()
			v.head, _ = parseDigest(r.Digest)
			v.pending, v.lines = v.pending[:0], 0
			v.runEvicted = nil
			v.report.Chains++
			return
		}
		sum := sha256.New()
		sum.Write(v.head[:])
		sum.Write(v.pending)
		var head [sha256.Size]byte
		copy(head[:], sum.Sum(nil))
		if hex.EncodeToString(head[:]) == r.Digest {
			v.runChained = append(v.runChained, v.runEvicted...)
		} else {
			v.report.Problems = append(v.report.Problems, where+": the records before this chain record were altered, added or removed")
		}
		v.runEvicted = nil
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
