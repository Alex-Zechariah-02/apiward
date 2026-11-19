// Generation identity: the label naming the base revision and overrides,
// and the digest of the compiled document and deadline.

package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Relabel returns a copy of g identified as the generation of revision
// with overrides, the temporary overrides applied to it in order.
// Compilation depends on neither, so only Revision, Overrides and ID
// differ, and g itself stays unchanged.
func (g *Generation) Relabel(revision int64, overrides []int64) *Generation {
	labelled := *g
	labelled.Revision = revision
	labelled.Overrides = overrides
	labelled.ID = labelled.identify()
	return &labelled
}

// identify names g by its base revision, the overrides applied to it (as
// "+o<id>.<id>…") and a digest of the compiled document and deadline. A
// generation without overrides keeps the form "r<revision>-…".
func (g *Generation) identify() string {
	sum := sha256.New()
	fmt.Fprintf(sum, "%s|%d|%d|", compilerVersion, g.Revision, g.NotAfter.UnixMilli())
	var label strings.Builder
	fmt.Fprintf(&label, "r%d", g.Revision)
	for i, id := range g.Overrides {
		separator := "."
		if i == 0 {
			separator = "+o"
		}
		fmt.Fprintf(&label, "%s%d", separator, id)
		fmt.Fprintf(sum, "o%d|", id)
	}
	sum.Write(g.document)
	// 48 bits tell apart the generations one deployment ever publishes; the
	// label already names the revision and overrides.
	return fmt.Sprintf("%s-%s", label.String(), hex.EncodeToString(sum.Sum(nil))[:12])
}
