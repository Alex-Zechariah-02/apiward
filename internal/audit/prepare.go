// Describing the next file to evict before it is needed. Under evict_oldest
// the writer must record a file's size, SHA-256 and first and last record
// times before it deletes it; reading a whole file on the writer, the one
// sync point of every admission, would stall them all. A rotated file never
// changes, so its description is made in the background as soon as the log
// is one rotation from full, and the eviction uses it.

package audit

// describedFile is one background description: of the file at name.
type describedFile struct {
	name  string
	event Event
	err   error
}

// prepareEviction starts describing the oldest rotated file when the next
// rotation will evict it, unless that file is already being described. Only
// the writer calls it.
func (a *AuditLog) prepareEviction() {
	if !a.evict || a.rotated < a.maxFiles-1 {
		return
	}
	set, err := rotatedFiles(a.path)
	if err != nil || set.oldest == "" || set.oldest == a.preparing {
		return
	}
	a.preparing = set.oldest
	result := make(chan describedFile, 1)
	a.prepared = result
	go func(name string) {
		event, err := describe(name)
		result <- describedFile{name: name, event: event, err: err}
	}(set.oldest)
}

// described returns the description of name: the one prepared in the
// background, waiting for it if it is still being made, or else one made
// now. Only the writer calls it.
func (a *AuditLog) described(name string) (Event, error) {
	prepared, preparing := a.prepared, a.preparing
	a.prepared, a.preparing = nil, ""
	if prepared != nil && preparing == name {
		result := <-prepared
		return result.event, result.err
	}
	return describe(name)
}
