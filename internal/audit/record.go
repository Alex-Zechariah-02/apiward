// Encoding one record without reflection: the fields of Event in their
// declared order, each written as encoding/json writes it (the same omitempty
// and omitzero rules, HTML escaping and number forms), so the bytes are those
// json.Marshal gives, without boxing the event or copying a Marshaler's
// result. A test compares the two on varied events.

package audit

import "strconv"

// appendRecord appends e as encoding/json would encode it, without the
// newline.
func appendRecord(b []byte, e *Event) []byte {
	b = append(b, `{"schema":`...)
	b = strconv.AppendInt(b, int64(e.Schema), 10)
	b = append(b, `,"event_id":`...)
	b = appendString(b, e.ID)
	b = append(b, `,"time":`...)
	b = appendTime(b, e.Time)
	b = append(b, `,"seq":`...)
	b = strconv.AppendUint(b, e.Seq, 10)
	b = append(b, `,"kind":`...)
	b = appendString(b, e.Kind)
	if e.RequestID != "" {
		b = append(b, `,"request_id":`...)
		b = appendString(b, e.RequestID)
	}
	if e.Stage != "" {
		b = append(b, `,"stage":`...)
		b = appendString(b, e.Stage)
	}
	if e.Stages != (stages{}) {
		b = append(b, `,"stages":`...)
		b = e.Stages.appendJSON(b)
	}
	if len(e.Modules) > 0 {
		b = append(b, `,"modules":`...)
		b = appendStringMap(b, e.Modules)
	}
	if e.Decision != "" {
		b = append(b, `,"decision":`...)
		b = appendString(b, e.Decision)
	}
	if e.Status != 0 {
		b = append(b, `,"status":`...)
		b = strconv.AppendInt(b, int64(e.Status), 10)
	}
	if e.Error != "" {
		b = append(b, `,"error":`...)
		b = appendString(b, e.Error)
	}
	if e.Method != "" {
		b = append(b, `,"method":`...)
		b = appendString(b, e.Method)
	}
	if e.Path != "" {
		b = append(b, `,"path":`...)
		b = appendString(b, e.Path)
	}
	if e.Truncated {
		b = append(b, `,"path_truncated":`...)
		b = append(b, "true"...)
	}
	if e.ForwardedPath != "" {
		b = append(b, `,"forwarded_path":`...)
		b = appendString(b, e.ForwardedPath)
	}
	if e.Operation != "" {
		b = append(b, `,"operation":`...)
		b = appendString(b, e.Operation)
	}
	if e.API != "" {
		b = append(b, `,"api":`...)
		b = appendString(b, e.API)
	}
	if e.Subject != "" {
		b = append(b, `,"subject":`...)
		b = appendString(b, e.Subject)
	}
	if len(e.Roles) > 0 {
		b = append(b, `,"roles":`...)
		b = appendStrings(b, e.Roles)
	}
	if len(e.IgnoredRoles) > 0 {
		b = append(b, `,"ignored_roles":`...)
		b = appendStrings(b, e.IgnoredRoles)
	}
	if e.ClientAddress != "" {
		b = append(b, `,"client_address":`...)
		b = appendString(b, e.ClientAddress)
	}
	if e.DurationMS != 0 {
		b = append(b, `,"duration_ms":`...)
		b = appendFloat(b, e.DurationMS)
	}
	if e.UpstreamMS != 0 {
		b = append(b, `,"upstream_ms":`...)
		b = appendFloat(b, e.UpstreamMS)
	}
	if e.Actor != "" {
		b = append(b, `,"actor":`...)
		b = appendString(b, e.Actor)
	}
	if e.Session != "" {
		b = append(b, `,"session":`...)
		b = appendString(b, e.Session)
	}
	if e.Generation != "" {
		b = append(b, `,"generation":`...)
		b = appendString(b, e.Generation)
	}
	if e.Profile != "" {
		b = append(b, `,"profile":`...)
		b = appendString(b, e.Profile)
	}
	if e.Upstream != "" {
		b = append(b, `,"upstream":`...)
		b = appendString(b, e.Upstream)
	}
	if e.UpstreamAddress != "" {
		b = append(b, `,"upstream_address":`...)
		b = appendString(b, e.UpstreamAddress)
	}
	if e.ResolvedDigest != "" {
		b = append(b, `,"settings_resolved_digest":`...)
		b = appendString(b, e.ResolvedDigest)
	}
	if e.Transition != "" {
		b = append(b, `,"transition":`...)
		b = appendString(b, e.Transition)
	}
	if e.Revision != 0 {
		b = append(b, `,"revision":`...)
		b = strconv.AppendInt(b, int64(e.Revision), 10)
	}
	if e.Candidate != 0 {
		b = append(b, `,"candidate":`...)
		b = strconv.AppendInt(b, int64(e.Candidate), 10)
	}
	if e.Provisional != 0 {
		b = append(b, `,"provisional":`...)
		b = strconv.AppendInt(b, int64(e.Provisional), 10)
	}
	if e.RollbackTarget != 0 {
		b = append(b, `,"rollback_target":`...)
		b = strconv.AppendInt(b, int64(e.RollbackTarget), 10)
	}
	if !e.Deadline.IsZero() {
		b = append(b, `,"deadline":`...)
		b = appendTime(b, e.Deadline)
	}
	if e.Override != 0 {
		b = append(b, `,"override":`...)
		b = strconv.AppendInt(b, int64(e.Override), 10)
	}
	if e.Target != "" {
		b = append(b, `,"target":`...)
		b = appendString(b, e.Target)
	}
	if !e.Expires.IsZero() {
		b = append(b, `,"expires_at":`...)
		b = appendTime(b, e.Expires)
	}
	if e.Reason != "" {
		b = append(b, `,"reason":`...)
		b = appendString(b, e.Reason)
	}
	if e.Lost != 0 {
		b = append(b, `,"lost":`...)
		b = strconv.AppendUint(b, e.Lost, 10)
	}
	if e.File != "" {
		b = append(b, `,"file":`...)
		b = appendString(b, e.File)
	}
	if e.Offset != 0 {
		b = append(b, `,"offset":`...)
		b = strconv.AppendInt(b, int64(e.Offset), 10)
	}
	if e.Bytes != 0 {
		b = append(b, `,"bytes":`...)
		b = strconv.AppendInt(b, int64(e.Bytes), 10)
	}
	if e.Digest != "" {
		b = append(b, `,"sha256":`...)
		b = appendString(b, e.Digest)
	}
	if e.Archived != 0 {
		b = append(b, `,"archived_bytes":`...)
		b = strconv.AppendInt(b, e.Archived, 10)
	}
	if !e.First.IsZero() {
		b = append(b, `,"first_record":`...)
		b = appendTime(b, e.First)
	}
	if !e.Last.IsZero() {
		b = append(b, `,"last_record":`...)
		b = appendTime(b, e.Last)
	}
	if len(e.Counts) > 0 {
		b = append(b, `,"counts":`...)
		b = appendCountMap(b, e.Counts)
	}
	if e.Signature != "" {
		b = append(b, `,"signature":`...)
		b = appendString(b, e.Signature)
	}
	if len(e.Addresses) > 0 {
		b = append(b, `,"addresses":`...)
		b = appendAddresses(b, e.Addresses)
	}
	if !e.OldHighWater.IsZero() {
		b = append(b, `,"old_high_water":`...)
		b = appendTime(b, e.OldHighWater)
	}
	if !e.NewHighWater.IsZero() {
		b = append(b, `,"new_high_water":`...)
		b = appendTime(b, e.NewHighWater)
	}
	if len(e.Ended) > 0 {
		b = append(b, `,"ended_transitions":`...)
		b = appendStrings(b, e.Ended)
	}
	return append(b, '}')
}
