// The record encoder writes exactly what encoding/json writes for the same
// event, so the log's bytes did not change with it.

package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRecordMatchesEncodingJSON(t *testing.T) {
	at := time.Date(2026, 11, 19, 8, 22, 33, 123456789, time.UTC)
	var all stages
	for i := range all {
		all[i] = StageReject
	}
	odd := "q\"b\\s<a>&\n\t\x01 é " + string(rune(0x2028)) + string(rune(0x2029)) + string([]byte{0xff, 'x'})
	events := []Event{
		{},
		{Schema: EventSchema, ID: "boot-1", Time: at, Seq: 1, Kind: "request.admitted", RequestID: "r1", Stage: "AUDIT",
			Stages: stages{StagePass}, Modules: map[string]string{"b": "PASS", "a": "NE"}, Decision: "admit", Status: 201,
			Method: "POST", Path: "/orders/" + odd, Truncated: true, ForwardedPath: "/x", Operation: "op", API: "api",
			Subject: odd, Roles: []string{"A", odd}, IgnoredRoles: []string{"Z"}, ClientAddress: "192.0.2.1",
			DurationMS: 1.25, UpstreamMS: 0.0000001, Actor: "admin", Session: "s", Generation: "g", Profile: "core"},
		{Kind: "audit.evicted", Stages: all, Upstream: "u", UpstreamAddress: "a:1", ResolvedDigest: "d", Transition: "t",
			Revision: -1, Candidate: 2, Provisional: 3, RollbackTarget: 4, Deadline: at, Override: 5, Target: "x", Expires: at,
			Reason: "r", Lost: 9, File: "f", Offset: 10, Bytes: 11, Digest: "h", First: at, Last: at.Add(time.Hour),
			Counts: map[string]uint64{"z": 1, "a": 2}, Signature: "sig", Addresses: []AddressCount{{"192.0.2.1", 3}, {odd, 4}},
			OldHighWater: at.Add(time.Hour), NewHighWater: at, Ended: []string{"t1", odd},
			DurationMS: 1e21, Status: -3},
		{DurationMS: 123456.789, UpstreamMS: 3e-9},
	}
	for i, e := range events {
		want, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(appendRecord(nil, &e)); got != string(want) {
			t.Errorf("event %d:\n got %s\nwant %s", i, got, want)
		}
	}
	if strings.Contains(string(appendRecord(nil, &events[1])), "<a>") {
		t.Error("HTML characters are written unescaped")
	}
}
