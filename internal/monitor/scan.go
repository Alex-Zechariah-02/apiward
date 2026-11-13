// Security log file scanning and cursors.

package monitor

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

var ErrCursorGone = errors.New("the file the search stopped in is no longer present")

// Search reads the files in dir newest first from start, at most
// scan bytes, until limit records match. Only the final record of each
// request (request.rejected or request.forwarded) is read, as the live views
// do. A line still being written at the end of the active file is skipped.
func Search(dir string, files []string, start *Cursor, query Query, limit int, scan int64) (Result, error) {
	result := Result{Items: []RequestView{}, Searched: []string{}}
	index, offset := 0, int64(-1) // -1 reads a file from its end
	if start != nil {
		index = -1
		// The named file first, then any other: a rotation renames the
		// active file, which keeps its first record.
		order := slices.Clone(files)
		if i := slices.Index(order, start.File); i > 0 {
			order[0], order[i] = order[i], order[0]
		}
		for _, name := range order {
			if first, err := firstRecordID(filepath.Join(dir, name)); err == nil && first == start.First {
				index, offset = slices.Index(files, name), start.Offset
				break
			}
		}
		if index < 0 {
			return result, ErrCursorGone
		}
	}
	budget := scan
	for ; index < len(files); index, offset = index+1, -1 {
		name := files[index]
		first, err := firstRecordID(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue // archived since it was listed
		}
		if err != nil {
			return result, err
		}
		if budget <= 0 {
			result.Next = &Cursor{File: name, First: first, Offset: offset}
			return result, nil
		}
		result.Searched = append(result.Searched, name)
		done, err := scanSecurityLogFile(filepath.Join(dir, name), name, first, offset, query, limit, &budget, &result)
		if err != nil || done {
			return result, err
		}
	}
	return result, nil
}

// scanSecurityLogFile searches one file backwards from end (-1: its logical
// size). It reports done when the search stops inside the file, with
// result.next set where it stopped.
func scanSecurityLogFile(path, name, first string, end int64, query Query, limit int, budget *int64, result *Result) (bool, error) {
	stop, stopped, err := scanLinesBackward(path, end, budget, func(line []byte, _ int64) bool {
		if view, ok := securityLogRecord(line, query, result); ok {
			result.Items = append(result.Items, view)
			return len(result.Items) >= limit
		}
		return false
	})
	if err != nil {
		return false, err
	}
	if stopped {
		result.Next = &Cursor{File: name, First: first, Offset: stop}
	}
	return stopped, nil
}

// scanLinesBackward calls visit for each complete line of a file, newest
// first, from end (-1: its logical end, audit.End), reading at most *budget bytes in
// windows. visit returns true to stop. stop is where reading can resume:
// lines before it are unread. A line still being written at the end of the
// file is skipped.
func scanLinesBackward(path string, end int64, budget *int64, visit func(line []byte, lineStart int64) bool) (stop int64, stopped bool, err error) {
	file, err := openLog(path)
	if err != nil {
		return 0, false, err
	}
	defer file.Close()
	if end < 0 {
		if end, err = audit.End(file); err != nil {
			return 0, false, err
		}
	}
	for end > 0 {
		if *budget <= 0 {
			return end, true, nil
		}
		size := min(end, securityLogWindow, *budget)
		base := end - size
		window := make([]byte, size)
		if _, err := file.ReadAt(window, base); err != nil && !errors.Is(err, io.EOF) {
			return 0, false, err
		}
		*budget -= size
		// Start at the first whole line; the part before it is read with
		// the next window. Records are at most maxRecordBytes, far smaller
		// than a window, so a window always holds a line break.
		if base > 0 {
			cut := bytes.IndexByte(window, '\n')
			if cut < 0 {
				return 0, false, errors.New("audit line longer than the read window")
			}
			window, base = window[cut+1:], base+int64(cut+1)
		}
		// Keep complete lines only.
		window = window[:bytes.LastIndexByte(window, '\n')+1]
		for len(window) > 0 {
			cut := bytes.LastIndexByte(window[:len(window)-1], '\n')
			line, lineStart := window[cut+1:len(window)-1], base+int64(cut+1)
			window = window[:cut+1]
			if visit(line, lineStart) {
				return lineStart, true, nil
			}
		}
		end = base
	}
	return 0, false, nil
}

var (
	rejectedKind  = []byte(`"kind":"request.rejected"`)
	forwardedKind = []byte(`"kind":"request.forwarded"`)
)

// securityLogRecord decodes a request's final record and applies the
// filters. A request record that cannot be decoded is counted, not hidden.
func securityLogRecord(line []byte, query Query, result *Result) (RequestView, bool) {
	if !bytes.Contains(line, rejectedKind) && !bytes.Contains(line, forwardedKind) {
		return RequestView{}, false
	}
	if query.ref != "" && !bytes.Contains(line, []byte(query.ref)) {
		return RequestView{}, false
	}
	var record auditRequestRecord
	if err := json.Unmarshal(line, &record); err != nil || record.RequestID == "" {
		result.Unreadable++
		return RequestView{}, false
	}
	view := View(audit.Event{
		Time: record.Time, RequestID: record.RequestID, Stage: record.Stage, Decision: record.Decision, Status: record.Status,
		Error: record.Error, Method: record.Method, Path: record.Path, Operation: record.Operation, API: record.API,
		Subject: record.Subject, Roles: record.Roles, ClientAddress: record.ClientAddress, Generation: record.Generation,
		DurationMS: record.DurationMS, Modules: record.Modules,
	})
	return view, query.matches(view)
}

// firstRecordID is the event ID of a file's first record, which names the
// file across a rotation; an empty file has none.
func firstRecordID(path string) (string, error) {
	record, err := firstRecord(path)
	return record.ID, err
}

// RecentRecord finds the first complete record that starts at or after span
// bytes before the file's logical end (audit.End). It returns the bytes from
// that record to the end and the record's time; zero time when the file holds
// less than span or no complete, decodable record starts there. Besides
// audit.End's search, it reads at most two records.
func RecentRecord(path string, span int64) (int64, time.Time, error) {
	file, err := openLog(path)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer file.Close()
	end, err := audit.End(file)
	if err != nil || end < span {
		return 0, time.Time{}, err // a file just rotated in holds no span yet
	}
	// From the byte before the span: a record starts after a line break, so
	// one that starts exactly at the span's first byte counts.
	start := max(end-span-1, 0)
	section := io.NewSectionReader(file, start, end-start)
	reader := bufio.NewReader(io.LimitReader(section, 2*(audit.MaxRecordBytes+1)))
	if end > span {
		skipped, err := reader.ReadBytes('\n')
		if err != nil {
			return 0, time.Time{}, ignoreEOF(err)
		}
		start += int64(len(skipped))
	}
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return 0, time.Time{}, ignoreEOF(err) // the line is still being written
	}
	var record headRecord
	if json.Unmarshal(line[:len(line)-1], &record) != nil {
		return 0, time.Time{}, nil
	}
	return end - start, record.Time, nil
}

// ignoreEOF drops io.EOF, which means no complete line was found.
func ignoreEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

type headRecord struct {
	ID   string    `json:"event_id"`
	Time time.Time `json:"time"`
}

// firstRecord decodes a file's first line, reading no further than its end
// or MaxRecordBytes.
func firstRecord(path string) (headRecord, error) {
	file, err := openLog(path)
	if err != nil {
		return headRecord{}, err
	}
	defer file.Close()
	line, err := bufio.NewReader(io.LimitReader(file, audit.MaxRecordBytes+1)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return headRecord{}, err
	}
	var record headRecord
	if json.Unmarshal(bytes.TrimSuffix(line, []byte("\n")), &record) != nil {
		return headRecord{}, nil
	}
	return record, nil
}

func EncodeCursor(c Cursor) string {
	data, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(data)
}

func DecodeCursor(text string) *Cursor {
	data, err := base64.RawURLEncoding.DecodeString(text)
	var c Cursor
	if err != nil || len(data) > 512 || policy.DecodeStrict(data, &c) != nil {
		return nil
	}
	if c.File == "" || filepath.Base(c.File) != c.File || strings.ContainsAny(c.File, `/\`) || c.Offset < -1 || len(c.First) > 128 {
		return nil
	}
	return &c
}
