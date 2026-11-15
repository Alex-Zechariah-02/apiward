// Security log CSV export.

package admin

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// The names and order are fixed, because a spreadsheet or script reads the
// export by column; a new column is added last.
var securityLogColumns = []string{"time", "request_id", "decision", "status", "code", "stage", "method", "path", "operation", "api", "subject", "roles", "client_address", "generation", "duration_ms", "path_truncated"}

// writeSecurityLogCSV writes the rows as CSV, with coverage in headers. A
// value a spreadsheet would read as a formula is prefixed with an apostrophe:
// methods, paths, account IDs and roles come from clients; the other columns
// are the gateway's own values or IDs an administrator wrote in the policy.
func writeSecurityLogCSV(w http.ResponseWriter, result monitor.Result, next *string, missing []string) {
	header := w.Header()
	header.Set("Content-Type", "text/csv; charset=utf-8")
	header.Set("Content-Disposition", `attachment; filename="security-log.csv"`)
	header.Set("X-Security-Log-Complete", strconv.FormatBool(next == nil))
	header.Set("X-Security-Log-Files-Searched", strings.Join(result.Searched, ","))
	header.Set("X-Security-Log-Files-Missing", strings.Join(missing, ","))
	header.Set("X-Security-Log-Unreadable-Lines", strconv.Itoa(result.Unreadable))
	if next != nil {
		header.Set("X-Security-Log-Next", *next)
	}
	w.WriteHeader(http.StatusOK)
	out := csv.NewWriter(w)
	out.Write(securityLogColumns)
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	for _, v := range result.Items {
		cut := ""
		if v.Truncated {
			cut = "true"
		}
		out.Write([]string{
			v.Time.UTC().Format(time.RFC3339Nano), v.RequestID, v.Decision, strconv.Itoa(v.Status), text(v.Code), v.Stage,
			safeCell(v.Method), safeCell(v.Path), text(v.Operation), text(v.API), safeCell(text(v.Subject)), safeCell(strings.Join(v.Roles, " ")),
			v.ClientAddress, v.Generation, strconv.FormatFloat(v.DurationMS, 'f', -1, 64), cut,
		})
	}
	out.Flush()
}

// safeCell keeps a spreadsheet from running a client-chosen value as a formula.
func safeCell(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}
