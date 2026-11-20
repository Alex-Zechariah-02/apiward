// Alert A3's storage conditions: the archive folder failing, a disk low on
// free space and rotated files piling up unarchived, each raised before the
// security log can no longer save records.

package admin

import (
	"fmt"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// waitingLimit is how many rotated files may wait for the archiver: one is
// normal right after a rotation, more means it is falling behind.
const waitingLimit = 2

// storageAlerts lists A3's storage conditions; none without an archiver.
func storageAlerts(state audit.ArchiveState, archives bool) []monitor.Finding {
	if !archives {
		return nil
	}
	var items []monitor.Finding
	if !state.Usable {
		items = append(items, monitor.Finding{ID: "A3", Severity: "critical", Object: "security_log",
			Message: "The security log archive folder " + state.Folder + " cannot be written. Rotated files are compressed in the log folder and the oldest are evicted there. Check the disk, mount and permissions."})
	}
	for _, disk := range []struct {
		name        string
		free, total int64
	}{{"log", state.FreeLog, state.TotalLog}, {"archive", state.FreeArchive, state.TotalArchive}} {
		if disk.free < 0 || disk.total <= 0 {
			continue
		}
		switch {
		case disk.free < state.ReserveSize:
			items = append(items, monitor.Finding{ID: "A3", Severity: "critical", Object: "security_log",
				Message: fmt.Sprintf("The security log's %s disk has %s free, less than the reserve. Free space now: the gateway refuses requests once no record can be saved.", disk.name, size(disk.free))})
		case float64(disk.free) < state.MinFree*float64(disk.total):
			items = append(items, monitor.Finding{ID: "A3", Severity: "medium", Object: "security_log",
				Message: fmt.Sprintf("The security log's %s disk has %s free, below its threshold; the oldest log files are being evicted early.", disk.name, size(disk.free))})
		}
	}
	if state.Waiting > waitingLimit {
		items = append(items, monitor.Finding{ID: "A3", Severity: "medium", Object: "security_log",
			Message: fmt.Sprintf("%d rotated security log files are waiting to be archived; the archiver is falling behind or failing.", state.Waiting)})
	}
	return items
}

// size words a byte count in MiB or GiB.
func size(bytes int64) string {
	if bytes >= 1<<30 {
		return fmt.Sprintf("%.1f GiB", float64(bytes)/(1<<30))
	}
	return fmt.Sprintf("%.0f MiB", float64(bytes)/(1<<20))
}
