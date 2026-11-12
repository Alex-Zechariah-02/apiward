//go:build !faultinject

// No-op fault points for builds without the faultinject tag.

package fault

import (
	"context"
	"os"
	"time"
)

func CancelPoint(context.Context, string) {}

func CrashPoint(string) {}

// WriteAudit writes data at offset and makes it durable with sync.
func WriteAudit(file *os.File, data []byte, offset int64, sync func(*os.File) error) error {
	if _, err := file.WriteAt(data, offset); err != nil {
		return err
	}
	return sync(file)
}

func RateClockFault() (int64, bool) { return 0, false }

func TimerFault() bool { return false }

func RollbackFault() error { return nil }

func CandidateReadFault() error { return nil }

func SignalCapture(string, string) {}

func WallOffset() time.Duration { return 0 }
