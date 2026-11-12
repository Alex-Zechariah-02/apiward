// Writing the active file: zero-filling ahead of the writer, writing in place
// at the logical end, and trimming the zero tail at rotation and close.
//
// On ext4 an append changes the file's size and allocation, so every sync
// commits the journal. Writing into blocks already zero-filled and synced
// changes neither, so fdatasync flushes only the data (the technique of
// PostgreSQL's wal_init_zero). The file is filled in steps of fillStep, so
// the zero tail, and a reader's skip past it, stays within one step.

package audit

import (
	"errors"
	"os"

	"github.com/Alex-Zechariah-02/apiward/internal/fault"
)

const fillStep = 1 << 20

// persist writes data at the logical end and syncs it, filling ahead first
// when the file is zero-filled.
func (a *AuditLog) persist(data []byte) error {
	if err := a.reserve(a.size + int64(len(data))); err != nil {
		return err
	}
	if err := fault.WriteAudit(a.file, data, a.size, a.sync); err != nil {
		return err
	}
	a.size += int64(len(data))
	return nil
}

// sync makes the file's writes durable: fdatasync for a zero-filled file,
// whose record writes change no size, else fsync (FlushFileBuffers on
// Windows), as an append needs.
func (a *AuditLog) sync(file *os.File) error {
	if a.prefill {
		return syncData(file)
	}
	return file.Sync()
}

// reserve zero-fills the file up to the fillStep boundary past need, but not
// past the file size limit unless need is, and syncs the zeros, so the
// records written into them change no size.
func (a *AuditLog) reserve(need int64) error {
	if !a.prefill || need <= a.filled {
		return nil
	}
	target := min((need+fillStep-1)/fillStep*fillStep, max(a.maxBytes, need))
	if _, err := a.file.WriteAt(make([]byte, target-a.filled), a.filled); err != nil {
		return err
	}
	if err := a.sync(a.file); err != nil {
		return err
	}
	a.filled = target
	return nil
}

// trim truncates the file to end, its logical end, and syncs the new size,
// so a rotated or closed file holds no zero tail.
func (a *AuditLog) trim(end int64) error {
	info, err := a.file.Stat()
	if err != nil {
		return err
	}
	if info.Size() == end {
		return nil
	}
	if err := a.file.Truncate(end); err != nil {
		return err
	}
	a.filled = end
	return a.file.Sync()
}

// closeFile trims the active file to the end its content shows, which after
// a failed write includes the partial record, left for inspection as an
// append leaves it, and closes it.
func (a *AuditLog) closeFile() error {
	end, err := End(a.file)
	if err == nil {
		err = a.trim(end)
	}
	return errors.Join(err, a.file.Close())
}
