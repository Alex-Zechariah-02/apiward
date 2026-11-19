// Files of the policy subcommands: bounded reads, and two outputs written
// in a fixed order, both or neither, never over an existing file.

package openapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
)

// write encodes the output and the report as 2-space JSON and writes both
// new files, or neither. Raw output is written as given.
func write(outPath string, output any, reportPath string, report any) error {
	if outPath == reportPath {
		return errors.New("the output and the report must be different files")
	}
	var files []newFile
	for _, f := range []struct {
		path  string
		value any
	}{{outPath, output}, {reportPath, report}} {
		if raw, ok := f.value.(json.RawMessage); ok {
			files = append(files, newFile{f.path, raw})
			continue
		}
		data, err := indent(f.value)
		if err != nil {
			return err
		}
		files = append(files, newFile{f.path, data})
	}
	return writeNew(files)
}

// indent is the written form of a JSON output: 2-space indent, final newline.
func indent(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	return append(data, '\n'), err
}

// readLimited reads at most limit bytes and refuses a longer file.
func readLimited(path string, limit int64, name string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s file: %w", name, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s file: %w", name, err)
	}
	if int64(len(data)) > limit {
		if limit%(1<<20) == 0 {
			return nil, fmt.Errorf("the %s file is larger than %d MiB", name, limit>>20)
		}
		return nil, fmt.Errorf("the %s file is larger than %d bytes", name, limit)
	}
	return data, nil
}

// newFile is one output: its path and its whole content.
type newFile struct {
	path string
	data []byte
}

// writeNew creates every file exclusively, in the given order, before
// writing any, and removes the files it created if any step fails, so no
// existing file is changed, a failure leaves no partial output and the same
// command fails the same way every time. Each file's directory is synced, so
// both names survive a power cut once the command succeeds.
func writeNew(files []newFile) error {
	var opened []*os.File
	var failure error
	for _, f := range files {
		// 0o600 keeps other local users from reading the policy or report written here.
		file, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			failure = fmt.Errorf("%s already exists; choose a new file", f.path)
			break
		}
		if err != nil {
			failure = err
			break
		}
		opened = append(opened, file)
	}
	for i, file := range opened {
		if failure == nil {
			_, failure = file.Write(files[i].data)
		}
		if err := file.Sync(); failure == nil {
			failure = err
		}
		if err := file.Close(); failure == nil {
			failure = err
		}
	}
	for i := range opened {
		if failure == nil {
			failure = filecheck.SyncDir(filepath.Dir(files[i].path))
		}
	}
	if failure != nil {
		for i := range opened {
			if err := os.Remove(files[i].path); err != nil {
				failure = errors.Join(failure, fmt.Errorf("%s was left behind; remove it by hand: %w", files[i].path, err))
			}
		}
	}
	return failure
}
