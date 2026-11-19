// Path checks for operator commands.

package operator

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func pathsAlias(a, b string) bool {
	a, _ = filepath.Abs(a)
	b, _ = filepath.Abs(b)
	if runtime.GOOS == "windows" && strings.EqualFold(a, b) || a == b {
		return true
	}
	return sameFile(a, b)
}

// CheckPaths refuses a deployment whose files (the configuration at
// configPath, the database and its companions, the audit log and the trust
// keys) are not distinct regular paths, and operator files of command that
// would overwrite any of them.
func CheckPaths(configPath string, cfg Config, command string, flags map[string]string) error {
	// Read-only inputs may be links (container secret mounts); writable
	// state may not.
	protected := []struct {
		name, path string
		readOnly   bool
	}{
		{"configuration", configPath, true},
		{"database", cfg.Database, false},
		{"audit log", cfg.AuditLog, false},
		{"deployment lock", cfg.Database + ".lock", false},
		{"database WAL", cfg.Database + "-wal", false},
		{"database SHM", cfg.Database + "-shm", false},
		{"database journal", cfg.Database + "-journal", false},
	}
	for _, file := range cfg.KeyFiles {
		protected = append(protected, struct {
			name, path string
			readOnly   bool
		}{"JWT public key", file, true})
	}
	if cfg.IdentityKey != "" {
		protected = append(protected, struct {
			name, path string
			readOnly   bool
		}{"identity key", cfg.IdentityKey, true})
	}
	for i, file := range protected {
		check := store.RegularPath
		if file.readOnly {
			check = store.ReadOnlyPath
		}
		if err := check(file.path); err != nil {
			return fmt.Errorf("%s: %w", file.name, err)
		}
		for _, previous := range protected[:i] {
			if pathsAlias(file.path, previous.path) {
				return fmt.Errorf("the %s (%s) and the %s (%s) name the same file; configuration paths must name distinct files", previous.name, previous.path, file.name, file.path)
			}
		}
	}
	var paths []string
	switch command {
	case "backup":
		paths = []string{flags["output"], flags["output"] + ".partial", manifestPath(flags["output"])}
	case "restore":
		if pathsAlias(flags["backup"], cfg.Database) {
			return errors.New("the backup cannot be the live database")
		}
		paths = []string{flags["backup"], manifestPath(flags["backup"]), cfg.Database + ".restore", cfg.Database + ".restore-wal", cfg.Database + ".restore-shm", cfg.Database + ".restore-journal"}
	}
	for i, path := range paths {
		if err := store.RegularPath(path); err != nil {
			return err
		}
		for _, other := range protected {
			if pathsAlias(path, other.path) {
				return fmt.Errorf("%s names the same file as the %s (%s); operator files must not touch deployment authority", path, other.name, other.path)
			}
		}
		for _, other := range paths[:i] {
			if pathsAlias(path, other) {
				return fmt.Errorf("%s and %s name the same file; the command's files must be distinct", other, path)
			}
		}
	}
	return nil
}
