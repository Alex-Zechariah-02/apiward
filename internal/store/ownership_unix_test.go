// The database, its companion files and the deployment lock are refused when
// the group or others can read or write them (Unix modes only).

//go:build unix

package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

func TestPrivateFiles(t *testing.T) {
	for _, tc := range []struct{ name, suffix string }{
		{"database", ""}, {"write-ahead log", "-wal"}, {"shared memory", "-shm"}, {"rollback journal", "-journal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gateway.db")
			storetest.Seed(t, path, storetest.Policy(false), storetest.Options{})
			if st, err := store.OpenStore(path); err != nil {
				t.Fatalf("private files refused: %v", err)
			} else {
				st.Close()
			}
			target := path + tc.suffix
			if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(target, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := store.OpenStore(path)
			if !errors.Is(err, store.ErrUnavailable) || !strings.Contains(err.Error(), "group or others") {
				t.Fatalf("%s readable by others: %v", tc.name, err)
			}
		})
	}
	t.Run("deployment lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "gateway.db")
		if err := os.WriteFile(path+".lock", nil, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path+".lock", 0o640); err != nil {
			t.Fatal(err)
		}
		if lock, err := store.LockDeployment(path); err == nil || !strings.Contains(err.Error(), "group or others") {
			if lock != nil {
				lock.Close()
			}
			t.Fatalf("lock readable by the group: %v", err)
		}
	})
}
