// Operator restore command and its checks.

package operator

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/fault"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// runRestore performs a declared historical restore. The backup is copied
// through SQLite into a staging file next to the live database, checked, and
// marked recovery_required there, with all restored authority quarantined,
// before it can become live. Each interruption leaves the original database,
// no database (the gateway stays unavailable) or the marked copy, never an
// unmarked historical database.
func runRestore(o *operatorContext, flags map[string]string) (int, error) {
	backup := flags["backup"]
	live := o.config.Database
	if backup == "" {
		return 1, errors.New("--backup is required")
	}
	if sameFile(backup, live) {
		return 1, errors.New("the backup cannot be the live database")
	}
	manifest, checked, err := checkBackup(backup)
	if err != nil {
		return 1, err
	}
	if err := checkLive(live, manifest.Installation); err != nil {
		return 1, err
	}
	o.openAudit()

	staging := live + ".restore"
	if err := removeStagedDatabase(staging, manifest.Installation); err != nil {
		return 1, err
	}
	defer removeFiles(staging, staging+"-wal", staging+"-shm", staging+"-journal")
	if err := copyDatabase(o.ctx, backup, staging); err != nil {
		return 1, fmt.Errorf("staging the backup: %w", err)
	}
	// SQLite opened the backup by name: it must still be the file checked.
	if err := samePath(backup, checked); err != nil {
		return 1, err
	}
	// A rewrite in place keeps the file's identity, so the staged copy's own
	// authority must still be the one the manifest describes.
	if err := checkBackupDatabase(staging, manifest); err != nil {
		return 1, fmt.Errorf("the staged copy does not match the backup manifest: %w", err)
	}

	now := time.Now()
	episode := randomHex(16)
	t := store.TransitionRecord{ID: "operator:restore:" + episode, Kind: "operator.restore", Actor: o.actor, Target: filepath.Base(backup), Digest: manifest.SHA256}
	if err := o.record(audit.Event{Kind: "transition.intent", Transition: t.ID, File: filepath.Base(backup)}); err != nil {
		return 1, err
	}
	if err := markRecovery(o.ctx, staging, t, episode, now); err != nil {
		return 1, fmt.Errorf("marking the staged database: %w", err)
	}
	fault.CrashPoint("restore-before-promote")

	retired := ""
	if _, err := os.Stat(live); err == nil {
		retired = fmt.Sprintf("%s.replaced-%s-%s", live, now.UTC().Format("20060102T150405Z"), randomHex(4))
		if err := os.Rename(live, retired); err != nil {
			return 1, err
		}
	}
	fault.CrashPoint("restore-after-retire")
	if err := os.Rename(staging, live); err != nil {
		if retired != "" {
			err = errors.Join(err, os.Rename(retired, live))
		}
		return 1, err
	}
	fault.CrashPoint("restore-after-promote")

	if err := o.record(audit.Event{Kind: "transition.committed", Transition: t.ID, File: filepath.Base(backup)}); err != nil {
		return 1, err
	}
	// The restore is complete. If its audit receipt cannot be recorded here,
	// the gateway records the outcome event again at its next startup.
	if st, err := store.OpenStore(live); err == nil {
		st.MarkAudited(o.ctx, t.ID, time.Now())
		st.Close()
	}
	fmt.Printf("restored %s as %s in %s mode (episode %s)\n", backup, live, store.ModeRecovery, episode)
	if retired != "" {
		fmt.Printf("the replaced database is kept as %s\n", retired)
	}
	fmt.Println("next: enrol an administrator, then confirm a deny-all recovery base")
	return 0, nil
}

// maxManifestBytes bounds the manifest read: one written by backup is under
// 1 KiB, so 64 KiB refuses only a file that is not one.
const maxManifestBytes = 64 << 10

// checkBackup verifies the backup against its manifest and runs the database
// checks on it without changing it. It returns the manifest and the identity
// of the file it checked.
func checkBackup(backup string) (backupManifest, os.FileInfo, error) {
	manifest, err := backupChecks(backup)
	if err != nil {
		return manifest, nil, err
	}
	sum, size, info, err := fileDigest(backup)
	if err != nil {
		return manifest, nil, err
	}
	if sum != manifest.SHA256 || size != manifest.Bytes {
		return manifest, nil, errors.New("the backup does not match its manifest checksum")
	}
	return manifest, info, checkBackupDatabase(backup, manifest)
}

// backupChecks reads and checks the backup's manifest.
func backupChecks(backup string) (backupManifest, error) {
	var manifest backupManifest
	data, err := readBounded(manifestPath(backup), maxManifestBytes)
	if err != nil {
		return manifest, fmt.Errorf("reading the backup manifest: %w", err)
	}
	if err := policy.DecodeStrict(data, &manifest); err != nil || manifest.Format != backupFormat {
		return manifest, errors.New("the backup manifest is not a gateway backup manifest")
	}
	if manifest.SchemaVersion != store.DatabaseVersion {
		return manifest, fmt.Errorf("the backup has schema version %d, this gateway needs %d", manifest.SchemaVersion, store.DatabaseVersion)
	}
	return manifest, nil
}

// checkBackupDatabase runs the integrity and schema checks on the backup and
// compares its authority with the manifest.
func checkBackupDatabase(backup string, manifest backupManifest) error {
	db, err := sql.Open("sqlite", store.DatabaseURI(backup)+"?mode=ro&_pragma=foreign_keys(ON)")
	if err != nil {
		return err
	}
	defer db.Close()
	// One connection at a time, so no two checks touch the backup file together.
	db.SetMaxOpenConns(1)
	var check string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		return fmt.Errorf("the backup fails the integrity check: %v %s", err, check)
	}
	if err := store.Verify(db); err != nil {
		return fmt.Errorf("the backup is not usable: %w", err)
	}
	var installation, mode string
	var revision int64
	if err := db.QueryRow("SELECT d.installation, d.mode, coalesce(b.confirmed, 0) FROM deployment d, base b WHERE d.id = 1 AND b.id = 1").Scan(&installation, &mode, &revision); err != nil {
		return err
	}
	if installation != manifest.Installation || mode != manifest.Mode || revision != manifest.Revision {
		return errors.New("the backup authority does not match its manifest")
	}
	return nil
}

// checkLive refuses to replace a live database that belongs to another
// installation, whose installation cannot be read, or that still has
// write-ahead log or rollback journal files beside it, which would be applied
// to the restored file. The deployment lock already refuses a database in use.
func checkLive(live, installation string) error {
	_, missing := os.Stat(live)
	if missing == nil {
		// Opening and closing the store folds a write-ahead log a stopped
		// gateway left back into the database; unavailable authority is
		// checked below.
		st, err := store.OpenStore(live)
		if err == nil {
			err = st.Close()
		}
		if err != nil && !errors.Is(err, store.ErrUnavailable) {
			return err
		}
	}
	// A leftover rollback journal is a hot journal SQLite would roll back into
	// the promoted database on its first open.
	for _, companion := range []string{live + "-wal", live + "-shm", live + "-journal"} {
		if _, err := os.Lstat(companion); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s exists; move the live database and its companion files aside before restoring", companion)
		}
	}
	if missing != nil {
		return nil
	}
	current, err := liveInstallation(live)
	if err != nil {
		return fmt.Errorf("the live database's installation cannot be read (%w); move the live database aside before restoring", err)
	}
	if current != installation {
		return fmt.Errorf("the backup belongs to installation %s, the live database to %s", installation, current)
	}
	return nil
}

// liveInstallation reads the installation straight from the live database,
// so one whose authority does not load is still checked. immutable opens it
// without locks or companion files: the deployment lock is held and the
// companions were refused above.
func liveInstallation(live string) (string, error) {
	db, err := sql.Open("sqlite", store.DatabaseURI(live)+"?mode=ro&immutable=1")
	if err != nil {
		return "", err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var installation string
	err = db.QueryRow("SELECT installation FROM deployment WHERE id = 1").Scan(&installation)
	return installation, err
}

// copyDatabase copies a database file through SQLite into a new file.
func copyDatabase(ctx context.Context, source, target string) error {
	db, err := sql.Open("sqlite", store.DatabaseURI(source)+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := store.CreatePrivate(target); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", target); err != nil {
		return err
	}
	return checkDatabaseFile(target)
}

func markRecovery(ctx context.Context, path string, t store.TransitionRecord, episode string, now time.Time) error {
	db, err := store.Connect(path, "DELETE")
	if err != nil {
		return err
	}
	s := store.Adopt(db)
	err = s.DeclareRecovery(ctx, t, episode, now)
	return errors.Join(err, s.Close())
}

func removeFiles(paths ...string) error {
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// A retry removes only a verified staging database of this installation.
// Unknown or damaged files need explicit operator disposition, not deletion.
func removeStagedDatabase(path, installation string) error {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		for _, companion := range []string{path + "-wal", path + "-shm", path + "-journal"} {
			if _, err := os.Lstat(companion); !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("unverified staging companion %s; move it aside explicitly", companion)
			}
		}
		return nil
	} else if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", store.DatabaseURI(path)+"?mode=ro&_pragma=foreign_keys(ON)")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	err = store.Verify(db)
	var identity string
	if err == nil {
		err = db.QueryRow("SELECT installation FROM deployment WHERE id = 1").Scan(&identity)
	}
	err = errors.Join(err, db.Close())
	if err != nil || identity != installation {
		return fmt.Errorf("refusing to remove unverified staging file %s; move it aside explicitly: %w", path, errors.Join(err, errors.New("staging identity must match this installation")))
	}
	return removeFiles(path, path+"-wal", path+"-shm", path+"-journal")
}
