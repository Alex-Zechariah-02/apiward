// Operator commands: install, enrol, migrate and dispatch.

package operator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Local operator commands. They run only on the gateway host, never over
// HTTP, and act on the database and audit log named in the gateway's own
// configuration file. Each needs the gateway stopped: the database's
// exclusive lock refuses them while it runs.

const (
	// A day lets the secret be handed over out of band; an unused one then
	// expires.
	enrolmentLifetime = 24 * time.Hour
	backupFormat      = "gateway-backup-1"
)

// Config is the part of the gateway's settings an operator command needs:
// the deployment's files, audit log limits and the trust key files, which no
// command may overwrite.
type Config struct {
	Database      string
	AuditLog      string
	AuditMaxBytes int64
	AuditMaxFiles int
	AuditWhenFull string
	AuditAppend   bool
	AuditTimeout  time.Duration
	KeyFiles      []string
	// IdentityKey is the identity assertion's signing key file, which
	// install creates when it is missing; empty when signing is off.
	IdentityKey string
}

// operatorContext is the deployment an operator command acts on and who
// runs it.
type operatorContext struct {
	ctx    context.Context
	config Config
	audit  *audit.AuditLog
	actor  string
}

// operatorActor names who ran the command: the operating system account, as
// the commands run only on the gateway host; unknown when it cannot be read.
func operatorActor() string {
	account, err := user.Current()
	if err != nil || account.Username == "" {
		return "operator:unknown"
	}
	return "operator:" + account.Username
}

// openAudit opens the deployment's audit log. Commands that act on an
// existing database call it only after that database proved not to be held
// by a running gateway, whose audit log has a single writer.
func (o *operatorContext) openAudit() {
	o.audit = audit.OpenAudit(o.config.AuditLog, audit.Settings{MaxBytes: o.config.AuditMaxBytes, MaxFiles: o.config.AuditMaxFiles, WhenFull: o.config.AuditWhenFull, Append: o.config.AuditAppend})
}

// close writes the command's queued audit events and closes the log; an
// incomplete write is reported, the command's result is unchanged.
func (o *operatorContext) close() {
	if o.audit == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), audit.AuditDrainWait)
	defer cancel()
	if err := o.audit.Close(ctx); err != nil {
		slog.Error("audit log not closed completely", "error", err)
	}
}

// record durably writes an operator event. No operator change proceeds
// without its record.
func (o *operatorContext) record(e audit.Event) error {
	e.Actor = o.actor
	ctx, cancel := context.WithTimeout(context.Background(), o.config.AuditTimeout)
	defer cancel()
	if err := o.audit.Commit(ctx, e); err != nil {
		return fmt.Errorf("recording %s: %w", e.Kind, err)
	}
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func runInstall(o *operatorContext, flags map[string]string) (int, error) {
	name := flags["admin"]
	if !store.IsAdminName(name) {
		return 1, fmt.Errorf("administrator name %q is not valid", name)
	}
	// An installed deployment is refused before the key: a new key there
	// would replace the identity its upstreams trust. CreateStore's
	// exclusive create still refuses one that appears after this check.
	if _, err := os.Lstat(o.config.Database); err == nil {
		return 1, fmt.Errorf("installing: %s already exists; install creates a new deployment only", o.config.Database)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return 1, fmt.Errorf("installing: %w", err)
	}
	// The key comes before the database: an install that fails here leaves
	// no database, so it can be run again.
	if created, err := createIdentityKey(o.config.IdentityKey); err != nil {
		return 1, fmt.Errorf("creating the identity key: %w", err)
	} else if created {
		fmt.Printf("created the identity assertion key %s\n", o.config.IdentityKey)
	}
	o.openAudit()

	now := time.Now()
	installation := randomHex(16)
	secret := session.NewToken()
	first := store.Enrolment{Name: name, Secret: session.Hash(secret), Permissions: store.PermAll, ExpiresAt: now.Add(enrolmentLifetime)}
	t := store.TransitionRecord{ID: "operator:install:" + installation, Kind: "operator.install", Actor: o.actor, Target: name, Digest: "operator"}
	if err := o.record(audit.Event{Kind: "transition.intent", Transition: t.ID, Target: name}); err != nil {
		return 1, err
	}
	st, err := store.CreateStore(o.ctx, o.config.Database, installation, first, t, now)
	if err != nil {
		return 1, fmt.Errorf("installing: %w", err)
	}
	defer st.Close()
	if err := o.record(audit.Event{Kind: "transition.committed", Transition: t.ID}); err != nil {
		return 1, err
	}
	if err := st.MarkAudited(o.ctx, t.ID, time.Now()); err != nil {
		return 1, err
	}

	fmt.Printf("installed %s (installation %s, mode %s)\n", o.config.Database, installation, store.ModeBootstrap)
	fmt.Printf("enrolment secret for %s, valid until %s: %s\n", name, first.ExpiresAt.UTC().Format(time.RFC3339), secret)
	return 0, nil
}

func runEnrol(o *operatorContext, flags map[string]string) (int, error) {
	name := flags["admin"]
	if !store.IsAdminName(name) {
		return 1, fmt.Errorf("administrator name %q is not valid", name)
	}
	permissions, err := store.ParsePermissions(flags["permissions"])
	if err != nil {
		return 1, err
	}
	st, err := store.OpenStore(o.config.Database)
	if err != nil {
		return 1, err
	}
	defer st.Close()
	o.openAudit()

	now := time.Now()
	secret := session.NewToken()
	e := store.Enrolment{Name: name, Secret: session.Hash(secret), Permissions: permissions, ExpiresAt: now.Add(enrolmentLifetime)}
	t := store.TransitionRecord{ID: fmt.Sprintf("operator:enrol:%s:%s", name, randomHex(8)), Kind: "operator.enrol", Actor: o.actor, Target: name, Digest: "operator"}
	granted := name + " (" + strings.Join(permissions.Names(), ", ") + ")"
	if err := o.record(audit.Event{Kind: "transition.intent", Transition: t.ID, Target: granted}); err != nil {
		return 1, err
	}
	if err := st.IssueEnrolment(o.ctx, t, e, now); err != nil {
		return 1, err
	}
	if err := o.record(audit.Event{Kind: "transition.committed", Transition: t.ID}); err != nil {
		return 1, err
	}
	if err := st.MarkAudited(o.ctx, t.ID, time.Now()); err != nil {
		return 1, err
	}
	fmt.Printf("enrolment secret for %s (%v), valid until %s: %s\n", name, permissions.Names(), e.ExpiresAt.UTC().Format(time.RFC3339), secret)
	return 0, nil
}

func runMigrate(o *operatorContext) (int, error) {
	st, from, err := store.OpenForMigration(o.config.Database)
	if err != nil {
		return 1, err
	}
	defer st.Close()
	o.openAudit()

	t := store.TransitionRecord{
		ID:     fmt.Sprintf("operator:migrate:%d:%s", store.DatabaseVersion, randomHex(8)),
		Kind:   "operator.migrate",
		Actor:  o.actor,
		Target: fmt.Sprintf("schema version %d", store.DatabaseVersion),
		Digest: "operator",
	}
	if err := o.record(audit.Event{Kind: "transition.intent", Transition: t.ID, Target: t.Target}); err != nil {
		return 1, err
	}
	if err := st.Migrate(o.ctx, from, t, time.Now()); err != nil {
		return 1, fmt.Errorf("migrating: %w", err)
	}
	if err := o.record(audit.Event{Kind: "transition.committed", Transition: t.ID}); err != nil {
		return 1, err
	}
	if err := st.MarkAudited(o.ctx, t.ID, time.Now()); err != nil {
		return 1, err
	}
	fmt.Printf("migrated %s from schema version %d to %d\n", o.config.Database, from, store.DatabaseVersion)
	return 0, nil
}

// Run runs the operator command with its flags on the deployment cfg names;
// flags["config"] is the configuration file's path. It holds the
// deployment's lock for the whole command, across restore's SQLite file
// replacement, and returns the exit code.
func Run(command string, cfg Config, flags map[string]string) (int, error) {
	// No deadline: a command runs in the foreground with the gateway
	// stopped and a fixed bound would fail a large backup. Ctrl+C or a stop
	// signal cancels the context instead of killing the process, so the
	// database work aborts and the deferred cleanup (lock, staged files, the
	// audit log's drain) still runs; SQLite recovers from its log.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	o := &operatorContext{ctx: ctx, config: cfg, actor: operatorActor()}
	if err := CheckPaths(flags["config"], o.config, command, flags); err != nil {
		return 1, err
	}
	lock, err := store.LockDeployment(o.config.Database)
	if err != nil {
		return 1, err
	}
	defer lock.Close()
	defer o.close()
	switch command {
	case "install":
		return runInstall(o, flags)
	case "enrol":
		return runEnrol(o, flags)
	case "migrate":
		return runMigrate(o)
	case "backup":
		return runBackup(o, flags)
	case "restore":
		return runRestore(o, flags)
	case "recover-clock":
		return runRecoverClock(o)
	}
	return 1, errors.New("unknown operator command")
}
