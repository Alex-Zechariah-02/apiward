// Administrator commands: enrol adds or resets an administrator with a
// one-time secret, and disable stops one administrator's access at once.
// Each writes its intent, the store transaction and its commitment record.

package operator

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

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

func runDisable(o *operatorContext, flags map[string]string) (int, error) {
	name := flags["admin"]
	if !store.IsAdminName(name) {
		return 1, fmt.Errorf("administrator name %q is not valid", name)
	}
	st, err := store.OpenStore(o.config.Database)
	if err != nil {
		return 1, err
	}
	defer st.Close()
	if _, found, err := st.Administrator(o.ctx, name); err != nil {
		return 1, err
	} else if !found {
		return 1, fmt.Errorf("no administrator is named %q", name)
	}
	o.openAudit()

	t := store.TransitionRecord{ID: fmt.Sprintf("operator:disable:%s:%s", name, randomHex(8)), Kind: "operator.disable", Actor: o.actor, Target: name, Digest: "operator"}
	if err := o.record(audit.Event{Kind: "transition.intent", Transition: t.ID, Target: name}); err != nil {
		return 1, err
	}
	err = st.DisableAdministrator(o.ctx, t, name, time.Now())
	if errors.Is(err, store.ErrNotUpdated) {
		return 1, fmt.Errorf("no administrator is named %q", name)
	}
	if err != nil {
		return 1, err
	}
	if err := o.record(audit.Event{Kind: "transition.committed", Transition: t.ID}); err != nil {
		return 1, err
	}
	if err := st.MarkAudited(o.ctx, t.ID, time.Now()); err != nil {
		return 1, err
	}
	fmt.Printf("disabled %s: its password and sessions no longer sign in; a new enrolment restores access\n", name)
	return 0, nil
}
