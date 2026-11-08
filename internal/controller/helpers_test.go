// Fixtures for the controller's unit tests: a deployment directory and its
// configuration, test policies and override requests.

package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

var issuer = issuertest.New(2048)

// env is one disposable deployment directory.
type env struct {
	t        *testing.T
	dir      string
	database string
}

func newEnv(t *testing.T) *env {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "issuer.pem"), issuer.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, dir: dir, database: filepath.Join(dir, "gateway.db")}
}

// controllerConfig never starts its admin address: tests call no Start.
func (e *env) controllerConfig() Config {
	return Config{
		Database:    e.database,
		AuditLog:    filepath.Join(e.dir, "audit.log"),
		AdminListen: "127.0.0.1:1",
		JWT: pipeline.TrustConfig{Issuer: issuertest.Name, Audience: issuertest.Audience,
			Keys: []pipeline.VerificationKey{{Kid: "test-a", PublicKeyFile: filepath.Join(e.dir, "issuer.pem")}}},
	}
}

// own prepares and opens a controller for cfg and stops it when the test ends.
func (e *env) own(cfg Config) *Controller {
	e.t.Helper()
	c, err := Prepare(cfg, slog.New(slog.DiscardHandler))
	if err == nil {
		err = c.Open()
	}
	if err != nil {
		e.t.Fatalf("opening the controller: %v", err)
	}
	e.t.Cleanup(func() { c.Stop() })
	return c
}

func permitOverride(kind, role, operation string, seconds int64) OverrideRequest {
	return OverrideRequest{Type: kind, Control: store.ControlPermit, Operation: operation, Role: new(role), ExpiresInSeconds: seconds}
}

func rateOverride(kind, operation string, count, seconds int64) OverrideRequest {
	return OverrideRequest{Type: kind, Control: store.ControlRate, Operation: operation, Count: new(count), ExpiresInSeconds: seconds}
}

func operationContainment(operation string, seconds int64) OverrideRequest {
	return OverrideRequest{Type: store.OverrideContainment, Control: store.ControlOperation, Operation: operation, ExpiresInSeconds: seconds}
}

func overrideErrorCode(err error) string {
	if policyErr, ok := errors.AsType[*policy.PolicyError](err); ok {
		return policyErr.Code + "@" + policyErr.Field
	}
	return fmt.Sprint(err)
}

func mustJSON(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
