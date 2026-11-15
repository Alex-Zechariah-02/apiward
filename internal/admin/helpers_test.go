// Fixtures for the Admin API's unit tests: a controller opened over a seeded
// database and the Admin API built on it.

package admin

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

var issuer = issuertest.New(2048)

// openController opens a controller whose confirmed policy is
// storetest.Protected and stops it when the test ends. Its admin address is
// never served.
func openController(t *testing.T) *controller.Controller {
	t.Helper()
	return openSeeded(t, storetest.Options{}, nil)
}

// openSeeded is openController over a seed with opts; adjust, when set,
// changes the database before the controller opens it.
func openSeeded(t *testing.T, opts storetest.Options, adjust func(database string)) *controller.Controller {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "issuer.pem")
	if err := os.WriteFile(key, issuer.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(dir, "gateway.db")
	storetest.Seed(t, database, storetest.Protected(), opts)
	if adjust != nil {
		adjust(database)
	}
	c, err := controller.Prepare(controller.Config{
		Database: database, AuditLog: filepath.Join(dir, "audit.log"), AdminListen: "127.0.0.1:1",
		JWT: pipeline.TrustConfig{Issuer: issuertest.Name, Audience: issuertest.Audience,
			Keys: []pipeline.VerificationKey{{Kid: "test-a", PublicKeyFile: key}}},
	}, slog.New(slog.DiscardHandler))
	if err == nil {
		err = c.Open()
	}
	if err != nil {
		t.Fatalf("opening the controller: %v", err)
	}
	t.Cleanup(func() { c.Stop() })
	return c
}

// testServer is the Admin API of c with its own rate counters and no
// dashboard files.
func testServer(c *controller.Controller) *Server {
	return New(Deps{Control: c, Limiter: pipeline.NewLimiter(policy.DefaultRateCounters), Logger: slog.New(slog.DiscardHandler)})
}
