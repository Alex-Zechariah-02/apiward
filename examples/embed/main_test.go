// The example host serves its own page, one allowed and one refused API
// request through the embedded gateway, and stops cleanly.

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/policy"
)

func TestEmbedServes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "items from "+r.URL.Path)
	}))
	defer upstream.Close()
	dir := t.TempDir()
	config := writeDeployment(t, dir, policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams:     []policy.Upstream{{ID: "shop", Dial: upstream.Listener.Addr().String()}},
		APIs:          []policy.API{{ID: "shop", Upstream: "shop"}},
		Operations: []policy.Operation{
			{ID: "list-items", API: "shop", Method: "GET", Target: "/items", Access: "allow", Auth: "none"},
			{ID: "drop-items", API: "shop", Method: "DELETE", Target: "/items", Access: "deny", Auth: "none"},
		},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, config, listener, slog.New(slog.DiscardHandler)) }()
	base := "http://" + listener.Addr().String()

	expect := func(method, path string, status int, body string) {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != status || (body != "" && string(got) != body) {
			t.Fatalf("%s %s: %d %q", method, path, resp.StatusCode, got)
		}
	}
	expect("GET", "/", http.StatusOK, "Host page. The API is served under /api/.\n")
	expect("GET", "/api/items", http.StatusOK, "items from /items")
	expect("DELETE", "/api/items", http.StatusForbidden, "")
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
}

// writeDeployment writes a configuration, a trust key and a database whose
// confirmed policy is p, standing in for installation and first publication
// through the Admin API. It returns the configuration file's path.
func writeDeployment(t *testing.T, dir string, p policy.Policy) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "issuer.pem")
	writeFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	database := filepath.Join(dir, "state.db")
	seed(t, database, p)
	settings := map[string]any{
		"version": 1,
		"gateway": map[string]any{
			"database":       database,
			"audit_log":      filepath.Join(dir, "audit.log"),
			"admin_listen":   freeAddr(t),
			"metrics_listen": freeAddr(t),
			"jwt": map[string]any{"issuer": "https://issuer.example", "audience": "shop",
				"keys": []any{map[string]any{"kid": "a", "public_key_file": keyFile}}},
		},
		"data": map[string]any{"listen": freeAddr(t)},
	}
	document, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "gateway.json")
	writeFile(t, config, document)
	return config
}

// seed creates the database with p as its confirmed revision 1.
func seed(t *testing.T, path string, p policy.Policy) {
	t.Helper()
	document, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", store.DatabaseURI(path)+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := store.ApplyMigrations(ctx, tx, 0, store.DatabaseVersion); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO deployment (id, installation, mode, recovery_episode, high_water) VALUES (1, '00000000000000000000000000e3bed0', ?, NULL, ?)`, []any{store.ModeNormal, now}},
		{`INSERT INTO revision VALUES (1, NULL, 'genesis', ?, ?, 'seed', ?)`, []any{document, store.DocumentChecksum(document), now}},
		{`INSERT INTO base VALUES (1, 1, NULL, NULL)`, nil},
	} {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
