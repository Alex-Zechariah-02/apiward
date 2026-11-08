// Demo setup: a new private demonstration directory with its signing keys,
// secrets, gateway configuration and policy documents, and the gateway's
// install of the first administrator.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
)

// setup creates a new demonstration directory: a signing key pair whose
// private half stays in this directory, the service control secret, the
// gateway configuration and two policy documents for the administrator to
// stage. It then runs the gateway's install command, which prints the first
// administrator's one-time enrolment secret. An existing directory is never
// reused, so setup cannot overwrite state, and a failed setup removes the
// directory it created, private key included, so it can simply be run again.
func setup(args []string) (err error) {
	set := flag.NewFlagSet("setup", flag.ContinueOnError)
	web := set.String("web", "", "built frontend directory holding admin/ and demo/")
	gateway := set.String("gateway", "", "gateway binary")
	admin := set.String("admin", "admin", "name of the first administrator")
	dir, err := parse(set, args)
	if err != nil {
		return err
	}
	if *web == "" || *gateway == "" {
		return errors.New("-web and -gateway are required")
	}
	webDir, err := filepath.Abs(*web)
	if err != nil {
		return err
	}
	if err := createDemo(dir, webDir, *gateway, *admin, os.Stdout); err != nil {
		return err
	}
	fmt.Printf("demonstration directory %s is ready; start it with: demo run -dir %s -gateway %s -services <services binary> -accounts <accounts binary>\n", dir, dir, *gateway)
	return nil
}

// createDemo does setup's work. The gateway's install output, which holds
// the enrolment secret, goes to out.
func createDemo(dir, webDir, gateway, admin string, out io.Writer) (err error) {
	for _, page := range []string{"admin", "demo"} {
		if _, err := os.Stat(filepath.Join(webDir, page, "index.html")); err != nil {
			return fmt.Errorf("-web %s has no %s/index.html: build the frontend first", webDir, page)
		}
	}
	if err := privateDirectory(dir); err != nil {
		return fmt.Errorf("creating a new demonstration directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	secret := make([]byte, 32)
	rand.Read(secret)

	baseline := baselinePolicy()
	files := map[string][]byte{
		privateKeyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
		publicKeyFile:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}),
		secretFile:     []byte(hex.EncodeToString(secret)),
		signingFile:    indented(map[string]string{"kid": "fetch-2026-10-a", "private_key_file": filepath.Join(dir, privateKeyFile)}),
		configFile:     indented(gatewayConfig(dir, webDir)),
		baselineFile:   indented(baseline),
		denyAllFile:    indented(denyAll(baseline)),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return err
		}
	}

	if err := identifyDemo(dir); err != nil {
		return err
	}

	install := exec.Command(gateway, "install", "--config", filepath.Join(dir, configFile), "--admin", admin)
	install.Stdout, install.Stderr = out, os.Stderr
	if err := install.Run(); err != nil {
		return fmt.Errorf("gateway install: %w", err)
	}
	return nil
}

func indented(value any) []byte {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

// gatewayConfig names the native controller, data listener and proxy settings.
// The native gateway validates this file before opening deployment state.
func gatewayConfig(dir, web string) map[string]any {
	return map[string]any{
		"version": 1,
		"gateway": map[string]any{
			"database":       filepath.Join(dir, databaseFile),
			"audit_log":      filepath.Join(dir, auditFile),
			"admin_listen":   adminListen,
			"metrics_listen": metricsListen,
			"admin_ui":       filepath.Join(web, "admin"),
			"jwt": map[string]any{
				"issuer":   issuerName,
				"audience": audience,
				"keys":     []map[string]string{{"kid": "fetch-2026-10-a", "public_key_file": filepath.Join(dir, publicKeyFile)}},
			},
		},
		"data": map[string]any{
			"listen":              dataListen,
			"max_body_bytes":      16384,
			"read_header_timeout": "5s",
			"read_timeout":        "10s",
			"write_timeout":       "30s",
		},
		"upstream": map[string]any{
			"dial_timeout":            "2s",
			"response_header_timeout": "5s",
			"read_idle_timeout":       "5s",
		},
	}
}

// denyAll is the baseline with every operation denied and no permits.
func denyAll(baseline map[string]any) map[string]any {
	policy := maps.Clone(baseline)
	var operations []map[string]any
	for _, op := range baseline["operations"].([]map[string]any) {
		denied := maps.Clone(op)
		denied["access"] = "deny"
		operations = append(operations, denied)
	}
	policy["operations"] = operations
	policy["permits"] = []any{}
	return policy
}
