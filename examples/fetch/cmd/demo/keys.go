// Signing key rotation and retirement through Fetch Accounts and the Admin
// API, with a warning before retiring a key that recently verified a token.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func keys(args []string) error {
	if len(args) == 0 || args[0] != "rotate" && args[0] != "retire" {
		return errors.New("choose keys rotate or keys retire")
	}
	set := flag.NewFlagSet("keys "+args[0], flag.ContinueOnError)
	var kid string
	if args[0] == "retire" {
		set.StringVar(&kid, "kid", "", "old key ID")
	}
	dir, err := parse(set, args[1:])
	if err != nil {
		return err
	}
	if args[0] == "retire" && kid == "" {
		return errors.New("-kid is required")
	}
	admin, err := operatorSession(dir)
	if err != nil {
		return err
	}
	defer admin.signOut()
	if args[0] == "retire" {
		warnRecentKeyUse(admin, kid, time.Now())
	}
	selected, err := changeKeys(dir, admin, args[0], kid)
	if err == nil {
		fmt.Printf("keys %s complete; key %s\n", args[0], selected)
	}
	return err
}

func changeKeys(dir string, admin *adminClient, action, kid string) (string, error) {
	if err := checkDemo(dir); err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(dir, signingFile))
	if err != nil {
		return "", err
	}
	var signing struct {
		Kid            string `json:"kid"`
		PrivateKeyFile string `json:"private_key_file"`
	}
	if json.Unmarshal(data, &signing) != nil || signing.Kid == "" {
		return "", errors.New("invalid Accounts settings")
	}
	data, err = os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		return "", err
	}
	var config map[string]any
	if json.Unmarshal(data, &config) != nil {
		return "", errors.New("invalid gateway settings")
	}
	gateway, ok := config["gateway"].(map[string]any)
	if !ok {
		return "", errors.New("missing gateway settings")
	}
	jwt, ok := gateway["jwt"].(map[string]any)
	if !ok {
		return "", errors.New("missing JWT settings")
	}
	trusted, ok := jwt["keys"].([]any)
	if !ok {
		return "", errors.New("missing trusted keys")
	}
	newPrivate := ""
	switch action {
	case "rotate":
		kid = "fetch-" + time.Now().UTC().Format("20060102T150405") + "-" + newKey()[:8]
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", err
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", err
		}
		public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return "", err
		}
		newPrivate = filepath.Join(dir, kid+"-key.pem")
		publicPath := filepath.Join(dir, kid+".pem")
		if err := writeNewFile(newPrivate, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})); err != nil {
			return "", err
		}
		if err := writeNewFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})); err != nil {
			return "", err
		}
		trusted = append(trusted, map[string]any{"kid": kid, "public_key_file": publicPath})
	case "retire":
		if kid == signing.Kid {
			return "", errors.New("cannot retire the current Accounts signing key")
		}
		kept, found := []any{}, false
		for _, value := range trusted {
			entry, ok := value.(map[string]any)
			if !ok {
				return "", errors.New("invalid trusted key entry")
			}
			if entry["kid"] == kid {
				found = true
			} else {
				kept = append(kept, value)
			}
		}
		if !found {
			return "", errors.New("that key is not configured")
		}
		trusted = kept
	default:
		return "", errors.New("unknown key action")
	}
	jwt["keys"] = trusted
	if err := replaceOperatorFile(filepath.Join(dir, configFile), indented(config)); err != nil {
		return "", err
	}
	if err := identifyDemo(dir); err != nil {
		return "", err
	}
	if _, _, err := admin.send("POST", "/admin/keys/reload", nil, mutationHeaders(""), 200); err != nil {
		return "", fmt.Errorf("settings written; key reload was not confirmed, Accounts signing is unchanged; inspect /admin/keys before continuing: %w", err)
	}
	if action == "rotate" {
		settings := map[string]string{"kid": kid, "private_key_file": newPrivate}
		if err := replaceOperatorFile(filepath.Join(dir, signingFile), indented(settings)); err != nil {
			return "", fmt.Errorf("gateway trusts new key but Accounts did not switch: %w", err)
		}
	}
	return kid, nil
}

// recentKeyUse is how recently a key must have verified a token for retiring
// it to warrant a warning.
const recentKeyUse = 15 * time.Minute

// warnRecentKeyUse warns, without stopping the retirement, when the gateway
// verified a token with the key recently: tokens it signed stop working once
// it is retired. A failed read is reported, not treated as "unused".
func warnRecentKeyUse(admin *adminClient, kid string, now time.Time) {
	_, body, err := admin.send("GET", "/admin/keys", nil, nil, 200)
	var keys struct {
		Items []keyUse `json:"items"`
	}
	if err == nil {
		err = json.Unmarshal(body, &keys)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read when key %s was last used: %v\n", kid, err)
		return
	}
	if message := keyUseWarning(keys.Items, kid, now); message != "" {
		fmt.Fprintln(os.Stderr, message)
	}
}

// keyUse is the part of a trusted key's report that the warning reads.
type keyUse struct {
	Kid            string     `json:"kid"`
	LastVerifiedAt *time.Time `json:"last_verified_at"`
}

// keyUseWarning words the warning for kid, or returns "" when the key has not
// verified a token within recentKeyUse.
func keyUseWarning(items []keyUse, kid string, now time.Time) string {
	for _, item := range items {
		if item.Kid != kid || item.LastVerifiedAt == nil || now.Sub(*item.LastVerifiedAt) > recentKeyUse {
			continue
		}
		ago := max(now.Sub(*item.LastVerifiedAt).Round(time.Second), 0)
		return fmt.Sprintf("warning: key %s verified a token %s ago; tokens it signed will be refused once it is retired", kid, ago)
	}
	return ""
}
