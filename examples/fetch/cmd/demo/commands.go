// Demo commands for a running stack: a demo account token from Fetch
// Accounts, a reset of every service's seed, and the gateway's request events.

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/examples/fetch/internal/services"
)

// token obtains a demo account token from Fetch Accounts. It never reads a
// private key or changes token claims or lifetime.
func token(args []string) error {
	set := flag.NewFlagSet("token", flag.ContinueOnError)
	subject := set.String("subject", "", "seeded demo account ID")
	ttl := set.Duration("ttl", maxTokenTTL, "fixed 15-minute Accounts lifetime")
	dir, err := parse(set, args)
	if err != nil {
		return err
	}
	if err = checkDemo(dir); err != nil {
		return err
	}
	if !validSubject(*subject) || *ttl != maxTokenTTL {
		return errors.New("use a seeded subject and the fixed 15m lifetime")
	}
	compact, expires, err := accountToken(*subject)
	if err != nil {
		return err
	}
	fmt.Println(compact)
	fmt.Fprintf(os.Stderr, "token for %s, expires %s\n", *subject, expires.UTC().Format(time.RFC3339))
	return nil
}

func accountToken(subject string) (string, time.Time, error) {
	for _, user := range services.Users() {
		if user.ID == subject {
			return accountLogin("http://"+fetchServices[4].listen, user.Email)
		}
	}
	return "", time.Time{}, errors.New("unknown demo account")
}
func validSubject(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// reset restores each service's seed through its isolated protected control.
func reset(args []string) error {
	dir, err := parse(flag.NewFlagSet("reset", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	if err = checkDemo(dir); err != nil {
		return err
	}
	secret, err := os.ReadFile(filepath.Join(dir, secretFile))
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: refuseRedirect}
	defer client.CloseIdleConnections()
	for _, service := range fetchServices {
		request, _ := http.NewRequest("POST", "http://"+service.control+"/reset", http.NoBody)
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(secret)))
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("resetting %s: no answer; its reset outcome is unknown: %w", service.name, err)
		}
		var state services.State
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&state)
		response.Body.Close()
		hash, hashErr := hex.DecodeString(state.SHA256)
		if response.StatusCode != 200 || decodeErr != nil || state.Service != service.name || hashErr != nil || len(hash) != 32 {
			return fmt.Errorf("resetting %s: invalid reset answer, status %d", service.name, response.StatusCode)
		}
		fmt.Printf("%-9s %s seed restored\n", service.name, state.SHA256)
	}
	return nil
}

// events prints the gateway's request events from the audit file, oldest
// first: every event of one request, or the last N.
func events(args []string) error {
	set := flag.NewFlagSet("events", flag.ContinueOnError)
	requestID := set.String("request", "", "request id shown by the website")
	last := set.Int("last", 20, "number of events to print without -request")
	dir, err := parse(set, args)
	if err != nil {
		return err
	}
	if *last < 1 {
		return errors.New("-last must be at least 1")
	}
	file, err := os.Open(filepath.Join(dir, auditFile))
	if err != nil {
		return err
	}
	defer file.Close()

	// Without -request only the last N matching events are kept, so the memory
	// used does not grow with the audit file.
	var matched []map[string]any
	malformed := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var event map[string]any
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			malformed++
			continue // a malformed record or an incomplete tail
		}
		kind, _ := event["kind"].(string)
		if !strings.HasPrefix(kind, "request.") {
			continue
		}
		if *requestID != "" && event["request_id"] != *requestID {
			continue
		}
		matched = append(matched, event)
		if *requestID == "" && len(matched) > *last {
			matched = matched[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	for _, event := range matched {
		var fields []string
		for _, name := range []string{"time", "kind", "stage", "decision", "status", "error", "reason", "subject", "operation", "generation", "request_id"} {
			if value, ok := event[name]; ok && value != "" {
				fields = append(fields, fmt.Sprintf("%s=%v", name, value))
			}
		}
		fmt.Println(strings.Join(fields, " "))
	}
	fmt.Fprintln(os.Stderr, "events: searched only the active audit file; retained rotated files were not searched")
	if malformed > 0 {
		fmt.Fprintf(os.Stderr, "events: skipped %d malformed or partial records\n", malformed)
	}
	if len(matched) == 0 {
		fmt.Fprintln(os.Stderr, "events: no matching records in the active file; this does not establish non-arrival")
	}
	return nil
}
