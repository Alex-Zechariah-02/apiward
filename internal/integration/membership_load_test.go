// Blocked-account changes during requests and under load.

package integration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func TestMembershipRemovalDuringRequest(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	holdFile, release := filepath.Join(e.Dir, "hold"), filepath.Join(e.Dir, "release")
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_HOLD_PATH=/a/item", "GATEWAY_HOLD_FILE="+holdFile, "GATEWAY_HOLD_RELEASE="+release)
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	before := e.Status()
	conn, captured := holdRequest(t, e, holdFile, gatewaytest.Issuer.TokenFor(t, "alice"))
	defer conn.Close()
	if captured != before.Generation {
		t.Fatalf("captured %s", captured)
	}
	if code, _, body := blockAccount(e, admin, "alice", "instant containment", "account-block-in-flight"); code != 200 {
		t.Fatalf("block: %d %s", code, body)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "true}")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 403 || !strings.Contains(string(data), "account_blocked") {
		t.Fatalf("held request bypassed containment: %d %s", response.StatusCode, data)
	}
	if code, _ := e.Get("/a/x", gatewaytest.Bearer(t, "alice")...); code != 403 {
		t.Fatal("new request bypassed containment")
	}
	e.AssertReceipts(0, 0, 0)
	if after := e.Status(); after.Generation != before.Generation {
		t.Fatal("containment changed captured policy")
	}
	if code, _ := unblockAccount(e, admin, "alice", "account-unblock-in-flight"); code != 200 {
		t.Fatal("unblock failed")
	}
	if code, _ := e.Get("/a/x", gatewaytest.Bearer(t, "alice")...); code != 200 {
		t.Fatal("unblocked request failed")
	}
}

func TestMembershipChangesUnderLoad(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	writer, reader := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword), e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	generation := e.Status().Generation
	token := gatewaytest.Issuer.TokenFor(t, "bob")
	stop := make(chan struct{})
	var unexpected, reads atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			client := &http.Client{Timeout: 10 * time.Second}
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest("GET", "http://"+e.DataAddr+"/a/x", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				response, err := client.Do(req)
				if err != nil {
					unexpected.Add(1)
					continue
				}
				response.Body.Close()
				if response.StatusCode != 200 && response.StatusCode != 403 {
					unexpected.Add(1)
				}
			}
		})
	}
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			code, body, _ := e.AdminSend("GET", "/admin/blocked-accounts", "", reader.Headers(e)...)
			var page struct {
				Items []store.BlockedAccount `json:"items"`
			}
			if code != 200 || json.Unmarshal([]byte(body), &page) != nil || len(page.Items) > 1 {
				unexpected.Add(1)
				continue
			}
			if len(page.Items) == 1 && (page.Items[0].Subject != "bob" || page.Items[0].Reason != "contain under load" || page.Items[0].BlockedBy != gatewaytest.HarnessAdmin || page.Items[0].BlockedAt.IsZero()) {
				unexpected.Add(1)
			}
			reads.Add(1)
		}
	})
	for i := range 60 {
		key := fmt.Sprintf("account-load-toggle-%04d", i)
		if i%2 == 0 {
			if code, _, body := blockAccount(e, writer, "bob", "contain under load", key); code != 200 {
				t.Fatalf("block: %d %s", code, body)
			}
		} else {
			if code, body := unblockAccount(e, writer, "bob", key); code != 200 {
				t.Fatalf("unblock: %d %s", code, body)
			}
		}
	}
	close(stop)
	wg.Wait()
	if unexpected.Load() != 0 {
		t.Fatalf("%d invalid responses or torn reads", unexpected.Load())
	}
	for _, receipt := range e.A.Receipts() {
		if receipt.Generation != generation || receipt.Headers.Get("X-Gateway-Roles") != "READER" {
			t.Fatalf("untrusted receipt %+v", receipt)
		}
	}
	e.Stop()
	forwarded, refused := 0, 0
	for _, event := range e.AuditEvents() {
		if event["kind"] == "request.forwarded" {
			forwarded++
		}
		if event["kind"] == "request.rejected" {
			refused++
			if event["error"] != "account_blocked" || event["reason"] != "account_blocked" {
				t.Fatalf("unexpected refusal %v", event)
			}
		}
	}
	if forwarded == 0 || refused == 0 || reads.Load() == 0 {
		t.Fatalf("load did not exercise all paths: %d allowed, %d refused, %d reads", forwarded, refused, reads.Load())
	}
	if n := gatewaytest.QueryInt(t, e.Database, `SELECT count(*) FROM transition WHERE kind IN ('account.block','account.unblock') AND outcome='committed' AND audited_at IS NOT NULL`); n != 60 {
		t.Fatalf("durable toggles: %d", n)
	}
	if n := gatewaytest.QueryInt(t, e.Database, `SELECT count(*) FROM revision`); n != 1 {
		t.Fatalf("containment changed policy: %d revisions", n)
	}
}
