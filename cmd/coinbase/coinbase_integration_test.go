//go:build integration

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

// TestCoinbaseIntegration exercises the real Coinbase App API v2 against a
// live CDP key.
//
// Required env vars:
//
//	COINBASE_API_KEY    (CDP key name)
//	COINBASE_API_SECRET (base64 of a 64-byte Ed25519 private key)
func TestCoinbaseIntegration(t *testing.T) {
	keyName := os.Getenv("COINBASE_API_KEY")
	secretB64 := os.Getenv("COINBASE_API_SECRET")
	if keyName == "" || secretB64 == "" {
		t.Skip("COINBASE_API_KEY and COINBASE_API_SECRET must be set")
	}

	secretRaw, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil || len(secretRaw) != ed25519.PrivateKeySize {
		t.Fatalf("COINBASE_API_SECRET must base64-decode to a %d-byte Ed25519 key: %v", ed25519.PrivateKeySize, err)
	}
	priv := ed25519.PrivateKey(secretRaw)

	cl := &client{http: http.DefaultClient, priv: priv, keyName: keyName, baseURL: defaultBase}
	ctx := t.Context()

	accounts, err := cl.fetchAllAccounts(ctx)
	if err != nil {
		t.Fatalf("fetchAllAccounts: %v", err)
	}
	t.Logf("fetched %d accounts", len(accounts))
	if len(accounts) == 0 {
		t.Fatal("want at least one account on a live retail Coinbase account")
	}

	since := time.Now().UTC().Add(-30 * 24 * time.Hour)
	selected := selectAccounts(accounts, time.Time{}) // first-run heuristic: nonzero balance only
	t.Logf("selected %d nonzero-balance accounts for backfill probe", len(selected))

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	total := 0
	for _, acct := range selected {
		acctID, _ := acct["id"].(string)
		if acctID == "" {
			continue
		}
		txns, err := cl.fetchTransactions(ctx, acctID, since)
		if err != nil {
			t.Fatalf("fetchTransactions(%s): %v", acctID, err)
		}
		currency := currencyCode(acct)
		for _, txn := range txns {
			evs, err := normalizeTxn(txn, acctID, currency)
			if err != nil {
				t.Fatalf("normalizeTxn: %v", err)
			}
			for _, ev := range evs {
				if err := enc.Encode(ev); err != nil {
					t.Fatalf("encode: %v", err)
				}
				total++
			}
		}
	}
	t.Logf("normalized %d transactions across %d accounts (last 30d)", total, len(selected))

	scanner := bufio.NewScanner(&buf)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		var ev event.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Errorf("line %d: invalid JSON: %v", lineNum, err)
			continue
		}
		if ev.ID == "" {
			t.Errorf("line %d: ID empty", lineNum)
		}
		if ev.Source != "coinbase" {
			t.Errorf("line %d: Source = %q, want coinbase", lineNum, ev.Source)
		}
	}
	t.Logf("validated %d JSONL events", lineNum)
}
