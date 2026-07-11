package normalize

import "testing"

// --- Coinbase ----------------------------------------------------------------

func TestCoinbaseSendIsCatchAllWithDestination(t *testing.T) {
	txn := map[string]any{
		"id":     "tx-1",
		"type":   "send",
		"status": "completed",
		"amount": map[string]any{"amount": "-0.10000000", "currency": "BTC"},
		"native_amount": map[string]any{
			"amount": "-100.00", "currency": "USD",
		},
		"details": map[string]any{"title": "Sent Bitcoin", "subtitle": "to unknown wallet"},
		"network": map[string]any{"status": "confirmed", "hash": "0xdeadbeef"},
		"to":      map[string]any{"resource": "bitcoin_address", "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
	}
	got := Coinbase("send", txn)
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d", len(got))
	}
	r := got[0]
	// HONESTY RULE: no canonical gate is semantically true for a crypto
	// transfer, so this MUST be the inert catch-all, never a stretched gate.
	if r.Type != CatchAll {
		t.Errorf("Type = %q, want %q", r.Type, CatchAll)
	}
	p := decode(t, r, txn)
	if p["tx_type"] != "send" {
		t.Errorf("tx_type = %v", p["tx_type"])
	}
	if p["amount"] != "-0.10000000" || p["currency"] != "BTC" {
		t.Errorf("amount/currency = %v/%v", p["amount"], p["currency"])
	}
	if p["native_amount"] != "-100.00" || p["native_currency"] != "USD" {
		t.Errorf("native_amount/currency = %v/%v", p["native_amount"], p["native_currency"])
	}
	if p["to_address"] != "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" {
		t.Errorf("to_address = %v", p["to_address"])
	}
	if p["network_hash"] != "0xdeadbeef" {
		t.Errorf("network_hash = %v", p["network_hash"])
	}
	if p["title"] != "Sent Bitcoin" || p["subtitle"] != "to unknown wallet" {
		t.Errorf("title/subtitle = %v/%v", p["title"], p["subtitle"])
	}
	if p["status"] != "completed" {
		t.Errorf("status = %v", p["status"])
	}
}

func TestCoinbaseSendFallsBackToResourceWhenNoAddress(t *testing.T) {
	txn := map[string]any{
		"type": "send",
		"to":   map[string]any{"resource": "email"},
	}
	r := wantType(t, Coinbase("send", txn), CatchAll)
	p := decode(t, r, txn)
	if p["to_address"] != "email" {
		t.Errorf("to_address = %v, want fallback to resource", p["to_address"])
	}
}

func TestCoinbaseReceiveCarriesFromCounterparty(t *testing.T) {
	txn := map[string]any{
		"id":     "tx-2",
		"type":   "receive",
		"status": "completed",
		"amount": map[string]any{"amount": "0.05000000", "currency": "ETH"},
		"from":   map[string]any{"resource": "user", "id": "user-abc"},
	}
	r := wantType(t, Coinbase("receive", txn), CatchAll)
	p := decode(t, r, txn)
	if p["from"] != "user-abc" {
		t.Errorf("from = %v, want user-abc (id fallback since resource=user is generic)", p["from"])
	}
}

func TestCoinbaseBuySellTradeStakingAllCatchAll(t *testing.T) {
	for _, txType := range []string{"buy", "sell", "trade", "staking_reward", "fiat_deposit", "fiat_withdrawal"} {
		txn := map[string]any{"type": txType, "status": "completed"}
		r := wantType(t, Coinbase(txType, txn), CatchAll)
		p := decode(t, r, txn)
		if p["tx_type"] != txType {
			t.Errorf("%s: tx_type = %v", txType, p["tx_type"])
		}
	}
}

func TestCoinbasePayloadCarriesRaw(t *testing.T) {
	txn := map[string]any{"id": "tx-9", "type": "buy", "secret": "AKIAIOSFODNN7EXAMPLE"}
	r := Coinbase("buy", txn)[0]
	p := decode(t, r, txn)
	if _, ok := p["raw"]; !ok {
		t.Fatalf("payload missing raw key: %+v", p)
	}
}
