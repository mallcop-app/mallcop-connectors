package normalize

import "testing"

// TestMercuryOutgoingPayment: a negative amount is an outgoing transaction.
func TestMercuryOutgoingPayment(t *testing.T) {
	txn := map[string]any{
		"id":               "txn-1",
		"amount":           -70.01,
		"kind":             "debitCardTransaction",
		"status":           "sent",
		"counterpartyName": "Microsoft",
		"dashboardLink":    "https://mercury.com/transactions/txn-1",
	}
	got := Mercury("debitCardTransaction", txn)
	r := wantType(t, got, CatchAll)
	p := decode(t, r, txn)

	if p["direction"] != "outgoing" {
		t.Errorf("direction = %v, want outgoing", p["direction"])
	}
	if p["amount"] != -70.01 {
		t.Errorf("amount = %v, want -70.01", p["amount"])
	}
	if p["currency"] != "USD" {
		t.Errorf("currency = %v, want USD", p["currency"])
	}
	if p["counterparty"] != "Microsoft" {
		t.Errorf("counterparty = %v, want Microsoft", p["counterparty"])
	}
	if p["status"] != "sent" {
		t.Errorf("status = %v, want sent", p["status"])
	}
	if p["dashboard_link"] != "https://mercury.com/transactions/txn-1" {
		t.Errorf("dashboard_link = %v", p["dashboard_link"])
	}
	if p["kind"] != "debitCardTransaction" {
		t.Errorf("kind = %v, want debitCardTransaction", p["kind"])
	}
	// raw event must be attached verbatim for injection-probe/secrets-exposure.
	if p["raw"] == nil {
		t.Error("payload missing raw")
	}
}

// TestMercuryIncomingWire: a positive amount is an incoming transaction.
func TestMercuryIncomingWire(t *testing.T) {
	txn := map[string]any{
		"amount":           1500.00,
		"kind":             "incomingDomesticWire",
		"counterpartyName": "Acme Client LLC",
	}
	got := Mercury("incomingDomesticWire", txn)
	r := wantType(t, got, CatchAll)
	p := decode(t, r, txn)

	if p["direction"] != "incoming" {
		t.Errorf("direction = %v, want incoming", p["direction"])
	}
}

// TestMercuryNeverInventsType is the honesty-rule regression test: no Mercury
// transaction kind maps to an existing mallcop gate type, since none of them
// are semantically IAM/access/admin events. Every kind must fall through to
// CatchAll rather than stretch semantics to force a gate.
func TestMercuryNeverInventsType(t *testing.T) {
	kinds := []string{
		"externalTransfer", "internalTransfer", "outgoingPayment",
		"debitCardTransaction", "incomingDomesticWire", "checkDeposit",
		"fee", "other", "someFutureUnknownKind",
	}
	for _, kind := range kinds {
		got := Mercury(kind, map[string]any{"amount": 1.0, "kind": kind})
		if len(got) != 1 {
			t.Fatalf("kind %q: want 1 result, got %d", kind, len(got))
		}
		if got[0].Type != CatchAll {
			t.Errorf("kind %q: Type = %q, want CatchAll — no financial gate type exists, this must never fire a non-financial detector", kind, got[0].Type)
		}
	}
}

// TestMercuryNoteMemoAndFailureReason: note, externalMemo, bankDescription and
// reasonForFailure all surface as separate flat fields when present.
func TestMercuryNoteMemoAndFailureReason(t *testing.T) {
	txn := map[string]any{
		"amount":           -212.5,
		"kind":             "debitCardTransaction",
		"note":             "reimbursable",
		"externalMemo":     "invoice #42",
		"bankDescription":  "ANTHROPIC* CLAUDE SUB",
		"reasonForFailure": "insufficient funds",
	}
	got := Mercury("debitCardTransaction", txn)
	p := decode(t, got[0], txn)

	if p["note"] != "reimbursable" {
		t.Errorf("note = %v", p["note"])
	}
	if p["external_memo"] != "invoice #42" {
		t.Errorf("external_memo = %v", p["external_memo"])
	}
	if p["bank_description"] != "ANTHROPIC* CLAUDE SUB" {
		t.Errorf("bank_description = %v", p["bank_description"])
	}
	if p["status_reason"] != "insufficient funds" {
		t.Errorf("status_reason = %v", p["status_reason"])
	}
}

// TestMercuryMerchantInfo: merchant.category/categoryCode surface on card txns.
func TestMercuryMerchantInfo(t *testing.T) {
	txn := map[string]any{
		"amount": -44.63,
		"kind":   "debitCardTransaction",
		"merchant": map[string]any{
			"category":     "Software",
			"categoryCode": "7372",
		},
	}
	got := Mercury("debitCardTransaction", txn)
	p := decode(t, got[0], txn)

	if p["merchant_category"] != "Software" {
		t.Errorf("merchant_category = %v", p["merchant_category"])
	}
	if p["merchant_category_code"] != "7372" {
		t.Errorf("merchant_category_code = %v", p["merchant_category_code"])
	}
}

// TestMercuryNoMerchantOmitsFields: transactions without a merchant object
// (wires, transfers, fees) must not carry empty merchant_* noise fields.
func TestMercuryNoMerchantOmitsFields(t *testing.T) {
	txn := map[string]any{"amount": 585.0, "kind": "other"}
	got := Mercury("other", txn)
	p := decode(t, got[0], txn)

	if _, ok := p["merchant_category"]; ok {
		t.Error("merchant_category should be absent when there is no merchant")
	}
}
