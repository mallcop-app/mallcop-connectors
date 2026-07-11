package normalize

// Mercury maps a raw Mercury bank transaction to canonical mallcop events.
//
// kind is txn["kind"] (e.g. "externalTransfer", "internalTransfer", "outgoingPayment",
// "debitCardTransaction", "incomingDomesticWire", "checkDeposit", "fee", "other", ...).
// txn is the JSON-decoded raw Mercury transaction record (GET
// /account/{id}/transactions).
//
// Mercury transactions are financial ledger events, not admin/IAM/access actions —
// none of the existing mallcop detector gate types (role_assignment, secret_access,
// data_export, bulk_export, config_change, ...) are semantically a wire transfer,
// card swipe, or check deposit, so every Mercury transaction kind flows through as
// CatchAll. That is the correct, honest mapping (never force a gate to fire on a
// transaction type it wasn't designed to detect). The type-less detectors
// (new-actor on a never-seen counterparty — this is the whole point of feeding
// Mercury into mallcop — volume-anomaly, unusual-timing, injection-probe /
// secrets-exposure scanning note/memo text) and inference triage read the flat
// payload below.
func Mercury(kind string, txn map[string]any) []Result {
	amount, _ := txn["amount"].(float64)
	direction := "incoming"
	if amount < 0 {
		direction = "outgoing"
	}

	p := map[string]any{
		"amount":    amount,
		"currency":  "USD",
		"kind":      kind,
		"direction": direction,
	}
	set(p, "counterparty", mapStr(txn, "counterpartyName"))
	set(p, "status", mapStr(txn, "status"))
	set(p, "status_reason", mapStr(txn, "reasonForFailure"))
	set(p, "note", mapStr(txn, "note"))
	set(p, "external_memo", mapStr(txn, "externalMemo"))
	set(p, "bank_description", mapStr(txn, "bankDescription"))
	set(p, "dashboard_link", mapStr(txn, "dashboardLink"))
	set(p, "check_number", mapStr(txn, "checkNumber"))
	set(p, "tracking_number", mapStr(txn, "trackingNumber"))

	if merch := subMap(txn, "merchant"); merch != nil {
		set(p, "merchant_category", mapStr(merch, "category"))
		set(p, "merchant_category_code", mapStr(merch, "categoryCode"))
	}

	return []Result{{Type: CatchAll, Payload: p}}
}
