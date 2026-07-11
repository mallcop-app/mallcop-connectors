package normalize

// Coinbase maps a raw Coinbase App API v2 transaction to canonical mallcop
// events.
//
// txType is txn["type"] (e.g. "send", "receive", "buy", "sell", "trade",
// "staking_reward"). txn is the JSON-decoded /v2/accounts/{id}/transactions
// entry: amount:{amount,currency}, native_amount:{amount,currency}, status,
// details:{title,subtitle,header}, network:{status,hash}, to/from (present on
// sends/receives).
//
// HONESTY RULE: no existing mallcop detector gate constant is semantically
// true for a crypto exchange transaction — the gate vocabulary (role_assignment,
// secret_access, bulk_export, config_change, ...) describes cloud-audit-log
// admin actions, not asset transfers. Stretching one of those gates onto a
// "send" or "buy" would fire a detector on a fact it was never designed to
// evaluate, which is worse than firing nothing. So every Coinbase transaction
// type maps to the inert CatchAll — the flat payload below still feeds the
// type-less detectors: new-actor sees to_address/from as the actor identity,
// secrets-exposure/injection-probe scan the "raw" sub-object recursively, and
// volume-anomaly/unusual-timing see event volume and timestamps. Inference
// triage also reads the flat fields directly.
func Coinbase(txType string, txn map[string]any) []Result {
	amount := subMap(txn, "amount")
	nativeAmount := subMap(txn, "native_amount")
	details := subMap(txn, "details")
	network := subMap(txn, "network")
	to := subMap(txn, "to")
	from := subMap(txn, "from")

	p := map[string]any{"tx_type": txType}
	set(p, "amount", mapStr(amount, "amount"))
	set(p, "currency", mapStr(amount, "currency"))
	set(p, "native_amount", mapStr(nativeAmount, "amount"))
	set(p, "native_currency", mapStr(nativeAmount, "currency"))
	set(p, "status", mapStr(txn, "status"))
	set(p, "to_address", firstNonEmpty(mapStr(to, "address"), mapStr(to, "resource")))
	set(p, "from", firstNonEmpty(mapStr(from, "id"), mapStr(from, "resource")))
	set(p, "network_hash", mapStr(network, "hash"))
	set(p, "title", mapStr(details, "title"))
	set(p, "subtitle", mapStr(details, "subtitle"))

	return []Result{{Type: CatchAll, Payload: p}}
}
