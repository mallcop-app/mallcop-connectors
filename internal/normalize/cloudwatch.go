package normalize

// CloudWatchAlarmType is the canonical mallcop event Type for every CloudWatch
// alarm state transition. Unlike the activity-stream sources (AWS CloudTrail,
// GitHub audit log, ...) where normalize maps a raw action to a detector gate
// (or CatchAll when none fits), a CloudWatch alarm history "StateUpdate" item
// already IS an alert — CloudWatch itself decided a threshold was crossed. So
// every transition maps to the same Type and carries "signal_class":"alert",
// distinguishing it from raw activity in the mallcop event stream
// (mallcoppro-ee9's alert-stream family: the free triage/investigation layer
// over alerts a customer's OTHER monitoring tools already raised).
const CloudWatchAlarmType = "cloudwatch_alarm"

// CloudWatchAlarm maps one CloudWatch alarm state transition (an
// AlarmHistoryItem with HistoryItemType=StateUpdate) to a canonical mallcop
// alert event. alarmName/namespace/metricName/oldState/newState/reason are
// already-extracted fields (the caller parses the raw AlarmHistoryItem and its
// JSON-encoded HistoryData — see cmd/cloudwatch/main.go — since that shape is
// AWS API-specific, not something this shared library should know about).
//
// severity comes from newState alone: ALARM firing is the actionable
// transition (high) — a threshold was actually crossed and something may need
// attention. A transition INTO OK (recovery) or INSUFFICIENT_DATA (a metric
// data gap) is informational (info): worth keeping in the stream for context
// and correlation, but not something that should page anyone the way a fresh
// ALARM should.
func CloudWatchAlarm(alarmName, namespace, metricName, oldState, newState, reason string) []Result {
	p := map[string]any{
		"signal_class": "alert",
		"severity":     cloudWatchAlarmSeverity(newState),
	}
	set(p, "alarm_name", alarmName)
	set(p, "namespace", namespace)
	set(p, "metric_name", metricName)
	set(p, "old_state", oldState)
	set(p, "new_state", newState)
	set(p, "reason", reason)

	return []Result{{Type: CloudWatchAlarmType, Payload: p}}
}

// cloudWatchAlarmSeverity maps a CloudWatch alarm's new state to a mallcop
// severity. Only "ALARM" is high; every other state (OK, INSUFFICIENT_DATA, or
// anything CloudWatch adds in the future) is info — an unrecognized future
// state must never silently escalate to high.
func cloudWatchAlarmSeverity(newState string) string {
	if newState == "ALARM" {
		return "high"
	}
	return "info"
}
