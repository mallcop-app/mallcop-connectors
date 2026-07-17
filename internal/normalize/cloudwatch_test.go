package normalize

import "testing"

// TestCloudWatchAlarmFiring: a transition into ALARM is the actionable case —
// severity must be high and every flat field must round-trip.
func TestCloudWatchAlarmFiring(t *testing.T) {
	raw := map[string]any{"AlarmName": "high-cpu", "HistoryItemType": "StateUpdate"}
	got := CloudWatchAlarm("high-cpu", "AWS/EC2", "CPUUtilization", "OK", "ALARM", "Threshold Crossed: 1 datapoint [95.0] was greater than the threshold (90.0).")
	r := wantType(t, got, CloudWatchAlarmType)
	p := decode(t, r, raw)

	if p["signal_class"] != "alert" {
		t.Errorf("signal_class = %v, want alert", p["signal_class"])
	}
	if p["severity"] != "high" {
		t.Errorf("severity = %v, want high", p["severity"])
	}
	if p["alarm_name"] != "high-cpu" {
		t.Errorf("alarm_name = %v, want high-cpu", p["alarm_name"])
	}
	if p["namespace"] != "AWS/EC2" {
		t.Errorf("namespace = %v, want AWS/EC2", p["namespace"])
	}
	if p["metric_name"] != "CPUUtilization" {
		t.Errorf("metric_name = %v, want CPUUtilization", p["metric_name"])
	}
	if p["old_state"] != "OK" {
		t.Errorf("old_state = %v, want OK", p["old_state"])
	}
	if p["new_state"] != "ALARM" {
		t.Errorf("new_state = %v, want ALARM", p["new_state"])
	}
	if p["reason"] == "" {
		t.Error("reason must not be empty")
	}
	// raw item must be attached verbatim for injection-probe/secrets-exposure.
	if p["raw"] == nil {
		t.Error("payload missing raw")
	}
}

// TestCloudWatchAlarmRecovery: a transition back to OK is informational, not
// actionable — severity must be info, never high, even though this is still a
// state *change* worth keeping in the stream for correlation.
func TestCloudWatchAlarmRecovery(t *testing.T) {
	got := CloudWatchAlarm("high-cpu", "AWS/EC2", "CPUUtilization", "ALARM", "OK", "Threshold Crossed: 1 datapoint [10.0] was not greater than the threshold (90.0).")
	r := wantType(t, got, CloudWatchAlarmType)
	p := decode(t, r, nil)

	if p["severity"] != "info" {
		t.Errorf("severity = %v, want info (OK is a recovery, not an alert)", p["severity"])
	}
	if p["new_state"] != "OK" {
		t.Errorf("new_state = %v, want OK", p["new_state"])
	}
}

// TestCloudWatchAlarmInsufficientData: a transition into INSUFFICIENT_DATA
// (a metric data gap, not a threshold breach) must also be info, not high.
func TestCloudWatchAlarmInsufficientData(t *testing.T) {
	got := CloudWatchAlarm("high-cpu", "AWS/EC2", "CPUUtilization", "OK", "INSUFFICIENT_DATA", "Insufficient Data: 1 datapoint was unknown.")
	r := wantType(t, got, CloudWatchAlarmType)
	p := decode(t, r, nil)

	if p["severity"] != "info" {
		t.Errorf("severity = %v, want info", p["severity"])
	}
	if p["new_state"] != "INSUFFICIENT_DATA" {
		t.Errorf("new_state = %v, want INSUFFICIENT_DATA", p["new_state"])
	}
}

// TestCloudWatchAlarmUnknownStateDefaultsInfo: an unrecognized future state
// value must never silently escalate to high — info is the safe default.
func TestCloudWatchAlarmUnknownStateDefaultsInfo(t *testing.T) {
	got := CloudWatchAlarm("mystery-alarm", "AWS/EC2", "CPUUtilization", "OK", "SOME_FUTURE_STATE", "")
	r := wantType(t, got, CloudWatchAlarmType)
	p := decode(t, r, nil)

	if p["severity"] != "info" {
		t.Errorf("severity = %v, want info for an unrecognized state", p["severity"])
	}
}

// TestCloudWatchAlarmEveryTypeConsistent: every call maps to the single
// cloudwatch_alarm Type — this connector has no CatchAll fallback because a
// StateUpdate history item is, by definition, already an alert.
func TestCloudWatchAlarmEveryTypeConsistent(t *testing.T) {
	states := [][2]string{{"OK", "ALARM"}, {"ALARM", "OK"}, {"", "INSUFFICIENT_DATA"}}
	for _, s := range states {
		got := CloudWatchAlarm("a", "ns", "m", s[0], s[1], "")
		if len(got) != 1 {
			t.Fatalf("old=%q new=%q: want 1 result, got %d", s[0], s[1], len(got))
		}
		if got[0].Type != CloudWatchAlarmType {
			t.Errorf("old=%q new=%q: Type = %q, want %q", s[0], s[1], got[0].Type, CloudWatchAlarmType)
		}
	}
}

// TestCloudWatchAlarmMissingFieldsOmitted: empty optional fields (e.g. an
// alarm no longer present in DescribeAlarms so namespace/metric are unknown)
// must be omitted from the flat payload, not emitted as noise.
func TestCloudWatchAlarmMissingFieldsOmitted(t *testing.T) {
	got := CloudWatchAlarm("deleted-alarm", "", "", "OK", "ALARM", "")
	r := wantType(t, got, CloudWatchAlarmType)
	p := decode(t, r, nil)

	if _, ok := p["namespace"]; ok {
		t.Error("namespace should be omitted when empty")
	}
	if _, ok := p["metric_name"]; ok {
		t.Error("metric_name should be omitted when empty")
	}
	if _, ok := p["reason"]; ok {
		t.Error("reason should be omitted when empty")
	}
	if p["alarm_name"] != "deleted-alarm" {
		t.Errorf("alarm_name = %v, want deleted-alarm", p["alarm_name"])
	}
}
