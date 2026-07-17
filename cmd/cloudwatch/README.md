# cloudwatch connector

Polls AWS **CloudWatch alarm history** and emits one event per alarm state
**transition** — not steady-state alarm status. This is an alert-stream
connector (mallcoppro-ee9): a CloudWatch alarm state transition already IS an
alert (CloudWatch itself decided a threshold was crossed), unlike the
activity-stream connectors (`aws`, `github`, ...) which normalize raw activity
that mallcop's own detectors then judge.

## Auth

Uses the standard AWS credentials chain (aws-sdk-go-v2) — the same chain and
the same read-only `mallcop-monitor` role the `aws` connector uses via GitHub
OIDC. Set any of:

| Variable | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_SESSION_TOKEN` | Required alongside the two above for temporary/OIDC credentials |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Region (overridden by `--region` flag) |

AWS profiles (`~/.aws/credentials`) and instance/pod roles are also supported via the SDK chain.

## Required IAM permissions

Both calls are free and strictly read-only — this connector never creates,
modifies, or deletes any AWS resource:

```json
{
  "Effect": "Allow",
  "Action": ["cloudwatch:DescribeAlarms", "cloudwatch:DescribeAlarmHistory"],
  "Resource": "*"
}
```

## Usage

```bash
mallcop-connector-cloudwatch --region us-east-1 [--since <iso-timestamp>] [--cursor <cursor>]
```

## How it works

1. **`DescribeAlarms`** — fetches every current metric alarm's namespace and
   metric name, building a name → context lookup table. This call is not
   time-filtered; it always returns the account's current alarm set.
2. **`DescribeAlarmHistory`** with `HistoryItemType=StateUpdate` — fetches every
   alarm state transition since the resume floor (`--since` / `--cursor`,
   whichever is later). Every other history item type (`ConfigurationUpdate`,
   `Action`, `AlarmContributorStateUpdate`, `AlarmContributorAction`) is an
   admin/notification event, not a state transition, and is out of scope.
3. Each `StateUpdate` item's `HistoryData` (an opaque JSON string CloudWatch
   does not formally contract the schema of) is best-effort parsed for
   `oldState.stateValue`, `newState.stateValue`, and `newState.stateReason`.
   A parse failure falls back to `HistorySummary` and `"unknown"` states
   rather than dropping the event — losing state-value fidelity is better
   than losing a real transition entirely.
4. An item is merged with its alarm's namespace/metric from step 1 by alarm
   name. **CloudWatch retains history for deleted alarms** — a miss in the
   lookup table is expected and handled gracefully (namespace/metric emitted
   empty, never a hard failure).
5. `internal/normalize.CloudWatchAlarm` maps the transition to
   `type: "cloudwatch_alarm"` with a flat payload:

   | Field | Description |
   |---|---|
   | `signal_class` | Always `"alert"` |
   | `severity` | `"high"` when `new_state == "ALARM"`, else `"info"` (`OK` recovery, `INSUFFICIENT_DATA`, or any future state) |
   | `alarm_name` | The alarm's name |
   | `namespace` | e.g. `AWS/EC2` (empty if the alarm has since been deleted) |
   | `metric_name` | e.g. `CPUUtilization` (empty if the alarm has since been deleted) |
   | `old_state` / `new_state` | `OK` / `ALARM` / `INSUFFICIENT_DATA` / `unknown` |
   | `reason` | `newState.stateReason`, falling back to `HistorySummary` |

   Every payload also carries `raw` (the verbatim `AlarmHistoryItem`, credential
   material redacted) for injection-probe / secrets-exposure scanning, same as
   every other connector's `PayloadJSON`.

## Sample output

```json
{"id":"a1b2c3...","source":"cloudwatch","type":"cloudwatch_alarm","actor":"","timestamp":"2026-07-01T12:00:00Z","org":"us-east-1","payload":{"alarm_name":"high-cpu","metric_name":"CPUUtilization","namespace":"AWS/EC2","new_state":"ALARM","old_state":"OK","reason":"Threshold Crossed: 1 datapoint [95.0] was greater than the threshold (90.0).","severity":"high","signal_class":"alert","raw":{...}}}
```

Note `actor` is always empty: a CloudWatch alarm state transition is
system-triggered by a metric crossing a threshold, not by a human or service
principal action — there is no actor to report.

## Cursor / resume

The cursor is a high-water mark on the alarm history item's own `Timestamp`
(never a pagination token — PR #7's lesson applied from day one), HMAC-signed
under `mallcop-cloudwatch-cursor:<region>` and printed to stderr as
`cursor: <value>`. If a `StateUpdate` item is ever missing its `Timestamp`
(not observed live, but not ruled out by the API contract either), the event
is still emitted but its timestamp never advances the cursor — the same
`tsReliable` guard `cmd/aws` and `cmd/github` use.

## Known limitations

- `DescribeAlarms` only returns **metric alarms** by default (composite and
  log alarms are out of scope for this connector — a metric-threshold
  transition is the alert-stream signal this connector targets).
- `HistoryData`'s JSON schema is not formally part of the CloudWatch API
  contract; this connector parses it best-effort and degrades to `"unknown"`
  states (never a hard failure) if AWS ever changes its shape.
