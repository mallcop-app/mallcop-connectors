package event

import (
	"encoding/json"
	"time"
)

// Event is the mallcop normalized event schema.
type Event struct {
	ID        string          `json:"id"`
	Source    string          `json:"source"`    // "github"
	Type      string          `json:"type"`      // e.g. "org.member_added", "repo.create"
	Actor     string          `json:"actor"`     // GitHub username
	Timestamp time.Time       `json:"timestamp"`
	Org       string          `json:"org"`
	Payload   json.RawMessage `json:"payload"` // raw audit log entry
}
