package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SourceRecord is what a producer appends to the notification outbox inside its business
// transaction (EPIC #1327 D2). It names the source that changed and the event it implies; the
// worker later turns it into an Event and matches rules, so a producer never runs rule matching or
// delivery inside its own transaction.
type SourceRecord struct {
	TenantID shared.ID
	// SourceKind and SourceID are the idempotency key: appending the same pair twice keeps the
	// first record.
	SourceKind   string
	SourceID     string
	EventType    EventType
	EngagementID shared.ID
	Severity     shared.Severity
	OccurredAt   time.Time
	// Data is not size-bounded here: it can carry user-sized content such as a finding title, and
	// an oversized payload must not fail the producer's business write. The projection refuses an
	// event whose data exceeds the Event bound instead.
	Data          json.RawMessage
	SchemaVersion int
	// SubjectKind and SubjectID name the entity the event is about (EPIC D8), for example
	// "incident" and its ID, apart from the source key.
	SubjectKind string
	SubjectID   string
	// Context is the template context snapshot taken by the event's builder (EPIC D5).
	Context json.RawMessage
}

const (
	maxSourceKeyLength = 512
	maxSubjectIDLength = 512
	maxContextBytes    = 1 << 20 // the column bound of migration 0190
)

var sourceKindShape = regexp.MustCompile(`^[a-z_]+$`)

// Normalize fills the defaults a producer may leave out and validates the record. It is called
// by every outbox adapter, so the Postgres and memory adapters accept exactly the same records.
func (r *SourceRecord) Normalize() error {
	r.SourceID = strings.TrimSpace(r.SourceID)
	r.SubjectID = strings.TrimSpace(r.SubjectID)
	r.OccurredAt = r.OccurredAt.UTC()
	if r.SchemaVersion == 0 {
		r.SchemaVersion = 1
	}
	if len(bytes.TrimSpace(r.Context)) == 0 {
		r.Context = json.RawMessage(`{}`)
	}
	return r.validate()
}

func (r SourceRecord) validate() error {
	if r.TenantID.IsZero() {
		return invalidRecord("tenant is required")
	}
	if !sourceKindShape.MatchString(r.SourceKind) || len(r.SourceKind) > maxSourceKeyLength {
		return invalidRecord("source kind must match ^[a-z_]+$")
	}
	if r.SourceID == "" || len(r.SourceID) > maxSourceKeyLength {
		return invalidRecord("source id is required and bounded")
	}
	spec, ok := LookupEvent(r.EventType)
	if !ok {
		return invalidRecord("event type is not in the catalog")
	}
	if r.SchemaVersion < 1 || r.SchemaVersion > spec.SchemaVersion {
		return invalidRecord("schema version is not known for this event type")
	}
	if r.OccurredAt.IsZero() {
		return invalidRecord("occurred time is required")
	}
	if r.SubjectKind != "" && !sourceKindShape.MatchString(r.SubjectKind) {
		return invalidRecord("subject kind must match ^[a-z_]+$")
	}
	if len(r.SubjectID) > maxSubjectIDLength {
		return invalidRecord("subject id is too long")
	}
	if !isJSONObject(r.Data, 0) {
		return invalidRecord("data must be a JSON object")
	}
	if !isJSONObject(r.Context, maxContextBytes) {
		return invalidRecord("context must be a JSON object of at most 1 MiB")
	}
	return nil
}

// isJSONObject reports whether raw is a JSON object of at most maxBytes; zero means unbounded.
func isJSONObject(raw json.RawMessage, maxBytes int) bool {
	if len(raw) == 0 || (maxBytes > 0 && len(raw) > maxBytes) {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(raw, &object) == nil && object != nil
}

func invalidRecord(reason string) error {
	return fmt.Errorf("%w: notification source record: %s", shared.ErrValidation, reason)
}
