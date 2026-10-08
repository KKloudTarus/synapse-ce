package siem

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Position is a source cursor. Audit and incident fields are independent;
// an audit id is never compared with an incident sequence.
type Position struct {
	Source      Source
	AuditID     int64
	AuditHash   string
	HashVersion int
	StreamSeq   int64
	IncidentID  string
	EventSeq    int
	Phase       Phase
}

// Zero reports whether the cursor has not yet consumed a record.
func (p Position) Zero() bool {
	switch p.Source {
	case SourceAudit:
		return p.AuditID == 0 && p.AuditHash == ""
	case SourceIncidentLive, SourceIncidentHistorical:
		return p.StreamSeq == 0
	default:
		return true
	}
}

// Validate checks the position against its source.
func (p Position) Validate() error {
	if !p.Source.Valid() {
		return fmt.Errorf("%w: unknown source", shared.ErrValidation)
	}
	switch p.Source {
	case SourceAudit:
		if p.StreamSeq != 0 || p.IncidentID != "" || p.EventSeq != 0 {
			return fmt.Errorf("%w: audit position cannot carry an incident cursor", shared.ErrValidation)
		}
		if p.Zero() {
			return nil
		}
		if p.AuditID <= 0 || p.AuditHash == "" || p.HashVersion != 2 {
			return fmt.Errorf("%w: audit cursor requires a v2 row id and hash", shared.ErrValidation)
		}
	default:
		if p.AuditID != 0 || p.AuditHash != "" || p.HashVersion != 0 {
			return fmt.Errorf("%w: incident position cannot carry an audit cursor", shared.ErrValidation)
		}
		if p.Zero() {
			return nil
		}
		if p.StreamSeq <= 0 || p.IncidentID == "" || p.EventSeq <= 0 {
			return fmt.Errorf("%w: incident cursor requires stream sequence, incident, and event sequence", shared.ErrValidation)
		}
		want := PhaseLive
		if p.Source == SourceIncidentHistorical {
			want = PhaseHistorical
		}
		if p.Phase != want {
			return fmt.Errorf("%w: incident cursor phase does not match its partition", shared.ErrValidation)
		}
	}
	return nil
}

// AuditFact is one committed v2 audit row after metadata allowlisting.
// Metadata that is not copied here is not available to a mapper.
type AuditFact struct {
	ID            int64
	Actor         string
	Action        string
	Target        string
	AtUnixMicro   int64
	Hash          string
	PreviousHash  string
	HashVersion   int
	Severity      string
	EngagementID  string
	AdvisoryID    string
	FindingID     string
	AssetID       string
	Host          string
	Title         string
	FindingStatus string
}

// IncidentFact is one captured incident event after the payload allowlist.
// It is the event as written, not a later fold of the incident.
type IncidentFact struct {
	StreamSeq    int64
	Phase        Phase
	IncidentID   string
	EventSeq     int
	Kind         string
	AtUnixMicro  int64
	Actor        string
	AssetID      string
	Title        string
	Severity     string
	ToStatus     string
	Owner        string
	Comment      string
	EngagementID string
	DetectionID  string
}

// Checkpoint is the last handled position for one sink partition.
type Checkpoint struct {
	SinkID     shared.ID
	TenantID   shared.ID
	Source     Source
	Generation int64
	Position   Position
	ChainHead  string
	UpdatedAt  time.Time
}

// BacklogAggregate contains only bounded operational counts, never payloads.
type BacklogAggregate struct {
	Records         int
	OldestUnixMicro int64
}

// AuditAnchor is what the reader observed in the same snapshot as the page.
type AuditAnchor struct {
	CursorID    int64
	CursorHash  string
	CursorFound bool
	HeadID      int64
	HeadHash    string
	V1Present   bool
	Unchained   int
}
