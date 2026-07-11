package finding

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ManualInput is the operator-supplied content for a hand-authored finding.
type ManualInput struct {
	Title       string
	Description string
	Severity    shared.Severity
	CVSSVector  string
	CWE         string
}

// NewManual validates operator input and builds a manual finding. Manual findings
// get a unique dedup key (manual:<id>) so distinct entries never merge, are
// Kind=manual (human-authored, not evidence-gated), and start Open at version 1.
// id + now are supplied by the use case (deterministic, testable).
func NewManual(id, engagementID shared.ID, in ManualInput, now time.Time) (Finding, error) {
	title := strings.TrimSpace(in.Title)
	if title == "" {
		return Finding{}, fmt.Errorf("%w: finding title is required", shared.ErrValidation)
	}
	sev := in.Severity
	if sev == "" {
		sev = shared.SeverityUnknown
	}
	if !sev.Valid() {
		return Finding{}, fmt.Errorf("%w: unknown severity %q", shared.ErrValidation, sev)
	}
	return Finding{
		ID:           id,
		EngagementID: engagementID,
		Title:        title,
		Description:  strings.TrimSpace(in.Description),
		Severity:     sev,
		CVSSVector:   strings.TrimSpace(in.CVSSVector),
		CWE:          strings.TrimSpace(in.CWE),
		Status:       StatusOpen,
		Kind:         KindManual,
		Class:        ClassThirdParty,
		Scope:        "unknown",
		Reachability: "unknown",
		Priority:     priorityForSeverity(sev),
		DedupKey:     "manual:" + id.String(),
		Version:      1,
		Audit:        shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}

// priorityForSeverity gives a manual finding a sensible default Synapse priority
// (1 highest.. 5 background) from its severity.
func priorityForSeverity(s shared.Severity) int {
	switch s {
	case shared.SeverityCritical, shared.SeverityHigh:
		return 1
	case shared.SeverityMedium:
		return 3
	default:
		return 4
	}
}

// Comment is a persisted collaboration note on a finding – distinct from
// the append-only audit log; comments are the human activity thread.
type Comment struct {
	ID           shared.ID
	EngagementID shared.ID
	FindingID    shared.ID
	Author       string
	Body         string
	CreatedAt    time.Time
}

// NewComment validates and builds a comment (non-empty body, attributed author).
func NewComment(id, engagementID, findingID shared.ID, author, body string, now time.Time) (Comment, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return Comment{}, fmt.Errorf("%w: comment body is required", shared.ErrValidation)
	}
	if strings.TrimSpace(author) == "" {
		return Comment{}, fmt.Errorf("%w: comment author is required", shared.ErrValidation)
	}
	return Comment{ID: id, EngagementID: engagementID, FindingID: findingID, Author: author, Body: body, CreatedAt: now}, nil
}
