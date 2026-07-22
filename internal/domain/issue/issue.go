// Package issue models Project-scoped code-quality issue projections and their
// triage lifecycle (open / accepted / false-positive / won't-fix). It mirrors the
// Security Hotspot review model: a tenant- and Project-scoped read projection whose
// lifecycle state is retained across rescans and never deleted, so a resolved issue
// stays gate-exempt but auditable.
package issue

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Candidate is the immutable scan-time projection input for one non-hotspot finding.
// Tenant, Project, analysis timestamps, lifecycle state and version are assigned by the
// persistence boundary so a rescan cannot reset a triage decision.
type Candidate struct {
	Key             string
	FindingIdentity string
	RuleKey         string
	Type            rule.Type
	Title           string
	Description     string
	Severity        shared.Severity
	Kind            finding.Kind
	CWE             string
	Language        string
	File            string
	Location        string
	SourceLocation  *finding.SourceLocation
}

// Issue is a tenant- and Project-scoped read model. It deliberately carries no
// Engagement identity or raw scan payload.
type Issue struct {
	ID              shared.ID
	TenantID        shared.ID
	ProjectID       shared.ID
	Key             string
	FindingIdentity string
	RuleKey         string
	Type            rule.Type
	Title           string
	Description     string
	Severity        shared.Severity
	Kind            finding.Kind
	CWE             string
	Language        string
	File            string
	Location        string
	SourceLocation  *finding.SourceLocation
	Status          Status
	Version         int
	// IsNew marks an issue that has only been observed in its latest analysis (i.e.
	// introduced since the previous analysis); it drives the New Code lens/facet.
	IsNew               bool
	FirstSeenAnalysisID string
	LastSeenAnalysisID  string
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
	LastReviewedBy      string
	LastReviewedAt      *time.Time
	Audit               shared.Audit
}

// DeterministicID gives a projection a stable opaque identifier across rescans. The
// tenant and Project are part of the input so equal finding identities in two tenants
// can never address the same resource.
func DeterministicID(tenantID, projectID shared.ID, key string) shared.ID {
	sum := sha256.Sum256([]byte(tenantID.String() + "\x00" + projectID.String() + "\x00" + key))
	return shared.ID(hex.EncodeToString(sum[:16]))
}

// Validate enforces the fields required for a safe read projection.
func (i Issue) Validate() error {
	// An empty tenant ID is the repository's valid default tenant in single-tenant
	// mode. Project and issue identities are always required.
	if i.ID.IsZero() || i.ProjectID.IsZero() {
		return fmt.Errorf("%w: issue identity is required", shared.ErrValidation)
	}
	if strings.TrimSpace(i.Key) == "" || strings.TrimSpace(i.FindingIdentity) == "" {
		return fmt.Errorf("%w: issue finding identity is required", shared.ErrValidation)
	}
	if !i.Severity.Valid() {
		return fmt.Errorf("%w: issue severity is invalid", shared.ErrValidation)
	}
	if !i.Type.Valid() {
		return fmt.Errorf("%w: issue type is invalid", shared.ErrValidation)
	}
	if i.SourceLocation != nil && i.SourceLocation.Validate() != nil {
		return fmt.Errorf("%w: issue source location is invalid", shared.ErrValidation)
	}
	if !i.Status.Valid() {
		return fmt.Errorf("%w: issue status is invalid", shared.ErrValidation)
	}
	if i.Version < 1 {
		return fmt.Errorf("%w: issue version must be positive", shared.ErrValidation)
	}
	if strings.TrimSpace(i.FirstSeenAnalysisID) == "" || strings.TrimSpace(i.LastSeenAnalysisID) == "" {
		return fmt.Errorf("%w: issue analysis identity is required", shared.ErrValidation)
	}
	if i.FirstSeenAt.IsZero() || i.LastSeenAt.IsZero() || i.LastSeenAt.Before(i.FirstSeenAt) {
		return fmt.Errorf("%w: issue seen timestamps are invalid", shared.ErrValidation)
	}
	return nil
}

// Project creates and validates the initial Project-scoped projection for one issue
// candidate detected in an analysis.
func Project(tenantID, projectID shared.ID, analysisID string, createdAt time.Time, candidate Candidate) (Issue, error) {
	item := Issue{
		ID:                  DeterministicID(tenantID, projectID, candidate.Key),
		TenantID:            tenantID,
		ProjectID:           projectID,
		Key:                 candidate.Key,
		FindingIdentity:     candidate.FindingIdentity,
		RuleKey:             candidate.RuleKey,
		Type:                candidate.Type,
		Title:               candidate.Title,
		Description:         candidate.Description,
		Severity:            candidate.Severity,
		Kind:                candidate.Kind,
		CWE:                 candidate.CWE,
		Language:            candidate.Language,
		File:                candidate.File,
		Location:            candidate.Location,
		SourceLocation:      candidate.SourceLocation,
		Status:              StatusOpen,
		Version:             1,
		IsNew:               true,
		FirstSeenAnalysisID: analysisID,
		LastSeenAnalysisID:  analysisID,
		FirstSeenAt:         createdAt,
		LastSeenAt:          createdAt,
		Audit:               shared.Audit{CreatedAt: createdAt, UpdatedAt: createdAt},
	}
	if err := item.Validate(); err != nil {
		return Issue{}, err
	}
	return item, nil
}

// ListFilter describes the read API's tenant/Project-local facet filters.
type ListFilter struct {
	Lens        Lens
	Status      *Status
	Type        *rule.Type
	Severity    *shared.Severity
	RuleKey     string
	Language    string
	PathPrefix  string
	NewCodeOnly bool
	Search      string
	Limit       int

	BeforeLastSeenAt time.Time
	BeforeID         shared.ID
}

// Lens scopes the returned issues to the whole project or only new code.
type Lens string

const (
	LensOverall Lens = "overall"
	LensNewCode Lens = "new-code"
)

func (l Lens) Valid() bool { return l == LensOverall || l == LensNewCode }

// Cursor is the deterministic keyset cursor returned by a list operation.
type Cursor struct {
	BeforeLastSeenAt time.Time
	BeforeID         shared.ID
}

// Facets are the per-facet counts computed over the filtered (but unpaginated) set.
type Facets struct {
	Types      map[string]int
	Statuses   map[string]int
	Severities map[string]int
	RuleKeys   map[string]int
	Languages  map[string]int
}

// Summary is the aggregate triage state used by the explorer header.
type Summary struct {
	Total    int
	Open     int
	Resolved int
}

// Page is a keyset page of issues plus its facets and summary.
type Page struct {
	Items   []Issue
	Facets  Facets
	Next    *Cursor
	Summary Summary
}
