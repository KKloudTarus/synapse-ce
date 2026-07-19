// Package hotspot models Project-scoped Security Hotspot projections.
package hotspot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Status is the review state vocabulary reserved for the Security Hotspots product.
// PR A only persists the initial state; transitions belong to PR B.
type Status string

const (
	StatusToReview     Status = "to_review"
	StatusAcknowledged Status = "acknowledged"
	StatusFixed        Status = "fixed"
	StatusSafe         Status = "safe"
)

func (s Status) Valid() bool {
	switch s {
	case StatusToReview, StatusAcknowledged, StatusFixed, StatusSafe:
		return true
	default:
		return false
	}
}

// Candidate is the immutable scan-time projection input produced by the classifier.
// Tenant, Project, analysis timestamps, review state and version are assigned by the
// persistence boundary so rescans cannot reset review state.
type Candidate struct {
	Key             string
	FindingIdentity string
	RuleKey         string
	Title           string
	Description     string
	Severity        shared.Severity
	Kind            finding.Kind
	CWE             string
	Location        string
}

// Hotspot is a tenant- and Project-scoped read model. It deliberately contains no
// Engagement identity or raw scan payload.
type Hotspot struct {
	ID                  shared.ID
	TenantID            shared.ID
	ProjectID           shared.ID
	Key                 string
	FindingIdentity     string
	RuleKey             string
	Title               string
	Description         string
	Severity            shared.Severity
	Kind                finding.Kind
	CWE                 string
	Location            string
	Status              Status
	Version             int
	FirstSeenAnalysisID string
	LastSeenAnalysisID  string
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
	LastReviewedBy      string
	LastReviewedAt      *time.Time
	Audit               shared.Audit
}

// DeterministicID gives a projection a stable opaque identifier across rescans.
// The tenant and Project are part of the input so equal finding identities in two
// tenants cannot accidentally address the same resource.
func DeterministicID(tenantID, projectID shared.ID, key string) shared.ID {
	sum := sha256.Sum256([]byte(tenantID.String() + "\x00" + projectID.String() + "\x00" + key))
	return shared.ID(hex.EncodeToString(sum[:16]))
}

// Validate enforces the fields required for a safe read projection.
func (h Hotspot) Validate() error {
	// An empty tenant ID is the repository's valid default tenant in
	// single-tenant mode. Project and hotspot identities are always required.
	if h.ID.IsZero() || h.ProjectID.IsZero() {
		return fmt.Errorf("%w: hotspot identity is required", shared.ErrValidation)
	}
	if strings.TrimSpace(h.Key) == "" || strings.TrimSpace(h.FindingIdentity) == "" {
		return fmt.Errorf("%w: hotspot finding identity is required", shared.ErrValidation)
	}
	if strings.TrimSpace(h.RuleKey) == "" {
		return fmt.Errorf("%w: hotspot rule key is required", shared.ErrValidation)
	}
	if !h.Severity.Valid() {
		return fmt.Errorf("%w: hotspot severity is invalid", shared.ErrValidation)
	}
	if !Status(h.Status).Valid() {
		return fmt.Errorf("%w: hotspot status is invalid", shared.ErrValidation)
	}
	if h.Version < 1 {
		return fmt.Errorf("%w: hotspot version must be positive", shared.ErrValidation)
	}
	if strings.TrimSpace(h.FirstSeenAnalysisID) == "" || strings.TrimSpace(h.LastSeenAnalysisID) == "" {
		return fmt.Errorf("%w: hotspot analysis identity is required", shared.ErrValidation)
	}
	if h.FirstSeenAt.IsZero() || h.LastSeenAt.IsZero() || h.LastSeenAt.Before(h.FirstSeenAt) {
		return fmt.Errorf("%w: hotspot seen timestamps are invalid", shared.ErrValidation)
	}
	return nil
}

// ListFilter describes the read API's tenant/project-local filters.
type ListFilter struct {
	Status           *Status
	RuleKey          string
	Severity         *shared.Severity
	Search           string
	Limit            int
	BeforeLastSeenAt time.Time
	BeforeID         shared.ID
}

// Cursor is the deterministic keyset cursor returned by a list operation.
type Cursor struct {
	BeforeLastSeenAt time.Time
	BeforeID         shared.ID
}

type Facets struct {
	Statuses   map[string]int
	RuleKeys   map[string]int
	Severities map[string]int
}

type Page struct {
	Items  []Hotspot
	Next   *Cursor
	Facets Facets
}
