package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type InventoryCompleteness string

const (
	InventoryUnknown    InventoryCompleteness = "unknown"
	InventoryComplete   InventoryCompleteness = "complete"
	InventoryIncomplete InventoryCompleteness = "incomplete"
)

func (c InventoryCompleteness) Valid() bool {
	return c == InventoryUnknown || c == InventoryComplete || c == InventoryIncomplete
}

// InventoryScope derives a stable, non-secret scope key from the server-normalized
// technical target. Engagement is deliberately not included because it is already
// part of every storage key.
func InventoryScope(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(target))
	return "target:" + hex.EncodeToString(digest[:16])
}

type InventoryAdmission struct {
	TenantID     shared.ID
	EngagementID shared.ID
	Scope        string
	Generation   int64
	AdmittedAt   time.Time
}

func (a InventoryAdmission) Validate() error {
	if a.TenantID.IsZero() || a.EngagementID.IsZero() || strings.TrimSpace(a.Scope) == "" || a.Generation <= 0 || a.AdmittedAt.IsZero() {
		return fmt.Errorf("%w: inventory admission identity is required", shared.ErrValidation)
	}
	return nil
}

type IdentityCoverage struct {
	Total       int
	Resolved    int
	Unsupported int
}

type InventoryPublication struct {
	InventoryAdmission
	SBOMID          shared.ID
	Completeness    InventoryCompleteness
	Authoritative   bool
	AuthorityReason string
	Coverage        IdentityCoverage
	PublishedAt     time.Time
	Current         bool
	Superseded      bool
}

type InventoryCursor struct {
	AfterEngagementID shared.ID
	AfterScope        string
}

type InventoryPublicationPage struct {
	Items []InventoryPublication
	Next  *InventoryCursor
}

func (p InventoryPublication) Validate() error {
	if err := p.InventoryAdmission.Validate(); err != nil {
		return err
	}
	if p.SBOMID.IsZero() || !p.Completeness.Valid() || p.PublishedAt.IsZero() {
		return fmt.Errorf("%w: inventory publication identity is required", shared.ErrValidation)
	}
	if p.Coverage.Total < 0 || p.Coverage.Resolved < 0 || p.Coverage.Unsupported < 0 || p.Coverage.Resolved+p.Coverage.Unsupported != p.Coverage.Total {
		return fmt.Errorf("%w: inventory identity coverage is invalid", shared.ErrValidation)
	}
	if p.Authoritative && (p.Completeness != InventoryComplete || strings.TrimSpace(p.AuthorityReason) == "") {
		return fmt.Errorf("%w: authoritative inventory requires complete acquisition evidence", shared.ErrValidation)
	}
	if p.Current && (!p.Authoritative || p.Superseded) {
		return fmt.Errorf("%w: current inventory publication is invalid", shared.ErrValidation)
	}
	return nil
}

type ComponentRecord struct {
	TenantID            shared.ID
	EngagementID        shared.ID
	SBOMID              shared.ID
	ComponentID         shared.ID
	Name                string
	Version             string
	PURL                string
	CPE                 string
	CPEPart             string
	CPEVendor           string
	CPEProduct          string
	CPEStatus           string
	CPEReason           string
	CPEHash             string
	Ecosystem           string
	Package             string
	IdentityHash        string
	IdentityStatus      string
	IdentityReason      string
	Scope               string
	Reachability        string
	Unreferenced        bool
	SBOMCreatedAt       time.Time
	InventoryScope      string
	InventoryGeneration int64
}

func (c ComponentRecord) Validate() error {
	switch {
	case c.SBOMID.IsZero(), c.ComponentID.IsZero():
		return fmt.Errorf("%w: component inventory identity is required", shared.ErrValidation)
	case c.SBOMCreatedAt.IsZero():
		return fmt.Errorf("%w: component inventory timestamp is required", shared.ErrValidation)
	case c.IdentityStatus == "":
		return fmt.Errorf("%w: component identity status is required", shared.ErrValidation)
	case (strings.TrimSpace(c.InventoryScope) == "") != (c.InventoryGeneration == 0):
		return fmt.Errorf("%w: component inventory scope and generation must be provided together", shared.ErrValidation)
	case c.InventoryGeneration < 0:
		return fmt.Errorf("%w: component inventory generation cannot be negative", shared.ErrValidation)
	}
	return nil
}

func (c ComponentRecord) CorrelationFingerprint() string {
	base := ""
	if c.IdentityStatus == IdentityResolved && c.IdentityHash != "" {
		base = c.IdentityHash
	}
	if base == "" && c.CPEStatus == IdentityResolved {
		base = c.CPEHash
	}
	if base == "" || c.InventoryScope == "" {
		return base
	}
	digest := sha256.Sum256([]byte(c.InventoryScope + "\x00" + base))
	return hex.EncodeToString(digest[:])
}

type ComponentCursor struct {
	BeforeSBOMCreatedAt time.Time
	BeforeSBOMID        shared.ID
	BeforeComponentID   shared.ID
}

type ComponentPage struct {
	Items []ComponentRecord
	Next  *ComponentCursor
}

type ComponentQuery struct {
	TenantID     shared.ID
	EngagementID shared.ID
	Ecosystem    string
	Package      string
	CPEPart      string
	CPEVendor    string
	CPEProduct   string
	Cursor       ComponentCursor
	Limit        int
	// A complete pin selects one immutable inventory generation. Partial pins are
	// rejected so pagination can never drift to another snapshot.
	SBOMID              shared.ID
	InventoryScope      string
	InventoryGeneration int64
}

func (q ComponentQuery) Normalize() (ComponentQuery, error) {
	q.Ecosystem = strings.TrimSpace(q.Ecosystem)
	q.Package = strings.TrimSpace(q.Package)
	q.CPEPart = strings.ToLower(strings.TrimSpace(q.CPEPart))
	q.CPEVendor = strings.ToLower(strings.TrimSpace(q.CPEVendor))
	q.CPEProduct = strings.ToLower(strings.TrimSpace(q.CPEProduct))
	packageQuery := q.Ecosystem != "" || q.Package != ""
	cpeQuery := q.CPEPart != "" || q.CPEVendor != "" || q.CPEProduct != ""
	pinParts := 0
	if !q.SBOMID.IsZero() {
		pinParts++
	}
	q.InventoryScope = strings.TrimSpace(q.InventoryScope)
	if q.InventoryScope != "" {
		pinParts++
	}
	if q.InventoryGeneration > 0 {
		pinParts++
	}
	if q.EngagementID.IsZero() || packageQuery == cpeQuery || (packageQuery && (q.Ecosystem == "" || q.Package == "")) || (cpeQuery && (q.CPEPart == "" || q.CPEVendor == "" || q.CPEProduct == "")) {
		return ComponentQuery{}, fmt.Errorf("%w: component query key is required", shared.ErrValidation)
	}
	if pinParts != 0 && pinParts != 3 {
		return ComponentQuery{}, fmt.Errorf("%w: component inventory pin must include scope, generation, and SBOM", shared.ErrValidation)
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 500 {
		q.Limit = 500
	}
	return q, nil
}

type SnapshotQuery struct {
	TenantID            shared.ID
	EngagementID        shared.ID
	SBOMID              shared.ID
	InventoryScope      string
	InventoryGeneration int64
	AfterComponentID    shared.ID
	Limit               int
}

func (q SnapshotQuery) Normalize() (SnapshotQuery, error) {
	q.InventoryScope = strings.TrimSpace(q.InventoryScope)
	if q.EngagementID.IsZero() || q.SBOMID.IsZero() || q.InventoryScope == "" || q.InventoryGeneration <= 0 {
		return SnapshotQuery{}, fmt.Errorf("%w: immutable inventory snapshot identity is required", shared.ErrValidation)
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 500 {
		q.Limit = 500
	}
	return q, nil
}
