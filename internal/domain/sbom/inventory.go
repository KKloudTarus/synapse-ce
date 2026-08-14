package sbom

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type ComponentRecord struct {
	TenantID       shared.ID
	EngagementID   shared.ID
	SBOMID         shared.ID
	ComponentID    shared.ID
	Name           string
	Version        string
	PURL           string
	CPE            string
	CPEPart        string
	CPEVendor      string
	CPEProduct     string
	CPEStatus      string
	CPEReason      string
	CPEHash        string
	Ecosystem      string
	Package        string
	IdentityHash   string
	IdentityStatus string
	IdentityReason string
	Scope          string
	Reachability   string
	Unreferenced   bool
	SBOMCreatedAt  time.Time
}

func (c ComponentRecord) Validate() error {
	switch {
	case c.SBOMID.IsZero(), c.ComponentID.IsZero():
		return fmt.Errorf("%w: component inventory identity is required", shared.ErrValidation)
	case c.SBOMCreatedAt.IsZero():
		return fmt.Errorf("%w: component inventory timestamp is required", shared.ErrValidation)
	case c.IdentityStatus == "":
		return fmt.Errorf("%w: component identity status is required", shared.ErrValidation)
	}
	return nil
}

func (c ComponentRecord) CorrelationFingerprint() string {
	if c.IdentityStatus == IdentityResolved && c.IdentityHash != "" {
		return c.IdentityHash
	}
	if c.CPEStatus == IdentityResolved {
		return c.CPEHash
	}
	return ""
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
}

func (q ComponentQuery) Normalize() (ComponentQuery, error) {
	q.Ecosystem = strings.TrimSpace(q.Ecosystem)
	q.Package = strings.TrimSpace(q.Package)
	q.CPEPart = strings.ToLower(strings.TrimSpace(q.CPEPart))
	q.CPEVendor = strings.ToLower(strings.TrimSpace(q.CPEVendor))
	q.CPEProduct = strings.ToLower(strings.TrimSpace(q.CPEProduct))
	packageQuery := q.Ecosystem != "" || q.Package != ""
	cpeQuery := q.CPEPart != "" || q.CPEVendor != "" || q.CPEProduct != ""
	if q.EngagementID.IsZero() || packageQuery == cpeQuery || (packageQuery && (q.Ecosystem == "" || q.Package == "")) || (cpeQuery && (q.CPEPart == "" || q.CPEVendor == "" || q.CPEProduct == "")) {
		return ComponentQuery{}, fmt.Errorf("%w: component query key is required", shared.ErrValidation)
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 500 {
		q.Limit = 500
	}
	return q, nil
}
