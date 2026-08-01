// Package businessservice defines the durable AppSec management boundary.
package businessservice

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var codePattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// BusinessService is a long-lived, tenant-scoped business capability that aggregates AppSec posture.
type BusinessService struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Code        string
	Owner       string
	Criticality string
	Audit       shared.Audit
}

func New(id, tenantID shared.ID, name, code, owner, criticality string, now time.Time) (*BusinessService, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: business service id is required", shared.ErrValidation)
	}
	name, code, owner, criticality = strings.TrimSpace(name), strings.TrimSpace(code), strings.TrimSpace(owner), strings.TrimSpace(criticality)
	if name == "" || len(name) > 200 || strings.ContainsAny(name, "\r\n\x00") {
		return nil, fmt.Errorf("%w: business service name is required", shared.ErrValidation)
	}
	if !codePattern.MatchString(code) {
		return nil, fmt.Errorf("%w: business service code must be a lowercase hyphenated slug", shared.ErrValidation)
	}
	if len(owner) > 200 || len(criticality) > 100 || strings.ContainsAny(owner+criticality, "\r\n\x00") {
		return nil, fmt.Errorf("%w: invalid business service metadata", shared.ErrValidation)
	}
	return &BusinessService{ID: id, TenantID: tenantID, Name: name, Code: code, Owner: owner, Criticality: criticality, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}, nil
}
