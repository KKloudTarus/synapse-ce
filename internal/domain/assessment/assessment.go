// Package assessment models a durable AppSec assessment beneath one business service.
package assessment

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Status string

const (
	StatusDraft  Status = "draft"
	StatusActive Status = "active"
	StatusClosed Status = "closed"
)

func (s Status) Valid() bool { return s == StatusDraft || s == StatusActive || s == StatusClosed }

type Policy struct {
	Cadence     string `json:"cadence"`
	Release     string `json:"release"`
	Environment string `json:"environment"`
}

func (p Policy) Validate() error {
	if utf8.RuneCountInString(p.Cadence) > 128 || utf8.RuneCountInString(p.Release) > 256 || utf8.RuneCountInString(p.Environment) > 128 {
		return fmt.Errorf("%w: assessment policy exceeds limits", shared.ErrValidation)
	}
	return nil
}

type Assessment struct {
	ID, TenantID, BusinessServiceID shared.ID
	Name, Objective                 string
	Status                          Status
	Policy                          Policy
	Audit                           shared.Audit
}

func New(id, tenant, service shared.ID, name, objective string, policy Policy, now time.Time) (Assessment, error) {
	a := Assessment{ID: id, TenantID: tenant, BusinessServiceID: service, Name: strings.TrimSpace(name), Objective: strings.TrimSpace(objective), Status: StatusDraft, Policy: policy, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
	return a, a.Validate()
}
func (a Assessment) Validate() error {
	if a.ID.IsZero() || a.BusinessServiceID.IsZero() || strings.TrimSpace(a.Name) == "" || utf8.RuneCountInString(a.Name) > 256 || utf8.RuneCountInString(a.Objective) > 4000 || !a.Status.Valid() {
		return fmt.Errorf("%w: invalid assessment", shared.ErrValidation)
	}
	return a.Policy.Validate()
}
