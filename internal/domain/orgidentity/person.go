// Package orgidentity models protocol-neutral human identity and organization membership.
package orgidentity

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type PersonStatus string

const (
	PersonActive    PersonStatus = "active"
	PersonSuspended PersonStatus = "suspended"
)

func (s PersonStatus) Valid() bool { return s == PersonActive || s == PersonSuspended }

// Person is global human identity. Contact claims deliberately do not live here: email, groups,
// domains and provider display claims are not stable identifiers and may never merge people.
type Person struct {
	ID              shared.ID
	DisplayName     string
	Status          PersonStatus
	CredentialEpoch int64
	Version         int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func NewPerson(id shared.ID, displayName string, now time.Time) (*Person, error) {
	displayName = strings.TrimSpace(displayName)
	if id.IsZero() || displayName == "" || len(displayName) > 200 || now.IsZero() {
		return nil, fmt.Errorf("%w: person id, bounded display name, and timestamp are required", shared.ErrValidation)
	}
	now = now.UTC()
	return &Person{ID: id, DisplayName: displayName, Status: PersonActive, CredentialEpoch: 1, Version: 1, CreatedAt: now, UpdatedAt: now}, nil
}

func (p Person) Valid() error {
	if p.ID.IsZero() || strings.TrimSpace(p.DisplayName) == "" || len(strings.TrimSpace(p.DisplayName)) > 200 || !p.Status.Valid() || p.CredentialEpoch <= 0 || p.Version <= 0 || p.CreatedAt.IsZero() || p.UpdatedAt.Before(p.CreatedAt) {
		return fmt.Errorf("%w: invalid person", shared.ErrValidation)
	}
	return nil
}

func (p *Person) Rename(displayName string, expectedVersion int64, now time.Time) error {
	displayName = strings.TrimSpace(displayName)
	if expectedVersion != p.Version {
		return fmt.Errorf("%w: stale person version", shared.ErrConflict)
	}
	if displayName == "" || len(displayName) > 200 || now.IsZero() {
		return fmt.Errorf("%w: bounded display name and timestamp are required", shared.ErrValidation)
	}
	if displayName == p.DisplayName {
		return nil
	}
	p.DisplayName = displayName
	p.bumpVersion(now)
	return nil
}

// Suspend invalidates every credential for the person across every organization. The epoch is
// bumped in the same transition so reactivation can never resurrect sessions minted beforehand.
func (p *Person) Suspend(expectedVersion int64, now time.Time) error {
	if expectedVersion != p.Version {
		return fmt.Errorf("%w: stale person version", shared.ErrConflict)
	}
	if p.Status == PersonSuspended {
		return nil
	}
	p.Status = PersonSuspended
	p.CredentialEpoch++
	p.bumpVersion(now)
	return nil
}

func (p *Person) Activate(expectedVersion int64, now time.Time) error {
	if expectedVersion != p.Version {
		return fmt.Errorf("%w: stale person version", shared.ErrConflict)
	}
	if p.Status == PersonActive {
		return nil
	}
	p.Status = PersonActive
	// A new active era must not validate credentials from before suspension.
	p.CredentialEpoch++
	p.bumpVersion(now)
	return nil
}

// RevokeCredentials invalidates this person's credentials without changing membership or person
// status, for example after a reported credential compromise.
func (p *Person) RevokeCredentials(expectedVersion int64, now time.Time) error {
	if expectedVersion != p.Version {
		return fmt.Errorf("%w: stale person version", shared.ErrConflict)
	}
	p.CredentialEpoch++
	p.bumpVersion(now)
	return nil
}

func (p *Person) bumpVersion(now time.Time) {
	p.Version++
	p.UpdatedAt = now.UTC()
}
