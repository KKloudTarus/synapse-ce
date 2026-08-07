// Package fleetagent is the epic-#405 fleet agent identity model: an enrolled, addressable agent
// and the single-use enrolment token that mints it. It is pure domain (imports only shared and the
// stdlib). Secret material (the enrolment token and the agent bearer credential) is never stored in
// the clear here; the domain carries only hashes, and the plaintext is returned to the caller once
// at creation time and never persisted.
//
// This is the minimal, token-based identity that the agent-facing API (#409) requires. Mutual TLS
// with per-agent client certificates is the hardening tracked under #408; this model is built so a
// certificate fingerprint can replace the bearer-token hash without changing the lifecycle.
package fleetagent

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// State is the agent lifecycle.
type State string

const (
	StateActive  State = "active"
	StateRevoked State = "revoked"
)

// Valid reports whether s is a known state.
func (s State) Valid() bool { return s == StateActive || s == StateRevoked }

// Agent is an enrolled fleet agent. TokenHash is the hash of the bearer credential presented on
// every call; the plaintext is shown once at enrolment and never stored.
type Agent struct {
	ID           shared.ID
	TenantID     shared.ID
	Name         string
	Platform     string
	OSVersion    string
	AgentVersion string
	Capabilities []string
	TokenHash    string
	State        State
	Audit        shared.Audit
	LastSeenAt   time.Time
}

// NewAgent validates and constructs an active agent. tokenHash must be the (non-empty) hash of the
// generated bearer credential; the plaintext is never passed to the domain.
func NewAgent(id, tenantID shared.ID, name, platform, osVersion, agentVersion string, capabilities []string, tokenHash string, now time.Time) (*Agent, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: agent id is required", shared.ErrValidation)
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: agent tenant id is required (empty tenant is DENY under RLS)", shared.ErrValidation)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%w: agent name is required", shared.ErrValidation)
	}
	if strings.TrimSpace(tokenHash) == "" {
		return nil, fmt.Errorf("%w: agent token hash is required", shared.ErrValidation)
	}
	return &Agent{
		ID:           id,
		TenantID:     tenantID,
		Name:         name,
		Platform:     strings.TrimSpace(platform),
		OSVersion:    strings.TrimSpace(osVersion),
		AgentVersion: strings.TrimSpace(agentVersion),
		Capabilities: dedupeCaps(capabilities),
		TokenHash:    tokenHash,
		State:        StateActive,
		Audit:        shared.Audit{CreatedAt: now, UpdatedAt: now},
		LastSeenAt:   now,
	}, nil
}

// Revoked reports whether the agent may no longer act.
func (a *Agent) Revoked() bool { return a.State == StateRevoked }

// EnrolToken is a single-use, tenant-scoped, expiring token an operator issues so an agent can
// enrol once. Only its hash is stored.
type EnrolToken struct {
	Hash      string
	TenantID  shared.ID
	IssuedBy  string
	ExpiresAt time.Time
	UsedAt    time.Time // zero until consumed
	CreatedAt time.Time
}

// NewEnrolToken validates and constructs an enrolment token record from the token's hash.
func NewEnrolToken(hash string, tenantID shared.ID, issuedBy string, expiresAt, now time.Time) (*EnrolToken, error) {
	if strings.TrimSpace(hash) == "" {
		return nil, fmt.Errorf("%w: enrol token hash is required", shared.ErrValidation)
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: enrol token tenant id is required (empty tenant is DENY under RLS)", shared.ErrValidation)
	}
	if !expiresAt.After(now) {
		return nil, fmt.Errorf("%w: enrol token expiry must be in the future", shared.ErrValidation)
	}
	return &EnrolToken{Hash: hash, TenantID: tenantID, IssuedBy: strings.TrimSpace(issuedBy), ExpiresAt: expiresAt, CreatedAt: now}, nil
}

// Usable reports whether the token can still be consumed at now (not used, not expired).
func (t *EnrolToken) Usable(now time.Time) bool {
	return t.UsedAt.IsZero() && t.ExpiresAt.After(now)
}

func dedupeCaps(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}
