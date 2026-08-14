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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CertFingerprint is the canonical agent certificate fingerprint: the hex SHA-256 of the
// certificate DER. It is the single source of truth shared by the issuing CA (infrastructure) and
// the authentication path (adapter), so the two can never drift.
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// State is the agent lifecycle.
type State string

const (
	StateActive State = "active"
	StateStale  State = "stale" // last seen longer ago than the freshness threshold (computed by fleet coverage)
	// StateRevoked is an OPERATOR decision: the credential is killed with attribution.
	StateRevoked State = "revoked"
	// StateDecommissioned is a terminal state the AGENT reports when it is cleanly uninstalled (#412).
	// It is distinct from Revoked (an operator killed it) and from Stale (it silently stopped reporting):
	// the control plane shows an orderly removal rather than leaving the identity to rot into Stale. A
	// decommissioned agent can no longer authenticate.
	StateDecommissioned State = "decommissioned"
)

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	return s == StateActive || s == StateStale || s == StateRevoked || s == StateDecommissioned
}

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
	// Group is the rollout group an OPERATOR placed this agent in. It is never self-declared: an agent
	// that could name its own group could place itself in one pinned to an older, vulnerable version,
	// turning a rollout control into a downgrade primitive. Empty means the default group.
	Group     string
	TokenHash string
	// Fingerprint is the SHA-256 of the agent's issued client certificate (#408). Empty until a
	// certificate is issued from a CSR; it is the cryptographic identity used by mutual-TLS auth.
	Fingerprint  string
	State        State
	Audit        shared.Audit
	LastSeenAt   time.Time
	RevokedAt    *time.Time
	RevokedBy    shared.ID
	RevokeReason string
	// DecommissionedAt is when the agent self-reported a clean uninstall (#412). Nil unless the agent
	// is in StateDecommissioned. There is no "by": decommission is self-reported, not operator-attributed.
	DecommissionedAt *time.Time
}

// AssignGroup places the agent in a rollout group. Validation lives in the rollout domain, which owns
// what a group name may be; this only records the operator's decision.
func (a *Agent) AssignGroup(group string, now time.Time) {
	a.Group = group
	a.Audit.UpdatedAt = now
}

// AttestCertificate records the SHA-256 fingerprint of the client certificate issued to the agent.
func (a *Agent) AttestCertificate(fingerprint string) { a.Fingerprint = fingerprint }

// Revoke marks the agent revoked with attribution, so its credential no longer authenticates.
func (a *Agent) Revoke(by shared.ID, reason string, now time.Time) {
	a.State = StateRevoked
	a.RevokedBy = by
	a.RevokeReason = reason
	t := now
	a.RevokedAt = &t
	a.Audit.UpdatedAt = now
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

// Decommission marks the agent cleanly removed (self-reported on uninstall, #412). It is a no-op on an
// already-revoked agent — an operator revocation is a stronger, attributed terminal state and must not
// be overwritten by a self-report. Idempotent: decommissioning an already-decommissioned agent only
// refreshes the audit timestamp.
func (a *Agent) Decommission(now time.Time) {
	if a.State == StateRevoked {
		return
	}
	a.State = StateDecommissioned
	t := now
	a.DecommissionedAt = &t
	a.Audit.UpdatedAt = now
}

// Revoked reports whether the agent may no longer act.
func (a *Agent) Revoked() bool { return a.State == StateRevoked }

// Decommissioned reports whether the agent was cleanly removed.
func (a *Agent) Decommissioned() bool { return a.State == StateDecommissioned }

// Removed reports whether the agent's credential may no longer authenticate for any reason — an
// operator revocation or a self-reported decommission. Auth and coverage both fail closed on it.
func (a *Agent) Removed() bool { return a.Revoked() || a.Decommissioned() }

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
