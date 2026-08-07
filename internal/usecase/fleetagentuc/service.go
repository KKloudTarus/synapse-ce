// Package fleetagentuc is the use-case layer for fleet agent identity (#409, epic #405): an
// operator mints a single-use enrolment token; an agent exchanges it for a long-lived bearer
// credential; the API authenticates every subsequent call by that credential. Secret material is
// generated and hashed here; only hashes reach the store, and the plaintext is returned once.
package fleetagentuc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/agenttoken"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ErrUnauthenticated means the presented credential is missing, malformed, unknown, or its secret
// does not match. ErrRevoked means the agent exists but has been revoked. Both are mapped to HTTP
// at the adapter edge (401 / 403).
var (
	ErrUnauthenticated = errors.New("fleetagent: unauthenticated")
	ErrRevoked         = errors.New("fleetagent: agent revoked")
)

// Service is the fleet agent identity use case.
type Service struct {
	store      ports.FleetAgentStore
	audit      ports.AuditLogger
	clock      ports.Clock
	ids        ports.IDGenerator
	ca         ports.CertificateIssuer // optional; enables CSR-based certificate identity (#408)
	workOrders ports.WorkOrderStore    // optional; enables cancelling a revoked agent's in-flight orders
}

// NewService validates its dependencies and returns the service.
func NewService(store ports.FleetAgentStore, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: fleet agent service needs store + audit + clock + ids", shared.ErrValidation)
	}
	return &Service{store: store, audit: audit, clock: clock, ids: ids}, nil
}

// SetCA wires the control-plane certificate issuer, enabling CSR-based certificate identity.
func (s *Service) SetCA(ca ports.CertificateIssuer) { s.ca = ca }

// SetWorkOrders wires the work order store so revoking an agent cancels its in-flight orders.
func (s *Service) SetWorkOrders(store ports.WorkOrderStore) { s.workOrders = store }

// MintEnrolToken issues a single-use enrolment token for tenantID valid for ttl, and returns the
// plaintext once. Only its hash is stored. This is an operator action (RBAC-gated at the adapter).
func (s *Service) MintEnrolToken(ctx context.Context, actor string, tenantID shared.ID, ttl time.Duration) (string, error) {
	if tenantID.IsZero() {
		return "", fmt.Errorf("%w: tenant id is required to mint an enrolment token", shared.ErrValidation)
	}
	now := s.clock.Now()
	token, hash, err := agenttoken.Mint(agenttoken.KindEnrol, tenantID.String(), "")
	if err != nil {
		return "", fmt.Errorf("mint enrol token: %w", err)
	}
	rec, err := fleetagent.NewEnrolToken(hash, tenantID, actor, now.Add(ttl), now)
	if err != nil {
		return "", err
	}
	if err := s.store.CreateEnrolToken(ctx, rec); err != nil {
		return "", fmt.Errorf("mint enrol token: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: "agent.enrol_token_minted", Target: tenantID.String(),
		Metadata: map[string]string{"tenant_id": tenantID.String()}, At: now,
	}); err != nil {
		return "", fmt.Errorf("mint enrol token: audit: %w", err)
	}
	return token, nil
}

// EnrolInput describes the enrolling agent.
type EnrolInput struct {
	Name         string
	Platform     string
	OSVersion    string
	AgentVersion string
	Capabilities []string
	// CSRPEM is an optional PEM certificate signing request. When present and a CA is configured,
	// the control plane issues a client certificate and records its fingerprint; the returned
	// certificate PEM is the agent's cryptographic identity for mutual-TLS auth (#408).
	CSRPEM []byte
}

// Enrol exchanges a valid enrolment token for a new agent identity and returns its bearer
// credential once. The tenant is taken from the enrolment token, never from the caller.
func (s *Service) Enrol(ctx context.Context, enrolToken string, in EnrolInput) (*fleetagent.Agent, string, []byte, error) {
	kind, tenantStr, _, secret, ok := agenttoken.Parse(enrolToken)
	if !ok || kind != agenttoken.KindEnrol {
		return nil, "", nil, ErrUnauthenticated
	}
	now := s.clock.Now()
	tenantID := shared.ID(tenantStr)
	agentID := s.ids.NewID()
	token, hash, err := agenttoken.Mint(agenttoken.KindAgent, tenantID.String(), agentID.String())
	if err != nil {
		return nil, "", nil, fmt.Errorf("enrol: mint agent token: %w", err)
	}

	// Issue the certificate FIRST (before consuming the single-use token or creating the agent) so a
	// malformed/weak CSR is a clean validation error with no side effect: the enrol token is not
	// burned and no orphan agent row is left behind.
	var (
		certPEM     []byte
		fingerprint string
	)
	if len(in.CSRPEM) > 0 && s.ca != nil {
		cp, fp, cerr := s.ca.Issue(in.CSRPEM, agentID.String(), tenantID.String(), now)
		if cerr != nil {
			return nil, "", nil, fmt.Errorf("%w: enrol: invalid certificate signing request: %s", shared.ErrValidation, cerr.Error())
		}
		certPEM, fingerprint = cp, fp
	}

	// Consume the single-use enrol token only after the CSR has been accepted.
	if _, err := s.store.ConsumeEnrolToken(ctx, tenantID, agenttoken.Hash(secret), now); err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, "", nil, ErrUnauthenticated
		}
		return nil, "", nil, fmt.Errorf("enrol: consume token: %w", err)
	}
	agent, err := fleetagent.NewAgent(agentID, tenantID, in.Name, in.Platform, in.OSVersion, in.AgentVersion, in.Capabilities, hash, now)
	if err != nil {
		return nil, "", nil, err
	}
	if fingerprint != "" {
		agent.AttestCertificate(fingerprint) // persisted in the single CreateAgent insert
	}
	if err := s.store.CreateAgent(ctx, agent); err != nil {
		return nil, "", nil, fmt.Errorf("enrol: create agent: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: agentID.String(), Action: "agent.enrolled", Target: agentID.String(),
		Metadata: map[string]string{"tenant_id": tenantID.String(), "name": agent.Name, "platform": agent.Platform},
		At:       now,
	}); err != nil {
		return nil, "", nil, fmt.Errorf("enrol: audit: %w", err)
	}
	if fingerprint != "" {
		if err := s.audit.Record(ctx, ports.AuditEntry{
			Actor: agentID.String(), Action: "agent.certificate_issued", Target: agentID.String(),
			Metadata: map[string]string{"tenant_id": tenantID.String(), "fingerprint": fingerprint}, At: now,
		}); err != nil {
			return nil, "", nil, fmt.Errorf("enrol: audit certificate: %w", err)
		}
	}
	return agent, token, certPEM, nil
}

// AuthenticateCertificate resolves and verifies an agent by its client-certificate identity
// (tenant and agent id read from the verified certificate subject, plus the certificate
// fingerprint). It returns ErrUnauthenticated for an unknown agent, an agent with no certificate,
// or a fingerprint mismatch, and ErrRevoked for a revoked agent. The fingerprint comparison is
// constant time.
func (s *Service) AuthenticateCertificate(ctx context.Context, tenantID, agentID shared.ID, fingerprint string) (*fleetagent.Agent, error) {
	if fingerprint == "" {
		return nil, ErrUnauthenticated
	}
	agent, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, ErrUnauthenticated
		}
		return nil, fmt.Errorf("authenticate certificate: %w", err)
	}
	if agent.Fingerprint == "" || subtle.ConstantTimeCompare([]byte(fingerprint), []byte(agent.Fingerprint)) != 1 {
		return nil, ErrUnauthenticated
	}
	if agent.Revoked() {
		return nil, ErrRevoked
	}
	return agent, nil
}

// Authenticate resolves and verifies an agent bearer credential. It returns ErrUnauthenticated for
// any missing/malformed/unknown credential or secret mismatch, and ErrRevoked for a revoked agent.
func (s *Service) Authenticate(ctx context.Context, token string) (*fleetagent.Agent, error) {
	kind, tenantStr, idStr, secret, ok := agenttoken.Parse(token)
	if !ok || kind != agenttoken.KindAgent {
		return nil, ErrUnauthenticated
	}
	agent, err := s.store.GetAgent(ctx, shared.ID(tenantStr), shared.ID(idStr))
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, ErrUnauthenticated
		}
		return nil, fmt.Errorf("authenticate: %w", err)
	}
	if !agenttoken.Equal(secret, agent.TokenHash) {
		return nil, ErrUnauthenticated
	}
	if agent.Revoked() {
		return nil, ErrRevoked
	}
	return agent, nil
}

// HeartbeatInput carries the liveness-report fields.
type HeartbeatInput struct {
	Platform     string
	OSVersion    string
	AgentVersion string
	Capabilities []string
}

// Heartbeat records liveness and refreshes the agent's reported attributes.
func (s *Service) Heartbeat(ctx context.Context, agent *fleetagent.Agent, in HeartbeatInput) error {
	if err := s.store.Heartbeat(ctx, agent.TenantID, agent.ID, in.Platform, in.OSVersion, in.AgentVersion, in.Capabilities, s.clock.Now()); err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	return nil
}

// Revoke marks an agent revoked (so its bearer token and certificate no longer authenticate) with
// operator attribution and a reason, and cancels the agent's in-flight work orders.
func (s *Service) Revoke(ctx context.Context, actor string, tenantID, id shared.ID, reason string) error {
	now := s.clock.Now()
	if err := s.store.Revoke(ctx, tenantID, id, shared.ID(actor), reason, now); err != nil {
		return fmt.Errorf("revoke agent: %w", err)
	}
	cancelled := 0
	if s.workOrders != nil {
		// Best-effort: a revoked agent must stop, but a failure to cancel its orders should not
		// leave it un-revoked. The orders also expire on their own NotAfter.
		if n, cerr := s.workOrders.CancelForAgent(ctx, tenantID, id, "agent revoked", now); cerr == nil {
			cancelled = n
		}
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: "agent.revoked", Target: id.String(),
		Metadata: map[string]string{"tenant_id": tenantID.String(), "reason": reason, "cancelled_orders": fmt.Sprintf("%d", cancelled)},
		At:       now,
	}); err != nil {
		return fmt.Errorf("revoke agent: audit: %w", err)
	}
	return nil
}

// ListAgents returns the tenant's agents.
func (s *Service) ListAgents(ctx context.Context, tenantID shared.ID) ([]*fleetagent.Agent, error) {
	return s.store.ListAgents(ctx, tenantID)
}
