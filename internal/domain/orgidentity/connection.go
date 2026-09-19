package orgidentity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Protocol string

const ProtocolOIDC Protocol = "oidc"

func (p Protocol) Valid() bool { return p == ProtocolOIDC }

type RevisionTestStatus string

const (
	RevisionUntested RevisionTestStatus = "untested"
	RevisionPassed   RevisionTestStatus = "passed"
	RevisionFailed   RevisionTestStatus = "failed"
)

func (s RevisionTestStatus) Valid() bool {
	return s == RevisionUntested || s == RevisionPassed || s == RevisionFailed
}

// Connection is the stable trust-boundary identity. Routine metadata/secret/key rotation happens
// through immutable revisions and does not change ID or revoke existing sessions. A changed issuer
// or equivalent trust identifier is a NEW Connection and requires explicit additive linking.
type Connection struct {
	TenantID       shared.ID
	ID             shared.ID
	Protocol       Protocol
	TrustIdentifier string
	Enabled        bool
	ActiveRevision int64
	ConnectionEpoch int64
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func NewConnection(tenantID, id shared.ID, protocol Protocol, trustIdentifier string, now time.Time) (*Connection, error) {
	trustIdentifier = strings.TrimSpace(trustIdentifier)
	if tenantID.IsZero() || id.IsZero() || !protocol.Valid() || trustIdentifier == "" || len(trustIdentifier) > 2048 || now.IsZero() {
		return nil, fmt.Errorf("%w: tenant, connection, protocol, bounded trust identifier, and timestamp are required", shared.ErrValidation)
	}
	now = now.UTC()
	return &Connection{TenantID: tenantID, ID: id, Protocol: protocol, TrustIdentifier: trustIdentifier, Enabled: true, ConnectionEpoch: 1, Version: 1, CreatedAt: now, UpdatedAt: now}, nil
}

func (c Connection) Valid() error {
	if c.TenantID.IsZero() || c.ID.IsZero() || !c.Protocol.Valid() || strings.TrimSpace(c.TrustIdentifier) == "" || len(c.TrustIdentifier) > 2048 || c.ActiveRevision < 0 || c.ConnectionEpoch <= 0 || c.Version <= 0 || c.CreatedAt.IsZero() || c.UpdatedAt.Before(c.CreatedAt) {
		return fmt.Errorf("%w: invalid SSO connection", shared.ErrValidation)
	}
	return nil
}

func (c *Connection) ActivateRevision(revision int64, passed bool, expectedVersion int64, now time.Time) error {
	if expectedVersion != c.Version {
		return fmt.Errorf("%w: stale connection version", shared.ErrConflict)
	}
	if revision <= 0 || !passed || now.IsZero() {
		return fmt.Errorf("%w: only a positive tested revision may be activated", shared.ErrValidation)
	}
	if c.ActiveRevision == revision {
		return nil
	}
	// Routine revision activation intentionally does NOT bump ConnectionEpoch: existing sessions are
	// tied to the stable connection, while transactions pin their assertion revision separately.
	c.ActiveRevision = revision
	c.Version++
	c.UpdatedAt = now.UTC()
	return nil
}

func (c *Connection) SetEnabled(enabled bool, expectedVersion int64, now time.Time) error {
	if expectedVersion != c.Version {
		return fmt.Errorf("%w: stale connection version", shared.ErrConflict)
	}
	if now.IsZero() {
		return fmt.Errorf("%w: timestamp is required", shared.ErrValidation)
	}
	if c.Enabled == enabled {
		return nil
	}
	c.Enabled = enabled
	// Both disable and re-enable start a fresh connection authority era so pre-disable sessions can
	// never become usable again merely because the connection was later enabled.
	c.ConnectionEpoch++
	c.Version++
	c.UpdatedAt = now.UTC()
	return nil
}

// ConnectionRevision is immutable once created. Configuration remains protocol-neutral JSON at the
// domain boundary; provider SDK types stay in adapters. Secrets are referenced, never embedded.
type ConnectionRevision struct {
	TenantID            shared.ID
	ConnectionID        shared.ID
	Revision            int64
	Protocol            Protocol
	Configuration       json.RawMessage
	EncryptedSecretRef  string
	TestStatus          RevisionTestStatus
	TestResult          json.RawMessage
	CreatedBy           string
	CreatedAt           time.Time
	TestedAt            *time.Time
}

func NewConnectionRevision(tenantID, connectionID shared.ID, revision int64, protocol Protocol, configuration json.RawMessage, encryptedSecretRef, createdBy string, now time.Time) (*ConnectionRevision, error) {
	createdBy = strings.TrimSpace(createdBy)
	encryptedSecretRef = strings.TrimSpace(encryptedSecretRef)
	configuration = append(json.RawMessage(nil), configuration...)
	if tenantID.IsZero() || connectionID.IsZero() || revision <= 0 || !protocol.Valid() || createdBy == "" || len(createdBy) > 256 || len(encryptedSecretRef) > 2048 || now.IsZero() {
		return nil, fmt.Errorf("%w: invalid connection revision identity", shared.ErrValidation)
	}
	if err := boundedJSONObject(configuration, 32768); err != nil {
		return nil, fmt.Errorf("%w: connection configuration: %v", shared.ErrValidation, err)
	}
	now = now.UTC()
	return &ConnectionRevision{TenantID: tenantID, ConnectionID: connectionID, Revision: revision, Protocol: protocol, Configuration: configuration, EncryptedSecretRef: encryptedSecretRef, TestStatus: RevisionUntested, TestResult: json.RawMessage(`{}`), CreatedBy: createdBy, CreatedAt: now}, nil
}

// WithTestResult returns a new immutable revision value rather than mutating persisted evidence.
// Callers publish the returned value as a distinct row/revision in D7; this helper exists to keep
// validation of bounded result evidence in the domain.
func (r ConnectionRevision) WithTestResult(status RevisionTestStatus, result json.RawMessage, at time.Time) (ConnectionRevision, error) {
	if status != RevisionPassed && status != RevisionFailed || at.IsZero() || at.Before(r.CreatedAt) {
		return ConnectionRevision{}, fmt.Errorf("%w: tested revision needs passed/failed status and valid timestamp", shared.ErrValidation)
	}
	result = append(json.RawMessage(nil), result...)
	if err := boundedJSONObject(result, 16384); err != nil {
		return ConnectionRevision{}, fmt.Errorf("%w: revision test result: %v", shared.ErrValidation, err)
	}
	out := r
	out.TestStatus = status
	out.TestResult = result
	testedAt := at.UTC()
	out.TestedAt = &testedAt
	return out, nil
}

func boundedJSONObject(raw json.RawMessage, max int) error {
	if len(raw) == 0 || len(raw) > max || !json.Valid(raw) {
		return fmt.Errorf("JSON object is required and must be at most %d bytes", max)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return fmt.Errorf("JSON object is required")
	}
	return nil
}
