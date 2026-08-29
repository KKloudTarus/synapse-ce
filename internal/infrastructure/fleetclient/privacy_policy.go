package fleetclient

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const privacyPolicyStateFile = "privacy-policy.json"

// PersistedPrivacyPolicy is the validated active source-redaction policy cached
// independently from bearer credentials and telemetry WAL content.
type PersistedPrivacyPolicy struct {
	AgentID      shared.ID      `json:"agent_id"`
	ControlPlane string         `json:"control_plane"`
	TenantID     shared.ID      `json:"tenant_id"`
	Policy       privacy.Policy `json:"policy"`
	Digest       string         `json:"digest"`
	CreatedBy    string         `json:"created_by"`
	CreatedAt    time.Time      `json:"created_at"`
}

// Assignment converts a validated wire response into the domain assignment used
// at the source-observation boundary.
func (r PrivacyPolicyResponse) AssignmentDomain() (privacy.Assignment, error) {
	dispositions := make(map[privacy.FieldCategory]privacy.FieldDisposition, len(r.Assignment.Policy.Dispositions))
	for category, disposition := range r.Assignment.Policy.Dispositions {
		dispositions[privacy.FieldCategory(category)] = privacy.FieldDisposition(disposition)
	}
	assignment := privacy.Assignment{
		TenantID: shared.ID(strings.TrimSpace(r.Assignment.TenantID)),
		Policy: privacy.Policy{
			Dispositions:  dispositions,
			RedactSecrets: r.Assignment.Policy.RedactSecrets,
			MaxArgLen:     r.Assignment.Policy.MaxArgLen,
			MaxArgCount:   r.Assignment.Policy.MaxArgCount,
			MaxPathLen:    r.Assignment.Policy.MaxPathLen,
			HashSalt:      r.Assignment.Policy.HashSalt,
			Version:       r.Assignment.Policy.Version,
		},
		Digest:    strings.TrimSpace(r.Assignment.Digest),
		CreatedBy: strings.TrimSpace(r.Assignment.CreatedBy),
		CreatedAt: r.Assignment.CreatedAt.UTC(),
	}
	if err := assignment.Validate(); err != nil {
		return privacy.Assignment{}, fmt.Errorf("validate active privacy policy: %w", err)
	}
	return assignment, nil
}

func privacyPolicyStatePath(dir string) string {
	return filepath.Join(dir, privacyPolicyStateFile)
}

func normalizeControlPlaneIdentity(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if err := ValidateControlPlaneURL(raw); err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse control-plane identity: %w", err)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid control-plane identity: credentials, query, and fragment are not allowed")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return "", fmt.Errorf("invalid control-plane identity: host is required")
	}
	host := hostname
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	u.Host = host
	// Capture both decoded and escaped forms before mutating either one. RawPath
	// is valid only as an encoding of Path; evaluating EscapedPath after trimming
	// Path while retaining the old RawPath can resurrect a trailing slash or
	// double-escape encoded bytes.
	path := strings.TrimRight(u.Path, "/")
	escapedPath := strings.TrimRight(u.EscapedPath(), "/")
	u.Path = path
	if path != "" && escapedPath != path {
		if decoded, unescapeErr := url.PathUnescape(escapedPath); unescapeErr == nil && decoded == path {
			u.RawPath = escapedPath
		} else {
			u.RawPath = ""
		}
	} else {
		u.RawPath = ""
	}
	return u.String(), nil
}

// PersistPrivacyPolicy validates and atomically replaces the cached active policy.
func PersistPrivacyPolicy(
	dir string,
	agentID shared.ID,
	controlPlane string,
	assignment privacy.Assignment,
) error {
	agentID = shared.ID(strings.TrimSpace(agentID.String()))
	if agentID.IsZero() {
		return fmt.Errorf("%w: privacy policy cache needs an agent identity", shared.ErrValidation)
	}
	controlPlane, err := normalizeControlPlaneIdentity(controlPlane)
	if err != nil {
		return fmt.Errorf("validate privacy policy cache control plane: %w", err)
	}
	if err := assignment.Validate(); err != nil {
		return fmt.Errorf("validate privacy policy cache: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("privacy policy state dir: %w", err)
	}
	persisted := PersistedPrivacyPolicy{
		AgentID:      agentID,
		ControlPlane: controlPlane,
		TenantID:     assignment.TenantID,
		Policy:       assignment.Policy,
		Digest:       assignment.Digest,
		CreatedBy:    assignment.CreatedBy,
		CreatedAt:    assignment.CreatedAt,
	}
	data, err := json.Marshal(persisted)
	if err != nil {
		return fmt.Errorf("marshal privacy policy cache: %w", err)
	}
	path := privacyPolicyStatePath(dir)
	tmp := path + ".tmp"
	if err := WriteSecret(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write privacy policy cache: %w", err)
	}
	if err := replacePrivacyPolicyFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace privacy policy cache: %w", err)
	}
	return nil
}

// LoadPrivacyPolicy returns only a structurally and cryptographically consistent
// cached policy; malformed or stale-on-disk content fails closed.
func LoadPrivacyPolicy(
	dir string,
	expectedAgentID shared.ID,
	expectedControlPlane string,
) (privacy.Assignment, bool) {
	expectedAgentID = shared.ID(strings.TrimSpace(expectedAgentID.String()))
	if expectedAgentID.IsZero() {
		return privacy.Assignment{}, false
	}
	expectedControlPlane, err := normalizeControlPlaneIdentity(expectedControlPlane)
	if err != nil {
		return privacy.Assignment{}, false
	}
	data, err := os.ReadFile(privacyPolicyStatePath(dir))
	if err != nil {
		return privacy.Assignment{}, false
	}
	var persisted PersistedPrivacyPolicy
	if err := json.Unmarshal(data, &persisted); err != nil {
		return privacy.Assignment{}, false
	}
	persistedAgentID := shared.ID(strings.TrimSpace(persisted.AgentID.String()))
	persistedControlPlane, err := normalizeControlPlaneIdentity(persisted.ControlPlane)
	if err != nil || persistedAgentID != expectedAgentID || persistedControlPlane != expectedControlPlane {
		return privacy.Assignment{}, false
	}
	assignment := privacy.Assignment{
		TenantID:  persisted.TenantID,
		Policy:    persisted.Policy,
		Digest:    persisted.Digest,
		CreatedBy: persisted.CreatedBy,
		CreatedAt: persisted.CreatedAt,
	}
	if err := assignment.Validate(); err != nil {
		return privacy.Assignment{}, false
	}
	return assignment, true
}
