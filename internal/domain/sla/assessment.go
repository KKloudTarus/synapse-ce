package sla

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AssessmentInput binds the pure risk inputs to one tenant-owned finding and to the immutable risk
// assessment that first supplied them, when present. SourceRiskAssessmentID is immutable provenance,
// not a scoring input: ordinary scanner findings have none, and a later intelligence assessment with
// identical SLA-relevant facts must not mint another deadline merely because its source ID changed.
type AssessmentInput struct {
	TenantID               shared.ID `json:"tenant_id"`
	EngagementID           shared.ID `json:"engagement_id"`
	FindingID              shared.ID `json:"finding_id"`
	SourceRiskAssessmentID shared.ID `json:"source_risk_assessment_id,omitempty"`
	Risk                   Inputs    `json:"risk"`
}

// Assessment is an immutable, reproducible SLA decision. A change to material risk input or policy
// creates another assessment linked to PreviousAssessmentID. Replaying the same finding, policy, and
// input hash resolves to the same deterministic ID and the store returns the original row, preserving
// its original due dates instead of moving them forward on every rescan.
type Assessment struct {
	TenantID               shared.ID `json:"tenant_id"`
	ID                     shared.ID `json:"id"`
	EngagementID           shared.ID `json:"engagement_id"`
	FindingID              shared.ID `json:"finding_id"`
	SourceRiskAssessmentID shared.ID `json:"source_risk_assessment_id,omitempty"`
	Inputs                 Inputs    `json:"inputs"`
	Result                 Result    `json:"result"`
	InputHash              string    `json:"input_hash"`
	ConfigHash             string    `json:"config_hash"`
	PreviousAssessmentID   shared.ID `json:"previous_assessment_id,omitempty"`
	AssessedAt             time.Time `json:"assessed_at"`
	CreatedAt              time.Time `json:"created_at"`
}

// AssessmentUpsertResult tells callers whether an immutable assessment was newly created or an
// idempotent replay returned the existing row.
type AssessmentUpsertResult struct {
	Assessment Assessment `json:"assessment"`
	Created    bool       `json:"created"`
}

// Policy is a tenant-owned immutable config version. Activating another policy changes only the
// active pointer; existing assessments retain their exact config version and digest.
type Policy struct {
	TenantID  shared.ID `json:"tenant_id"`
	Config    Config    `json:"config"`
	SHA256    string    `json:"sha256"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// NewPolicy validates and canonicalizes a stored policy version.
func NewPolicy(tenantID shared.ID, cfg Config, createdBy string, now time.Time) (Policy, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	createdBy = strings.TrimSpace(createdBy)
	if tenantID.IsZero() || createdBy == "" || now.IsZero() {
		return Policy{}, fmt.Errorf("%w: sla policy tenant, actor, and time are required", shared.ErrValidation)
	}
	if err := cfg.Validate(); err != nil {
		return Policy{}, err
	}
	digest, err := ConfigDigest(cfg)
	if err != nil {
		return Policy{}, err
	}
	return Policy{TenantID: tenantID, Config: cfg, SHA256: digest, CreatedBy: createdBy, CreatedAt: now.UTC()}, nil
}

// Validate verifies durable policy provenance rather than trusting a stored digest.
func (p Policy) Validate() error {
	if p.TenantID.IsZero() || strings.TrimSpace(p.CreatedBy) == "" || p.CreatedAt.IsZero() {
		return fmt.Errorf("%w: sla policy provenance is incomplete", shared.ErrValidation)
	}
	if err := p.Config.Validate(); err != nil {
		return err
	}
	digest, err := ConfigDigest(p.Config)
	if err != nil {
		return err
	}
	if digest != p.SHA256 {
		return fmt.Errorf("%w: sla policy digest does not match config", shared.ErrValidation)
	}
	return nil
}

// ConfigDigest returns a stable SHA-256 over the declarative config.
func ConfigDigest(cfg Config) (string, error) {
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal sla config: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Evaluate creates a candidate immutable assessment. Stores bind PreviousAssessmentID and preserve
// the original candidate when the deterministic ID already exists.
func Evaluate(input AssessmentInput, cfg Config, now time.Time) (Assessment, error) {
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	if input.TenantID.IsZero() || input.EngagementID.IsZero() || input.FindingID.IsZero() || now.IsZero() {
		return Assessment{}, fmt.Errorf("%w: sla assessment identity and time are required", shared.ErrValidation)
	}
	if err := input.Risk.Validate(); err != nil {
		return Assessment{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Assessment{}, err
	}
	inputHash, err := assessmentInputHash(input)
	if err != nil {
		return Assessment{}, err
	}
	configHash, err := ConfigDigest(cfg)
	if err != nil {
		return Assessment{}, err
	}
	now = now.UTC()
	return Assessment{
		TenantID: input.TenantID, ID: AssessmentID(input.TenantID, input.FindingID, cfg.Version, inputHash),
		EngagementID: input.EngagementID, FindingID: input.FindingID,
		SourceRiskAssessmentID: input.SourceRiskAssessmentID, Inputs: input.Risk,
		Result: Compute(input.Risk, cfg, now), InputHash: inputHash, ConfigHash: configHash,
		AssessedAt: now, CreatedAt: now,
	}, nil
}

// AssessmentID is stable for a material input and policy version. Tenant and finding identity are
// included so identical findings in different security boundaries never share an artifact identity.
func AssessmentID(tenantID, findingID shared.ID, configVersion, inputHash string) shared.ID {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		shared.TenantOrDefault(tenantID).String(), findingID.String(), strings.TrimSpace(configVersion), inputHash,
	}, "\x00")))
	return shared.ID(hex.EncodeToString(digest[:16]))
}

// Validate recomputes every binding used at the persistence and promotion boundaries.
func (a Assessment) Validate() error {
	if a.TenantID.IsZero() || a.ID.IsZero() || a.EngagementID.IsZero() || a.FindingID.IsZero() ||
		a.AssessedAt.IsZero() || a.CreatedAt.IsZero() || len(a.InputHash) != 64 || len(a.ConfigHash) != 64 {
		return fmt.Errorf("%w: sla assessment identity or provenance is incomplete", shared.ErrValidation)
	}
	if err := a.Inputs.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(a.Result.ConfigVersion) == "" || a.Result.ComputedAt.IsZero() ||
		a.Result.MitigateBy.Before(a.Result.ComputedAt) || a.Result.RemediateBy.Before(a.Result.MitigateBy) {
		return fmt.Errorf("%w: sla assessment result is invalid", shared.ErrValidation)
	}
	inputHash, err := assessmentInputHash(AssessmentInput{
		TenantID: a.TenantID, EngagementID: a.EngagementID, FindingID: a.FindingID,
		SourceRiskAssessmentID: a.SourceRiskAssessmentID, Risk: a.Inputs,
	})
	if err != nil {
		return err
	}
	if inputHash != a.InputHash || AssessmentID(a.TenantID, a.FindingID, a.Result.ConfigVersion, inputHash) != a.ID {
		return fmt.Errorf("%w: sla assessment identity does not match inputs", shared.ErrValidation)
	}
	return nil
}

func assessmentInputHash(input AssessmentInput) (string, error) {
	payload := struct {
		TenantID     string `json:"tenant_id"`
		EngagementID string `json:"engagement_id"`
		FindingID    string `json:"finding_id"`
		Risk         Inputs `json:"risk"`
	}{
		TenantID: input.TenantID.String(), EngagementID: input.EngagementID.String(), FindingID: input.FindingID.String(),
		Risk: input.Risk,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal sla assessment input: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
