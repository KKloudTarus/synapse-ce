// Package aitriagereview models the human decision that follows an AI false-positive
// critique which the deterministic gate policy refused to authorize on its own.
package aitriagereview

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// State is the closed lifecycle for an AI-triage review.
type State string

const (
	StatePending  State = "pending"
	StateAccepted State = "accepted" // a human accepts the AI false-positive recommendation
	StateRejected State = "rejected" // a human rejects it; the finding remains in the gate
)

func (s State) Valid() bool {
	switch s {
	case StatePending, StateAccepted, StateRejected:
		return true
	default:
		return false
	}
}

// Decision is the explicit reviewer action.
type Decision string

const (
	DecisionAccept Decision = "accept"
	DecisionReject Decision = "reject"
)

func (d Decision) Valid() bool { return d == DecisionAccept || d == DecisionReject }

// Review is a durable snapshot of the finding, model verdicts, policy decision,
// and evidence link that a human reviewed. Findings remain visible independently.
type Review struct {
	ID                  shared.ID       `json:"id"`
	TenantID            shared.ID       `json:"tenant_id"`
	EngagementID        shared.ID       `json:"engagement_id"`
	ProjectID           shared.ID       `json:"project_id,omitempty"`
	FindingID           shared.ID       `json:"finding_id"`
	DedupKey            string          `json:"dedup_key"`
	Title               string          `json:"title"`
	Severity            shared.Severity `json:"severity"`
	CWE                 string          `json:"cwe,omitempty"`
	Owner               string          `json:"owner,omitempty"`
	State               State           `json:"state"`
	Verdict             string          `json:"verdict"`
	Driver              string          `json:"driver"`
	Confidence          int             `json:"confidence"`
	SuspectedFP         bool            `json:"suspected_fp"`
	ProposerModel       string          `json:"proposer_model"`
	ProposerProvider    string          `json:"proposer_provider"`
	ProposerModelFamily string          `json:"proposer_model_family"`
	VerifierModel       string          `json:"verifier_model,omitempty"`
	VerifierProvider    string          `json:"verifier_provider,omitempty"`
	VerifierModelFamily string          `json:"verifier_model_family,omitempty"`
	IndependencePolicy  string          `json:"independence_policy"`
	PromptVersion       string          `json:"prompt_version"`
	Verified            bool            `json:"verified"`
	VerifierVerdict     string          `json:"verifier_verdict,omitempty"`
	VerifierDriver      string          `json:"verifier_driver,omitempty"`
	VerifierConfidence  int             `json:"verifier_confidence,omitempty"`
	PolicyVersion       string          `json:"policy_version"`
	PolicyReason        string          `json:"policy_reason"`
	Shadow              bool            `json:"shadow"`
	WouldGateExempt     bool            `json:"would_gate_exempt"`
	GateExempt          bool            `json:"gate_exempt"`
	ReviewRequired      bool            `json:"review_required"`
	EvidenceRef         shared.ID       `json:"evidence_ref"`
	DecidedBy           string          `json:"decided_by,omitempty"`
	DecisionRationale   string          `json:"decision_rationale,omitempty"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	DecidedAt           *time.Time      `json:"decided_at,omitempty"`
	Version             int             `json:"version"`
}

// Input contains the immutable snapshot captured when a policy-held critique is queued.
type Input struct {
	ID, TenantID, EngagementID, ProjectID, FindingID, EvidenceRef shared.ID
	DedupKey, Title, CWE                                          string
	Severity                                                      shared.Severity
	Verdict, Driver, ProposerModel, ProposerProvider              string
	ProposerModelFamily, VerifierModel, VerifierProvider          string
	VerifierModelFamily, IndependencePolicy, PromptVersion        string
	Confidence                                                    int
	SuspectedFP, Verified                                         bool
	VerifierVerdict, VerifierDriver                               string
	VerifierConfidence                                            int
	PolicyVersion, PolicyReason                                   string
	Shadow, WouldGateExempt, GateExempt, ReviewRequired           bool
}

// NewPending validates and creates one pending review snapshot.
func NewPending(in Input, now time.Time) (Review, error) {
	r := Review{
		ID: in.ID, TenantID: in.TenantID, EngagementID: in.EngagementID, ProjectID: in.ProjectID,
		FindingID: in.FindingID, DedupKey: strings.TrimSpace(in.DedupKey), Title: strings.TrimSpace(in.Title),
		Severity: in.Severity, CWE: strings.TrimSpace(in.CWE),
		State: StatePending, Verdict: in.Verdict, Driver: in.Driver, Confidence: in.Confidence,
		SuspectedFP: in.SuspectedFP, ProposerModel: strings.TrimSpace(in.ProposerModel),
		ProposerProvider: strings.TrimSpace(in.ProposerProvider), ProposerModelFamily: strings.TrimSpace(in.ProposerModelFamily),
		VerifierModel: strings.TrimSpace(in.VerifierModel), VerifierProvider: strings.TrimSpace(in.VerifierProvider),
		VerifierModelFamily: strings.TrimSpace(in.VerifierModelFamily), IndependencePolicy: strings.TrimSpace(in.IndependencePolicy),
		PromptVersion: strings.TrimSpace(in.PromptVersion), Verified: in.Verified,
		VerifierVerdict: in.VerifierVerdict, VerifierDriver: in.VerifierDriver,
		VerifierConfidence: in.VerifierConfidence, PolicyVersion: strings.TrimSpace(in.PolicyVersion),
		PolicyReason: strings.TrimSpace(in.PolicyReason), Shadow: in.Shadow, WouldGateExempt: in.WouldGateExempt, GateExempt: in.GateExempt,
		ReviewRequired: in.ReviewRequired, EvidenceRef: in.EvidenceRef,
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	if r.ID.IsZero() || r.TenantID.IsZero() || r.EngagementID.IsZero() || r.FindingID.IsZero() || r.EvidenceRef.IsZero() {
		return Review{}, fmt.Errorf("%w: AI-triage review requires id, tenant, engagement, finding, and evidence", shared.ErrValidation)
	}
	if r.DedupKey == "" || r.Title == "" || !r.Severity.Valid() {
		return Review{}, fmt.Errorf("%w: AI-triage review requires finding identity, title, and severity", shared.ErrValidation)
	}
	if !r.ReviewRequired || r.GateExempt {
		return Review{}, fmt.Errorf("%w: only policy-held, non-exempt critiques enter human review", shared.ErrValidation)
	}
	if r.ProposerModel == "" || r.PromptVersion == "" || r.PolicyVersion == "" || r.PolicyReason == "" || now.IsZero() {
		return Review{}, fmt.Errorf("%w: AI-triage review requires model, prompt, policy, reason, and timestamp", shared.ErrValidation)
	}
	if requiresIndependentModelMetadata(r.PolicyVersion) && (r.ProposerProvider == "" || r.ProposerModelFamily == "" || r.IndependencePolicy == "") {
		return Review{}, fmt.Errorf("%w: independence-aware AI policy requires provider/model-family identity and independence policy", shared.ErrValidation)
	}
	if requiresIndependentModelMetadata(r.PolicyVersion) {
		if r.VerifierModel == "" {
			if r.VerifierProvider != "" || r.VerifierModelFamily != "" {
				return Review{}, fmt.Errorf("%w: verifier metadata requires a verifier model", shared.ErrValidation)
			}
		} else if r.VerifierProvider == "" || r.VerifierModelFamily == "" {
			return Review{}, fmt.Errorf("%w: verifier model requires provider and family metadata", shared.ErrValidation)
		}
	}
	if r.Confidence < 0 || r.Confidence > 100 || r.VerifierConfidence < 0 || r.VerifierConfidence > 100 || (r.WouldGateExempt && !r.Shadow) {
		return Review{}, fmt.Errorf("%w: invalid AI-triage confidence or rollout metadata", shared.ErrValidation)
	}
	return r, nil
}

// Only explicitly historical policies are exempt. Unknown/future policy versions therefore inherit the
// strongest separation-of-duties metadata requirement instead of failing open when a new version lands.
func requiresIndependentModelMetadata(policyVersion string) bool {
	switch strings.TrimSpace(policyVersion) {
	case "fp-gate-v1", "fp-gate-v2", "fp-gate-v3":
		return false
	default:
		return true
	}
}

// Decide transitions a pending review and enforces rationale, optimistic concurrency,
// attribution, and defense-in-depth separation of duties.
func (r Review) Decide(decision Decision, actor, rationale string, expectedVersion int, now time.Time) (Review, error) {
	if r.State != StatePending {
		return Review{}, fmt.Errorf("%w: AI-triage review is already %s", shared.ErrConflict, r.State)
	}
	if r.Version != expectedVersion {
		return Review{}, fmt.Errorf("%w: AI-triage review version mismatch", shared.ErrConflict)
	}
	if !decision.Valid() {
		return Review{}, fmt.Errorf("%w: unknown AI-triage review decision %q", shared.ErrValidation, decision)
	}
	actor = strings.TrimSpace(actor)
	rationale = strings.TrimSpace(rationale)
	if actor == "" || machineActor(actor) || sameIdentity(actor, r.ProposerModel) || sameIdentity(actor, r.VerifierModel) {
		return Review{}, fmt.Errorf("%w: an AI or machine principal cannot decide its own triage review", shared.ErrValidation)
	}
	if r.Owner == "" || !strings.EqualFold(actor, r.Owner) {
		return Review{}, fmt.Errorf("%w: AI-triage review must be decided by its assigned owner", shared.ErrConflict)
	}
	if len([]rune(rationale)) < 3 || len([]rune(rationale)) > 4000 {
		return Review{}, fmt.Errorf("%w: rationale must contain 3 to 4000 characters", shared.ErrValidation)
	}
	for _, ch := range rationale {
		if ch < 32 && ch != '\n' && ch != '\t' {
			return Review{}, fmt.Errorf("%w: rationale contains invalid control characters", shared.ErrValidation)
		}
	}
	if now.IsZero() {
		return Review{}, fmt.Errorf("%w: decision timestamp is required", shared.ErrValidation)
	}
	if decision == DecisionAccept {
		r.State = StateAccepted
	} else {
		r.State = StateRejected
	}
	r.DecidedBy, r.DecisionRationale = actor, rationale
	r.DecidedAt, r.UpdatedAt = &now, now
	r.Version++
	return r, nil
}

// Claim assigns a pending review to the authenticated human reviewer.
func (r Review) Claim(actor string, expectedVersion int, now time.Time) (Review, error) {
	if r.State != StatePending || r.Version != expectedVersion {
		return Review{}, fmt.Errorf("%w: AI-triage review changed", shared.ErrConflict)
	}
	actor = strings.TrimSpace(actor)
	if actor == "" || machineActor(actor) || sameIdentity(actor, r.ProposerModel) || sameIdentity(actor, r.VerifierModel) {
		return Review{}, fmt.Errorf("%w: an AI or machine principal cannot own its triage review", shared.ErrValidation)
	}
	if now.IsZero() {
		return Review{}, fmt.Errorf("%w: claim timestamp is required", shared.ErrValidation)
	}
	if r.Owner != "" {
		return Review{}, fmt.Errorf("%w: AI-triage review is already owned by %s", shared.ErrConflict, r.Owner)
	}
	r.Owner, r.UpdatedAt = actor, now
	r.Version++
	return r, nil
}

// machineActor reports whether actor is a non-human principal.
//
// This is the SECOND line: RBAC is the first, and machine roles are granted nothing on the human REST
// API (user.rolePermissions), so a machine cannot reach Decide over HTTP at all. This exists for the
// in-process callers that do not pass through that gate.
//
// It must therefore cover the prefixes this codebase actually mints, and "system:" is the largest family
// of them -- system:dast-engine, system:dast-verifier, system:taint-scan, system:cross-check,
// system:callgraph-engine and more are all reserved capability identities. Omitting it left the widest
// class of machine principal able to decide a human review, which is exactly what this check exists to
// prevent.
//
// A prefix DENYLIST fails open on the next identity scheme somebody invents. The durable fix is to
// invert it -- require an actor to be a known human principal -- but that needs a definition of human
// identity that this package does not own, so it is left as a follow-up rather than guessed at here.
func machineActor(actor string) bool {
	a := strings.ToLower(strings.TrimSpace(actor))
	for _, prefix := range []string{"agent:", "llm:", "mcp:", "system:", "machine:", "bot:", "service:"} {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

func sameIdentity(actor, model string) bool {
	a, m := strings.TrimSpace(actor), strings.TrimSpace(model)
	return m != "" && (strings.EqualFold(a, m) || strings.EqualFold(strings.TrimPrefix(strings.ToLower(a), "llm:"), strings.ToLower(m)))
}
