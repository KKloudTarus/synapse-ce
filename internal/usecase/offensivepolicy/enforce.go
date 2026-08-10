// Package offensivepolicy enforces the offensive governance policy
// (docs/redteam/offensive-policy.md, issue #418) before an offensive action is admitted.
//
// It sits in FRONT of safety.Gate rather than replacing it. The gate already enforces engagement scope,
// the authorization window and human approval; this package answers the question those three do not:
// of the actions inside scope and inside the window, which are permitted at all, and under whose
// signature.
//
// Every refusal path returns shared.ErrForbidden and is audited. Every permission is sealed into the
// hash-chained evidence for the action BEFORE it may run, because the document requires approval to be
// evidence rather than configuration: a stored flag saying "approved" is not an approval.
package offensivepolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// EvidenceKindAuthorization is the evidence kind for a sealed offensive authorization. Exported so the
// adapter that implements EvidenceSealer seals under the same kind this package documents.
const EvidenceKindAuthorization = "offensive_authorization"

// machinePrefixes are the identity families this codebase mints for non-human principals. A machine may
// propose an offensive plan; it may never satisfy an approval requirement (document 4).
//
// This mirrors aitriagereview.machineActor deliberately rather than importing it: that check governs a
// different decision, and a shared helper would couple two policies that should be free to diverge. The
// list is the same because the identity scheme is.
var machinePrefixes = []string{"agent:", "llm:", "mcp:", "system:", "machine:", "bot:", "service:"}

// Approval is one recorded human signature for a specific technique, target and window.
type Approval struct {
	Approver  string
	Technique string
	Target    string
	At        time.Time
}

// RulesOfEngagement is the set of engagement fields document 5 requires before ANY offensive action is
// permitted. A missing field is a refusal, not a default.
type RulesOfEngagement struct {
	AuthorizedScope   []string
	WindowStart       time.Time
	WindowEnd         time.Time
	CustomerContact   string
	EmergencyContact  string
	RiskCeiling       offensivepolicy.RiskClass
	ExcludedAssets    []string
	ExclusionsChecked bool
}

// missingFields lists the required fields that are absent, in a deterministic order so a refusal message
// is reproducible.
//
// ExcludedAssets may legitimately be empty — an engagement can exclude nothing — but the operator must
// have CONSIDERED it. ExclusionsChecked distinguishes "nothing excluded" from "nobody looked", which an
// empty slice cannot.
func (r RulesOfEngagement) missingFields() []string {
	var missing []string
	if len(r.AuthorizedScope) == 0 {
		missing = append(missing, "authorized_scope")
	}
	if r.WindowStart.IsZero() || r.WindowEnd.IsZero() || !r.WindowEnd.After(r.WindowStart) {
		missing = append(missing, "authorization_window")
	}
	if strings.TrimSpace(r.CustomerContact) == "" {
		missing = append(missing, "customer_contact")
	}
	if strings.TrimSpace(r.EmergencyContact) == "" {
		missing = append(missing, "emergency_contact")
	}
	if !r.RiskCeiling.Valid() {
		missing = append(missing, "risk_ceiling")
	}
	if !r.ExclusionsChecked {
		missing = append(missing, "excluded_assets_reviewed")
	}
	sort.Strings(missing)
	return missing
}

// Request is one offensive action seeking authorization.
type Request struct {
	EngagementID shared.ID
	Technique    string
	Target       string
	Actor        string
	RoE          RulesOfEngagement
	Approvals    []Approval
	Now          time.Time
}

// Decision is the sealed record of a granted authorization. It exists only when Authorize returned no
// error: there is no "denied" Decision, because a refusal is an error and cannot be mistaken for a
// permission by a caller that forgets to check.
type Decision struct {
	Technique    string
	Target       string
	RiskClass    offensivepolicy.RiskClass
	Approval     offensivepolicy.ApprovalMode
	BlastRadius  offensivepolicy.Radius
	Approvers    []string
	EvidenceID   shared.ID
	AuthorizedAt time.Time
}

// sealedAuthorization is the evidence payload. It carries exactly what document 4 requires: the
// approving humans, the technique, the target, the window and the timestamp.
type sealedAuthorization struct {
	Technique      string    `json:"technique"`
	Target         string    `json:"target"`
	RiskClass      string    `json:"risk_class"`
	Approval       string    `json:"approval_mode"`
	BlastRadius    string    `json:"blast_radius"`
	Approvers      []string  `json:"approvers"`
	WindowStart    time.Time `json:"window_start"`
	WindowEnd      time.Time `json:"window_end"`
	AuthorizedAt   time.Time `json:"authorized_at"`
	Actor          string    `json:"actor"`
	PolicyReviewed bool      `json:"policy_legal_review_recorded"`
}

// EvidenceSealer is the narrow consumer-side interface this package needs: seal a payload and tell me
// the id it was sealed under.
type EvidenceSealer interface {
	SealOffensiveAuthorization(ctx context.Context, engagementID shared.ID, content []byte, createdBy string) (shared.ID, error)
}

// Service enforces the policy. All dependencies are required: a policy that cannot audit or cannot seal
// is not enforcing anything it can prove afterwards.
type Service struct {
	register *offensivepolicy.Register
	evidence EvidenceSealer
	audit    ports.AuditLogger
}

// NewService validates its dependencies.
func NewService(register *offensivepolicy.Register, ev EvidenceSealer, audit ports.AuditLogger) (*Service, error) {
	if register == nil || ev == nil || audit == nil {
		return nil, fmt.Errorf("%w: offensive policy service requires a register, evidence and audit", shared.ErrValidation)
	}
	return &Service{register: register, evidence: ev, audit: audit}, nil
}

// Authorize decides whether one offensive action may run.
//
// Order matters and is deliberate: the cheapest, most absolute refusals come first so that a prohibited
// technique is never evaluated against an engagement's configuration. Nothing about an engagement can
// make a prohibited technique permissible, so asking about approvals first would imply otherwise.
func (s *Service) Authorize(ctx context.Context, req Request) (Decision, error) {
	if s == nil {
		return Decision{}, fmt.Errorf("%w: offensive policy service is not configured", shared.ErrForbidden)
	}
	technique := strings.TrimSpace(req.Technique)
	target := strings.TrimSpace(req.Target)

	// 1. Register lookup. Absent means refused: the register is an allowlist.
	policy, ok := s.register.Lookup(technique)
	if !ok {
		return s.refuse(ctx, req, "no_register_entry",
			fmt.Errorf("%w: technique %q has no offensive policy entry", shared.ErrForbidden, technique))
	}
	// 2. Prohibited categories. No scope, window, approval or seniority changes this.
	if policy.RiskClass == offensivepolicy.RiskProhibited {
		return s.refuse(ctx, req, "prohibited_category",
			fmt.Errorf("%w: technique %q is in a prohibited category", shared.ErrForbidden, technique))
	}
	if target == "" {
		return s.refuse(ctx, req, "no_target",
			fmt.Errorf("%w: offensive action has no target", shared.ErrForbidden))
	}
	// 3. Rules of engagement. A missing field is a refusal.
	if missing := req.RoE.missingFields(); len(missing) > 0 {
		return s.refuse(ctx, req, "missing_roe",
			fmt.Errorf("%w: engagement is missing required rules of engagement: %s", shared.ErrForbidden, strings.Join(missing, ", ")))
	}
	// 4. Window. Outside it, nothing runs.
	now := req.Now
	if now.IsZero() {
		return s.refuse(ctx, req, "no_timestamp",
			fmt.Errorf("%w: offensive authorization needs a decision timestamp", shared.ErrForbidden))
	}
	if now.Before(req.RoE.WindowStart) || now.After(req.RoE.WindowEnd) {
		return s.refuse(ctx, req, "outside_window",
			fmt.Errorf("%w: %s is outside the authorization window", shared.ErrForbidden, now.UTC().Format(time.RFC3339)))
	}
	// 5. The engagement's ceiling narrows the register; it never widens it.
	if !offensivepolicy.RiskCeilingPermits(req.RoE.RiskCeiling, policy.RiskClass) {
		return s.refuse(ctx, req, "above_risk_ceiling",
			fmt.Errorf("%w: technique %q is class %q, above the engagement ceiling %q",
				shared.ErrForbidden, technique, policy.RiskClass, req.RoE.RiskCeiling))
	}
	// 6. Approvals: enough of them, distinct, human, and about THIS technique and target.
	approvers, err := s.validApprovers(policy, technique, target, req)
	if err != nil {
		return s.refuse(ctx, req, "approval_missing", err)
	}
	// 7. Seal BEFORE returning a permission. If the authorization cannot be recorded, it is not granted:
	// the document requires approval to be evidence, and evidence that failed to seal is not evidence.
	payload, err := json.Marshal(sealedAuthorization{
		Technique: technique, Target: target, RiskClass: string(policy.RiskClass),
		Approval: string(policy.Approval), BlastRadius: string(policy.BlastRadius),
		Approvers: approvers, WindowStart: req.RoE.WindowStart.UTC(), WindowEnd: req.RoE.WindowEnd.UTC(),
		AuthorizedAt: now.UTC(), Actor: req.Actor,
		PolicyReviewed: s.register.LegalReview.Reviewed,
	})
	if err != nil {
		return Decision{}, fmt.Errorf("marshal offensive authorization: %w", err)
	}
	evidenceID, err := s.evidence.SealOffensiveAuthorization(ctx, req.EngagementID, payload, req.Actor)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: offensive authorization could not be sealed as evidence: %v", shared.ErrForbidden, err)
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: req.Actor, Action: "offensive.authorized", Target: target, At: now.UTC(),
		Metadata: map[string]string{
			"technique": technique, "risk_class": string(policy.RiskClass),
			"approval": string(policy.Approval), "approvers": strings.Join(approvers, ","),
			"evidence_id": evidenceID.String(),
		},
	})
	return Decision{
		Technique: technique, Target: target, RiskClass: policy.RiskClass, Approval: policy.Approval,
		BlastRadius: policy.BlastRadius, Approvers: approvers, EvidenceID: evidenceID, AuthorizedAt: now.UTC(),
	}, nil
}

// validApprovers returns the distinct human approvers that cover this technique and target, or an error
// naming what is missing.
func (s *Service) validApprovers(policy offensivepolicy.TechniquePolicy, technique, target string, req Request) ([]string, error) {
	need := policy.Approval.RequiredApprovals()
	if need == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	var approvers []string
	for _, a := range req.Approvals {
		who := strings.TrimSpace(a.Approver)
		if who == "" || isMachine(who) {
			continue
		}
		// An approval is for a specific technique and target. A signature collected for something else
		// is not a signature for this.
		if strings.TrimSpace(a.Technique) != technique || strings.TrimSpace(a.Target) != target {
			continue
		}
		key := strings.ToLower(who)
		if _, dup := seen[key]; dup {
			continue // dual approval means two DISTINCT humans, not one human twice
		}
		seen[key] = struct{}{}
		approvers = append(approvers, who)
	}
	if len(approvers) < need {
		return nil, fmt.Errorf("%w: technique %q needs %d distinct human approval(s) for this target, have %d",
			shared.ErrForbidden, technique, need, len(approvers))
	}
	sort.Strings(approvers)
	return approvers[:need], nil
}

// refuse audits the refusal and returns the error. A refusal that is not recorded cannot be explained
// afterwards, which is the whole point of the chain of custody this policy claims.
func (s *Service) refuse(ctx context.Context, req Request, reason string, err error) (Decision, error) {
	at := req.Now
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: req.Actor, Action: "offensive.refused", Target: strings.TrimSpace(req.Target), At: at.UTC(),
		Metadata: map[string]string{"technique": strings.TrimSpace(req.Technique), "reason": reason},
	})
	return Decision{}, err
}

func isMachine(actor string) bool {
	a := strings.ToLower(strings.TrimSpace(actor))
	for _, prefix := range machinePrefixes {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}
