// Package promotion defines deterministic cross-pillar finding-priority rules.
package promotion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Rule is one stable, documented promotion policy.
type Rule struct {
	Key        string
	Inputs     string
	Effect     judgment.PromotionChange
	Confidence string
	Reversal   string
}

// Rules returns immutable, local catalogue values in key order.
func Rules() []Rule {
	catalogue := []struct {
		key        string
		inputs     string
		confidence string
		reversal   string
	}{
		{judgment.RuleCorroboratingSignalLoss, "prior applied escalation plus lost or superseded corroborating input", "deterministic signal loss", "restores the prior escalation's before priority"},
		{judgment.RuleDeterministicUnreachable, "publishable deterministic not-reachable judgment", "deterministic proof", "a later reachable proof is reevaluated"},
		{judgment.RuleRuntimeReachableExposed, "publishable reachable judgment, confident internet-exposure path, active detection on a path asset", "all inputs confirmed or observed", "signal loss proposes de-escalation"},
		{judgment.RuleUncertainCorroboration, "plausible runtime corroboration with inferred path or unknown reachability", "uncertain", "reevaluated when inputs become certain"},
	}
	out := make([]Rule, 0, len(catalogue))
	for _, entry := range catalogue {
		effect, ok := judgment.ExpectedEffect(entry.key)
		if !ok {
			continue
		}
		out = append(out, Rule{Key: entry.key, Inputs: entry.inputs, Effect: effect, Confidence: entry.confidence, Reversal: entry.reversal})
	}
	return out
}

// Signal is a typed promotion input record.
type Signal struct {
	Kind       judgment.PromotionInputKind
	ID         shared.ID
	EvidenceID shared.ID
}

// PriorEscalation is the latest applied escalation that may need reversal.
type PriorEscalation struct {
	EventID        shared.ID
	BeforePriority int
	InputsActive   bool
	// InputsMatch reports that the current deterministic escalation evidence
	// exactly matches this applied escalation. Matching evidence is already
	// reflected in priority and must not cascade another escalation.
	InputsMatch bool
	// DeescalationInputsMatch reports that the current deterministic
	// unreachability evidence exactly matches the latest applied de-escalation.
	// Matching evidence is already reflected in priority and must not cascade.
	DeescalationInputsMatch bool
}

// Snapshot is the normalized, I/O-free input to the promotion rules.
type Snapshot struct {
	FindingID                 shared.ID
	FindingVersion            int
	Priority                  int
	Reachability              judgment.ReachabilityState
	ReachabilityPublishable   bool
	ReachabilityDeterministic bool
	ReachabilitySignal        Signal
	AttackPathSignal          Signal
	PathPresent               bool
	PathConfident             bool
	DetectionSignals          []Signal
	PriorEscalation           *PriorEscalation
}

// Evaluate returns at most one deterministic promotion claim. Signal-loss reversal restores the
// exact prior priority recorded in the applied escalation event rather than stepping one level.
func Evaluate(s Snapshot) (*judgment.PromotionClaim, error) {
	if s.FindingID.IsZero() || s.FindingVersion < 1 || s.Priority < 1 || s.Priority > 5 {
		return nil, fmt.Errorf("%w: promotion snapshot has invalid finding state", shared.ErrValidation)
	}
	inputs := []Signal{s.ReachabilitySignal}
	if s.ReachabilityPublishable && s.ReachabilityDeterministic && s.Reachability == judgment.NotReachable && s.Priority < 5 && (s.PriorEscalation == nil || !s.PriorEscalation.DeescalationInputsMatch) {
		return claim(s, judgment.RuleDeterministicUnreachable, judgment.PromotionDeescalate, s.Priority+1, inputs, nil)
	}
	if s.PriorEscalation != nil && !s.PriorEscalation.InputsActive {
		prior := s.PriorEscalation.BeforePriority
		if prior > s.Priority && prior >= 1 && prior <= 5 {
			inputs = append(inputs, Signal{Kind: judgment.PromotionInputPrior, ID: s.PriorEscalation.EventID})
			return claim(s, judgment.RuleCorroboratingSignalLoss, judgment.PromotionDeescalate, prior, inputs, nil)
		}
	}
	if len(s.DetectionSignals) == 0 || !s.PathPresent {
		return nil, nil
	}
	inputs = append(inputs, s.AttackPathSignal)
	inputs = append(inputs, s.DetectionSignals...)
	if s.ReachabilityPublishable && s.Reachability == judgment.Reachable && s.PathConfident && s.Priority > 1 && (s.PriorEscalation == nil || !s.PriorEscalation.InputsMatch) {
		return claim(s, judgment.RuleRuntimeReachableExposed, judgment.PromotionEscalate, s.Priority-1, inputs, nil)
	}
	uncertainty := make([]string, 0, 2)
	if !s.PathConfident {
		uncertainty = append(uncertainty, "inferred_edge")
	}
	if !s.ReachabilityPublishable || s.Reachability == judgment.ReachUnknown {
		uncertainty = append(uncertainty, "unknown_reachability")
	}
	if len(uncertainty) == 0 {
		return nil, nil
	}
	return claim(s, judgment.RuleUncertainCorroboration, judgment.PromotionFlagForReview, s.Priority, inputs, uncertainty)
}

func claim(s Snapshot, rule string, effect judgment.PromotionChange, after int, signals []Signal, uncertainty []string) (*judgment.PromotionClaim, error) {
	inputs := make([]judgment.PromotionInput, 0, len(signals))
	for _, signal := range signals {
		if signal.ID.IsZero() {
			continue
		}
		inputs = append(inputs, judgment.PromotionInput{
			Kind:       signal.Kind,
			ID:         signal.ID,
			EvidenceID: signal.EvidenceID,
		})
	}
	sort.Slice(inputs, func(i, j int) bool {
		if inputs[i].Kind != inputs[j].Kind {
			return inputs[i].Kind < inputs[j].Kind
		}
		if inputs[i].ID != inputs[j].ID {
			return inputs[i].ID < inputs[j].ID
		}
		return inputs[i].EvidenceID < inputs[j].EvidenceID
	})
	sort.Strings(uncertainty)
	material := struct {
		FindingID      shared.ID                 `json:"finding_id"`
		Rule           string                    `json:"rule"`
		Inputs         []judgment.PromotionInput `json:"inputs"`
		Proposed       judgment.PromotionChange  `json:"proposed"`
		Uncertainty    []string                  `json:"uncertainty,omitempty"`
		FindingVersion int                       `json:"finding_version"`
		BeforePriority int                       `json:"before_priority"`
		AfterPriority  int                       `json:"after_priority"`
	}{
		FindingID:      s.FindingID,
		Rule:           rule,
		Inputs:         inputs,
		Proposed:       effect,
		Uncertainty:    uncertainty,
		FindingVersion: s.FindingVersion,
		BeforePriority: s.Priority,
		AfterPriority:  after,
	}
	data, err := json.Marshal(material)
	if err != nil {
		return nil, fmt.Errorf("marshal promotion fingerprint: %w", err)
	}
	digest := sha256.Sum256(data)
	out := &judgment.PromotionClaim{
		FindingID:      s.FindingID,
		Rule:           rule,
		Inputs:         inputs,
		Proposed:       effect,
		Uncertainty:    uncertainty,
		Fingerprint:    hex.EncodeToString(digest[:]),
		FindingVersion: s.FindingVersion,
		BeforePriority: s.Priority,
		AfterPriority:  after,
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}
