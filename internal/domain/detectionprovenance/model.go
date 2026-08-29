package detectionprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Status is the read-layer result of reconciling a detection's durable evidence and telemetry facts.
type Status string

const (
	StatusPending  Status = "pending"
	StatusComplete Status = "complete"
	StatusExpired  Status = "expired"
	StatusBroken   Status = "broken"
)

func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusComplete, StatusExpired, StatusBroken:
		return true
	default:
		return false
	}
}

// TransitionKind is an immutable provenance lifecycle fact. It is intentionally separate from the
// sealed envelope: changing transport durability must not mutate permanent evidence bytes.
type TransitionKind string

const (
	Received          TransitionKind = "received"
	TelemetryDurable  TransitionKind = "telemetry_durable"
	CommitmentPending TransitionKind = "commitment_pending"
	CommitmentSealed  TransitionKind = "commitment_sealed"
	Acknowledged      TransitionKind = "acknowledged"
	Expired           TransitionKind = "expired"
	Broken            TransitionKind = "broken"
)

func (k TransitionKind) Valid() bool {
	switch k {
	case Received, TelemetryDurable, CommitmentPending, CommitmentSealed, Acknowledged, Expired, Broken:
		return true
	default:
		return false
	}
}

// Current is the durable query projection. DetectionID is unique only within EngagementID.
type Current struct {
	TenantID     shared.ID `json:"tenant_id"`
	EngagementID shared.ID `json:"engagement_id"`
	DetectionID  shared.ID `json:"detection_id"`
	Status       Status    `json:"status"`
	EvidenceID   shared.ID `json:"evidence_id,omitempty"`
	PendingInput []byte    `json:"-"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (c Current) Validate() error {
	if c.TenantID.IsZero() || c.EngagementID.IsZero() || c.DetectionID.IsZero() || !c.Status.Valid() || c.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: invalid detection provenance current state", shared.ErrValidation)
	}
	if len(c.PendingInput) == 0 {
		return fmt.Errorf("%w: detection provenance needs durable input", shared.ErrValidation)
	}
	return nil
}

// Transition is append-only. Sequence orders an item's lifecycle facts without relying on clock precision.
type Transition struct {
	TenantID      shared.ID                       `json:"tenant_id"`
	EngagementID  shared.ID                       `json:"engagement_id"`
	DetectionID   shared.ID                       `json:"detection_id"`
	Sequence      uint64                          `json:"sequence"`
	Kind          TransitionKind                  `json:"kind"`
	Status        Status                          `json:"status"`
	EvidenceID    shared.ID                       `json:"evidence_id,omitempty"`
	TelemetryRefs []fleetagent.TelemetryReference `json:"telemetry_refs,omitempty"`
	AgentID       shared.ID                       `json:"agent_id,omitempty"`
	AssetID       shared.ID                       `json:"asset_id,omitempty"`
	Reason        string                          `json:"reason,omitempty"`
	PreviousHash  string                          `json:"previous_hash"`
	Hash          string                          `json:"hash"`
	OccurredAt    time.Time                       `json:"occurred_at"`
}

func (t Transition) Validate() error {
	if t.TenantID.IsZero() || t.EngagementID.IsZero() || t.DetectionID.IsZero() || t.Sequence == 0 || !t.Kind.Valid() || !t.Status.Valid() || t.OccurredAt.IsZero() {
		return fmt.Errorf("%w: invalid detection provenance transition", shared.ErrValidation)
	}
	if t.Kind == Broken && strings.TrimSpace(t.Reason) == "" {
		return fmt.Errorf("%w: broken provenance transition needs a reason", shared.ErrValidation)
	}
	switch t.Kind {
	case Received:
		if t.Status != StatusPending || !t.EvidenceID.IsZero() {
			return fmt.Errorf("%w: received transition requires pending status without evidence", shared.ErrValidation)
		}
	case TelemetryDurable, CommitmentPending:
		if t.Status != StatusPending || !t.EvidenceID.IsZero() {
			return fmt.Errorf("%w: provenance transition %q requires pending status without evidence", shared.ErrValidation, t.Kind)
		}
	case CommitmentSealed:
		if t.Status != StatusPending || t.EvidenceID.IsZero() {
			return fmt.Errorf("%w: sealed transition requires pending status and evidence", shared.ErrValidation)
		}
	case Acknowledged:
		if t.Status != StatusComplete || t.EvidenceID.IsZero() {
			return fmt.Errorf("%w: acknowledged transition requires complete status and evidence", shared.ErrValidation)
		}
	case Expired:
		if t.Status != StatusExpired {
			return fmt.Errorf("%w: expired transition requires expired status", shared.ErrValidation)
		}
	case Broken:
		if t.Status != StatusBroken {
			return fmt.Errorf("%w: broken transition requires broken status", shared.ErrValidation)
		}
	}
	if t.Kind == Received {
		if t.AgentID.IsZero() || t.AssetID.IsZero() {
			return fmt.Errorf("%w: received provenance transition needs agent and asset", shared.ErrValidation)
		}
		if len(t.TelemetryRefs) == 0 {
			return fmt.Errorf("%w: received provenance transition needs causal telemetry references", shared.ErrValidation)
		}
	}
	for _, ref := range t.TelemetryRefs {
		if err := ref.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// EquivalentTransition compares two append-only facts exactly, treating causal references as an
// unordered set because their signed v2 representation is deliberately order independent.
// SealTransition binds an immutable transition to its predecessor and canonical content.
func SealTransition(transition Transition, previousHash string) Transition {
	transition.PreviousHash = previousHash
	transition.Hash = ComputeHash(transition)
	return transition
}

// ComputeHash returns the deterministic SHA-256 identity of one provenance fact.
func ComputeHash(transition Transition) string {
	h := sha256.New()
	write := func(value string) {
		_, _ = fmt.Fprintf(h, "%d:", len(value))
		_, _ = h.Write([]byte(value))
	}
	write(transition.PreviousHash)
	write(transition.TenantID.String())
	write(transition.EngagementID.String())
	write(transition.DetectionID.String())
	write(fmt.Sprintf("%d", transition.Sequence))
	write(string(transition.Kind))
	write(string(transition.Status))
	write(transition.EvidenceID.String())
	write(transition.AgentID.String())
	write(transition.AssetID.String())
	write(transition.Reason)
	refs := append([]fleetagent.TelemetryReference(nil), transition.TelemetryRefs...)
	sort.Slice(refs, func(i, j int) bool {
		left, right := telemetryReferenceKey(refs[i]), telemetryReferenceKey(refs[j])
		if left != right {
			return left < right
		}
		return refs[i].Digest < refs[j].Digest
	})
	for _, ref := range refs {
		write(ref.StreamID.String())
		write(fmt.Sprintf("%d", ref.Epoch))
		write(fmt.Sprintf("%d", ref.Sequence))
		write(ref.EventID.String())
		write(ref.Digest)
	}
	write(transition.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChain rejects missing links, forks in sequence, or modified transition content.
func VerifyChain(transitions []Transition) error {
	previousHash := ""
	for i, transition := range transitions {
		if err := transition.Validate(); err != nil {
			return fmt.Errorf("%w: transition %d has invalid immutable content: %v", shared.ErrConflict, i, err)
		}
		if transition.Sequence != uint64(i+1) {
			return fmt.Errorf("%w: transition %d has non-contiguous sequence", shared.ErrConflict, i)
		}
		if transition.PreviousHash != previousHash {
			return fmt.Errorf("%w: transition %d previous hash does not match", shared.ErrConflict, i)
		}
		if transition.Hash == "" || transition.Hash != ComputeHash(transition) {
			return fmt.Errorf("%w: transition %d hash does not match immutable content", shared.ErrConflict, i)
		}
		previousHash = transition.Hash
	}
	return nil
}

func EquivalentTransition(left, right Transition) bool {
	if left.TenantID != right.TenantID || left.EngagementID != right.EngagementID ||
		left.DetectionID != right.DetectionID || left.Sequence != right.Sequence ||
		left.Kind != right.Kind || left.Status != right.Status || left.EvidenceID != right.EvidenceID ||
		left.AgentID != right.AgentID || left.AssetID != right.AssetID || left.Reason != right.Reason ||
		!left.OccurredAt.UTC().Equal(right.OccurredAt.UTC()) || len(left.TelemetryRefs) != len(right.TelemetryRefs) {
		return false
	}
	refs := make(map[string]string, len(left.TelemetryRefs))
	for _, ref := range left.TelemetryRefs {
		key := telemetryReferenceKey(ref)
		if _, duplicate := refs[key]; duplicate {
			return false
		}
		refs[key] = ref.Digest
	}
	for _, ref := range right.TelemetryRefs {
		key := telemetryReferenceKey(ref)
		if digest, ok := refs[key]; !ok || digest != ref.Digest {
			return false
		}
	}
	return true
}

func telemetryReferenceKey(ref fleetagent.TelemetryReference) string {
	return strings.Join([]string{ref.StreamID.String(), fmt.Sprint(ref.Epoch), fmt.Sprint(ref.Sequence), ref.EventID.String()}, "\x1f")
}

// Apply produces the next current projection after validating the append-only lifecycle fact.
// Retries are removed by the stores before this function, so every accepted transition must be the
// next legal state change. Integrity failures and expiry may terminalize any non-terminal state.
func Apply(current *Current, previousKind TransitionKind, transition Transition) (Current, error) {
	if err := transition.Validate(); err != nil {
		return Current{}, err
	}
	if current == nil {
		return Current{}, fmt.Errorf("%w: provenance transition requires admitted current state", shared.ErrConflict)
	}
	if err := current.Validate(); err != nil {
		return Current{}, err
	}
	if current.TenantID != transition.TenantID || current.EngagementID != transition.EngagementID || current.DetectionID != transition.DetectionID {
		return Current{}, fmt.Errorf("%w: provenance transition identity differs from current state", shared.ErrValidation)
	}
	if previousKind == Expired || current.Status == StatusExpired {
		return Current{}, fmt.Errorf("%w: expired provenance is terminal", shared.ErrConflict)
	}
	if previousKind == Broken || current.Status == StatusBroken {
		return Current{}, fmt.Errorf("%w: broken provenance is terminal", shared.ErrConflict)
	}

	if transition.Kind == Broken {
		if transition.Status != StatusBroken {
			return Current{}, fmt.Errorf("%w: broken transition requires broken status", shared.ErrValidation)
		}
	} else if transition.Kind == Expired {
		if transition.Status != StatusExpired {
			return Current{}, fmt.Errorf("%w: expired transition requires expired status", shared.ErrValidation)
		}
	} else {
		nextKind, ok := nextLifecycleKind(previousKind)
		if !ok || transition.Kind != nextKind {
			return Current{}, fmt.Errorf("%w: provenance transition %q cannot follow %q", shared.ErrConflict, transition.Kind, previousKind)
		}
		switch transition.Kind {
		case TelemetryDurable, CommitmentPending, CommitmentSealed:
			if transition.Status != StatusPending {
				return Current{}, fmt.Errorf("%w: provenance transition %q requires pending status", shared.ErrValidation, transition.Kind)
			}
		case Acknowledged:
			if transition.Status != StatusComplete {
				return Current{}, fmt.Errorf("%w: acknowledged transition requires complete status", shared.ErrValidation)
			}
		}
	}

	evidenceID := transition.EvidenceID
	if evidenceID.IsZero() {
		evidenceID = current.EvidenceID
	}
	if transition.Kind == CommitmentSealed && evidenceID.IsZero() {
		return Current{}, fmt.Errorf("%w: sealed commitment requires evidence id", shared.ErrValidation)
	}
	if !current.EvidenceID.IsZero() && !transition.EvidenceID.IsZero() && transition.EvidenceID != current.EvidenceID {
		return Current{}, fmt.Errorf("%w: provenance evidence id cannot change", shared.ErrConflict)
	}
	if transition.Kind == Acknowledged && evidenceID.IsZero() {
		return Current{}, fmt.Errorf("%w: acknowledged transition requires sealed evidence id", shared.ErrValidation)
	}

	return Current{
		TenantID: current.TenantID, EngagementID: current.EngagementID, DetectionID: current.DetectionID,
		Status: transition.Status, EvidenceID: evidenceID, PendingInput: append([]byte(nil), current.PendingInput...),
		UpdatedAt: transition.OccurredAt.UTC(),
	}, nil
}

func nextLifecycleKind(previous TransitionKind) (TransitionKind, bool) {
	switch previous {
	case Received:
		return TelemetryDurable, true
	case TelemetryDurable:
		return CommitmentPending, true
	case CommitmentPending:
		return CommitmentSealed, true
	case CommitmentSealed:
		return Acknowledged, true
	default:
		return "", false
	}
}
