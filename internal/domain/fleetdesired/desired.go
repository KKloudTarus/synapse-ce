// Package fleetdesired defines control-plane-owned fleet intent for canonical technical assets.
//
// Desired state is deliberately separate from fleetagent.Agent.Capabilities. Capabilities are an
// OBSERVATION reported by an untrusted agent; desired capabilities are an operator decision. Folding
// the two together would let an agent erase a missing sensor by ceasing to advertise it. The durable
// subject is the canonical host/cluster AssetID, not an enrolment-scoped AgentID, so replacing or
// re-enrolling an agent does not orphan the policy it is expected to satisfy.
package fleetdesired

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	MaxCapabilities     = 64
	MaxCapabilityInputs = 256
	MaxCapabilityLen    = 128
)

// State is the operator-owned desired capability set for one canonical host/cluster AssetID.
// PolicyID identifies one policy lifecycle and never changes during updates; clearing and recreating
// the policy mints a new PolicyID. Version starts at 1 within that lifecycle and increments once per
// semantic replacement. The pair prevents both lost updates and delete/recreate ABA races.
type State struct {
	TenantID     shared.ID
	AssetID      shared.ID
	PolicyID     shared.ID
	Capabilities []string
	UpdatedBy    shared.ID
	Version      int64
	Audit        shared.Audit
}

// GapReason names why a desired capability is not covered by a healthy bound agent. It is a closed set
// so a consumer can reason over every uncovered case rather than an open-ended string.
type GapReason string

const (
	GapAgentMissing        GapReason = "agent_missing"
	GapAgentStale          GapReason = "agent_stale"
	GapAgentRevoked        GapReason = "agent_revoked"
	GapAgentDecommissioned GapReason = "agent_decommissioned"
	GapCapabilityMissing   GapReason = "capability_missing"
)

// Valid reports whether r is a known gap reason.
func (r GapReason) Valid() bool {
	switch r {
	case GapAgentMissing, GapAgentStale, GapAgentRevoked, GapAgentDecommissioned, GapCapabilityMissing:
		return true
	default:
		return false
	}
}

// SupportedAssetKind reports whether desired capabilities may target an asset of this kind. Only the
// canonical host and cluster kinds carry a fleet agent that can satisfy a desired capability.
func SupportedAssetKind(kind asset.Kind) bool {
	return kind == asset.KindHost || kind == asset.KindCluster
}

// NormalizeCapabilities returns the canonical persistence/comparison representation: trimmed,
// de-duplicated, sorted, and bounded. Empty raw slots are ignored; an empty canonical result is handled
// by the mutation API (which requires an explicit Clear rather than persisting a meaningless empty row).
func NormalizeCapabilities(in []string) ([]string, error) {
	if len(in) > MaxCapabilityInputs {
		return nil, fmt.Errorf("%w: desired state received %d capability inputs, over the %d input bound",
			shared.ErrValidation, len(in), MaxCapabilityInputs)
	}
	seen := make(map[string]struct{}, min(len(in), MaxCapabilities))
	out := make([]string, 0, min(len(in), MaxCapabilities))
	for _, raw := range in {
		capability := strings.TrimSpace(raw)
		if capability == "" {
			continue
		}
		if !utf8.ValidString(capability) {
			return nil, fmt.Errorf("%w: capability %q is not valid UTF-8", shared.ErrValidation, capability)
		}
		if len(capability) > MaxCapabilityLen {
			return nil, fmt.Errorf("%w: capability %q is longer than %d bytes", shared.ErrValidation, capability, MaxCapabilityLen)
		}
		if strings.IndexFunc(capability, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("%w: capability %q contains a control character", shared.ErrValidation, capability)
		}
		if _, exists := seen[capability]; exists {
			continue
		}
		if len(out) == MaxCapabilities {
			return nil, fmt.Errorf("%w: desired state names more than %d distinct capabilities", shared.ErrValidation, MaxCapabilities)
		}
		seen[capability] = struct{}{}
		out = append(out, capability)
	}
	sort.Strings(out)
	return out, nil
}

func (s State) Validate() error {
	if s.TenantID.IsZero() {
		return fmt.Errorf("%w: desired state needs a tenant", shared.ErrValidation)
	}
	if s.AssetID.IsZero() {
		return fmt.Errorf("%w: desired state needs a canonical asset", shared.ErrValidation)
	}
	if s.PolicyID.IsZero() {
		return fmt.Errorf("%w: desired state needs a policy id", shared.ErrValidation)
	}
	if strings.TrimSpace(s.UpdatedBy.String()) == "" {
		return fmt.Errorf("%w: desired state change needs an actor", shared.ErrValidation)
	}
	if s.Version < 1 {
		return fmt.Errorf("%w: desired state version must be at least 1", shared.ErrValidation)
	}
	if s.Audit.CreatedAt.IsZero() || s.Audit.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: desired state needs audit timestamps", shared.ErrValidation)
	}
	if s.Audit.UpdatedAt.Before(s.Audit.CreatedAt) {
		return fmt.Errorf("%w: desired state updated_at precedes created_at", shared.ErrValidation)
	}
	canonical, err := NormalizeCapabilities(s.Capabilities)
	if err != nil {
		return err
	}
	if len(canonical) == 0 {
		return fmt.Errorf("%w: desired state must contain at least one capability; clear the intent instead", shared.ErrValidation)
	}
	if len(canonical) != len(s.Capabilities) {
		return fmt.Errorf("%w: desired capabilities must be canonical (trimmed, unique, sorted)", shared.ErrValidation)
	}
	for i := range canonical {
		if canonical[i] != s.Capabilities[i] {
			return fmt.Errorf("%w: desired capabilities must be canonical (trimmed, unique, sorted)", shared.ErrValidation)
		}
	}
	return nil
}
