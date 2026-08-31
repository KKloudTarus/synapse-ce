// Package response is the pure domain for governed defensive response actions (issue #425): contain,
// isolate, quarantine. It adds NO new trust model — it reuses the one that governs exploitation:
// server-side admission, an argv-only sandbox, an append-only audit, approval-as-evidence, and a
// decision a model can propose but never make. This package defines the actions and their MANDATORY
// reversals; admission, approval and execution live in internal/usecase/response.
//
// Every action is REVERSIBLE by construction: an Action with no declared reversal cannot be built, and a
// catalogue drift test fails CI if a Kind is ever added without one. Every action is argv-only — no
// shell, ever, including the reversal.
package response

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Kind is a response action type. The first cut is deliberately small, high-confidence, and each maps to
// an agent capability with a clean reversal (#425 requirement 5).
type Kind string

const (
	KindIsolateHost    Kind = "isolate_host"    // network-isolate a host; reversal restores connectivity
	KindQuarantineFile Kind = "quarantine_file" // move a file to quarantine; reversal restores it
	KindStopProcess    Kind = "stop_process"    // stop a process; reversal is documented as best-effort restart
)

// ReversalKind is the response Kind that undoes a given action. Keeping the reversal typed (a Kind, not a
// free string) means a reversal is itself a first-class, admittable, auditable action.
type ReversalKind string

const (
	ReversalRestoreHost    ReversalKind = "restore_host"
	ReversalRestoreFile    ReversalKind = "restore_file"
	ReversalRestartProcess ReversalKind = "restart_process"
)

// ReversalSpec declares how an action is undone. It is REQUIRED on every action: Description states the
// intent for the operator/audit, and Argv is the argv-only reversal command (no shell). An empty spec is
// refused at construction, and the catalogue drift test fails CI if a Kind lacks one.
type ReversalSpec struct {
	Kind        ReversalKind `json:"kind"`
	Description string       `json:"description"`
	Argv        []string     `json:"argv"`
}

func (r ReversalSpec) valid() bool {
	return r.Kind != "" && r.Description != "" && len(r.Argv) > 0 && !containsShell(r.Argv)
}

// Action is one governed response. It is state-changing by nature, declares its blast radius (enforced
// at execution), and carries its mandatory reversal. Argv is the exact argv-only command.
type Action struct {
	ID          shared.ID
	Kind        Kind
	Target      shared.ID // the asset the action affects
	BlastRadius offensivepolicy.Radius
	Argv        []string // argv-only; no shell
	Reversal    ReversalSpec
}

// NewAction builds a complete, valid action for a kind + target from the catalogue: the argv-only
// command, the catalogued blast radius, and the mandatory reversal. It is the single constructor callers
// (the HTTP surface, the agent proposer) use so an action can never be assembled with a bogus argv or a
// mismatched reversal — Validate is run before returning. The argv verb is derived from the kind
// (isolate_host → "isolate-host"), matching the agent-response CLI contract.
func NewAction(id shared.ID, kind Kind, target shared.ID) (Action, error) {
	spec, ok := SpecFor(kind)
	if !ok {
		return Action{}, fmt.Errorf("%w: unknown response kind %q", shared.ErrValidation, kind)
	}
	a := Action{
		ID:          id,
		Kind:        kind,
		Target:      target,
		BlastRadius: spec.Radius,
		Argv:        []string{"synapse-agent-response", strings.ReplaceAll(string(kind), "_", "-"), target.String()},
		Reversal:    spec.Reversal,
	}
	if err := a.Validate(); err != nil {
		return Action{}, err
	}
	return a, nil
}

// Validate fails CLOSED: a missing reversal, empty argv, a shell metacharacter, an unknown kind, or an
// invalid radius each make the action unimplementable. Reversibility is mandatory, so an action without
// a valid reversal is refused here (not at runtime).
func (a Action) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("%w: response action has no id", shared.ErrValidation)
	}
	if !a.Kind.valid() {
		return fmt.Errorf("%w: unknown response kind %q", shared.ErrValidation, a.Kind)
	}
	if a.Target == "" {
		return fmt.Errorf("%w: response action %s has no target", shared.ErrValidation, a.ID)
	}
	if !a.BlastRadius.Valid() {
		return fmt.Errorf("%w: response action %s has an invalid blast radius %q", shared.ErrValidation, a.ID, a.BlastRadius)
	}
	if len(a.Argv) == 0 || containsShell(a.Argv) {
		return fmt.Errorf("%w: response action %s must be argv-only with no shell", shared.ErrValidation, a.ID)
	}
	if !a.Reversal.valid() {
		return fmt.Errorf("%w: response action %s has no valid reversal — reversibility is mandatory", shared.ErrValidation, a.ID)
	}
	// The reversal for this kind must be the catalogued one, so an action cannot declare a bogus reversal.
	if want := catalogue[a.Kind].Reversal.Kind; a.Reversal.Kind != want {
		return fmt.Errorf("%w: response %s reversal must be %q, got %q", shared.ErrValidation, a.Kind, want, a.Reversal.Kind)
	}
	return nil
}

func (k Kind) valid() bool {
	_, ok := catalogue[k]
	return ok
}

// Spec is the catalogued contract for a Kind: its blast radius and the required reversal kind. It is the
// single source of truth the drift test guards.
type Spec struct {
	Kind     Kind
	Radius   offensivepolicy.Radius
	Reversal ReversalSpec
}

// catalogue maps each response Kind to its contract. EVERY entry carries a reversal; the drift test
// (action_test.go) fails CI if any Kind is added without one — the "an action with no reversal fails a
// CI check, not a runtime check" requirement.
var catalogue = map[Kind]Spec{
	KindIsolateHost: {
		Kind: KindIsolateHost, Radius: offensivepolicy.RadiusStateChanging,
		Reversal: ReversalSpec{Kind: ReversalRestoreHost, Description: "restore host network connectivity", Argv: []string{"synapse-agent-response", "restore-host"}},
	},
	KindQuarantineFile: {
		Kind: KindQuarantineFile, Radius: offensivepolicy.RadiusStateChanging,
		Reversal: ReversalSpec{Kind: ReversalRestoreFile, Description: "restore the quarantined file to its path", Argv: []string{"synapse-agent-response", "restore-file"}},
	},
	KindStopProcess: {
		Kind: KindStopProcess, Radius: offensivepolicy.RadiusStateChanging,
		Reversal: ReversalSpec{Kind: ReversalRestartProcess, Description: "restart the stopped process (best-effort)", Argv: []string{"synapse-agent-response", "restart-process"}},
	},
}

// Catalogue returns the response contracts in a deterministic order.
func Catalogue() []Spec {
	kinds := make([]Kind, 0, len(catalogue))
	for k := range catalogue {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	out := make([]Spec, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, catalogue[k])
	}
	return out
}

// SpecFor returns the catalogued contract for a kind.
func SpecFor(k Kind) (Spec, bool) { s, ok := catalogue[k]; return s, ok }

// containsShell reports whether any argv token carries a shell metacharacter — a coarse guard so a
// caller cannot smuggle a shell fragment into an "argv-only" command.
func containsShell(argv []string) bool {
	const meta = "|&;<>()$`\\\"'\n\t*?[]{}"
	for _, tok := range argv {
		for _, r := range tok {
			for _, m := range meta {
				if r == m {
					return true
				}
			}
		}
	}
	return false
}
