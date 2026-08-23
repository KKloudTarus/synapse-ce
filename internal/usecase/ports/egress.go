package ports

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
)

// EgressRule is one egress decision: allow or deny traffic to Net on Ports (empty Ports
// = all ports). Rules are matched in order; an EgressPolicy is default-DENY, so only
// explicit allow rules open anything and deny rules (out-of-scope) are ordered first.
type EgressRule struct {
	Allow bool
	Net   netip.Prefix
	Ports []uint16 // nil/empty = all ports
}

// DomainRule defers a hostname rule until sandbox setup resolves and pins it.
// Ports follows EgressRule semantics: empty covers every port; otherwise it
// constrains each resolved IP to the declared TCP/UDP ports. URL allows carry
// their effective port, while out-of-scope URL carve-outs use empty Ports so the
// resolved host is denied on every port.
type DomainRule struct {
	Host  string
	Ports []uint16
}

// EgressPolicy is an ordered, default-deny ruleset compiled from engagement
// scope. It lives in ports so the usecase compiler and infrastructure applier
// both depend inward on the shared contract. AllowDomains and DenyDomains remain
// for hostname-wide callers; the structured rules preserve URL port semantics
// until run-start resolution and pinning.
type EgressPolicy struct {
	Rules            []EgressRule
	AllowDomains     []string // hostname-wide in-scope domains to resolve + allow
	DenyDomains      []string // hostname-wide out-of-scope domains to resolve + deny
	AllowDomainRules []DomainRule
	DenyDomainRules  []DomainRule
	PinnedHosts      map[string][]netip.Addr // prevalidated host-to-address bindings; no second DNS lookup
}

// EgressNamespace is the lifecycle handle for one configured execution network
// namespace. Concrete namespace setup and teardown remain infrastructure concerns.
type EgressNamespace interface {
	NamespaceName() string
	HostsPath() string
	Rules() []EgressRule
	Teardown(context.Context) error
}

// EgressEnforcer configures a scope-bound execution network namespace. Sandboxed
// runners depend on this inward-facing port rather than a concrete broker client.
type EgressEnforcer interface {
	Probe(context.Context) error
	Setup(context.Context, string, int, int, string, string, EgressPolicy) (EgressNamespace, error)
}

// CanonicalEgressRule is the normalized rule signed by the control plane and
// passed over the broker protocol.
type CanonicalEgressRule struct {
	Allow bool     `json:"allow"`
	CIDR  string   `json:"cidr"`
	Ports []uint16 `json:"ports,omitempty"`
}

// CanonicalEgressRulesEqual compares canonical rules without string conversion so
// grant signing and broker enforcement share the same exact ordering invariant.

func CanonicalEgressRulesEqual(left, right []CanonicalEgressRule) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Allow != right[i].Allow || left[i].CIDR != right[i].CIDR || !slices.Equal(left[i].Ports, right[i].Ports) {
			return false
		}
	}
	return true
}

// EgressGrantRequest binds a signed grant to the exact tenant, execution,
// Bubblewrap process, namespace slot, and canonical policy.
type EgressGrantRequest struct {
	TenantID      string
	ExecutionKind string
	ExecutionID   string
	RunID         string
	Slot          int
	PID           int
	Rules         []CanonicalEgressRule
}

// EgressGrantSigner signs a short-lived process-bound grant.
type EgressGrantSigner interface {
	Sign(EgressGrantRequest, time.Time, time.Duration) (string, error)
}

// EgressPolicyCanonicalizer resolves and normalizes a policy for signing.
type EgressPolicyCanonicalizer interface {
	Canonicalize(context.Context, EgressPolicy) ([]CanonicalEgressRule, error)
}

// EgressPolicyCompiler derives a default-deny policy from authoritative scope.
type EgressPolicyCompiler interface {
	Compile(engagement.Scope) EgressPolicy
}
