package engagement

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// InferTargetKind classifies a raw target string into a scope TargetKind. It is the canonical
// classifier for turning an operator- or agent-supplied string into a typed Target: a scheme
// separator means URL, a parseable prefix means CIDR, a parseable address means IP, and
// anything else is treated as a domain. Repo/image kinds are never inferred from a bare
// string (they are explicit). The recon use-case carries an equivalent private classifier
// (frozen P2); new callers – notably the agent tool catalog – use this canonical one.
func InferTargetKind(v string) TargetKind {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "://") {
		return TargetURL
	}
	if strings.Contains(v, "/") {
		if _, err := netip.ParsePrefix(v); err == nil {
			return TargetCIDR
		}
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return TargetIP
	}
	return TargetDomain
}

// ValidateTargetValue guards a target string against being smuggled in as a CLI flag or
// carrying whitespace – the value-level check behind argv-only execution. It
// is the layer-owned guard a caller applies BEFORE building a tool argv, so a safe argv never
// depends on each tool adapter re-validating its input. Mirrors the recon use-case's private
// validateTargetValue (and the per-tool safeHost backstop).
func ValidateTargetValue(v string) error {
	if v == "" {
		return fmt.Errorf("%w: a target is required", shared.ErrValidation)
	}
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("%w: target may not start with '-'", shared.ErrValidation)
	}
	if strings.ContainsAny(v, " \t\n\r") {
		return fmt.Errorf("%w: target may not contain whitespace", shared.ErrValidation)
	}
	return nil
}
