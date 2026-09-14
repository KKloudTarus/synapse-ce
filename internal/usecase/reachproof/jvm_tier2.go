package reachproof

import (
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// JVM Tier-2 actor identities are intentionally local to this use case and intentionally NOT registered
// in judgment.IsDeterministicReachabilityProof. JVM bytecode call graphs are blind to reflection, DI,
// ServiceLoader, JNDI, invokedynamic/proxies, JNI and custom classloaders, so their positive direction may
// raise urgency but their negative direction must never authorize suppression/OpenVEX not_affected.
const (
	jvmTier2Proposer         = "system:jvmbytecode-scan"
	jvmTier2Verifier         = "system:jvmbytecode-engine"
	jvmTier2SubjectSeparator = "\x1f"
)

// JVMTier2Coordinator scopes affected symbols to their Maven package before delegating to the generic
// judgment lifecycle. This prevents a reached same-named method in dependency A from raising a finding for
// dependency B. A missing/non-Maven PURL is unknown attribution and is therefore skipped, never guessed.
type JVMTier2Coordinator struct {
	inner *Coordinator
}

var _ ports.ReachabilityRecorder = (*JVMTier2Coordinator)(nil)

// NewJVMTier2Coordinator returns a Tier-2 coordinator permanently configured RAISE-ONLY. It reuses the
// standard propose->verify->supersede lifecycle and proof-path sealing, while overriding the generic Tier-2
// actors before the coordinator can mint anything. Keeping these JVM actors out of the domain proof allowlist
// is a second fail-safe beyond raiseOnly: even a persisted claim cannot satisfy the deterministic suppression
// provenance predicate.
func NewJVMTier2Coordinator(a analyzer, r recorder, audit ports.AuditLogger, clock ports.Clock) (*JVMTier2Coordinator, error) {
	c, err := NewCoordinatorForLanguage(a, r, audit, clock, judgment.Tier2, LanguageJVM)
	if err != nil {
		return nil, err
	}
	c.proposer = jvmTier2Proposer
	c.verifier = jvmTier2Verifier
	c.proofLabel = "tier-2 jvm bytecode call-graph proof"
	c.raiseOnly = true
	c.skipUnresolvedSubjects = true
	return &JVMTier2Coordinator{inner: c}, nil
}

// Record implements ports.ReachabilityRecorder. Package identity is encoded only inside the JVM analyzer
// seam; the generic coordinator still performs exact result-to-finding mapping and never sees an ambiguous
// unscoped JVM symbol.
func (c *JVMTier2Coordinator) Record(ctx context.Context, engagementID shared.ID, targetRef string, subjects []ports.ReachabilitySubject) (int, error) {
	if c == nil || c.inner == nil {
		return 0, nil
	}
	scoped := make([]ports.ReachabilitySubject, 0, len(subjects))
	for _, subject := range subjects {
		purl := strings.TrimSpace(subject.PackagePURL)
		if !strings.HasPrefix(purl, "pkg:maven/") {
			continue
		}
		symbols := make([]string, 0, len(subject.Symbols))
		for _, symbol := range subject.Symbols {
			symbol = strings.TrimSpace(symbol)
			if symbol == "" {
				continue
			}
			symbols = append(symbols, purl+jvmTier2SubjectSeparator+symbol)
		}
		if len(symbols) == 0 {
			continue
		}
		scoped = append(scoped, ports.ReachabilitySubject{
			FindingID:   subject.FindingID,
			Symbols:     symbols,
			PackagePURL: purl,
		})
	}
	if len(scoped) == 0 {
		return 0, nil
	}
	return c.inner.Record(ctx, engagementID, targetRef, scoped)
}
