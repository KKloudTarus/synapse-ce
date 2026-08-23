package egressbroker

import (
	"context"
	"errors"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// EgressGrantCanonicalizer independently resolves the control-plane policy and
// converts it through the broker's exact canonical wire contract.
type EgressGrantCanonicalizer struct{}

func (EgressGrantCanonicalizer) Canonicalize(ctx context.Context, policy ports.EgressPolicy) ([]ports.CanonicalEgressRule, error) {
	resolved, err := sandbox.ResolveEgressPolicy(ctx, policy)
	if err != nil {
		return nil, err
	}
	rules, err := canonicalPolicy(resolved)
	if err != nil {
		return nil, err
	}
	out := make([]ports.CanonicalEgressRule, len(rules))
	for i, rule := range rules {
		out[i] = ports.CanonicalEgressRule{
			Allow: rule.Allow,
			CIDR:  rule.CIDR,
			Ports: append([]uint16(nil), rule.Ports...),
		}
	}
	return out, nil
}

// EgressGrantSigner adapts the use-case signing port without exposing the
// private signing seed outside the trusted control-plane process.
type EgressGrantSigner struct {
	signer *GrantSigner
}

func NewEgressGrantSigner(signer *GrantSigner) (*EgressGrantSigner, error) {
	if signer == nil {
		return nil, errors.New("egress grant signer is required")
	}
	return &EgressGrantSigner{signer: signer}, nil
}

func (s *EgressGrantSigner) Sign(req ports.EgressGrantRequest, now time.Time, lifetime time.Duration) (string, error) {
	rules := make([]CanonicalRule, len(req.Rules))
	for i, rule := range req.Rules {
		rules[i] = CanonicalRule{
			Allow: rule.Allow,
			CIDR:  rule.CIDR,
			Ports: append([]uint16(nil), rule.Ports...),
		}
	}
	return s.signer.Sign(GrantRequest{
		TenantID:      req.TenantID,
		ExecutionKind: req.ExecutionKind,
		ExecutionID:   req.ExecutionID,
		RunID:         req.RunID,
		Slot:          req.Slot,
		PID:           req.PID,
		Rules:         rules,
	}, now, lifetime)
}

var _ ports.EgressPolicyCanonicalizer = EgressGrantCanonicalizer{}
var _ ports.EgressGrantSigner = (*EgressGrantSigner)(nil)
