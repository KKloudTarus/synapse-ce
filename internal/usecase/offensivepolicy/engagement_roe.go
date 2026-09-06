package offensivepolicy

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
)

// RoEFromEngagement projects an engagement's stored offensive rules of engagement into the
// RulesOfEngagement the governance policy authorizes against. It does no validation of its own: a field
// the engagement left unset stays unset, so the policy's own missing-field refusal (RulesOfEngagement)
// remains the single source of truth for what an offensive action requires. This is the mapping that lets
// the offensive pillar (adversary emulation, exploitation chains) run under an engagement's RoE without
// coupling the engagement aggregate to the offensive-policy domain.
func RoEFromEngagement(e engagement.Engagement) RulesOfEngagement {
	roe := RulesOfEngagement{
		CustomerContact:   e.CustomerContact,
		EmergencyContact:  e.EmergencyContact,
		RiskCeiling:       offensivepolicy.RiskClass(e.RiskCeiling),
		ExclusionsChecked: e.ExclusionsChecked,
	}
	if e.AuthorizedFrom != nil {
		roe.WindowStart = *e.AuthorizedFrom
	}
	if e.AuthorizedTo != nil {
		roe.WindowEnd = *e.AuthorizedTo
	}
	for _, t := range e.Scope.InScope {
		roe.AuthorizedScope = append(roe.AuthorizedScope, string(t.Kind)+":"+t.Value)
	}
	for _, t := range e.Scope.OutOfScope {
		roe.ExcludedAssets = append(roe.ExcludedAssets, string(t.Kind)+":"+t.Value)
	}
	return roe
}
