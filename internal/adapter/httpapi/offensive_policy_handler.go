package httpapi

import (
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
)

// SetOffensivePolicy wires the offensive policy register the binary loaded and validated at startup, and
// enables the read route that shows operators exactly what the running binary enforces.
func (rt *Router) SetOffensivePolicy(register *offensivepolicy.Register) {
	if register != nil {
		rt.offensivePolicy = register
	}
}

type offensivePolicyTechniqueDTO struct {
	Technique      string `json:"technique"`
	TaxonomyRef    string `json:"taxonomy_ref,omitempty"`
	Disruption     string `json:"disruption"`
	Reversibility  string `json:"reversibility"`
	RiskClass      string `json:"risk_class"`
	Approval       string `json:"approval,omitempty"`
	BlastRadius    string `json:"blast_radius"`
	ProductionSafe bool   `json:"production_safe"`
	Prohibited     bool   `json:"prohibited"`
}

type offensivePolicyDTO struct {
	LegalReview struct {
		Reviewed        bool   `json:"reviewed"`
		Date            string `json:"date,omitempty"`
		Owner           string `json:"owner,omitempty"`
		CounselReviewed bool   `json:"counsel_reviewed"`
		CounselDate     string `json:"counsel_date,omitempty"`
	} `json:"legal_review"`
	Techniques     []offensivePolicyTechniqueDTO `json:"techniques"`
	Prohibited     int                           `json:"prohibited"`
	ProductionSafe int                           `json:"production_safe"`
}

// getOffensivePolicy returns the register as loaded: every classified technique with its risk class,
// approval mode, blast radius and whether the binary treats it as prohibited or production-safe.
func (rt *Router) getOffensivePolicy(w http.ResponseWriter, r *http.Request) {
	reg := rt.offensivePolicy
	var out offensivePolicyDTO
	out.LegalReview.Reviewed = reg.LegalReview.Reviewed
	out.LegalReview.Date = reg.LegalReview.Date
	out.LegalReview.Owner = reg.LegalReview.Owner
	out.LegalReview.CounselReviewed = reg.LegalReview.CounselReviewed
	out.LegalReview.CounselDate = reg.LegalReview.CounselDate
	out.Techniques = make([]offensivePolicyTechniqueDTO, 0, len(reg.TechniqueIDs()))
	for _, id := range reg.TechniqueIDs() {
		p, ok := reg.Lookup(id)
		if !ok {
			continue
		}
		dto := offensivePolicyTechniqueDTO{
			Technique: p.Technique, TaxonomyRef: p.TaxonomyRef, Disruption: string(p.Disruption), Reversibility: string(p.Reversibility),
			RiskClass: string(p.RiskClass), Approval: string(p.Approval), BlastRadius: string(p.BlastRadius),
			ProductionSafe: p.ProductionSafe, Prohibited: p.RiskClass == offensivepolicy.RiskProhibited,
		}
		if dto.Prohibited {
			out.Prohibited++
		}
		if dto.ProductionSafe {
			out.ProductionSafe++
		}
		out.Techniques = append(out.Techniques, dto)
	}
	writeJSON(w, http.StatusOK, out)
}
