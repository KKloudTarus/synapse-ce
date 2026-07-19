package hotspot

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Summary provides a review progress snapshot for a set of Security Hotspots.
type Summary struct {
	Total       int          `json:"total"`
	Reviewed    int          `json:"reviewed"`
	ReviewedPct float64      `json:"reviewed_pct"`
	Grade       rating.Grade `json:"grade"`
}

// NewSummary computes a summary from raw counts, applying zero-hotspot and grade semantics.
func NewSummary(total, reviewed int) (Summary, error) {
	if total < 0 || reviewed < 0 {
		return Summary{}, fmt.Errorf("%w: total and reviewed counts must be non-negative", shared.ErrValidation)
	}
	if reviewed > total {
		return Summary{}, fmt.Errorf("%w: reviewed count cannot exceed total count", shared.ErrValidation)
	}

	// Zero-hotspot semantics: total = 0, reviewed = 0, pct = 100, Grade = A
	if total == 0 {
		return Summary{
			Total:       0,
			Reviewed:    0,
			ReviewedPct: 100.0,
			Grade:       rating.GradeA,
		}, nil
	}

	pct := (float64(reviewed) / float64(total)) * 100.0

	// Cap at 100.0
	if pct > 100.0 {
		pct = 100.0
	}

	// Grade threshold:
	// A = 100%
	// B = >= 80% and < 100%
	// C = >= 60% and < 80%
	// D = >= 40% and < 60%
	// E = < 40%
	var grade rating.Grade
	if pct >= 100.0 {
		grade = rating.GradeA
	} else if pct >= 80.0 {
		grade = rating.GradeB
	} else if pct >= 60.0 {
		grade = rating.GradeC
	} else if pct >= 40.0 {
		grade = rating.GradeD
	} else {
		grade = rating.GradeE
	}

	return Summary{
		Total:       total,
		Reviewed:    reviewed,
		ReviewedPct: pct,
		Grade:       grade,
	}, nil
}
