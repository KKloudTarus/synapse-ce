package hotspot

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNewSummary(t *testing.T) {
	tests := []struct {
		name        string
		total       int
		reviewed    int
		wantErr     error
		wantPct     float64
		wantGrade   rating.Grade
	}{
		{
			name:      "zero hotspots",
			total:     0,
			reviewed:  0,
			wantErr:   nil,
			wantPct:   100.0,
			wantGrade: rating.GradeA,
		},
		{
			name:      "all reviewed",
			total:     10,
			reviewed:  10,
			wantErr:   nil,
			wantPct:   100.0,
			wantGrade: rating.GradeA,
		},
		{
			name:      "none reviewed",
			total:     10,
			reviewed:  0,
			wantErr:   nil,
			wantPct:   0.0,
			wantGrade: rating.GradeE,
		},
		{
			name:      "B grade - 80 percent",
			total:     10,
			reviewed:  8,
			wantErr:   nil,
			wantPct:   80.0,
			wantGrade: rating.GradeB,
		},
		{
			name:      "C grade - 60 percent",
			total:     10,
			reviewed:  6,
			wantErr:   nil,
			wantPct:   60.0,
			wantGrade: rating.GradeC,
		},
		{
			name:      "D grade - 40 percent",
			total:     10,
			reviewed:  4,
			wantErr:   nil,
			wantPct:   40.0,
			wantGrade: rating.GradeD,
		},
		{
			name:      "E grade - 39 percent",
			total:     100,
			reviewed:  39,
			wantErr:   nil,
			wantPct:   39.0,
			wantGrade: rating.GradeE,
		},
		{
			name:      "invalid - negative total",
			total:     -1,
			reviewed:  0,
			wantErr:   shared.ErrValidation,
		},
		{
			name:      "invalid - reviewed > total",
			total:     5,
			reviewed:  6,
			wantErr:   shared.ErrValidation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSummary(tt.total, tt.reviewed)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("NewSummary() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewSummary() unexpected error: %v", err)
			}
			if got.Total != tt.total {
				t.Errorf("Total = %v, want %v", got.Total, tt.total)
			}
			if got.Reviewed != tt.reviewed {
				t.Errorf("Reviewed = %v, want %v", got.Reviewed, tt.reviewed)
			}
			if got.ReviewedPct != tt.wantPct {
				t.Errorf("ReviewedPct = %v, want %v", got.ReviewedPct, tt.wantPct)
			}
			if got.Grade != tt.wantGrade {
				t.Errorf("Grade = %v, want %v", got.Grade, tt.wantGrade)
			}
		})
	}
}
