package report

import (
	"context"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// judgmentReader is the narrow read slice the report needs to surface ACCEPTED risk-narrative and
// correlation judgments. Only these two ungated capabilities are read, and only their closed-token
// fields are rendered — the report path stays LLM-free (no model prose ever reaches a deliverable).
type judgmentReader interface {
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
}

// SetJudgments wires the optional reader that projects accepted risk-narrative + correlation judgments
// into the report insight. nil leaves those sections empty.
func (s *Service) SetJudgments(r judgmentReader) { s.judgments = r }

// projectAcceptedJudgments reads the engagement's judgments and fills insight.RiskRationales /
// CorrelationNotes from the PUBLISHABLE (human-accepted) risk-narrative + correlation ones, as closed
// tokens. Deterministic order (byte-reproducible report). Best-effort: a read error leaves them empty.
func projectAcceptedJudgments(ctx context.Context, r judgmentReader, engagementID shared.ID, insight *ports.ReportInsight) {
	js, err := r.ListByEngagement(ctx, engagementID)
	if err != nil {
		return
	}
	for _, j := range js {
		if !j.Publishable() { // ungated ⇒ publishable == human-accepted (confirmed)
			continue
		}
		subject := string(j.SubjectKind) + ":" + string(j.SubjectID)
		switch j.Capability {
		case judgment.CapRiskNarrative:
			if c, ok := j.Claim.(judgment.RiskNarrativeClaim); ok {
				insight.RiskRationales = append(insight.RiskRationales, ports.RiskRationale{
					Subject: subject, Drivers: append([]string(nil), c.Drivers...), Priority: c.Priority,
				})
			}
		case judgment.CapCorrelation:
			if c, ok := j.Claim.(judgment.CorrelationClaim); ok {
				insight.CorrelationNotes = append(insight.CorrelationNotes, ports.CorrelationNote{
					Subject: subject, Reporters: append([]string(nil), c.Reporters...), Missing: append([]string(nil), c.Missing...),
				})
			}
		}
	}
	// TOTAL comparators (tie-break down to every field) so the order is byte-reproducible even when a
	// subject carries multiple accepted judgments — reports are SHA-256-sealed + hash-chained, so an
	// unstable permutation of equal-subject rows would change the sealed bytes across regenerations.
	sort.Slice(insight.RiskRationales, func(a, b int) bool {
		x, y := insight.RiskRationales[a], insight.RiskRationales[b]
		if x.Subject != y.Subject {
			return x.Subject < y.Subject
		}
		if x.Priority != y.Priority {
			return x.Priority < y.Priority
		}
		return strings.Join(x.Drivers, ",") < strings.Join(y.Drivers, ",")
	})
	sort.Slice(insight.CorrelationNotes, func(a, b int) bool {
		x, y := insight.CorrelationNotes[a], insight.CorrelationNotes[b]
		if x.Subject != y.Subject {
			return x.Subject < y.Subject
		}
		if r := strings.Join(x.Reporters, ",") + "|" + strings.Join(x.Missing, ","); r != strings.Join(y.Reporters, ",")+"|"+strings.Join(y.Missing, ",") {
			return r < strings.Join(y.Reporters, ",")+"|"+strings.Join(y.Missing, ",")
		}
		return false
	})
}
