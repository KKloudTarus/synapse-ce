// Package correlationuc is the Phase-C orchestration seam (#594 C2/C3): it reads an engagement's sealed
// detections, folds them into incidents with the deterministic domain correlator, persists the new
// incidents (idempotently), and — when a tri-score reassessor is wired — scores each freshly created
// incident so a correlated incident lands with its RiskAssessment already computed. It is the caller that
// turns the built-but-dormant correlator + incident store + tri-score assembler into a running
// detection → incident → risk pipeline.
//
// Discipline: incident creation is the durable, must-succeed step; the tri-score pass is a best-effort
// enhancement over an already-persisted incident, so a scoring failure never rolls back a recorded
// incident — it is counted (ReassessFailed) and surfaced, never silently swallowed and never fatal.
package correlationuc

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DetectionReader lists an engagement's sealed detection records (tenant-scoped via ctx).
// ports.DetectionRecordStore satisfies it.
type DetectionReader interface {
	ListDetections(ctx context.Context, engagementID shared.ID) ([]detection.Record, error)
}

// IncidentRecorder persists correlator output as new incidents, idempotently. incidentuc.Service
// satisfies it.
type IncidentRecorder interface {
	RecordCorrelation(ctx context.Context, events []incident.IncidentEvent) ([]incident.Incident, error)
}

// RiskReassessor runs the tri-score assembler for one incident. riskscoreuc.Service satisfies it. Optional:
// a nil reassessor records incidents without a scoring pass (correlation still succeeds).
type RiskReassessor interface {
	Reassess(ctx context.Context, actor string, incidentID shared.ID) (incident.Incident, error)
}

// Result reports what one correlation pass produced. Created is the incidents newly recorded this pass;
// Reassessed/ReassessFailed account for the best-effort tri-score pass over them.
type Result struct {
	Created        []incident.Incident
	Reassessed     int
	ReassessFailed int
}

// Service correlates an engagement's detections into scored incidents.
type Service struct {
	detections DetectionReader
	incidents  IncidentRecorder
	reassessor RiskReassessor // may be nil
	cfg        correlation.Config
	audit      ports.AuditLogger
	now        func() time.Time
}

// NewService constructs the orchestrator. detections, incidents, audit and now are required; reassessor is
// optional. cfg must be a valid correlation.Config (Window > 0, MaxPerIncident > 0).
func NewService(detections DetectionReader, incidents IncidentRecorder, reassessor RiskReassessor, cfg correlation.Config, audit ports.AuditLogger, now func() time.Time) (*Service, error) {
	switch {
	case detections == nil:
		return nil, fmt.Errorf("%w: correlation requires a detection reader", shared.ErrValidation)
	case incidents == nil:
		return nil, fmt.Errorf("%w: correlation requires an incident recorder", shared.ErrValidation)
	case audit == nil:
		return nil, fmt.Errorf("%w: correlation requires an audit logger", shared.ErrValidation)
	case now == nil:
		return nil, fmt.Errorf("%w: correlation requires a clock", shared.ErrValidation)
	case cfg.Window <= 0:
		return nil, fmt.Errorf("%w: correlation window must be positive", shared.ErrValidation)
	case cfg.MaxPerIncident <= 0:
		return nil, fmt.Errorf("%w: correlation max-per-incident must be positive", shared.ErrValidation)
	}
	return &Service{detections: detections, incidents: incidents, reassessor: reassessor, cfg: cfg, audit: audit, now: now}, nil
}

// CorrelateEngagement reads the engagement's detections, correlates them into incidents, records the new
// ones, and (best-effort) tri-scores each. It is idempotent: the correlator mints deterministic incident
// ids, so a re-run over the same detections records nothing new and reassesses nothing.
func (s *Service) CorrelateEngagement(ctx context.Context, actor string, engagementID shared.ID) (Result, error) {
	if actor == "" {
		return Result{}, fmt.Errorf("%w: correlation requires an actor", shared.ErrValidation)
	}
	if engagementID.IsZero() {
		return Result{}, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	records, err := s.detections.ListDetections(ctx, engagementID)
	if err != nil {
		return Result{}, fmt.Errorf("list detections: %w", err)
	}
	events, err := correlation.Correlate(s.cfg, signalsFromDetections(records))
	if err != nil {
		return Result{}, fmt.Errorf("correlate: %w", err)
	}
	created, err := s.incidents.RecordCorrelation(ctx, events)
	if err != nil {
		return Result{}, fmt.Errorf("record correlation: %w", err)
	}

	res := Result{Created: created}
	// Best-effort tri-score pass. A scoring failure never rolls back a durably-recorded incident; it is
	// counted so a caller sees that scoring was partial.
	if s.reassessor != nil {
		for i, inc := range created {
			scored, rerr := s.reassessor.Reassess(ctx, actor, inc.ID)
			if rerr != nil {
				res.ReassessFailed++
				continue
			}
			created[i] = scored
			res.Reassessed++
		}
	}

	entry := ports.AuditEntry{
		Actor: actor, Action: "fleet.correlate_engagement", Target: engagementID.String(), At: s.now().UTC(),
		Metadata: map[string]string{
			"detections":      strconv.Itoa(len(records)),
			"created":         strconv.Itoa(len(created)),
			"reassessed":      strconv.Itoa(res.Reassessed),
			"reassess_failed": strconv.Itoa(res.ReassessFailed),
		},
	}
	if err := s.audit.Record(ctx, entry); err != nil {
		return res, fmt.Errorf("audit correlate: %w", err)
	}
	return res, nil
}

// signalsFromDetections maps sealed detection records to correlation signals. The entity is the host the
// detection was observed on, so detections on one host within the window fold into one incident; the
// title is the detection's class + rule for a human-readable incident summary.
func signalsFromDetections(records []detection.Record) []correlation.Signal {
	signals := make([]correlation.Signal, 0, len(records))
	for _, r := range records {
		d := r.Detection
		signals = append(signals, correlation.Signal{
			ID:         r.ID,
			AssetID:    r.AssetID,
			EntityID:   d.HostID,
			OccurredAt: d.Observed,
			Severity:   d.Severity,
			RuleID:     d.RuleID,
			Title:      string(d.Class) + ": " + d.RuleID,
		})
	}
	return signals
}
