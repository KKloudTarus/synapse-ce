// Package privacyexport assembles a data-subject / DPO data-export bundle for one engagement (#635): the
// governance-relevant data the control plane holds — the detection projection rows + the engagement's
// active legal holds + a generated-at stamp — in a structured, read-only export. It answers a
// subject-access / data-portability request without mutating anything; the immutable evidence chain is
// unaffected (and, being source-side redacted, carries no raw PII).
package privacyexport

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/legalhold"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DetectionReader lists an engagement's detection projection rows (tenant-scoped via ctx).
// ports.DetectionRecordStore satisfies it.
type DetectionReader interface {
	ListDetections(ctx context.Context, engagementID shared.ID) ([]detection.Record, error)
}

// HoldReader lists the tenant's active legal holds. legalholduc.Service satisfies it.
type HoldReader interface {
	ListActive(ctx context.Context) ([]legalhold.Hold, error)
}

// Bundle is the structured export for one engagement.
type Bundle struct {
	EngagementID shared.ID          `json:"engagement_id"`
	GeneratedAt  time.Time          `json:"generated_at"`
	Detections   []detection.Record `json:"detections"`
	LegalHolds   []legalhold.Hold   `json:"legal_holds"` // active holds covering this engagement's data
	Count        int                `json:"detection_count"`
}

// Service assembles the export.
type Service struct {
	detections DetectionReader
	holds      HoldReader
	audit      ports.AuditLogger
	now        func() time.Time
}

// NewService constructs the exporter. holds is optional (nil ⇒ no hold section); the rest are required.
func NewService(detections DetectionReader, holds HoldReader, audit ports.AuditLogger, now func() time.Time) (*Service, error) {
	if detections == nil || audit == nil || now == nil {
		return nil, fmt.Errorf("%w: privacy export needs a detection reader, an audit logger and a clock", shared.ErrValidation)
	}
	return &Service{detections: detections, holds: holds, audit: audit, now: now}, nil
}

// Export gathers the engagement's detection projection + active legal holds into a read-only bundle. The
// export itself is an audited access (a subject-access request is a governance event), but reads nothing
// it should not and mutates nothing.
func (s *Service) Export(ctx context.Context, actor string, engagementID shared.ID) (Bundle, error) {
	if actor == "" {
		return Bundle{}, fmt.Errorf("%w: a data export requires an actor", shared.ErrValidation)
	}
	if engagementID.IsZero() {
		return Bundle{}, fmt.Errorf("%w: a data export requires an engagement id", shared.ErrValidation)
	}
	recs, err := s.detections.ListDetections(ctx, engagementID)
	if err != nil {
		return Bundle{}, fmt.Errorf("list detections: %w", err)
	}
	var holds []legalhold.Hold
	if s.holds != nil {
		all, herr := s.holds.ListActive(ctx)
		if herr != nil {
			return Bundle{}, fmt.Errorf("list legal holds: %w", herr)
		}
		for _, h := range all {
			if h.EngagementID == engagementID {
				holds = append(holds, h)
			}
		}
	}
	at := s.now().UTC()
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: "fleet.privacy.data_export", Target: engagementID.String(), At: at,
		Metadata: map[string]string{"engagement": engagementID.String(), "detections": fmt.Sprint(len(recs))},
	}); err != nil {
		return Bundle{}, fmt.Errorf("audit data export: %w", err)
	}
	return Bundle{EngagementID: engagementID, GeneratedAt: at, Detections: recs, LegalHolds: holds, Count: len(recs)}, nil
}
