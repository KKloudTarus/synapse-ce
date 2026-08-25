package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// detectionFieldScope is the A6 on-plane field authorization decision for detection/hunt-style reads.
// Coarse route admission remains at Router.authz(PermView); this second, subtract-only decision controls
// whether direct-value evidence fields may leave the HTTP boundary. It deliberately reuses the existing
// role capabilities instead of inventing a parallel permission lattice that could drift from authz.
type detectionFieldScope string

const (
	detectionFieldScopeRestricted detectionFieldScope = "restricted"
	detectionFieldScopeFull       detectionFieldScope = "full"
	detectionFieldScopeSummary    detectionFieldScope = "summary"
)

// detectionFieldScopeFor derives field visibility from the same Role.Can capability table used by the
// single authz chokepoint. A pure read-only principal may see detection metadata but not direct-value
// evidence. Roles that already hold an investigative/mutating/review capability may see the source-side
// redacted evidence. Unknown/machine roles fail closed even if this helper is ever called outside authz.
func detectionFieldScopeFor(ctx context.Context) (detectionFieldScope, error) {
	p, ok := principalObj(ctx)
	if !ok {
		return "", fmt.Errorf("%w: detection field authorization requires an authenticated principal", shared.ErrForbidden)
	}
	role := userdom.Role(p.Role)
	if !role.Can(userdom.PermView) {
		return "", fmt.Errorf("%w: detection field authorization requires view permission", shared.ErrForbidden)
	}
	if role.Can(userdom.PermOperate) || role.Can(userdom.PermReview) || role.Can(userdom.PermAdminister) {
		return detectionFieldScopeFull, nil
	}
	return detectionFieldScopeRestricted, nil
}

// projectDetectionRecords returns a deep copy of the query result. Restricted scope strips fields whose
// direct values can carry user/host-sensitive material while preserving structural metadata needed to
// understand that evidence exists. The source-side A6 scrub remains the first privacy layer; this is a
// second, subtract-only authorization layer and can never restore a value already redacted at source.
func projectDetectionRecords(records []detection.Record, scope detectionFieldScope) []detection.Record {
	out := make([]detection.Record, len(records))
	for i, record := range records {
		out[i] = record
		evidence := make([]detection.Event, len(record.Detection.Evidence))
		for j, event := range record.Detection.Evidence {
			evidence[j] = projectDetectionEvent(event, scope)
		}
		out[i].Detection.Evidence = evidence
	}
	return out
}

func projectDetectionEvent(event detection.Event, scope detectionFieldScope) detection.Event {
	out := event
	if event.Process != nil {
		process := *event.Process
		process.Args = append([]string(nil), event.Process.Args...)
		if scope == detectionFieldScopeRestricted {
			process.Path = ""
			process.Args = nil
			process.Comm = ""
		}
		out.Process = &process
	}
	if event.Network != nil {
		network := *event.Network
		if scope == detectionFieldScopeRestricted {
			network.RemoteAddr = ""
			network.Comm = ""
		}
		out.Network = &network
	}
	if event.File != nil {
		file := *event.File
		if scope == detectionFieldScopeRestricted {
			file.Path = ""
			file.Comm = ""
		}
		out.File = &file
	}
	if event.Privilege != nil {
		privilege := *event.Privilege
		if scope == detectionFieldScopeRestricted {
			privilege.Comm = ""
		}
		out.Privilege = &privilege
	}
	return out
}

// auditDetectionQuery records the governed read BEFORE any query executes. Query audit is mandatory for
// this A6 surface: an unavailable audit sink fails closed, so raw evidence can never be returned from an
// unaudited read. Router.vulnerabilityAudit is the existing writable append-only audit port wired by the
// composition root; despite the historical field name it points at the shared audit log used system-wide.
func (rt *Router) auditDetectionQuery(ctx context.Context, engagementID shared.ID, view string, scope detectionFieldScope) error {
	p, ok := principalObj(ctx)
	if !ok {
		return fmt.Errorf("%w: detection query audit requires an authenticated principal", shared.ErrForbidden)
	}
	if rt.vulnerabilityAudit == nil {
		return fmt.Errorf("%w: detection query audit sink is not configured", shared.ErrSaturated)
	}
	if err := rt.vulnerabilityAudit.Record(ctx, ports.AuditEntry{
		Actor:  p.ID,
		Action: "detection.query",
		Target: engagementID.String(),
		At:     time.Now().UTC(),
		Metadata: map[string]string{
			"view":        view,
			"field_scope": string(scope),
		},
	}); err != nil {
		return fmt.Errorf("%w: record detection query audit: %v", shared.ErrSaturated, err)
	}
	return nil
}
