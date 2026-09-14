package sca

import (
	"context"
	"errors"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AddReachabilityRecorder composes an additional deterministic reachability recorder onto the scan pass.
// Each recorder runs independently over the same subjects/target: a no-coverage failure from one must not
// prevent another language engine from producing a positive proof. The scan pipeline already treats the
// aggregate recorder as best-effort; joined errors preserve diagnostics without changing that contract.
func (s *Service) AddReachabilityRecorder(r ports.ReachabilityRecorder) {
	if r == nil {
		return
	}
	if s.reachability == nil {
		s.reachability = r
		return
	}
	if multi, ok := s.reachability.(*multiReachabilityRecorder); ok {
		multi.recorders = append(multi.recorders, r)
		return
	}
	s.reachability = &multiReachabilityRecorder{recorders: []ports.ReachabilityRecorder{s.reachability, r}}
}

type multiReachabilityRecorder struct {
	recorders []ports.ReachabilityRecorder
}

var _ ports.ReachabilityRecorder = (*multiReachabilityRecorder)(nil)

func (m *multiReachabilityRecorder) Record(ctx context.Context, engagementID shared.ID, targetRef string, subjects []ports.ReachabilitySubject) (int, error) {
	minted := 0
	var errs []error
	for _, recorder := range m.recorders {
		if recorder == nil {
			continue
		}
		n, err := recorder.Record(ctx, engagementID, targetRef, subjects)
		minted += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return minted, errors.Join(errs...)
}
