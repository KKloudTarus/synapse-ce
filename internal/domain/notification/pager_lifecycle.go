package notification

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// PagerLifecycle identifies the source occurrence at capture time. Zero is a legacy event.
type PagerLifecycle struct {
	Episode  int64
	Revision int64
	Terminal bool
}

func (p PagerLifecycle) validate(eventType EventType, subjectKind, subjectID string) error {
	if p == (PagerLifecycle{}) {
		return nil
	}
	validType := false
	switch subjectKind {
	case "finding":
		switch eventType {
		case EventFindingCreated, EventFindingStatusChanged, EventFindingRetestCompleted, EventFindingCommented, EventFindingMentioned:
			validType = true
		}
	case "incident":
		validType = eventType == EventIncidentCreated || eventType == EventIncidentUpdated
	}
	if !validType || strings.TrimSpace(subjectID) == "" || p.Episode <= 0 || p.Revision <= 0 {
		return fmt.Errorf("%w: invalid pager lifecycle metadata", shared.ErrValidation)
	}
	return nil
}
