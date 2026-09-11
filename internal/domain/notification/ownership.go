package notification

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// OwnershipChanged is the version 1 public event payload. It deliberately omits
// source content, paths, legacy free-text assignees and policy evidence. IDs refer
// to resources in the event's tenant; clients construct links using their own base URL.
type OwnershipChanged struct {
	Title         string    `json:"title"`
	Summary       string    `json:"summary"`
	DecisionID    shared.ID `json:"decision_id"`
	FindingID     shared.ID `json:"finding_id"`
	EngagementID  shared.ID `json:"engagement_id"`
	OldTeamID     shared.ID `json:"old_team_id"`
	NewTeamID     shared.ID `json:"new_team_id"`
	OldAssigneeID shared.ID `json:"old_assignee_id"`
	NewAssigneeID shared.ID `json:"new_assignee_id"`
	Actor         string    `json:"actor"`
	Reason        string    `json:"reason"`
}

func (r *Rule) normalizeTeamScope() error {
	if r.EventType != EventOwnershipChanged {
		if len(r.TeamIDs) > 0 || r.AllTeams {
			return fmt.Errorf("%w: team scope only applies to ownership events", shared.ErrValidation)
		}
		return nil
	}
	// Fail closed: a blank/malformed filter must never become a tenant-wide rule.
	if len(r.TeamIDs) > 200 || r.AllTeams == (len(r.TeamIDs) > 0) {
		return fmt.Errorf("%w: choose team IDs or explicitly subscribe to all teams", shared.ErrValidation)
	}
	for _, id := range r.TeamIDs {
		if id.IsZero() || len(id.String()) > 200 || strings.TrimSpace(id.String()) != id.String() {
			return fmt.Errorf("%w: invalid notification team ID", shared.ErrValidation)
		}
	}
	r.TeamIDs = uniqueIDs(r.TeamIDs)
	return nil
}

func (r Rule) matchesOwnership(e Event) bool {
	var data OwnershipChanged
	if json.Unmarshal(e.Data, &data) != nil || data.DecisionID.IsZero() || data.FindingID.IsZero() || data.EngagementID != e.EngagementID {
		return false
	}
	if r.AllTeams {
		return len(r.TeamIDs) == 0
	}
	return !data.OldTeamID.IsZero() && containsID(r.TeamIDs, data.OldTeamID) ||
		!data.NewTeamID.IsZero() && containsID(r.TeamIDs, data.NewTeamID)
}
