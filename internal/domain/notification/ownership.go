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

func (r *Rule) normalizeTeamScope(selected []EventType, specs []EventSpec) error {
	teamScoped := false
	for _, spec := range specs {
		if spec.Allows(FilterTeams) {
			teamScoped = true
			break
		}
	}
	if !teamScoped {
		if len(r.TeamIDs) > 0 || r.AllTeams {
			return requireAllFilters(selected, specs, FilterTeams, "team scope")
		}
		return nil
	}
	// A selected team-capable event must retain the existing explicit-scope invariant. If another
	// selected event cannot carry that scope, it is rejected below instead of silently never matching.
	if len(r.TeamIDs) == 0 && !r.AllTeams {
		return fmt.Errorf("%w: choose team IDs or explicitly subscribe to all teams", shared.ErrValidation)
	}
	if err := requireAllFilters(selected, specs, FilterTeams, "team scope"); err != nil {
		return err
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

// matchesTeams applies the team scope. Ownership keeps its old/new semantics;
// lifecycle and finding events carry the event-time team_id source fact.
func (r Rule) matchesTeams(e Event) bool {
	if e.Type == EventOwnershipChanged {
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
	if r.AllTeams {
		if len(r.TeamIDs) != 0 {
			return false
		}
		var data struct {
			TeamID shared.ID `json:"team_id"`
		}
		return json.Unmarshal(e.Data, &data) == nil
	}
	var data struct {
		TeamID shared.ID `json:"team_id"`
	}
	return json.Unmarshal(e.Data, &data) == nil && !data.TeamID.IsZero() && containsID(r.TeamIDs, data.TeamID)
}
