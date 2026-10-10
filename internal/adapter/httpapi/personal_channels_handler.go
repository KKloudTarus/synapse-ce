package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	inboxuc "github.com/KKloudTarus/synapse-ce/internal/usecase/inbox"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/teamslink"
)

// Personal channels (#1418, #1419, #1420): tenant defaults for administrators, the Slack and Teams
// link flows in the signed-in person's profile, and the Teams bot's messaging endpoint.

// SetTeamsLink wires Microsoft Teams personal delivery (#1420): the profile link route and the bot
// endpoint, verified by verifier.
func (rt *Router) SetTeamsLink(service *teamslink.Service, verifier ports.TeamsActivityVerifier) {
	rt.teamsLink, rt.teamsVerifier = service, verifier
}

// listPersonalDefaults serves the tenant defaults of every external personal channel.
func (rt *Router) listPersonalDefaults(w http.ResponseWriter, r *http.Request) {
	if rt.inbox == nil {
		writeError(w, rt.log, shared.ErrNotFound)
		return
	}
	items, err := rt.inbox.PersonalDefaults(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// savePersonalDefault changes one tenant default.
func (rt *Router) savePersonalDefault(w http.ResponseWriter, r *http.Request) {
	if rt.inbox == nil {
		writeError(w, rt.log, shared.ErrNotFound)
		return
	}
	var in inboxuc.PersonalDefaultInput
	if err := decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.inbox.SavePersonalDefault(r.Context(), shared.ID(TenantFrom(r.Context())), PrincipalFrom(r.Context()), in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// personalChannelsView tells the profile which personal channels this deployment can link.
type personalChannelsView struct {
	Slack struct {
		Available  bool                            `json:"available"`
		Workspaces []notificationuc.SlackWorkspace `json:"workspaces"`
	} `json:"slack"`
	Teams struct {
		Available bool `json:"available"`
	} `json:"teams"`
}

// getMyPersonalChannels lists the Slack workspaces the tenant has an app in and whether Teams is
// set up. It names no channel, token or bot credential.
func (rt *Router) getMyPersonalChannels(w http.ResponseWriter, r *http.Request) {
	var view personalChannelsView
	view.Slack.Workspaces = []notificationuc.SlackWorkspace{}
	if rt.notifications != nil {
		workspaces, err := rt.notifications.SlackWorkspaces(r.Context())
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		view.Slack.Workspaces = workspaces
		view.Slack.Available = len(workspaces) > 0
	}
	view.Teams.Available = rt.teamsLink != nil
	writeJSON(w, http.StatusOK, view)
}

// linkMyTeams claims a Teams link code for the signed-in person.
func (rt *Router) linkMyTeams(w http.ResponseWriter, r *http.Request) {
	if rt.teamsLink == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "microsoft teams linking is unavailable"})
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid Teams link request"})
		return
	}
	tenantID, userID := myContactScope(r)
	contact, err := rt.teamsLink.Link(r.Context(), tenantID, userID, body.Code)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, contact)
}

// teamsBotBodyCap bounds an inbound activity. A message activity is a few kilobytes.
const teamsBotBodyCap = 256 << 10

// handleTeamsActivity is the bot's messaging endpoint. It sits outside the human auth chain: the
// Bot Framework JWT is the only credential, verified against the activity's own service URL before
// anything else is read. Every refusal is the same 401, and every accepted activity answers 200 so
// the Bot Framework does not retry.
func (rt *Router) handleTeamsActivity(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, teamsBotBodyCap))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "activity too large"})
		return
	}
	var activity struct {
		Type         string `json:"type"`
		Text         string `json:"text"`
		ServiceURL   string `json:"serviceUrl"`
		Conversation struct {
			ID               string `json:"id"`
			ConversationType string `json:"conversationType"`
			TenantID         string `json:"tenantId"`
		} `json:"conversation"`
		From struct {
			AADObjectID string `json:"aadObjectId"`
		} `json:"from"`
	}
	if json.Unmarshal(raw, &activity) != nil {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthorized"})
		return
	}
	if err := rt.teamsVerifier.Verify(r.Context(), r.Header.Get("Authorization"), activity.ServiceURL); err != nil {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthorized"})
		return
	}
	err = rt.teamsLink.HandleActivity(r.Context(), ports.TeamsActivity{
		Type: activity.Type, Text: activity.Text, ServiceURL: activity.ServiceURL,
		ConversationID: activity.Conversation.ID, ConversationType: activity.Conversation.ConversationType,
		FromObjectID: activity.From.AADObjectID, TenantID: activity.Conversation.TenantID,
	})
	if err != nil {
		// The reply failed; the person can message the bot again. Nothing about it is returned.
		rt.log.Warn("teams bot activity not answered", "error", errorCode(err))
	}
	w.WriteHeader(http.StatusOK)
}

// errorCode keeps only the first word of an error for a log line, so no detail of a provider
// reply is logged.
func errorCode(err error) string {
	var coder ports.TeamsErrorCoder
	if errors.As(err, &coder) {
		return coder.TeamsResult().ErrorCode
	}
	text := err.Error()
	if i := strings.IndexAny(text, ":\n"); i > 0 {
		return text[:i]
	}
	return text
}
