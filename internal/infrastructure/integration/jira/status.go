package jira

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketStatusWriter = (*Adapter)(nil)
var _ ports.TicketReader = (*Adapter)(nil)
var _ ports.TicketIdentityReader = (*Adapter)(nil)

func (a *Adapter) TicketIdentity(ctx context.Context) (string, error) {
	return a.authenticatedIdentity(ctx)
}

func (a *Adapter) TransitionTicket(ctx context.Context, key, transitionID, comment string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !issueKeyPattern.MatchString(key) || !issueTypePattern.MatchString(transitionID) || a.containsCredential(key) || a.containsCredential(transitionID) || strings.TrimSpace(comment) == "" || len(comment) > 16<<10 {
		return ticketError(0, "invalid_transition", 0, false)
	}
	body, err := a.FormatTicketDescription(comment, nil)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		Transition map[string]string `json:"transition"`
		Update     map[string]any    `json:"update"`
	}{map[string]string{"id": transitionID}, map[string]any{"comment": []any{map[string]any{"add": map[string]any{"body": body}}}}})
	if err != nil {
		return ticketError(0, "invalid_transition", 0, false)
	}
	if err = a.ValidateTicketPayload(payload); err != nil {
		return err
	}
	_, err = a.request(ctx, http.MethodPost, "/issue/"+key+"/transitions", nil, payload, nil, http.StatusNoContent)
	if err == nil {
		return nil
	}
	var classified *ports.TicketProviderError
	if errors.As(err, &classified) {
		if classified.Status >= 200 && classified.Status < 300 {
			copy := *classified
			copy.Ambiguous = true
			return &copy
		}
		return err
	}
	return ticketError(0, "network", 0, true)
}

func (a *Adapter) GetTicket(ctx context.Context, key string) (ports.TicketObservation, error) {
	if !issueKeyPattern.MatchString(key) || a.containsCredential(key) {
		return ports.TicketObservation{}, ticketError(0, "invalid_issue_key", 0, false)
	}
	var out struct {
		Key    string `json:"key"`
		Fields struct {
			Updated string           `json:"updated"`
			Created string           `json:"created"`
			Creator jiraStatusAuthor `json:"creator"`
			Status  struct {
				ID       string `json:"id"`
				Category struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
			Resolution *struct {
				Name string `json:"name"`
			} `json:"resolution"`
		} `json:"fields"`
		Changelog *struct {
			Total     int                 `json:"total"`
			Histories []jiraStatusHistory `json:"histories"`
		} `json:"changelog"`
	}
	_, err := a.request(ctx, http.MethodGet, "/issue/"+key, url.Values{"fields": {"status,updated,resolution,created,creator"}, "expand": {"changelog"}}, nil, &out, http.StatusOK)
	if err != nil {
		// Jira deliberately uses 404 for both deleted and unreadable issues. Keep
		// the distinction unknown; neither outcome permits a finding mutation.
		var refusal *ports.TicketProviderError
		if errors.As(err, &refusal) && refusal.Status == http.StatusNotFound {
			return ports.TicketObservation{ExternalID: key, Deleted: true}, nil
		}
		return ports.TicketObservation{}, err
	}
	if out.Key != key || a.containsCredential(out.Key) {
		return ports.TicketObservation{}, ticketError(200, "invalid_issue_response", 0, false)
	}
	category := out.Fields.Status.Category.Key
	if category != "new" && category != "indeterminate" && category != "done" {
		return ports.TicketObservation{}, ticketError(200, "invalid_status_category", 0, false)
	}
	updated, err := parseJiraTime(out.Fields.Updated)
	if err != nil {
		return ports.TicketObservation{}, ticketError(200, "invalid_updated_time", 0, false)
	}
	observation := ports.TicketObservation{ExternalID: key, StatusCategory: category, UpdatedAt: updated}
	if out.Changelog != nil {
		var latest jiraStatusHistory
		var latestAt time.Time
		ambiguous := false
		for _, history := range out.Changelog.Histories {
			for _, item := range history.Items {
				if item.FieldID != "status" && item.Field != "status" {
					continue
				}
				at, e := parseJiraTime(history.Created)
				if e != nil || at.After(updated) {
					ambiguous = true
					continue
				}
				if at.Equal(latestAt) {
					ambiguous = true
				}
				if !at.After(latestAt) {
					continue
				}
				latest, latestAt = history, at
			}
		}
		if !ambiguous && !latestAt.IsZero() {
			for _, item := range latest.Items {
				if (item.FieldID == "status" || item.Field == "status") && item.To != "" && item.To == out.Fields.Status.ID {
					observation.AuthorID = a.statusAuthor(latest.Author)
					observation.StatusChangedAt = latestAt
				}
			}
		} else if out.Changelog.Total == 0 && len(out.Changelog.Histories) == 0 {
			if at, e := parseJiraTime(out.Fields.Created); e == nil && !at.After(updated) {
				observation.AuthorID = a.statusAuthor(out.Fields.Creator)
				observation.StatusChangedAt = at
			}
		}
	}
	if out.Fields.Resolution != nil {
		name := out.Fields.Resolution.Name
		if len(name) > 255 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || a.containsCredential(name) {
			return ports.TicketObservation{}, ticketError(200, "unsafe_provider_response", 0, false)
		}
		observation.ResolutionName = redact.String(name, nil)
	}
	return observation, nil
}

type jiraStatusAuthor struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
}
type jiraStatusHistory struct {
	Created string           `json:"created"`
	Author  jiraStatusAuthor `json:"author"`
	Items   []struct {
		Field   string `json:"field"`
		FieldID string `json:"fieldId"`
		To      string `json:"to"`
	} `json:"items"`
}

func (a *Adapter) statusAuthor(author jiraStatusAuthor) string {
	id := author.Name
	if a.cloud {
		id = author.AccountID
	}
	if id == "" || strings.TrimSpace(id) != id || len(id) > 255 || !utf8.ValidString(id) || strings.ContainsRune(id, 0) || a.containsCredential(id) {
		return ""
	}
	return id
}

func parseJiraTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999-0700"} {
		if at, err := time.Parse(layout, value); err == nil {
			return at.UTC(), nil
		}
	}
	return time.Time{}, errors.New("invalid Jira timestamp")
}
