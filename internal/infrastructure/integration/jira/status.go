package jira

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketStatusWriter = (*Adapter)(nil)
var _ ports.TicketCommentWriter = (*Adapter)(nil)
var _ ports.TicketCommentReader = (*Adapter)(nil)
var _ ports.TicketReader = (*Adapter)(nil)
var _ ports.TicketIdentityReader = (*Adapter)(nil)

func (a *Adapter) TicketIdentity(ctx context.Context) (string, error) {
	return a.authenticatedIdentity(ctx)
}

func (a *Adapter) TransitionTicket(ctx context.Context, key, transitionID, comment string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !issueKeyPattern.MatchString(key) || !issueTypePattern.MatchString(transitionID) || a.containsCredential(key) || a.containsCredential(transitionID) || len(comment) > 16<<10 || a.containsCredential(comment) {
		return ticketError(0, "invalid_transition", 0, false)
	}
	payload := struct {
		Transition map[string]string `json:"transition"`
		Update     map[string]any    `json:"update,omitempty"`
	}{Transition: map[string]string{"id": transitionID}}
	if comment != "" {
		body, err := a.FormatTicketDescription(comment, nil)
		if err != nil {
			return err
		}
		payload.Update = map[string]any{"comment": []any{map[string]any{"add": map[string]any{"body": body}}}}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ticketError(0, "invalid_transition", 0, false)
	}
	if err = a.ValidateTicketPayload(raw); err != nil {
		return err
	}
	_, err = a.request(ctx, http.MethodPost, "/issue/"+key+"/transitions", nil, raw, nil, http.StatusNoContent)
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

type jiraComment struct {
	ID     string           `json:"id"`
	Author jiraStatusAuthor `json:"author"`
	Body   json.RawMessage  `json:"body"`
}

func (a *Adapter) CommentTicket(ctx context.Context, key, comment, author string) (ports.TicketCommentReceipt, error) {
	if !issueKeyPattern.MatchString(key) || a.containsCredential(key) || strings.TrimSpace(comment) == "" || len(comment) > 16<<10 || strings.TrimSpace(author) != author || author == "" || len(author) > 255 || a.containsCredential(comment) || a.containsCredential(author) {
		return ports.TicketCommentReceipt{}, ticketError(0, "invalid_comment", 0, false)
	}
	body, err := a.FormatTicketDescription(comment, nil)
	if err != nil {
		return ports.TicketCommentReceipt{}, err
	}
	raw, err := json.Marshal(struct {
		Body json.RawMessage `json:"body"`
	}{Body: body})
	if err != nil {
		return ports.TicketCommentReceipt{}, ticketError(0, "invalid_comment", 0, false)
	}
	var receipt jiraComment
	if _, err = a.request(ctx, http.MethodPost, "/issue/"+url.PathEscape(key)+"/comment", nil, raw, &receipt, http.StatusCreated); err != nil {
		return ports.TicketCommentReceipt{}, err
	}
	if !validCommentID(receipt.ID) {
		return ports.TicketCommentReceipt{}, ticketError(http.StatusCreated, "invalid_comment_receipt", 0, false)
	}
	var confirmed jiraComment
	if _, err = a.request(ctx, http.MethodGet, "/issue/"+url.PathEscape(key)+"/comment/"+url.PathEscape(receipt.ID), nil, nil, &confirmed, http.StatusOK); err != nil {
		// The POST already succeeded. A failed receipt read cannot distinguish a
		// missing comment from permission or replication lag, so it must remain
		// recoverable by an exact read rather than admitting a resend.
		return ports.TicketCommentReceipt{}, ambiguousCommentReceiptError(err)
	}
	if confirmed.ID != receipt.ID || !a.commentMatches(confirmed, body, commentMarker(comment), author) {
		return ports.TicketCommentReceipt{}, ticketError(http.StatusOK, "invalid_comment_receipt", 0, false)
	}
	return ports.TicketCommentReceipt{ID: receipt.ID}, nil
}

func ambiguousCommentReceiptError(err error) error {
	var classified *ports.TicketProviderError
	if errors.As(err, &classified) {
		copy := *classified
		copy.Ambiguous = true
		return &copy
	}
	return ticketError(0, "comment_receipt_unavailable", 0, true)
}

func (a *Adapter) FindTicketComment(ctx context.Context, key, expected, marker, author string) (bool, error) {
	if !issueKeyPattern.MatchString(key) || !markerPattern.MatchString(marker) || strings.TrimSpace(expected) == "" || len(expected) > 16<<10 || strings.TrimSpace(author) != author || author == "" || len(author) > 255 || a.containsCredential(key) || a.containsCredential(expected) || a.containsCredential(author) || !strings.Contains(expected, "["+marker+"]") {
		return false, ticketError(0, "invalid_comment_reconcile", 0, false)
	}
	body, err := a.FormatTicketDescription(expected, nil)
	if err != nil {
		return false, err
	}
	startAt := 0
	matches := 0
	complete := false
	for page := 0; page < maxPages; page++ {
		query := url.Values{"maxResults": {"50"}, "startAt": {fmt.Sprintf("%d", startAt)}}
		var result struct {
			Comments   []jiraComment `json:"comments"`
			Total      *int          `json:"total"`
			StartAt    *int          `json:"startAt"`
			MaxResults *int          `json:"maxResults"`
		}
		if _, err = a.request(ctx, http.MethodGet, "/issue/"+url.PathEscape(key)+"/comment", query, nil, &result, http.StatusOK); err != nil {
			return false, err
		}
		if len(result.Comments) > pageSize {
			return false, ticketError(http.StatusOK, "comment_truncated", 0, false)
		}
		for _, candidate := range result.Comments {
			if !validCommentID(candidate.ID) {
				return false, ticketError(http.StatusOK, "invalid_comment_response", 0, false)
			}
			var literal any
			if len(candidate.Body) == 0 || json.Unmarshal(candidate.Body, &literal) != nil || a.statusAuthor(candidate.Author) == "" {
				return false, ticketError(http.StatusOK, "invalid_comment_response", 0, false)
			}
			if a.commentMatches(candidate, body, marker, author) {
				matches++
			}
		}
		if result.Total == nil || result.StartAt == nil || result.MaxResults == nil || *result.Total < 0 || *result.StartAt != startAt || *result.MaxResults < len(result.Comments) || *result.Total > maxPages*pageSize || *result.StartAt > *result.Total || len(result.Comments) > *result.Total-*result.StartAt {
			return false, ticketError(http.StatusOK, "comment_truncated", 0, false)
		}
		if startAt+len(result.Comments) >= *result.Total {
			complete = true
			break
		}
		if len(result.Comments) == 0 {
			return false, ticketError(http.StatusOK, "comment_truncated", 0, false)
		}
		startAt += len(result.Comments)
	}
	if !complete {
		return false, ticketError(http.StatusOK, "comment_truncated", 0, false)
	}
	if matches > 1 {
		return false, ticketError(http.StatusOK, "comment_ambiguous", 0, false)
	}
	return matches == 1, nil
}

func validCommentID(id string) bool {
	if id == "" || len(id) > 255 || strings.TrimSpace(id) != id {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func commentMarker(comment string) string {
	const prefix = "[synapse-intent-"
	start := strings.LastIndex(comment, prefix)
	if start < 0 {
		return ""
	}
	rest := comment[start+1:]
	end := strings.IndexByte(rest, ']')
	if end < 0 {
		return ""
	}
	marker := rest[:end]
	if markerPattern.MatchString(marker) {
		return marker
	}
	return ""
}

func (a *Adapter) commentMatches(candidate jiraComment, expectedBody json.RawMessage, marker, author string) bool {
	if marker == "" || !markerPattern.MatchString(marker) || a.statusAuthor(candidate.Author) != author || len(candidate.Body) == 0 || !jsonBodyEqual(candidate.Body, expectedBody) {
		return false
	}
	return true
}

func jsonBodyEqual(actual, expected json.RawMessage) bool {
	var left, right any
	return json.Unmarshal(actual, &left) == nil && json.Unmarshal(expected, &right) == nil && reflect.DeepEqual(left, right)
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
