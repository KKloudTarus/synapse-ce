package jira

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketUpdater = (*Adapter)(nil)

func (a *Adapter) UpdateTicket(ctx context.Context, key string, payload json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !issueKeyPattern.MatchString(key) || a.containsCredential(key) {
		return ticketError(0, "invalid_issue_key", 0, false)
	}
	if err := a.ValidateTicketPayload(payload); err != nil {
		return err
	}
	var envelope map[string]json.RawMessage
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil || len(envelope) != 1 || json.Unmarshal(envelope["fields"], &fields) != nil || len(fields) == 0 {
		return ticketError(0, "invalid_update_payload", 0, false)
	}
	// Changing identity needs a separate governed move, not a group membership edit.
	for _, name := range []string{"project", "issuetype", "reporter", "assignee", "id", "key", "self"} {
		if _, ok := fields[name]; ok {
			return ticketError(0, "immutable_issue_field", 0, false)
		}
	}
	_, err := a.request(ctx, http.MethodPut, "/issue/"+key, nil, payload, nil, http.StatusNoContent)
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
	// Cancellation after dispatch may have lost an accepted PUT acknowledgement.
	// Return only a classification; transport diagnostics may contain credentials.
	return ticketError(0, "network", 0, true)
}
