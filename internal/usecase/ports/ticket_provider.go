package ports

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
)

type TicketChoice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type TicketField struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Required   bool           `json:"required"`
	Values     []TicketChoice `json:"values"`
	Type       string         `json:"type,omitempty"`
	ItemType   string         `json:"item_type,omitempty"`
	HasDefault bool           `json:"has_default"`
}

type TicketMetadata struct {
	Projects       []TicketChoice `json:"projects"`
	IssueTypes     []TicketChoice `json:"issue_types"`
	Priorities     []TicketChoice `json:"priorities"`
	SecurityLevels []TicketChoice `json:"security_levels"`
	Components     []TicketChoice `json:"components"`
	Fields         []TicketField  `json:"fields"`
	Transitions    []TicketChoice `json:"transitions"`
	// ResolvedReporter is the authenticated Jira DC identity. It is populated
	// only when a required reporter user field has no Jira default.
	ResolvedReporter string `json:"resolved_reporter,omitempty"`
}

// TicketProvider is a capability of an adapter in the shared integration registry.
// A marker search is bounded, verifies the exact label, and never proves absence.
type TicketProvider interface {
	DiscoverTickets(context.Context, string, string, string) (TicketMetadata, error)
	FormatTicketDescription(string, []RenderedLink) (json.RawMessage, error)
	// ValidateTicketPayload refuses configured credential material without returning
	// secrets to the application layer. It performs no provider request.
	ValidateTicketPayload(json.RawMessage) error
	CreateTicket(context.Context, json.RawMessage) (ticketing.RemoteTicket, error)
	SearchTicketMarker(context.Context, string, string, string) ([]ticketing.RemoteTicket, error)
}

// TicketProviderError contains classifications only, never a URL, response body or credential.
type TicketProviderError struct {
	Status     int
	Code       string
	RetryAfter time.Duration
	Ambiguous  bool
}

func (e *TicketProviderError) Error() string { return fmt.Sprintf("Jira request failed (%s)", e.Code) }
