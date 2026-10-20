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
	// SecurityPolicy is the single provider-native visibility policy accepted by
	// a non-Jira ticket provider, such as private_repository,
	// confidential_issue, or provider_access. Jira continues to use
	// SecurityLevels.
	SecurityPolicy string `json:"security_policy,omitempty"`
	// These flags are explicit for native providers. The ticket workflow fills
	// Jira's historical capabilities when a legacy Jira adapter returns zeroes.
	SupportsGrouping          bool `json:"supports_grouping"`
	SupportsStatusSync        bool `json:"supports_status_sync"`
	SupportsStatusTransitions bool `json:"supports_status_transitions"`
	// ResolvedReporter is the authenticated Jira DC identity. It is populated
	// only when a required reporter user field has no Jira default.
	ResolvedReporter string `json:"resolved_reporter,omitempty"`
}

// TicketMarkerStrategy describes the one code-owned, reversible marker mutation
// that Submit may make to a preview's immutable provider wire payload.
type TicketMarkerStrategy string

const (
	TicketMarkerJSONArray    TicketMarkerStrategy = "json_array"
	TicketMarkerTag          TicketMarkerStrategy = "tag"
	TicketMarkerScalar       TicketMarkerStrategy = "scalar"
	TicketMarkerTextSuffix   TicketMarkerStrategy = "text_suffix"
	TicketMarkerJSONPatchAdd TicketMarkerStrategy = "json_patch_add"
)

// TicketMarkerDescriptor freezes the target and representation of an intent
// marker. Path is a JSON object path for every strategy except json_patch_add,
// where it is the JSON Pointer target of the generated add operation.
type TicketMarkerDescriptor struct {
	Version  int                  `json:"version"`
	Strategy TicketMarkerStrategy `json:"strategy"`
	Path     []string             `json:"path"`
}

// TicketPayloadInput is the policy-filtered information a native provider can
// serialize at preview time. It intentionally has no intent marker: only Submit
// may add the server-issued marker to the frozen output.
type TicketPayloadInput struct {
	ProjectKey     string                     `json:"project_key"`
	IssueType      string                     `json:"issue_type"`
	Summary        string                     `json:"summary"`
	Description    json.RawMessage            `json:"description"`
	Links          []RenderedLink             `json:"links"`
	Fields         map[string]json.RawMessage `json:"fields"`
	SecurityPolicy string                     `json:"security_policy"`
}

// TicketPayload is the exact native request body and the code-validated marker
// operation used later by Submit. A payload builder runs only while previewing;
// dispatch never calls it or re-renders mutable data.
type TicketPayload struct {
	Wire   json.RawMessage        `json:"wire"`
	Marker TicketMarkerDescriptor `json:"marker"`
}

// TicketPayloadBuilder is optional. Jira adapters retain their established
// fields serializer; native adapters use this seam to build their exact wire
// format once at preview time.
type TicketPayloadBuilder interface {
	BuildTicketPayload(context.Context, TicketPayloadInput) (TicketPayload, error)
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
