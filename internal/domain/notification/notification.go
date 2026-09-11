// Package notification defines tenant-owned notification channels, rules, events,
// and durable delivery history. It contains no transport or persistence code.
package notification

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type ChannelType string

const (
	ChannelWebhook ChannelType = "webhook"
	ChannelSlack   ChannelType = "slack"
	ChannelEmail   ChannelType = "email"
)

func (v ChannelType) Valid() bool {
	return v == ChannelWebhook || v == ChannelSlack || v == ChannelEmail
}

type EventType string

const (
	EventVulnerabilityAction EventType = "vulnerability_action.created"
	EventScanCompleted       EventType = "scan.completed"
	EventQualityGateFailed   EventType = "quality_gate.failed"
	EventSLAApproaching      EventType = "sla.approaching_deadline"
	EventFleetAgentOffline   EventType = "fleet.agent.offline"
	EventIncidentCreated     EventType = "incident.created"
	EventOwnershipChanged    EventType = "finding.ownership_changed"
	EventTest                EventType = "notification.test"
)

func (v EventType) Valid() bool {
	switch v {
	case EventVulnerabilityAction, EventScanCompleted, EventQualityGateFailed,
		EventSLAApproaching, EventFleetAgentOffline, EventIncidentCreated, EventOwnershipChanged, EventTest:
		return true
	}
	return false
}

type DeliveryState string

const (
	DeliveryPending   DeliveryState = "pending"
	DeliveryRetrying  DeliveryState = "retrying"
	DeliverySucceeded DeliveryState = "delivered"
	DeliveryDead      DeliveryState = "dead_letter"
	DeliveryCancelled DeliveryState = "cancelled"
)

func (v DeliveryState) Valid() bool {
	return v == DeliveryPending || v == DeliveryRetrying || v == DeliverySucceeded || v == DeliveryDead || v == DeliveryCancelled
}

// Channel exposes only safe metadata. Destination is always redacted; transport
// credentials and complete URLs live in an encrypted version record.
type Channel struct {
	TenantID      shared.ID   `json:"-"`
	ID            shared.ID   `json:"id"`
	Name          string      `json:"name"`
	Type          ChannelType `json:"type"`
	Enabled       bool        `json:"enabled"`
	Destination   string      `json:"destination"`
	Recipients    []string    `json:"recipients,omitempty"`
	Revision      int         `json:"revision"`
	SecretVersion int         `json:"secret_version"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
	DeletedAt     *time.Time  `json:"deleted_at,omitempty"`
}

func (c Channel) Validate() error {
	if c.TenantID.IsZero() || c.ID.IsZero() || strings.TrimSpace(c.Name) == "" || !c.Type.Valid() || c.Revision < 1 || c.SecretVersion < 1 || c.CreatedAt.IsZero() || c.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: invalid notification channel", shared.ErrValidation)
	}
	if c.Type == ChannelEmail && len(c.Recipients) == 0 {
		return fmt.Errorf("%w: email channel requires recipients", shared.ErrValidation)
	}
	return nil
}

type Rule struct {
	TenantID      shared.ID       `json:"tenant_id"`
	ID            shared.ID       `json:"id"`
	Name          string          `json:"name"`
	Enabled       bool            `json:"enabled"`
	EventType     EventType       `json:"event_type"`
	MinSeverity   shared.Severity `json:"min_severity,omitempty"`
	ActionTypes   []string        `json:"action_types,omitempty"`
	EngagementIDs []shared.ID     `json:"engagement_ids,omitempty"`
	TeamIDs       []shared.ID     `json:"team_ids,omitempty"`
	AllTeams      bool            `json:"all_teams,omitempty"`
	ChannelIDs    []shared.ID     `json:"channel_ids"`
	LeadTime      time.Duration   `json:"-"`
	LeadTimeSecs  int64           `json:"lead_time_seconds,omitempty"`
	Revision      int             `json:"revision"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

func (r *Rule) Normalize() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.LeadTimeSecs < 0 || r.LeadTimeSecs > 2592000 {
		return fmt.Errorf("%w: invalid lead time", shared.ErrValidation)
	}
	if r.LeadTime == 0 && r.LeadTimeSecs > 0 {
		r.LeadTime = time.Duration(r.LeadTimeSecs) * time.Second
	}
	if r.EventType == EventSLAApproaching && r.LeadTime == 0 {
		r.LeadTime = 24 * time.Hour
	}
	r.LeadTimeSecs = int64(r.LeadTime / time.Second)
	if r.TenantID.IsZero() || r.ID.IsZero() || r.Name == "" || !r.EventType.Valid() || r.EventType == EventTest || len(r.ChannelIDs) == 0 || r.Revision < 1 || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: invalid notification rule", shared.ErrValidation)
	}
	if r.MinSeverity != "" && shared.SeverityRank(r.MinSeverity) == 0 {
		return fmt.Errorf("%w: invalid notification minimum severity", shared.ErrValidation)
	}
	if r.MinSeverity != "" && r.EventType != EventVulnerabilityAction && r.EventType != EventIncidentCreated {
		return fmt.Errorf("%w: minimum severity only applies to vulnerability and incident events", shared.ErrValidation)
	}
	if len(r.ActionTypes) > 0 && r.EventType != EventVulnerabilityAction {
		return fmt.Errorf("%w: action types only apply to vulnerability action events", shared.ErrValidation)
	}
	for _, action := range r.ActionTypes {
		if !validActionType(strings.TrimSpace(action)) {
			return fmt.Errorf("%w: invalid vulnerability action type", shared.ErrValidation)
		}
	}
	if r.EventType != EventSLAApproaching && r.LeadTime != 0 {
		return fmt.Errorf("%w: lead time only applies to SLA events", shared.ErrValidation)
	}
	if r.LeadTime < 0 || r.LeadTime > 30*24*time.Hour {
		return fmt.Errorf("%w: notification lead time must be between zero and 30 days", shared.ErrValidation)
	}
	r.ActionTypes = uniqueStrings(r.ActionTypes)
	r.ChannelIDs = uniqueIDs(r.ChannelIDs)
	r.EngagementIDs = uniqueIDs(r.EngagementIDs)
	if err := r.normalizeTeamScope(); err != nil {
		return err
	}
	if len(r.ChannelIDs) == 0 || len(r.ChannelIDs) > 50 || len(r.EngagementIDs) > 200 || len(r.Name) > 200 {
		return fmt.Errorf("%w: invalid rule bounds", shared.ErrValidation)
	}
	return nil
}

type Event struct {
	TenantID      shared.ID       `json:"-"`
	ID            shared.ID       `json:"id"`
	Type          EventType       `json:"type"`
	SourceKind    string          `json:"source_kind"`
	SourceID      string          `json:"source_id"`
	EngagementID  shared.ID       `json:"engagement_id,omitempty"`
	Severity      shared.Severity `json:"severity,omitempty"`
	SchemaVersion int             `json:"schema_version"`
	OccurredAt    time.Time       `json:"occurred_at"`
	Data          json.RawMessage `json:"data"`
}

func (e Event) Validate() error {
	if e.TenantID.IsZero() || e.ID.IsZero() || !e.Type.Valid() || strings.TrimSpace(e.SourceKind) == "" || strings.TrimSpace(e.SourceID) == "" || e.SchemaVersion != 1 || e.OccurredAt.IsZero() {
		return fmt.Errorf("%w: invalid notification event", shared.ErrValidation)
	}
	var data map[string]any
	if len(e.Data) == 0 || len(e.Data) > 16384 || json.Unmarshal(e.Data, &data) != nil || data == nil {
		return fmt.Errorf("%w: notification event data must be an object", shared.ErrValidation)
	}
	return nil
}

func (r Rule) Matches(e Event) bool {
	if !r.Enabled || r.TenantID != e.TenantID || r.EventType != e.Type {
		return false
	}
	if r.MinSeverity != "" && (e.Severity == "" || shared.SeverityRank(e.Severity) < shared.SeverityRank(r.MinSeverity)) {
		return false
	}
	if len(r.EngagementIDs) > 0 && !containsID(r.EngagementIDs, e.EngagementID) {
		return false
	}
	if e.Type == EventOwnershipChanged && !r.matchesOwnership(e) {
		return false
	}
	if len(r.ActionTypes) > 0 {
		var data struct {
			ActionType string `json:"action_type"`
		}
		if json.Unmarshal(e.Data, &data) != nil || !contains(r.ActionTypes, data.ActionType) {
			return false
		}
	}
	if e.Type == EventSLAApproaching {
		var data struct {
			LeadTimeSeconds int64 `json:"lead_time_seconds"`
		}
		if json.Unmarshal(e.Data, &data) != nil || data.LeadTimeSeconds != r.LeadTimeSecs {
			return false
		}
	}
	return true
}

type Delivery struct {
	TenantID       shared.ID     `json:"-"`
	ID             shared.ID     `json:"id"`
	EventID        shared.ID     `json:"event_id"`
	ChannelID      shared.ID     `json:"channel_id"`
	ChannelType    ChannelType   `json:"channel_type"`
	Recipient      string        `json:"recipient,omitempty"`
	MatchedRuleIDs []shared.ID   `json:"matched_rule_ids"`
	State          DeliveryState `json:"state"`
	Attempts       int           `json:"attempts"`
	LastError      string        `json:"last_error,omitempty"`
	NextAttemptAt  *time.Time    `json:"next_attempt_at,omitempty"`
	DeliveredAt    *time.Time    `json:"delivered_at,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

type Attempt struct {
	ID           shared.ID  `json:"id"`
	DeliveryID   shared.ID  `json:"delivery_id"`
	Number       int        `json:"number"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	Outcome      string     `json:"outcome"`
	ResponseCode int        `json:"response_code,omitempty"`
	ErrorCode    string     `json:"error_code,omitempty"`
}

type Page struct {
	Items []Delivery `json:"items"`
	Next  string     `json:"next,omitempty"`
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func uniqueIDs(in []shared.ID) []shared.ID {
	seen := map[shared.ID]bool{}
	out := make([]shared.ID, 0, len(in))
	for _, v := range in {
		if !v.IsZero() && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
func contains(in []string, v string) bool {
	for _, x := range in {
		if x == v {
			return true
		}
	}
	return false
}
func containsID(in []shared.ID, v shared.ID) bool {
	for _, x := range in {
		if x == v {
			return true
		}
	}
	return false
}

func validActionType(v string) bool {
	switch v {
	case "new_exposure", "escalation", "withdrawal", "reexposure", "retest_required", "risk_review":
		return true
	}
	return false
}
