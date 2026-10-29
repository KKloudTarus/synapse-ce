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
	ChannelWebhook    ChannelType = "webhook"
	ChannelSlack      ChannelType = "slack"
	ChannelEmail      ChannelType = "email"
	ChannelTeams      ChannelType = "teams"
	ChannelTelegram   ChannelType = "telegram"
	ChannelGoogleChat ChannelType = "google_chat"
	ChannelDiscord    ChannelType = "discord"
	ChannelMattermost ChannelType = "mattermost"
	ChannelRocketChat ChannelType = "rocket_chat"
	ChannelPagerDuty  ChannelType = "pagerduty"
	ChannelJSM        ChannelType = "jsm"
	// ChannelSlackBot posts as a Slack app with a bot token through chat.postMessage (#1383),
	// unlike ChannelSlack, which posts to an incoming webhook.
	ChannelSlackBot ChannelType = "slack_bot"
)

func (v ChannelType) Valid() bool {
	switch v {
	case ChannelWebhook, ChannelSlack, ChannelEmail, ChannelTeams, ChannelTelegram, ChannelGoogleChat, ChannelDiscord, ChannelMattermost, ChannelRocketChat, ChannelPagerDuty, ChannelJSM, ChannelSlackBot:
		return true
	}
	return false
}

// HTTPEndpoint reports whether the channel type delivers to one HTTPS endpoint, so its masked
// destination is "https://host/…" and a host change is a destination change admins are told about.
// Email is the only type that delivers to recipients instead.
func (v ChannelType) HTTPEndpoint() bool {
	return v.Valid() && v != ChannelEmail
}

// CodeProviderDisabled is the reason a delivery is cancelled when the operator switched its channel
// type off with SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED. The operator owns it: it is never a fault
// of the channel, so channel health must not count it and the channel is not retried for it.
const CodeProviderDisabled = "provider_disabled"

// CodeEngagementSuppressed is the reason a delivery is cancelled when its engagement allows no
// external notification (#1360). Like a disabled provider it is an operator decision, never a
// fault of the channel.
const CodeEngagementSuppressed = "engagement_suppressed"

type EventType string

const (
	EventVulnerabilityAction      EventType = "vulnerability_action.created"
	EventScanCompleted            EventType = "scan.completed"
	EventQualityGateFailed        EventType = "quality_gate.failed"
	EventSLAApproaching           EventType = "sla.approaching_deadline"
	EventFleetAgentOffline        EventType = "fleet.agent.offline"
	EventIncidentCreated          EventType = "incident.created"
	EventOwnershipChanged         EventType = "finding.ownership_changed"
	EventDestinationChanged       EventType = "notification.destination_changed"
	EventChannelPaused            EventType = "notification.channel_paused"
	EventTest                     EventType = "notification.test"
	EventDigest                   EventType = "notification.digest"
	EventFindingCreated           EventType = "finding.created"
	EventFindingStatusChanged     EventType = "finding.status_changed"
	EventFindingRetestCompleted   EventType = "finding.retest_completed"
	EventScanFailed               EventType = "scan.failed"
	EventDASTRunFinished          EventType = "dast.run_finished"
	EventReconRunFinished         EventType = "recon.run_finished"
	EventCSPMRunFinished          EventType = "cspm.run_finished"
	EventSLABreached              EventType = "sla.breached"
	EventRiskAcceptanceCreated    EventType = "risk_acceptance.created"
	EventRiskAcceptanceExpiring   EventType = "risk_acceptance.expiring"
	EventRiskAcceptanceExpired    EventType = "risk_acceptance.expired"
	EventEngagementCreated        EventType = "engagement.created"
	EventEngagementStatusChanged  EventType = "engagement.status_changed"
	EventEngagementWindowStarting EventType = "engagement.window_starting"
	EventEngagementWindowEnding   EventType = "engagement.window_ending"
	EventFindingCommented         EventType = "finding.commented"
	EventFindingMentioned         EventType = "finding.mentioned"
	EventApprovalRequested        EventType = "approval.requested"
	EventApprovalDecided          EventType = "approval.decided"
	EventApprovalTimedOut         EventType = "approval.timed_out"
	EventIncidentUpdated          EventType = "incident.updated"
	EventResponseFinished         EventType = "response.finished"
	EventEvidenceChainBroken      EventType = "evidence.chain_broken"
	EventReportGenerated          EventType = "report.generated"
)

// Valid reports whether the event type is declared in the catalog.
func (v EventType) Valid() bool {
	_, ok := catalog[v]
	return ok
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
	// Health is maintained by the delivery worker (#1464); administrators change it only by resuming.
	Health ChannelHealth `json:"health"`
	// DataClass is the most sensitive content the channel's messages may carry (#1360). Empty means
	// the type's default (DefaultDataClass).
	DataClass DataClass `json:"data_class"`
	// RawEvent is an audited opt-in to the legacy webhook envelope at detail class.
	RawEvent bool `json:"raw_event"`
	// TemplateBinding is the channel's template and locale (#1371).
	TemplateBinding
}

func (c Channel) Validate() error {
	if c.TenantID.IsZero() || c.ID.IsZero() || strings.TrimSpace(c.Name) == "" || !c.Type.Valid() || c.Revision < 1 || c.SecretVersion < 1 || c.CreatedAt.IsZero() || c.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: invalid notification channel", shared.ErrValidation)
	}
	if c.Type == ChannelEmail && len(c.Recipients) == 0 {
		return fmt.Errorf("%w: email channel requires recipients", shared.ErrValidation)
	}
	if c.DataClass != "" && !c.DataClass.Valid() {
		return invalidDataClass()
	}
	if c.RawEvent && (c.Type != ChannelWebhook || c.Class() != DataClassDetail || c.CustomBody) {
		return fmt.Errorf("%w: raw event mode requires a detail webhook without a custom body", shared.ErrValidation)
	}
	return c.TemplateBinding.Validate(c.Type)
}

type Rule struct {
	Cadence          DeliveryCadence `json:"cadence"`
	RecipientUserIDs []shared.ID     `json:"recipient_user_ids,omitempty"`
	TenantID         shared.ID       `json:"tenant_id"`
	ID               shared.ID       `json:"id"`
	Name             string          `json:"name"`
	Enabled          bool            `json:"enabled"`
	EventType        EventType       `json:"event_type"`
	// EventTypes is an explicit, bounded selection in input order. EventType stays the first
	// selected type for compatibility with existing API clients and stored rules. A nil or empty
	// selection means this legacy single-event rule selects EventType only.
	EventTypes    []EventType     `json:"event_types,omitempty"`
	MinSeverity   shared.Severity `json:"min_severity,omitempty"`
	ActionTypes   []string        `json:"action_types,omitempty"`
	EngagementIDs []shared.ID     `json:"engagement_ids,omitempty"`
	TeamIDs       []shared.ID     `json:"team_ids,omitempty"`
	AllTeams      bool            `json:"all_teams,omitempty"`
	EventFilters
	ChannelIDs []shared.ID `json:"channel_ids"`
	// RecipientRoles address people by their relation to the event (#1415), in addition to the
	// channels. A rule may have roles and no channel.
	RecipientRoles []string      `json:"recipient_roles,omitempty"`
	LeadTime       time.Duration `json:"-"`
	LeadTimeSecs   int64         `json:"lead_time_seconds,omitempty"`
	// DisabledReason explains a rule the system disabled; any save by an administrator clears it.
	DisabledReason string    `json:"disabled_reason,omitempty"`
	Revision       int       `json:"revision"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// DisabledEngagementFilterUnsupported marks rules that migration 0181 disabled because their event
// type carries no engagement, so their engagement filter could never match.
const DisabledEngagementFilterUnsupported = "engagement_filter_unsupported"

func (r *Rule) Normalize() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Cadence == "" {
		r.Cadence = CadenceImmediate
	}
	if !r.Cadence.Valid() {
		return fmt.Errorf("%w: invalid delivery cadence", shared.ErrValidation)
	}
	r.RecipientUserIDs = uniqueIDs(r.RecipientUserIDs)
	if len(r.RecipientUserIDs) > 200 {
		return fmt.Errorf("%w: too many recipient users", shared.ErrValidation)
	}
	selected, specs, err := r.selectedEventSpecs()
	if err != nil {
		return err
	}
	for _, eventType := range selected {
		if eventType != EventFindingMentioned {
			continue
		}
		if len(selected) != 1 || len(r.RecipientUserIDs) > 0 {
			return fmt.Errorf("%w: mentions address only the mentioned user", shared.ErrValidation)
		}
	}
	if r.LeadTimeSecs < 0 || r.LeadTimeSecs > 2592000 {
		return fmt.Errorf("%w: invalid lead time", shared.ErrValidation)
	}
	if r.LeadTime == 0 && r.LeadTimeSecs > 0 {
		r.LeadTime = time.Duration(r.LeadTimeSecs) * time.Second
	}
	if anyHasLeadTime(specs) && r.LeadTime == 0 {
		r.LeadTime = 24 * time.Hour
	}
	r.LeadTimeSecs = int64(r.LeadTime / time.Second)
	if r.TenantID.IsZero() || r.ID.IsZero() || r.Name == "" || r.Revision < 1 || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: invalid notification rule", shared.ErrValidation)
	}
	if r.MinSeverity != "" && shared.SeverityRank(r.MinSeverity) == 0 {
		return fmt.Errorf("%w: invalid notification minimum severity", shared.ErrValidation)
	}
	if r.MinSeverity != "" {
		if err := requireAllFilters(selected, specs, FilterMinSeverity, "minimum severity"); err != nil {
			return err
		}
	}
	if len(r.ActionTypes) > 0 {
		if err := requireAllFilters(selected, specs, FilterActionTypes, "action types"); err != nil {
			return err
		}
	}
	for _, action := range r.ActionTypes {
		if !validActionType(strings.TrimSpace(action)) {
			return fmt.Errorf("%w: invalid vulnerability action type", shared.ErrValidation)
		}
	}
	if r.LeadTime != 0 {
		if err := requireAllFilters(selected, specs, FilterLeadTime, "lead time"); err != nil {
			return err
		}
	}
	if r.LeadTime < 0 || r.LeadTime > 30*24*time.Hour {
		return fmt.Errorf("%w: notification lead time must be between zero and 30 days", shared.ErrValidation)
	}
	r.ActionTypes = uniqueStrings(r.ActionTypes)
	r.ChannelIDs = uniqueIDs(r.ChannelIDs)
	r.EngagementIDs = uniqueIDs(r.EngagementIDs)
	if len(r.EngagementIDs) > 0 {
		if err := requireAllFilters(selected, specs, FilterEngagements, "engagement scope"); err != nil {
			return err
		}
	}
	if err := r.normalizeTeamScope(selected, specs); err != nil {
		return err
	}
	if err := r.normalizeEventFilters(selected, specs); err != nil {
		return err
	}
	if err := r.normalizeRecipientRoles(selected); err != nil {
		return err
	}
	if selected[0] == EventFindingMentioned && len(r.ChannelIDs) > 0 {
		return fmt.Errorf("%w: mentions require personal recipient routing", shared.ErrValidation)
	}
	if len(r.ChannelIDs) == 0 && len(r.RecipientRoles) == 0 && len(r.RecipientUserIDs) == 0 {
		return fmt.Errorf("%w: a rule needs a channel or a recipient role", shared.ErrValidation)
	}
	if len(r.ChannelIDs) > 50 || len(r.EngagementIDs) > 200 || len(r.Name) > 200 {
		return fmt.Errorf("%w: invalid rule bounds", shared.ErrValidation)
	}
	return nil
}

// SelectedEventTypes returns the explicit selection, or the legacy primary selector when the
// array is absent or empty. It returns a copy so callers cannot mutate a stored rule's selection.
func (r Rule) SelectedEventTypes() []EventType {
	if len(r.EventTypes) == 0 {
		return []EventType{r.EventType}
	}
	return append([]EventType(nil), r.EventTypes...)
}

// MatchesEventType reports whether an event type belongs to this rule's explicit selection.
func (r Rule) MatchesEventType(eventType EventType) bool {
	if len(r.EventTypes) == 0 {
		return r.EventType == eventType
	}
	for _, selected := range r.EventTypes {
		if selected == eventType {
			return true
		}
	}
	return false
}

func (r Rule) selectedEventSpecs() ([]EventType, []EventSpec, error) {
	if len(r.EventTypes) > 8 {
		return nil, nil, fmt.Errorf("%w: a rule can select at most eight event types", shared.ErrValidation)
	}
	selected := r.SelectedEventTypes()
	if len(r.EventTypes) > 0 && r.EventType != selected[0] {
		return nil, nil, fmt.Errorf("%w: event type must be the first selected event type", shared.ErrValidation)
	}
	seen := make(map[EventType]struct{}, len(selected))
	specs := make([]EventSpec, 0, len(selected))
	for _, eventType := range selected {
		if _, duplicate := seen[eventType]; duplicate {
			return nil, nil, fmt.Errorf("%w: duplicate selected event type %s", shared.ErrValidation, eventType)
		}
		seen[eventType] = struct{}{}
		spec, known := catalog[eventType]
		if !known || spec.OperatorOnly {
			return nil, nil, fmt.Errorf("%w: invalid notification rule", shared.ErrValidation)
		}
		specs = append(specs, spec)
	}
	return selected, specs, nil
}

func anyHasLeadTime(specs []EventSpec) bool {
	for _, spec := range specs {
		if spec.HasLeadTime {
			return true
		}
	}
	return false
}

func requireAllFilters(selected []EventType, specs []EventSpec, filter Filter, name string) error {
	for index, spec := range specs {
		if !spec.Allows(filter) {
			return unsupportedFilter(selected[index], name)
		}
	}
	return nil
}

func unsupportedFilter(t EventType, filter string) error {
	return fmt.Errorf("%w: %s is not a filter for %s events", shared.ErrValidation, filter, t)
}

type Event struct {
	// DigestItems are authoritative members hydrated only for send-time filtering and links.
	DigestItems []DigestItem `json:"-"`
	// TestTemplate is the immutable template snapshot for a fixture-only console test.
	TestTemplate  *TemplateVersion `json:"-"`
	TenantID      shared.ID        `json:"-"`
	ID            shared.ID        `json:"id"`
	Type          EventType        `json:"type"`
	SourceKind    string           `json:"source_kind"`
	SourceID      string           `json:"source_id"`
	EngagementID  shared.ID        `json:"engagement_id,omitempty"`
	Severity      shared.Severity  `json:"severity,omitempty"`
	SchemaVersion int              `json:"schema_version"`
	OccurredAt    time.Time        `json:"occurred_at"`
	Data          json.RawMessage  `json:"data"`
	// SubjectKind and SubjectID name the entity the event is about (EPIC D8), and Context is the
	// template context snapshot its builder took at projection (D5). They are not part of the
	// webhook body, which is the raw event and a public contract (D4).
	SubjectKind    string          `json:"-"`
	SubjectID      string          `json:"-"`
	Context        json.RawMessage `json:"-"`
	PagerLifecycle PagerLifecycle  `json:"-"`
}

// schemaVersionKnown accepts any envelope version from 1 up to the one the catalog declares for the
// event type. The schema no longer pins version 1 (migration 0190), so a type can move to a new
// version by changing its catalog entry; an event claiming a version this build does not know is
// still refused.
func (e Event) schemaVersionKnown() bool {
	spec, ok := LookupEvent(e.Type)
	return ok && e.SchemaVersion >= 1 && e.SchemaVersion <= spec.SchemaVersion
}

func (e Event) Validate() error {
	if e.TenantID.IsZero() || e.ID.IsZero() || !e.Type.Valid() || strings.TrimSpace(e.SourceKind) == "" || strings.TrimSpace(e.SourceID) == "" || !e.schemaVersionKnown() || e.OccurredAt.IsZero() {
		return fmt.Errorf("%w: invalid notification event", shared.ErrValidation)
	}
	var data map[string]any
	if len(e.Data) == 0 || len(e.Data) > 16384 || json.Unmarshal(e.Data, &data) != nil || data == nil {
		return fmt.Errorf("%w: notification event data must be an object", shared.ErrValidation)
	}
	if (e.SubjectKind != "" && !sourceKindShape.MatchString(e.SubjectKind)) || len(e.SubjectID) > maxSubjectIDLength {
		return fmt.Errorf("%w: invalid notification event subject", shared.ErrValidation)
	}
	if err := e.PagerLifecycle.validate(e.Type, e.SubjectKind, e.SubjectID); err != nil {
		return err
	}
	if len(e.Context) != 0 && !isJSONObject(e.Context, maxContextBytes) {
		return fmt.Errorf("%w: notification event context must be an object", shared.ErrValidation)
	}
	return nil
}

func (r Rule) Matches(e Event) bool {
	spec, known := catalog[e.Type]
	if !known || spec.OperatorOnly || !r.Enabled || r.TenantID != e.TenantID || !r.MatchesEventType(e.Type) {
		return false
	}
	if r.MinSeverity != "" && (e.Severity == "" || shared.SeverityRank(e.Severity) < shared.SeverityRank(r.MinSeverity)) {
		return false
	}
	if len(r.EngagementIDs) > 0 && !containsID(r.EngagementIDs, e.EngagementID) {
		return false
	}
	if spec.Allows(FilterTeams) && !r.matchesTeams(e) {
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
	if spec.HasLeadTime {
		var data struct {
			LeadTimeSeconds int64 `json:"lead_time_seconds"`
		}
		if json.Unmarshal(e.Data, &data) != nil || data.LeadTimeSeconds != r.LeadTimeSecs {
			return false
		}
	}
	if !r.matchesEventFilters(e) {
		return false
	}
	return true
}

type Delivery struct {
	TenantID    shared.ID   `json:"-"`
	ID          shared.ID   `json:"id"`
	EventID     shared.ID   `json:"event_id"`
	ChannelID   shared.ID   `json:"channel_id"`
	ChannelType ChannelType `json:"channel_type"`
	// RedriveFence is the durable queue's claim fence for this delivery's stable job.
	// It is returned for optimistic redrive requests; every claim and redrive advances it.
	RedriveFence   int64         `json:"redrive_fence"`
	Recipient      string        `json:"recipient,omitempty"`
	MatchedRuleIDs []shared.ID   `json:"matched_rule_ids"`
	State          DeliveryState `json:"state"`
	Attempts       int           `json:"attempts"`
	LastError      string        `json:"last_error,omitempty"`
	NextAttemptAt  *time.Time    `json:"next_attempt_at,omitempty"`
	DeliveredAt    *time.Time    `json:"delivered_at,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
	// TemplateRef is the template pinned by the first attempt (#1365); retries render with it.
	TemplateRef string `json:"template_ref,omitempty"`
	// RemoteRef is the acknowledged provider message handle. It is used only to
	// anchor later deliveries of the same subject to this channel configuration.
	RemoteRef string `json:"remote_ref,omitempty"`
	// ProviderRequestRef resumes an accepted asynchronous operation. It is not an
	// acknowledgement or subject anchor and is never exposed through delivery APIs.
	ProviderRequestRef string `json:"-"`
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
	// TemplateRef is the template this attempt rendered with (#1365).
	TemplateRef string `json:"template_ref,omitempty"`
}

type Page struct {
	Items []Delivery `json:"items"`
	Next  string     `json:"next,omitempty"`
}

// SourceFailure is a captured event that could not be projected. It contains
// source identity and a fixed reason code, never the captured payload.
type SourceFailure struct {
	SourceKind   string    `json:"source_kind"`
	SourceID     string    `json:"source_id"`
	EventType    EventType `json:"event_type"`
	OccurredAt   time.Time `json:"occurred_at"`
	ProcessedAt  time.Time `json:"processed_at"`
	FailedReason string    `json:"failed_reason"`
}

type SourceFailurePage struct {
	Items      []SourceFailure `json:"items"`
	NextOffset *int            `json:"next_offset,omitempty"`
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

// actionTypes is shared by rule validation and schema drift guards.
var actionTypes = [...]string{"new_exposure", "escalation", "withdrawal", "reexposure", "retest_required", "risk_review"}

// ActionTypes returns a defensive copy of the accepted action vocabulary.
func ActionTypes() []string {
	return append([]string(nil), actionTypes[:]...)
}

func validActionType(v string) bool {
	for _, allowed := range actionTypes {
		if v == allowed {
			return true
		}
	}
	return false
}

// Class is the channel's data class, or its type's default when none was set.
func (c Channel) Class() DataClass {
	if c.DataClass.Valid() {
		return c.DataClass
	}
	return DefaultDataClass(c.Type)
}
