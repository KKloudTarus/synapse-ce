// Package ticketing models tenant-scoped ticket mappings, external links, and durable write intents.
package ticketing

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
)

type Scope string

const (
	Project    Scope = "project"
	Engagement Scope = "engagement"
)

// GroupingMode controls whether a mapping creates one ticket per finding or
// groups a canonical vulnerability across a long-lived project.
type GroupingMode string

const (
	GroupingFinding              GroupingMode = "finding"
	GroupingVulnerabilityProject GroupingMode = "vulnerability_project"
)

func (m GroupingMode) Valid() bool { return m == GroupingFinding || m == GroupingVulnerabilityProject }

// SyncState is the one-way Jira state represented by a current Synapse finding
// or effective SLA lifecycle. A mapping opts in by configuring its transition.
type SyncState string

const (
	SyncRemediated    SyncState = "remediated"
	SyncAccepted      SyncState = "accepted"
	SyncFalsePositive SyncState = "false_positive"
	SyncReopen        SyncState = "reopen"
)

func (s SyncState) Valid() bool {
	return s == SyncRemediated || s == SyncAccepted || s == SyncFalsePositive || s == SyncReopen
}

type Mapping struct {
	ID            shared.ID
	TenantID      shared.ID
	IntegrationID shared.ID
	Scope         Scope
	ScopeID       shared.ID
	ProjectKey    string
	IssueType     string
	Component     string
	Labels        []string
	PriorityMap   map[string]string
	SecurityLevel string
	// SummaryTemplate and DescriptionTemplate are msgtemplate sources. They are
	// stored with the mapping so a preview and its eventual intent use the same
	// administrator-approved shape.
	SummaryTemplate     string
	DescriptionTemplate string
	FieldValues         map[string]string
	Transition          string
	DataClass           notification.DataClass
	Locale              string
	WaiverReason        string
	// AutoPush is deliberately opt-in per mapping. EnabledAt fences historical
	// status events so enabling a mapping never backfills tickets unexpectedly.
	AutoPushEnabled     bool
	AutoPushMinSeverity shared.Severity
	AutoPushEnabledAt   *time.Time
	GroupingMode        GroupingMode
	StatusTransitions   map[SyncState]string
	Version             int
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func (m Mapping) Validate() error {
	// The persisted default keeps direct foundation callers compatible with
	// mappings created before grouping was introduced. Workflows normalize this
	// before validation; stores do the same before writing the explicit column.
	if m.GroupingMode == "" {
		m.GroupingMode = GroupingFinding
	}
	if m.ID.IsZero() || m.TenantID.IsZero() || m.IntegrationID.IsZero() ||
		m.ScopeID.IsZero() || (m.Scope != Project && m.Scope != Engagement) ||
		!bounded(m.ProjectKey, 255) || !bounded(m.IssueType, 255) ||
		len(m.Component) > 255 || !validText(m.Component) || len(m.SecurityLevel) > 255 || !validText(m.SecurityLevel) ||
		len(m.Labels) > 32 || len(m.PriorityMap) > 32 || len(m.FieldValues) > 64 || m.Version < 1 ||
		m.CreatedAt.IsZero() || m.UpdatedAt.Before(m.CreatedAt) {
		return fmt.Errorf("%w: invalid ticket mapping", shared.ErrValidation)
	}
	for _, label := range m.Labels {
		if !bounded(label, 255) {
			return fmt.Errorf("%w: invalid ticket label", shared.ErrValidation)
		}
	}
	for k, v := range m.PriorityMap {
		if !bounded(k, 64) || !bounded(v, 255) {
			return fmt.Errorf("%w: invalid ticket priority mapping", shared.ErrValidation)
		}
	}
	for k, v := range m.FieldValues {
		if !bounded(k, 255) || len(v) > 4096 || !validText(v) {
			return fmt.Errorf("%w: invalid ticket field value", shared.ErrValidation)
		}
	}
	if len(m.SummaryTemplate) > 4096 || len(m.DescriptionTemplate) > 16384 ||
		!validText(m.SummaryTemplate) || !validText(m.DescriptionTemplate) ||
		len(m.Transition) > 255 || !validText(m.Transition) ||
		(m.DataClass != "" && !m.DataClass.Valid()) ||
		(m.Locale != "" && m.Locale != "en" && m.Locale != "vi") ||
		len(m.WaiverReason) > 1024 || !validText(m.WaiverReason) {
		return fmt.Errorf("%w: invalid ticket template or transition", shared.ErrValidation)
	}
	if m.AutoPushMinSeverity != "" && (!m.AutoPushMinSeverity.Valid() || shared.SeverityRank(m.AutoPushMinSeverity) == 0) {
		return fmt.Errorf("%w: invalid ticket auto-push severity", shared.ErrValidation)
	}
	if !m.GroupingMode.Valid() || (m.GroupingMode == GroupingVulnerabilityProject && (m.Scope != Project || m.DataClass != notification.DataClassDetail)) {
		return fmt.Errorf("%w: vulnerability/project grouping requires a project mapping with detail data class", shared.ErrValidation)
	}
	if m.AutoPushEnabled {
		if m.AutoPushEnabledAt == nil || m.AutoPushEnabledAt.IsZero() {
			return fmt.Errorf("%w: enabled ticket auto-push requires an activation time", shared.ErrValidation)
		}
		if shared.SeverityRank(m.AutoPushMinSeverity) == 0 {
			return fmt.Errorf("%w: enabled ticket auto-push requires a minimum severity", shared.ErrValidation)
		}
	} else if m.AutoPushEnabledAt != nil {
		return fmt.Errorf("%w: disabled ticket auto-push cannot retain an activation time", shared.ErrValidation)
	}
	if len(m.StatusTransitions) > 4 {
		return fmt.Errorf("%w: too many ticket status transitions", shared.ErrValidation)
	}
	for state, transition := range m.StatusTransitions {
		if !state.Valid() || !bounded(transition, 255) {
			return fmt.Errorf("%w: invalid ticket status transition", shared.ErrValidation)
		}
	}
	labels, err := json.Marshal(m.Labels)
	if err != nil {
		return fmt.Errorf("%w: invalid ticket labels", shared.ErrValidation)
	}
	priorities, err := json.Marshal(m.PriorityMap)
	if err != nil {
		return fmt.Errorf("%w: invalid ticket priorities", shared.ErrValidation)
	}
	if len(labels) > 8192 || len(priorities) > 8192 {
		return fmt.Errorf("%w: ticket mapping JSON exceeds persistence limit", shared.ErrValidation)
	}
	fields, err := json.Marshal(m.FieldValues)
	if err != nil || len(fields) > 16384 {
		return fmt.Errorf("%w: ticket field values exceed persistence limit", shared.ErrValidation)
	}
	return nil
}
func (m Mapping) Clone() Mapping {
	m.Labels = append([]string(nil), m.Labels...)
	if m.PriorityMap != nil {
		out := make(map[string]string, len(m.PriorityMap))
		for k, v := range m.PriorityMap {
			out[k] = v
		}
		m.PriorityMap = out
	}
	if m.FieldValues != nil {
		out := make(map[string]string, len(m.FieldValues))
		for k, v := range m.FieldValues {
			out[k] = v
		}
		m.FieldValues = out
	}
	if m.StatusTransitions != nil {
		out := make(map[SyncState]string, len(m.StatusTransitions))
		for k, v := range m.StatusTransitions {
			out[k] = v
		}
		m.StatusTransitions = out
	}
	if m.AutoPushEnabledAt != nil {
		at := *m.AutoPushEnabledAt
		m.AutoPushEnabledAt = &at
	}
	return m
}
func validText(v string) bool { return utf8.ValidString(v) && !strings.ContainsRune(v, 0) }
func bounded(v string, max int) bool {
	return validText(v) && strings.TrimSpace(v) != "" && len(v) <= max
}

// CanonicalURL refuses credentials, query-string tokens, fragments and non-HTTPS schemes.
// For manual links no provider is required; a linked URL is display-only and is never fetched.
func CanonicalURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !validText(raw) || u.Scheme != "https" || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || len(raw) > 2048 {
		return "", fmt.Errorf("%w: external ticket URL must be HTTPS without credentials, query or fragment", shared.ErrValidation)
	}
	return u.String(), nil
}

type Link struct {
	ID            shared.ID
	TenantID      shared.ID
	FindingID     shared.ID
	EngagementID  shared.ID
	IntegrationID shared.ID // empty for manual links
	ExternalID    string
	ExternalURL   string
	CreatedAt     time.Time
}

// RemoteTicket is the provider identity recorded after a successful remote write.
// It intentionally contains only the durable identity needed to rebuild a Link.
type RemoteTicket struct {
	ID  string
	URL string
}

func (r RemoteTicket) validate() error {
	if !bounded(r.ID, 512) {
		return fmt.Errorf("%w: remote ticket needs a bounded ID", shared.ErrValidation)
	}
	normalized, err := CanonicalURL(r.URL)
	if err != nil || normalized != r.URL {
		return fmt.Errorf("%w: remote ticket URL must be canonical HTTPS", shared.ErrValidation)
	}
	return nil
}

// ReconcileLink converges a reconstructed provider link with a stored one without
// changing its local identity or creation time. A manual link may be promoted once a
// provider identity is known, but a provider identity is never replaced.
func ReconcileLink(existing, desired Link) (Link, error) {
	if err := existing.Validate(); err != nil {
		return Link{}, err
	}
	if err := desired.Validate(); err != nil {
		return Link{}, err
	}
	if existing.TenantID != desired.TenantID || existing.FindingID != desired.FindingID ||
		existing.EngagementID != desired.EngagementID || existing.ExternalURL != desired.ExternalURL {
		return Link{}, fmt.Errorf("%w: ticket link reconciliation target differs", shared.ErrConflict)
	}
	if existing.IntegrationID == desired.IntegrationID && existing.ExternalID == desired.ExternalID {
		return existing, nil
	}
	if existing.IntegrationID.IsZero() && existing.ExternalID == "" && !desired.IntegrationID.IsZero() {
		existing.IntegrationID = desired.IntegrationID
		existing.ExternalID = desired.ExternalID
		return existing, nil
	}
	return Link{}, fmt.Errorf("%w: ticket link provider identity differs", shared.ErrConflict)
}

func (l Link) Validate() error {
	if l.ID.IsZero() || l.TenantID.IsZero() || l.FindingID.IsZero() || l.EngagementID.IsZero() || l.CreatedAt.IsZero() || len(l.ExternalID) > 512 || !validText(l.ExternalID) {
		return fmt.Errorf("%w: invalid ticket link", shared.ErrValidation)
	}
	normalized, err := CanonicalURL(l.ExternalURL)
	if err != nil {
		return err
	}
	if normalized != l.ExternalURL {
		return fmt.Errorf("%w: noncanonical ticket URL", shared.ErrValidation)
	}
	if l.IntegrationID.IsZero() && l.ExternalID != "" {
		return fmt.Errorf("%w: manual ticket link cannot claim a provider ID", shared.ErrValidation)
	}
	if !l.IntegrationID.IsZero() && !bounded(l.ExternalID, 512) {
		return fmt.Errorf("%w: provider ticket link needs an external ID", shared.ErrValidation)
	}
	return nil
}

type Action string

const (
	Create     Action = "create"
	Update     Action = "update"
	Transition Action = "transition"
	Comment    Action = "comment"
)

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var errorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type Intent struct {
	ID            shared.ID
	TenantID      shared.ID
	IntegrationID shared.ID
	MappingID     shared.ID
	FindingID     shared.ID
	EngagementID  shared.ID
	Action        Action
	RequestKey    string
	PayloadDigest string
	Marker        string
	State         writeintent.State
	Version       int
	Attempts      int
	LeaseUntil    *time.Time
	RemoteID      string
	RemoteURL     string
	ErrorCode     string // stable classification only; no raw HTTP/provider errors
	// Snapshot is the exact provider payload (including a server-issued marker),
	// plus the revisions and security decision which authorized it. It is never
	// recomputed by a worker from mutable finding or mapping rows.
	Snapshot           json.RawMessage
	MappingVersion     int
	ConnectionRevision int
	CredentialRevision int
	SecurityLevel      string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type DispatchTuple struct {
	TenantID, IntegrationID shared.ID
	ProjectKey, IssueType   string
}

// DispatchTarget derives the breaker identity exclusively from the immutable intent
// snapshot. Current mappings are deliberately not consulted by a worker.
func (i Intent) DispatchTarget() (DispatchTuple, error) {
	if i.TenantID.IsZero() || i.IntegrationID.IsZero() || len(i.Snapshot) == 0 {
		return DispatchTuple{}, fmt.Errorf("%w: ticket dispatch snapshot missing", shared.ErrValidation)
	}
	var payload struct {
		Fields struct {
			Project struct {
				Key string `json:"key"`
			} `json:"project"`
			IssueType struct {
				ID string `json:"id"`
			} `json:"issuetype"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(i.Snapshot, &payload); err != nil || !bounded(payload.Fields.Project.Key, 255) || !bounded(payload.Fields.IssueType.ID, 255) {
		return DispatchTuple{}, fmt.Errorf("%w: ticket dispatch snapshot target invalid", shared.ErrValidation)
	}
	return DispatchTuple{TenantID: i.TenantID, IntegrationID: i.IntegrationID, ProjectKey: payload.Fields.Project.Key, IssueType: payload.Fields.IssueType.ID}, nil
}

// IntentTransition supplies the evidence for one state-machine transition.
// Remote is required only for transitions that finish a remote write.
type IntentTransition struct {
	Event      writeintent.Event
	LeaseUntil *time.Time
	Remote     *RemoteTicket
	ErrorCode  string
}

func (i Intent) Validate() error {
	if i.ID.IsZero() || i.TenantID.IsZero() || i.IntegrationID.IsZero() || i.MappingID.IsZero() ||
		i.FindingID.IsZero() || i.EngagementID.IsZero() || !bounded(i.RequestKey, 128) || !sha256Pattern.MatchString(i.PayloadDigest) ||
		i.Marker != "synapse-intent-"+i.ID.String() || len(i.Marker) > 256 ||
		!i.State.Valid() || i.Version < 1 || i.Attempts < 0 || i.CreatedAt.IsZero() ||
		i.UpdatedAt.Before(i.CreatedAt) || len(i.Snapshot) > 64<<10 {
		return fmt.Errorf("%w: invalid ticket intent", shared.ErrValidation)
	}
	if len(i.Snapshot) != 0 {
		var snapshot any
		if err := json.Unmarshal(i.Snapshot, &snapshot); err != nil || snapshot == nil ||
			i.MappingVersion < 1 || i.ConnectionRevision < 1 || i.CredentialRevision < 0 {
			return fmt.Errorf("%w: ticket intent snapshot is invalid", shared.ErrValidation)
		}
	}
	switch i.Action {
	case Create, Update, Transition, Comment:
	default:
		return fmt.Errorf("%w: invalid ticket intent action", shared.ErrValidation)
	}
	if i.ErrorCode != "" && !errorCodePattern.MatchString(i.ErrorCode) {
		return fmt.Errorf("%w: ticket intent error code must be a bounded classification", shared.ErrValidation)
	}
	if (i.State == writeintent.InFlight) != (i.LeaseUntil != nil) {
		return fmt.Errorf("%w: only in-flight ticket intents have a lease", shared.ErrValidation)
	}
	if i.LeaseUntil != nil && !i.LeaseUntil.After(i.UpdatedAt) {
		return fmt.Errorf("%w: ticket intent lease must be in the future", shared.ErrValidation)
	}
	if i.State == writeintent.Done {
		if err := (RemoteTicket{ID: i.RemoteID, URL: i.RemoteURL}).validate(); err != nil {
			return err
		}
		if i.ErrorCode != "" {
			return fmt.Errorf("%w: completed ticket intent cannot have an error code", shared.ErrValidation)
		}
	} else if i.RemoteID != "" || i.RemoteURL != "" {
		return fmt.Errorf("%w: only completed ticket intents have a remote ticket", shared.ErrValidation)
	}
	if i.State == writeintent.Failed && i.ErrorCode == "" {
		return fmt.Errorf("%w: failed ticket intent needs an error code", shared.ErrValidation)
	}
	if i.State != writeintent.Failed && i.State != writeintent.Uncertain && i.ErrorCode != "" {
		return fmt.Errorf("%w: only failed or uncertain ticket intents have an error code", shared.ErrValidation)
	}
	if i.State == writeintent.Uncertain && i.ErrorCode != "" && i.ErrorCode != "multiple_matches" {
		return fmt.Errorf("%w: uncertain ticket intent has an invalid error code", shared.ErrValidation)
	}
	return nil
}

// Apply advances an intent using the evidence recorded by the caller. It is pure so
// every durable adapter can validate the identical outcome before storing it.
func (i Intent) Apply(change IntentTransition, at time.Time) (Intent, error) {
	if err := i.Validate(); err != nil {
		return Intent{}, err
	}
	if at.IsZero() || at.Before(i.UpdatedAt) {
		return Intent{}, fmt.Errorf("%w: ticket intent transition time is invalid", shared.ErrValidation)
	}
	next, err := writeintent.Next(i.State, change.Event)
	if err != nil {
		return Intent{}, err
	}
	if change.Event == writeintent.LeaseExpired &&
		(i.LeaseUntil == nil || at.Before(*i.LeaseUntil)) {
		return Intent{}, fmt.Errorf("%w: ticket intent lease has not expired", shared.ErrConflict)
	}
	if change.Event == writeintent.Claim {
		if change.LeaseUntil == nil || !change.LeaseUntil.After(at) {
			return Intent{}, fmt.Errorf("%w: ticket intent claim needs a future lease", shared.ErrValidation)
		}
		lease := change.LeaseUntil.UTC()
		i.LeaseUntil = &lease
		i.Attempts++
	} else {
		if change.LeaseUntil != nil {
			return Intent{}, fmt.Errorf("%w: only a ticket intent claim may set a lease", shared.ErrValidation)
		}
		i.LeaseUntil = nil
	}
	if next == writeintent.Done {
		if change.Remote == nil {
			return Intent{}, fmt.Errorf("%w: completed ticket intent needs a remote ticket", shared.ErrValidation)
		}
		if err := change.Remote.validate(); err != nil {
			return Intent{}, err
		}
		i.RemoteID = change.Remote.ID
		i.RemoteURL = change.Remote.URL
	} else {
		if change.Remote != nil {
			return Intent{}, fmt.Errorf("%w: only a completed ticket intent may set a remote ticket", shared.ErrValidation)
		}
		i.RemoteID = ""
		i.RemoteURL = ""
	}
	switch change.Event {
	case writeintent.Reject:
		if !errorCodePattern.MatchString(change.ErrorCode) {
			return Intent{}, fmt.Errorf("%w: rejected ticket intent needs a bounded error code", shared.ErrValidation)
		}
		i.ErrorCode = change.ErrorCode
	case writeintent.ReconcileMultiple:
		if change.ErrorCode != "" {
			return Intent{}, fmt.Errorf("%w: reconciliation derives its multiple-match code", shared.ErrValidation)
		}
		i.ErrorCode = "multiple_matches"
	default:
		if change.ErrorCode != "" {
			return Intent{}, fmt.Errorf("%w: only a rejection supplies an error code", shared.ErrValidation)
		}
		i.ErrorCode = ""
	}
	i.State = next
	i.Version++
	i.UpdatedAt = at.UTC()
	if err := i.Validate(); err != nil {
		return Intent{}, err
	}
	return i, nil
}

// CompletionLink returns the idempotent link that must be persisted with a done intent.
func (i Intent) CompletionLink() (Link, error) {
	if err := i.Validate(); err != nil {
		return Link{}, err
	}
	if i.State != writeintent.Done {
		return Link{}, fmt.Errorf("%w: only a completed ticket intent has a completion link", shared.ErrConflict)
	}
	return Link{
		ID:            i.ID,
		TenantID:      i.TenantID,
		FindingID:     i.FindingID,
		EngagementID:  i.EngagementID,
		IntegrationID: i.IntegrationID,
		ExternalID:    i.RemoteID,
		ExternalURL:   i.RemoteURL,
		CreatedAt:     i.UpdatedAt,
	}, nil
}
func (i Intent) Clone() Intent {
	if i.LeaseUntil != nil {
		at := *i.LeaseUntil
		i.LeaseUntil = &at
	}
	i.Snapshot = append(json.RawMessage(nil), i.Snapshot...)
	return i
}
