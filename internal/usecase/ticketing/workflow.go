package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"golang.org/x/sync/singleflight"
)

type TicketProviderRegistry interface {
	TicketProvider(context.Context, integration.Integration) (ports.TicketProvider, error)
}
type metadataEntry struct {
	value ports.TicketMetadata
	at    time.Time
}

type Workflow struct {
	*Service
	integrations ports.IntegrationStore
	providers    TicketProviderRegistry
	policy       ports.TicketPolicyReader
	audit        ports.AuditLogger
	mappingAudit ports.TicketAuditStore
	intentAudit  ports.TicketIntentAuditStore
	dispatch     ports.TicketDispatchStore
	publicBase   string
	// autoPushSourceAvailable is set only by a runtime with the durable
	// notification_events projection. Development memory mode has no safe
	// unbounded event feed, so enabling this policy fails closed there.
	autoPushSourceAvailable bool
	sla                     ports.SLAStore
	inboundDeduper          ports.InboundWebhookEventDeduper
	// Metadata is bounded to 32 entries/256 KiB each, TTL 30s. The mutex protects
	// cache values and active discovery admission; singleflight coalesces same-key
	// HTTP without holding it. At most four distinct discoveries run at once.
	metadataMu     sync.Mutex
	metadata       map[string]metadataEntry
	metadataActive map[string]struct{}
	discovery      singleflight.Group
}

func (w *Workflow) SetPublicBaseURL(base string) {
	w.publicBase = strings.TrimRight(strings.TrimSpace(base), "/")
}
func (w *Workflow) SetAutoPushSourceAvailable(available bool) { w.autoPushSourceAvailable = available }

// SetSLAStore enables effective accepted-risk evaluation for status sync. A nil
// reader leaves automatic status synchronization unavailable rather than
// guessing lifecycle state from an audit stream.
func (w *Workflow) SetSLAStore(store ports.SLAStore) { w.sla = store }
func (w *Workflow) SetInboundWebhookDeduper(store ports.InboundWebhookEventDeduper) {
	w.inboundDeduper = store
}
func NewWorkflow(store ports.TicketStore, integrations ports.IntegrationStore, providers TicketProviderRegistry, findings ports.FindingRepository, engagements ports.EngagementRepository, policy ports.TicketPolicyReader, audit ports.AuditLogger, ids ports.IDGenerator, clock ports.Clock) (*Workflow, error) {
	base, err := NewService(store, findings, engagements, ids, clock)
	if err != nil {
		return nil, err
	}
	if integrations == nil || providers == nil || policy == nil || audit == nil {
		return nil, fmt.Errorf("%w: ticket workflow dependencies required", shared.ErrValidation)
	}
	ma, ok := store.(ports.TicketAuditStore)
	if !ok {
		return nil, fmt.Errorf("%w: atomic ticket mapping audit required", shared.ErrValidation)
	}
	ia, ok := store.(ports.TicketIntentAuditStore)
	if !ok {
		return nil, fmt.Errorf("%w: atomic ticket intent audit required", shared.ErrValidation)
	}
	ds, ok := store.(ports.TicketDispatchStore)
	if !ok {
		return nil, fmt.Errorf("%w: durable ticket dispatch required", shared.ErrValidation)
	}
	if configurable, ok := store.(interface{ SetAudit(ports.AuditLogger) }); ok {
		configurable.SetAudit(audit)
	}
	return &Workflow{Service: base, integrations: integrations, providers: providers, policy: policy, audit: audit, mappingAudit: ma, intentAudit: ia, dispatch: ds, metadata: make(map[string]metadataEntry), metadataActive: make(map[string]struct{})}, nil
}

type PreviewRequest struct {
	TenantID     shared.ID `json:"-"`
	MappingID    shared.ID `json:"mapping_id"`
	FindingID    shared.ID `json:"finding_id"`
	EngagementID shared.ID `json:"engagement_id"`
	Locale       string    `json:"locale"`
}
type Preview struct {
	Payload        json.RawMessage        `json:"payload"`
	Digest         string                 `json:"preview_digest"`
	Summary        string                 `json:"summary"`
	Description    string                 `json:"description"`
	MappingVersion int                    `json:"mapping_version"`
	MarkerRequired bool                   `json:"marker_required"`
	MarkerFormat   string                 `json:"marker_format"`
	DataClass      notification.DataClass `json:"data_class"`
	Links          []ports.RenderedLink   `json:"-"`
	SecurityWaived bool                   `json:"security_waived"`
}
type SubmitRequest struct {
	TenantID      shared.ID `json:"-"`
	MappingID     shared.ID `json:"mapping_id"`
	FindingID     shared.ID `json:"finding_id"`
	EngagementID  shared.ID `json:"engagement_id"`
	RequestKey    string    `json:"request_key"`
	PreviewDigest string    `json:"preview_digest"`
	Actor         string    `json:"-"`
}
type MappingInput struct {
	IntegrationID       shared.ID                   `json:"integration_id"`
	Scope               domain.Scope                `json:"scope"`
	ScopeID             shared.ID                   `json:"scope_id"`
	ProjectKey          string                      `json:"project_key"`
	IssueType           string                      `json:"issue_type"`
	Component           string                      `json:"component"`
	Labels              []string                    `json:"labels"`
	PriorityMap         map[string]string           `json:"priority_map"`
	SecurityLevel       string                      `json:"security_level"`
	SummaryTemplate     string                      `json:"summary_template"`
	DescriptionTemplate string                      `json:"description_template"`
	FieldValues         map[string]string           `json:"field_values"`
	Transition          string                      `json:"transition_id"`
	DataClass           notification.DataClass      `json:"data_class"`
	Locale              string                      `json:"locale"`
	Version             int                         `json:"version"`
	WaiverReason        string                      `json:"waiver_reason"`
	AutoPushEnabled     bool                        `json:"auto_push_enabled"`
	AutoPushMinSeverity shared.Severity             `json:"auto_push_min_severity"`
	GroupingMode        domain.GroupingMode         `json:"grouping_mode"`
	StatusTransitions   map[domain.SyncState]string `json:"status_transitions"`
	Actor               string                      `json:"-"`
	AllowAdmin          bool                        `json:"-"`
}

var jiraTransitionIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

type FindingTickets struct {
	Links    []domain.Link    `json:"links"`
	Intents  []domain.Intent  `json:"intents"`
	Mappings []domain.Mapping `json:"mappings"`
}

func (w *Workflow) SaveMapping(ctx context.Context, tenant, id shared.ID, in MappingInput) (domain.Mapping, error) {
	if tenant.IsZero() || in.IntegrationID.IsZero() || in.ScopeID.IsZero() || strings.TrimSpace(in.Actor) == "" {
		return domain.Mapping{}, shared.ErrValidation
	}
	if in.DataClass == "" {
		in.DataClass = notification.DataClassSummary
	}
	if in.GroupingMode == "" {
		in.GroupingMode = domain.GroupingFinding
	}
	// Persist only redacted administrator literals: settings reads must not expose
	// a secret accidentally pasted into a template or custom field.
	in.SummaryTemplate = ticketRenderedText(in.SummaryTemplate)
	in.DescriptionTemplate = ticketRenderedText(in.DescriptionTemplate)
	cleanFields := make(map[string]string, len(in.FieldValues))
	for key, value := range in.FieldValues {
		cleanFields[key] = ticketRenderedText(value)
	}
	in.FieldValues = cleanFields
	if in.Locale == "" {
		in.Locale = "en"
	}
	if !in.DataClass.Valid() || (in.Locale != "en" && in.Locale != "vi") {
		return domain.Mapping{}, shared.ErrValidation
	}
	for state, transition := range in.StatusTransitions {
		if !state.Valid() || !jiraTransitionIDPattern.MatchString(transition) {
			return domain.Mapping{}, shared.ErrValidation
		}
	}
	if in.AutoPushEnabled && !in.AllowAdmin {
		return domain.Mapping{}, shared.ErrForbidden
	}
	if in.AutoPushEnabled && !w.autoPushSourceAvailable {
		return domain.Mapping{}, fmt.Errorf("%w: ticket auto-push requires durable notification events", shared.ErrConflict)
	}
	if in.AutoPushEnabled && in.AutoPushMinSeverity == "" {
		in.AutoPushMinSeverity = shared.SeverityHigh
	}
	if in.SecurityLevel == "" && (!in.AllowAdmin || strings.TrimSpace(in.WaiverReason) == "") {
		return domain.Mapping{}, fmt.Errorf("%w: select an issue security level or record an administrator waiver", shared.ErrValidation)
	}
	if len(in.WaiverReason) > 1024 {
		return domain.Mapping{}, shared.ErrValidation
	}
	in.WaiverReason = ticketAuditText(in.WaiverReason)
	now := w.clock.Now().UTC()
	m := domain.Mapping{ID: id, TenantID: tenant, IntegrationID: in.IntegrationID, Scope: in.Scope, ScopeID: in.ScopeID, ProjectKey: in.ProjectKey, IssueType: in.IssueType, Component: in.Component, Labels: in.Labels, PriorityMap: in.PriorityMap, SecurityLevel: in.SecurityLevel, SummaryTemplate: in.SummaryTemplate, DescriptionTemplate: in.DescriptionTemplate, FieldValues: in.FieldValues, Transition: in.Transition, DataClass: in.DataClass, Locale: in.Locale, WaiverReason: in.WaiverReason, AutoPushEnabled: in.AutoPushEnabled, AutoPushMinSeverity: in.AutoPushMinSeverity, GroupingMode: in.GroupingMode, StatusTransitions: in.StatusTransitions, Version: 1, CreatedAt: now, UpdatedAt: now}
	action := "ticket.mapping.created"
	if id.IsZero() {
		m.ID = w.ids.NewID()
	} else {
		old, err := w.store.GetMapping(ctx, tenant, id)
		if err != nil {
			return domain.Mapping{}, err
		}
		if old.IntegrationID != m.IntegrationID || old.Scope != m.Scope || old.ScopeID != m.ScopeID {
			return domain.Mapping{}, fmt.Errorf("%w: mapping identity cannot be retargeted", shared.ErrConflict)
		}
		if old.Version != in.Version {
			return domain.Mapping{}, shared.ErrConflict
		}
		if old.DataClass.Raises(m.DataClass) && !in.AllowAdmin {
			return domain.Mapping{}, shared.ErrForbidden
		}
		m.Version = old.Version + 1
		m.CreatedAt = old.CreatedAt
		if m.AutoPushEnabled && old.AutoPushEnabled {
			m.AutoPushEnabledAt = old.AutoPushEnabledAt
		} else if m.AutoPushEnabled {
			m.AutoPushEnabledAt = &now
		}
		action = "ticket.mapping.updated"
	}
	if id.IsZero() && m.AutoPushEnabled {
		m.AutoPushEnabledAt = &now
	}
	if m.DataClass == notification.DataClassDetail && !in.AllowAdmin {
		return domain.Mapping{}, shared.ErrForbidden
	}
	if err := m.Validate(); err != nil {
		return domain.Mapping{}, err
	}
	if id != "" {
		if groups, ok := w.store.(ports.TicketGroupStore); ok {
			integrationItem, integrationErr := w.integration(ctx, tenant, m.IntegrationID)
			if integrationErr != nil {
				return domain.Mapping{}, integrationErr
			}
			candidate := ports.TicketGroup{TenantID: tenant, MappingID: m.ID, IntegrationID: integrationItem.ID, Endpoint: integrationItem.Endpoint, ProjectKey: m.ProjectKey, IssueType: m.IssueType, SecurityLevel: m.SecurityLevel}
			if destinationErr := groups.ValidateTicketGroupDestination(ctx, tenant, candidate); destinationErr != nil {
				return domain.Mapping{}, destinationErr
			}
		}
	}
	if err := w.validateScope(ctx, m); err != nil {
		return domain.Mapping{}, err
	}
	if err := validateTicketTemplates(m); err != nil {
		return domain.Mapping{}, err
	}
	meta, err := w.Metadata(ctx, tenant, m.IntegrationID, m.ProjectKey, m.IssueType, "")
	if err != nil {
		return domain.Mapping{}, err
	}
	if err = w.validateSelections(m, meta); err != nil {
		return domain.Mapping{}, err
	}
	literals, err := json.Marshal(m)
	if err != nil {
		return domain.Mapping{}, shared.ErrValidation
	}
	if err = w.validateTicketLiterals(ctx, tenant, m.IntegrationID, literals); err != nil {
		return domain.Mapping{}, err
	}
	entry := ports.AuditEntry{Actor: in.Actor, Action: action, Target: m.ID.String(), At: now, Metadata: map[string]string{"integration_id": m.IntegrationID.String(), "project_key": m.ProjectKey, "issue_type": m.IssueType, "security_level": m.SecurityLevel, "data_class": string(m.DataClass), "waiver_reason": m.WaiverReason}}
	if id.IsZero() {
		if err = w.mappingAudit.CreateMappingAudited(ctx, tenant, m, entry); err != nil {
			return domain.Mapping{}, err
		}
		return m, nil
	}
	return w.mappingAudit.UpdateMappingAudited(ctx, tenant, m, in.Version, entry)
}
func (w *Workflow) DeleteMapping(ctx context.Context, tenant, id shared.ID, version int, actor string) error {
	if strings.TrimSpace(actor) == "" {
		return shared.ErrValidation
	}
	return w.mappingAudit.DeleteMappingAudited(ctx, tenant, id, version, ports.AuditEntry{Actor: actor, Action: "ticket.mapping.deleted", Target: id.String(), At: w.clock.Now().UTC()})
}
func (w *Workflow) ListMappings(ctx context.Context, tenant shared.ID, scope domain.Scope, scopeID shared.ID) ([]domain.Mapping, error) {
	if tenant.IsZero() || (scope != "" && scope != domain.Engagement && scope != domain.Project) {
		return nil, shared.ErrValidation
	}
	if scope == "" && scopeID.IsZero() {
		return w.store.ListMappings(ctx, tenant, 200, "")
	}
	if scope == "" || scopeID.IsZero() {
		return nil, shared.ErrValidation
	}
	return w.store.ListScopedMappings(ctx, tenant, scope, scopeID, 200)
}
func (w *Workflow) GetFindingTickets(ctx context.Context, tenant, engagement, finding shared.ID) (FindingTickets, error) {
	if _, err := w.findings.GetByEngagementAndID(shared.WithTenant(ctx, tenant), engagement, finding); err != nil {
		return FindingTickets{}, err
	}
	links, err := w.store.ListLinks(ctx, tenant, finding)
	if err != nil {
		return FindingTickets{}, err
	}
	intents, err := w.store.ListFindingIntents(ctx, tenant, finding, 100)
	if err != nil {
		return FindingTickets{}, err
	}
	maps, err := w.store.ListFindingMappings(ctx, tenant, engagement, 200)
	if err != nil {
		return FindingTickets{}, err
	}
	return FindingTickets{Links: links, Intents: intents, Mappings: maps}, nil
}
func (w *Workflow) Unlink(ctx context.Context, tenant, engagement, finding, link shared.ID) error {
	if _, err := w.findings.GetByEngagementAndID(shared.WithTenant(ctx, tenant), engagement, finding); err != nil {
		return err
	}
	l, err := w.store.GetLink(ctx, tenant, link)
	if err != nil {
		return err
	}
	if l.FindingID != finding || l.EngagementID != engagement {
		return shared.ErrNotFound
	}
	return w.store.DeleteLink(ctx, tenant, link)
}
func (w *Workflow) RetryUncertain(ctx context.Context, tenant, id shared.ID, version int, ack bool, reason, actor string) (domain.Intent, error) {
	if !ack || strings.TrimSpace(reason) == "" || len(reason) > 1024 || strings.TrimSpace(actor) == "" {
		return domain.Intent{}, shared.ErrValidation
	}
	i, err := w.store.GetIntent(ctx, tenant, id)
	if err != nil {
		return domain.Intent{}, err
	}
	if i.Version != version || (i.State != writeintent.Uncertain && i.State != writeintent.Failed) {
		return domain.Intent{}, shared.ErrConflict
	}
	// Check the administrator-supplied text against the current credential before
	// reconciliation or an audit record can persist it. The provider recognizes
	// exact configured values that generic pattern redaction cannot infer.
	reasonPayload, marshalErr := json.Marshal(map[string]string{"reason": reason})
	if marshalErr != nil {
		return domain.Intent{}, shared.ErrValidation
	}
	if err = w.validateTicketLiterals(ctx, tenant, i.IntegrationID, reasonPayload); err != nil {
		return domain.Intent{}, err
	}
	// Human recovery is deliberately explicit: absent Jira search is never an
	// automatic retry. Reconcile first again in case the index has caught up.
	if i.State == writeintent.Uncertain {
		reconciled, e := w.Reconcile(ctx, tenant, id, i.Version)
		if e != nil {
			return domain.Intent{}, e
		}
		if reconciled.State == writeintent.Done {
			return reconciled, nil
		}
		if reconciled.ErrorCode == "multiple_matches" {
			return domain.Intent{}, fmt.Errorf("%w: multiple matches require choosing an existing ticket", shared.ErrConflict)
		}
		i = reconciled
	}
	entry := ports.AuditEntry{Actor: actor, Action: "ticket.intent.retry_duplicate_risk", Target: id.String(), At: w.clock.Now().UTC(), Metadata: map[string]string{"reason": ticketAuditText(reason)}}
	return w.dispatch.RetryIntentAudited(ctx, tenant, id, i.Version, entry.At, entry)
}

// ResetBreaker releases only the tuple gate. Retained commands, approval facts
// and active dispatch leases are unchanged; execution preflight still applies.
func (w *Workflow) ResetBreaker(ctx context.Context, tenant, integrationID shared.ID, project, issueType, actor string) error {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(project) == "" || strings.TrimSpace(issueType) == "" || len(project) > 255 || len(issueType) > 255 {
		return shared.ErrValidation
	}
	literals, err := json.Marshal(map[string]string{"project_key": project, "issue_type": issueType})
	if err != nil {
		return shared.ErrValidation
	}
	if err = w.validateTicketLiterals(ctx, tenant, integrationID, literals); err != nil {
		return err
	}
	entry := ports.AuditEntry{Actor: actor, Action: "ticket.breaker.reset", Target: integrationID.String(), At: w.clock.Now().UTC(), Metadata: map[string]string{"project_key": ticketAuditText(project), "issue_type": ticketAuditText(issueType)}}
	return w.dispatch.ResetBreaker(shared.WithTenant(ctx, tenant), tenant, integrationID, project, issueType, entry)
}

type snapshotFacts struct {
	Provider             integration.Provider   `json:"provider"`
	Endpoint             string                 `json:"endpoint"`
	DataClass            notification.DataClass `json:"data_class"`
	PolicyRevision       int                    `json:"policy_revision"`
	MappingVersion       int                    `json:"mapping_version"`
	ConnectionRevision   int                    `json:"connection_revision"`
	CredentialRevision   int                    `json:"credential_revision"`
	WaiverReason         string                 `json:"waiver_reason"`
	UpdateRemoteID       string                 `json:"update_remote_id,omitempty"`
	UpdateRemoteURL      string                 `json:"update_remote_url,omitempty"`
	StatusTransitionID   string                 `json:"status_transition_id,omitempty"`
	StatusComment        string                 `json:"status_comment,omitempty"`
	StatusSource         string                 `json:"status_source,omitempty"`
	GroupRevision        int                    `json:"group_revision,omitempty"`
	GroupVulnerability   string                 `json:"group_vulnerability,omitempty"`
	GroupFactsDigest     string                 `json:"group_facts_digest,omitempty"`
	RequestPreviewDigest string                 `json:"request_preview_digest,omitempty"`
}

// Preview never writes to Jira. Destination/security/policy facts participate in
// the digest; the correlation marker is the only declared provider-field addition.
// Submit also records internal request identity for lost-response recovery.
func (w *Workflow) Preview(ctx context.Context, req PreviewRequest) (Preview, error) {
	if req.TenantID.IsZero() || req.MappingID.IsZero() || req.FindingID.IsZero() || req.EngagementID.IsZero() {
		return Preview{}, shared.ErrValidation
	}
	tenantCtx := shared.WithTenant(ctx, req.TenantID)
	m, err := w.store.GetMapping(tenantCtx, req.TenantID, req.MappingID)
	if err != nil {
		return Preview{}, err
	}
	if err = w.validateFindingScope(tenantCtx, m, req.EngagementID); err != nil {
		return Preview{}, err
	}
	in, err := w.integration(tenantCtx, req.TenantID, m.IntegrationID)
	if err != nil {
		return Preview{}, err
	}
	policy, err := w.policy.GetEngagementNotificationSetting(tenantCtx, req.TenantID, req.EngagementID)
	if err != nil {
		return Preview{}, err
	}
	class, allowed := notification.EffectiveDataClass(mappingClass(m), policy.ExternalNotifications)
	if !allowed {
		return Preview{}, fmt.Errorf("%w: external ticketing disabled for engagement", shared.ErrForbidden)
	}
	f, err := w.findings.GetByEngagementAndID(tenantCtx, req.EngagementID, req.FindingID)
	if err != nil {
		return Preview{}, err
	}
	// Grouped descriptions include vulnerability and attributed-asset detail.
	// Never silently downgrade that table under an engagement override.
	if m.GroupingMode == domain.GroupingVulnerabilityProject && class != notification.DataClassDetail {
		return Preview{}, fmt.Errorf("%w: vulnerability/project grouping requires detail data class", shared.ErrForbidden)
	}
	meta, err := w.Metadata(tenantCtx, req.TenantID, m.IntegrationID, m.ProjectKey, m.IssueType, "")
	if err != nil {
		return Preview{}, err
	}
	if err = w.validateSelections(m, meta); err != nil {
		return Preview{}, err
	}
	summary, body, links, err := RenderTicket(m, f, class, m.Locale, w.publicBase)
	if err != nil {
		return Preview{}, err
	}
	provider, err := w.providers.TicketProvider(tenantCtx, in)
	if err != nil {
		return Preview{}, safeTicketError(err)
	}
	defer closeTicketProvider(provider)
	var description json.RawMessage
	groupRevision, groupFactsDigest, groupVulnerability := 0, "", ""
	if m.GroupingMode == domain.GroupingVulnerabilityProject && strings.TrimSpace(f.AdvisoryID) != "" {
		factsReader, ok := w.store.(ports.TicketGroupFactsReader)
		if !ok {
			return Preview{}, fmt.Errorf("%w: durable ticket group facts required", shared.ErrConflict)
		}
		facts, factsErr := factsReader.GroupTicketFacts(tenantCtx, req.TenantID, m.ID, m.ScopeID, strings.TrimSpace(f.AdvisoryID), ports.TicketGroupMember{EngagementID: req.EngagementID, FindingID: req.FindingID})
		if factsErr != nil {
			return Preview{}, factsErr
		}
		groupFactsDigest, factsErr = ticketGroupFactsDigest(facts)
		if factsErr != nil {
			return Preview{}, factsErr
		}
		groupRevision, groupVulnerability = facts[0].GroupRevision, strings.TrimSpace(f.AdvisoryID)
		headers, rows, rowsErr := w.groupTicketRows(facts, m.Locale)
		if rowsErr != nil {
			return Preview{}, rowsErr
		}
		formatter, ok := provider.(ports.TicketGroupFormatter)
		if !ok {
			return Preview{}, fmt.Errorf("%w: ticket provider does not support grouped descriptions", shared.ErrValidation)
		}
		description, err = formatter.FormatTicketGroupDescription(body, links, headers, rows)
	} else {
		description, err = provider.FormatTicketDescription(body, links)
	}
	if err != nil {
		return Preview{}, err
	}
	fields := map[string]any{"project": map[string]string{"key": m.ProjectKey}, "issuetype": map[string]string{"id": m.IssueType}, "summary": summary, "description": description, "labels": append([]string{}, m.Labels...)}
	if m.Component != "" {
		fields["components"] = []map[string]string{{"id": m.Component}}
	}
	if priority := m.PriorityMap[string(f.Severity)]; priority != "" {
		fields["priority"] = map[string]string{"id": priority}
	}
	if m.SecurityLevel != "" {
		fields["security"] = map[string]string{"id": m.SecurityLevel}
	}
	if reporter, ok := requiredResolvedReporter(meta); ok {
		fields["reporter"] = map[string]string{"name": reporter}
	}
	// Mapping literals are administrator-approved content, but they still pass
	// shared redaction. Class-limited findings never populate arbitrary fields.
	for _, field := range meta.Fields {
		value, configured := m.FieldValues[field.ID]
		if !configured {
			continue
		}
		if class == notification.DataClassSignal {
			return Preview{}, fmt.Errorf("%w: custom fields require summary or detail class", shared.ErrValidation)
		}
		converted, e := ticketFieldValue(field, ticketText(value))
		if e != nil {
			return Preview{}, e
		}
		fields[field.ID] = converted
	}
	payload := map[string]any{"fields": fields, "_synapse": snapshotFacts{Provider: in.Provider, Endpoint: in.Endpoint, DataClass: class, PolicyRevision: policy.Revision, MappingVersion: m.Version, ConnectionRevision: in.ConnectionRevision, CredentialRevision: in.CredentialRevision, WaiverReason: m.WaiverReason, GroupRevision: groupRevision, GroupVulnerability: groupVulnerability, GroupFactsDigest: groupFactsDigest}}
	if m.Transition != "" {
		payload["transition"] = map[string]string{"id": m.Transition}
	}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > 60<<10 {
		return Preview{}, fmt.Errorf("%w: ticket payload too large", shared.ErrValidation)
	}
	if err = provider.ValidateTicketPayload(raw); err != nil {
		return Preview{}, safeTicketError(err)
	}
	return Preview{Payload: raw, Digest: ticketDigest(raw), Summary: summary, Description: body, MappingVersion: m.Version, MarkerRequired: true, MarkerFormat: "synapse-intent-{intent_id}", DataClass: class, Links: links, SecurityWaived: m.SecurityLevel == ""}, nil
}

func (w *Workflow) groupTicketRows(facts []ports.TicketGroupFact, locale string) ([]string, [][]string, error) {
	if len(facts) == 0 || len(facts) > 100 {
		return nil, nil, shared.ErrValidation
	}
	headers := []string{"Asset", "Finding", "Severity", "Status"}
	unassigned := "Unassigned"
	if normalizedLocale(locale) == "vi" {
		headers, unassigned = []string{"Tài sản", "Phát hiện", "Mức độ", "Trạng thái"}, "Chưa gán"
	}
	rows := make([][]string, 0, len(facts))
	for _, fact := range facts {
		if fact.EngagementID.IsZero() || fact.FindingID.IsZero() {
			return nil, nil, shared.ErrValidation
		}
		asset := ticketText(fact.AssetName)
		if asset == "" {
			asset = unassigned
		}
		rows = append(rows, []string{asset, ticketText(fact.Title), localSeverity(fact.Severity, normalizedLocale(locale)), localStatus(fact.Status, normalizedLocale(locale))})
	}
	return headers, rows, nil
}
func (w *Workflow) Submit(ctx context.Context, req SubmitRequest) (domain.Intent, bool, error) {
	if strings.TrimSpace(req.RequestKey) == "" || len(req.RequestKey) > 128 || strings.TrimSpace(req.Actor) == "" {
		return domain.Intent{}, false, shared.ErrValidation
	}
	if requests, ok := w.store.(ports.TicketRequestReader); ok {
		previous, found, err := requests.FindTicketRequest(shared.WithTenant(ctx, req.TenantID), req.TenantID, req.MappingID, req.EngagementID, req.FindingID, req.RequestKey)
		if err != nil {
			return domain.Intent{}, false, err
		}
		if found {
			var envelope struct {
				Facts snapshotFacts `json:"_synapse"`
			}
			if json.Unmarshal(previous.Snapshot, &envelope) != nil || envelope.Facts.RequestPreviewDigest == "" || envelope.Facts.RequestPreviewDigest != req.PreviewDigest {
				return domain.Intent{}, false, shared.ErrConflict
			}
			return previous, false, nil
		}
	}
	p, err := w.Preview(ctx, PreviewRequest{TenantID: req.TenantID, MappingID: req.MappingID, FindingID: req.FindingID, EngagementID: req.EngagementID})
	if err != nil {
		return domain.Intent{}, false, err
	}
	if req.PreviewDigest != p.Digest {
		return domain.Intent{}, false, fmt.Errorf("%w: stale ticket preview", shared.ErrConflict)
	}
	m, err := w.store.GetMapping(ctx, req.TenantID, req.MappingID)
	if err != nil {
		return domain.Intent{}, false, err
	}
	in, err := w.integration(ctx, req.TenantID, m.IntegrationID)
	if err != nil {
		return domain.Intent{}, false, err
	}
	requestLiteral, err := json.Marshal(map[string]string{"request_key": req.RequestKey})
	if err != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	if err = w.validateTicketLiterals(ctx, req.TenantID, in.ID, requestLiteral); err != nil {
		return domain.Intent{}, false, err
	}
	if !in.Enabled {
		return domain.Intent{}, false, fmt.Errorf("%w: test and enable Jira before submit", shared.ErrConflict)
	}
	var payload map[string]json.RawMessage
	if err = json.Unmarshal(p.Payload, &payload); err != nil {
		return domain.Intent{}, false, shared.ErrValidation
	}
	var facts snapshotFacts
	if json.Unmarshal(payload["_synapse"], &facts) != nil || facts.MappingVersion != m.Version || facts.ConnectionRevision != in.ConnectionRevision || facts.CredentialRevision != in.CredentialRevision || facts.Endpoint != in.Endpoint {
		return domain.Intent{}, false, shared.ErrConflict
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(payload["fields"], &fields)
	var labels []string
	_ = json.Unmarshal(fields["labels"], &labels)
	grouped := false
	var group ports.TicketGroup
	action := domain.Create
	facts.RequestPreviewDigest = p.Digest
	if m.GroupingMode == domain.GroupingVulnerabilityProject {
		f, getErr := w.findings.GetByEngagementAndID(shared.WithTenant(ctx, req.TenantID), req.EngagementID, req.FindingID)
		if getErr != nil {
			return domain.Intent{}, false, getErr
		}
		if vulnerability := strings.TrimSpace(f.AdvisoryID); vulnerability != "" {
			groups, ok := w.store.(ports.TicketGroupStore)
			if !ok {
				return domain.Intent{}, false, fmt.Errorf("%w: durable ticket grouping store required", shared.ErrConflict)
			}
			existing, found, groupErr := groups.GetTicketGroup(ctx, req.TenantID, m.ID, m.ScopeID, vulnerability)
			if groupErr != nil {
				return domain.Intent{}, false, groupErr
			}
			group = ports.TicketGroup{ID: w.ids.NewID(), TenantID: req.TenantID, MappingID: m.ID, ProjectID: m.ScopeID, Vulnerability: vulnerability, IntegrationID: in.ID, Endpoint: in.Endpoint, ProjectKey: m.ProjectKey, IssueType: m.IssueType, SecurityLevel: m.SecurityLevel, Revision: facts.GroupRevision}
			if found {
				group.ID, group.CreatedAt = existing.ID, existing.CreatedAt
				if existing.Remote.ID != "" && existing.Remote.URL != "" {
					action, facts.UpdateRemoteID, facts.UpdateRemoteURL = domain.Update, existing.Remote.ID, existing.Remote.URL
				}
			}
			grouped = true
		}
	}
	payload["_synapse"], _ = json.Marshal(facts)
	unsigned, _ := json.Marshal(payload)
	digest := ticketDigest(unsigned)
	id := w.ids.NewID()
	marker := "synapse-intent-" + id.String()
	labels = append(labels, marker)
	fields["labels"], _ = json.Marshal(labels)
	payload["fields"], _ = json.Marshal(fields)
	raw, _ := json.Marshal(payload)
	now := w.clock.Now().UTC()
	if grouped {
		if group.CreatedAt.IsZero() {
			group.CreatedAt = now
		}
		group.UpdatedAt = now
	}
	i := domain.Intent{ID: id, TenantID: req.TenantID, IntegrationID: m.IntegrationID, MappingID: m.ID, FindingID: req.FindingID, EngagementID: req.EngagementID, Action: action, RequestKey: req.RequestKey, PayloadDigest: digest, Marker: marker, State: writeintent.Pending, Version: 1, Snapshot: raw, MappingVersion: facts.MappingVersion, ConnectionRevision: facts.ConnectionRevision, CredentialRevision: facts.CredentialRevision, SecurityLevel: m.SecurityLevel, CreatedAt: now, UpdatedAt: now}
	entry := ports.AuditEntry{Actor: req.Actor, Action: "ticket.intent.created", Target: id.String(), At: now, Metadata: map[string]string{"mapping_id": m.ID.String(), "preview_digest": p.Digest}}
	if grouped {
		groups := w.store.(ports.TicketGroupStore)
		return groups.CreateOrGetGroupedIntent(ctx, req.TenantID, group, ports.TicketGroupMember{EngagementID: req.EngagementID, FindingID: req.FindingID}, i, entry)
	}
	return w.intentAudit.CreateOrGetIntentAudited(ctx, req.TenantID, i, entry)
}

const (
	ticketTickStageUnit     = 5 * time.Second
	ticketTickStageUnits    = 7
	ticketOutboundStageUnit = 4
)

// ticketStageContext reserves time for every workflow stage. A deadline shorter
// than the normal 35-second allocation is divided by the same weights, so a
// hung maintenance read cannot consume the caller's entire worker lease.
func ticketStageContext(ctx context.Context, units int) (context.Context, context.CancelFunc) {
	budget := time.Duration(units) * ticketTickStageUnit
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining < time.Duration(ticketTickStageUnits)*ticketTickStageUnit {
			budget = (remaining / ticketTickStageUnits) * time.Duration(units)
			if budget <= 0 {
				budget = time.Nanosecond
			}
		}
	}
	return context.WithTimeout(ctx, budget)
}

// Tick makes independently bounded progress across automatic planning, outbound
// writes, status planning, and inbound observation. The outbound queue runs
// before inbound polling because it is the only stage that dispatches durable
// user-approved intents. A timed-out child stage is retried on the next tick;
// parent cancellation is still returned immediately.
func (w *Workflow) Tick(ctx context.Context, tenant shared.ID, limit int) (int, error) {
	if tenant.IsZero() || limit < 1 || limit > 100 {
		return 0, shared.ErrValidation
	}
	tenantCtx := shared.WithTenant(ctx, tenant)
	var stageErrors []error
	run := func(units int, work func(context.Context) error) bool {
		if err := ctx.Err(); err != nil {
			stageErrors = append(stageErrors, err)
			return false
		}
		stageCtx, cancel := ticketStageContext(tenantCtx, units)
		err := work(stageCtx)
		stageTimedOut := errors.Is(stageCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
		cancel()
		if ctx.Err() != nil {
			stageErrors = append(stageErrors, ctx.Err())
			return false
		}
		if err != nil && !(stageTimedOut && errors.Is(err, context.DeadlineExceeded)) {
			stageErrors = append(stageErrors, err)
		}
		return true
	}

	if auto, ok := w.store.(ports.TicketAutoPushStore); ok && w.autoPushSourceAvailable {
		if !run(1, func(stageCtx context.Context) error {
			_, err := w.tickAutoPush(stageCtx, tenant, auto, min(limit, 100))
			return err
		}) {
			return 0, errors.Join(stageErrors...)
		}
	}

	if statuses, ok := w.store.(ports.TicketStatusStore); ok && w.sla != nil {
		if !run(1, func(stageCtx context.Context) error {
			_, err := w.tickTicketStatuses(stageCtx, tenant, statuses, min(limit, 100))
			return err
		}) {
			return 0, errors.Join(stageErrors...)
		}
	}

	completed := 0
	if !run(ticketOutboundStageUnit, func(stageCtx context.Context) error {
		var err error
		completed, err = w.tickOutboundIntents(stageCtx, tenant, limit)
		return err
	}) {
		return completed, errors.Join(stageErrors...)
	}

	if inbound, ok := w.store.(ports.TicketInboundStore); ok {
		if !run(1, func(stageCtx context.Context) error {
			return w.tickInboundTicketObservationsWithProgress(stageCtx, tenantCtx, tenant, inbound, min(limit, 250))
		}) {
			return completed, errors.Join(stageErrors...)
		}
	}
	return completed, errors.Join(stageErrors...)
}

func (w *Workflow) tickOutboundIntents(tenantCtx context.Context, tenant shared.ID, limit int) (int, error) {
	due, err := w.store.ListDueIntents(tenantCtx, tenant, w.clock.Now().UTC(), limit)
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, i := range due {
		if tenantCtx.Err() != nil {
			return completed, tenantCtx.Err()
		}
		now := w.clock.Now().UTC()
		if i.State == writeintent.InFlight {
			if _, e := w.store.TransitionIntent(tenantCtx, tenant, i.ID, i.Version, domain.IntentTransition{Event: writeintent.LeaseExpired}, now); e != nil && !errors.Is(e, shared.ErrConflict) {
				return completed, e
			}
			continue
		}
		// Legacy rows are retained for recovery but cannot become external writes.
		facts, request, e := readTicketSnapshot(i)
		if e != nil {
			lease := now.Add(time.Minute)
			claimed, ce := w.store.TransitionIntent(tenantCtx, tenant, i.ID, i.Version, domain.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
			if ce == nil {
				_, ce = w.store.TransitionIntent(tenantCtx, tenant, claimed.ID, claimed.Version, domain.IntentTransition{Event: writeintent.Reject, ErrorCode: "invalid_snapshot"}, now)
			}
			if ce != nil && !errors.Is(ce, shared.ErrConflict) {
				return completed, ce
			}
			continue
		}
		lease := now.Add(time.Minute)
		claimed, ok, e := w.dispatch.AcquireDispatch(tenantCtx, tenant, i.ID, i.Version, now, lease)
		if e != nil {
			if errors.Is(e, shared.ErrConflict) {
				continue
			}
			return completed, e
		}
		if !ok {
			continue
		}
		in, preflightErr := w.executionPreflight(tenantCtx, claimed, facts)
		if preflightErr != nil {
			if _, e = w.dispatch.FinishDispatch(tenantCtx, tenant, claimed.ID, claimed.Version, domain.IntentTransition{Event: writeintent.Reject, ErrorCode: "preflight_refused"}, w.clock.Now().UTC(), nil, ""); e != nil && !errors.Is(e, shared.ErrConflict) {
				return completed, e
			}
			continue
		}
		provider, e := w.providers.TicketProvider(tenantCtx, in)
		if e != nil {
			_, e = w.dispatch.FinishDispatch(tenantCtx, tenant, claimed.ID, claimed.Version, domain.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_unavailable"}, w.clock.Now().UTC(), nil, "")
			if e != nil && !errors.Is(e, shared.ErrConflict) {
				return completed, e
			}
			continue
		}
		callCtx, cancel := context.WithTimeout(tenantCtx, 20*time.Second)
		var remote domain.RemoteTicket
		var sendErr error
		if claimed.Action == domain.Transition {
			writer, ok := provider.(ports.TicketStatusWriter)
			if !ok || facts.UpdateRemoteID == "" || facts.StatusTransitionID == "" || facts.StatusComment == "" {
				sendErr = &ports.TicketProviderError{Code: "transition_unsupported"}
			} else {
				remote = domain.RemoteTicket{ID: facts.UpdateRemoteID, URL: facts.UpdateRemoteURL}
				sendErr = writer.TransitionTicket(callCtx, facts.UpdateRemoteID, facts.StatusTransitionID, facts.StatusComment)
			}
		} else if claimed.Action == domain.Update {
			updater, ok := provider.(ports.TicketUpdater)
			if !ok || facts.UpdateRemoteID == "" || facts.UpdateRemoteURL == "" {
				sendErr = &ports.TicketProviderError{Code: "update_unsupported"}
			} else {
				remote = domain.RemoteTicket{ID: facts.UpdateRemoteID, URL: facts.UpdateRemoteURL}
				sendErr = updater.UpdateTicket(callCtx, facts.UpdateRemoteID, request)
			}
		} else if claimed.Action == domain.Create {
			remote, sendErr = provider.CreateTicket(callCtx, request)
		} else {
			sendErr = &ports.TicketProviderError{Code: "unsupported_action"}
		}
		cancel()
		closeTicketProvider(provider)
		change := domain.IntentTransition{Event: writeintent.Ambiguous}
		var until *time.Time
		code := ""
		if sendErr == nil {
			if !sameRemoteOrigin(in.Endpoint, remote.URL) {
				change = domain.IntentTransition{Event: writeintent.Ambiguous}
			} else {
				change = domain.IntentTransition{Event: writeintent.Acknowledge, Remote: &remote}
			}
		} else {
			var refusal *ports.TicketProviderError
			if errors.As(sendErr, &refusal) && !refusal.Ambiguous {
				if refusal.Status == 0 && (refusal.Code == "unsupported_action" || refusal.Code == "update_unsupported" || refusal.Code == "transition_unsupported") {
					code = "invalid_action"
					change = domain.IntentTransition{Event: writeintent.Reject, ErrorCode: code}
				}
				switch refusal.Status {
				case 400, 401, 403, 404:
					code = fmt.Sprintf("http_%d", refusal.Status)
					change = domain.IntentTransition{Event: writeintent.Reject, ErrorCode: code}
				case 429:
					delay := refusal.RetryAfter
					if delay < time.Second {
						delay = time.Second
					}
					at := w.clock.Now().UTC().Add(delay)
					until = &at
					code = "rate_limited"
					change = domain.IntentTransition{Event: writeintent.Reject, ErrorCode: code}
				}
			}
		}
		// Persist even after caller cancellation using a bounded independent context;
		// failure leaves the durable lease to expire into uncertainty, never resends.
		finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(tenantCtx), 5*time.Second)
		saved, e := w.dispatch.FinishDispatch(finishCtx, tenant, claimed.ID, claimed.Version, change, w.clock.Now().UTC(), until, code)
		finishCancel()
		if e != nil {
			if !errors.Is(e, shared.ErrConflict) {
				return completed, e
			}
			continue
		}
		if saved.State == writeintent.Done {
			if saved.Action == domain.Create {
				if groups, ok := w.store.(ports.TicketGroupStore); ok {
					if groupErr := groups.CompleteGroupedIntent(tenantCtx, tenant, saved.ID, domain.RemoteTicket{ID: saved.RemoteID, URL: saved.RemoteURL}, w.clock.Now().UTC()); groupErr != nil && !errors.Is(groupErr, shared.ErrNotFound) {
						return completed, groupErr
					}
				}
			}
			completed++
		}
	}
	return completed, nil
}

// tickAutoPush consumes the durable finding.status_changed stream rather than a
// recent-events view. Replays are harmless because every event/mapping pair has
// a stable request key; malformed or no-longer-eligible events advance so they
// cannot block later healthy changes.
func (w *Workflow) tickAutoPush(ctx context.Context, tenant shared.ID, store ports.TicketAutoPushStore, limit int) (int, error) {
	now := w.clock.Now().UTC()
	events, err := store.ListAutoPushEvents(ctx, tenant, now, limit)
	if err != nil {
		return 0, err
	}
	created := 0
	for _, event := range events {
		if ctx.Err() != nil {
			return created, ctx.Err()
		}
		if event.FindingID.IsZero() || event.EngagementID.IsZero() || event.ToStatus != string(finding.StatusConfirmed) {
			if err := store.CompleteAutoPushEvent(ctx, tenant, event, w.clock.Now().UTC()); err != nil {
				return created, err
			}
			continue
		}
		mappings, err := w.store.ListFindingMappings(ctx, tenant, event.EngagementID, 200)
		if err != nil {
			if deferErr := store.DeferAutoPushEvent(ctx, tenant, event, now.Add(time.Minute)); deferErr != nil {
				return created, deferErr
			}
			continue
		}
		retry := false
		for _, mapping := range mappings {
			if !mapping.AutoPushEnabled || mapping.AutoPushEnabledAt == nil || event.OccurredAt.Before(mapping.AutoPushEnabledAt.UTC()) || shared.SeverityRank(mapping.AutoPushMinSeverity) == 0 {
				continue
			}
			f, err := w.findings.GetByEngagementAndID(ctx, event.EngagementID, event.FindingID)
			if err != nil {
				if errors.Is(err, shared.ErrNotFound) {
					break
				}
				retry = true
				break
			}
			if f.Status != finding.StatusConfirmed || f.Kind == finding.KindExternal || !f.CanPromote() || shared.SeverityRank(f.Severity) < shared.SeverityRank(mapping.AutoPushMinSeverity) {
				continue
			}
			preview, err := w.Preview(ctx, PreviewRequest{TenantID: tenant, MappingID: mapping.ID, FindingID: f.ID, EngagementID: event.EngagementID})
			if err != nil {
				if autoPushPermanent(err) {
					continue
				}
				retry = true
				break
			}
			sum := sha256.Sum256([]byte(event.ID.String() + "\x00" + mapping.ID.String()))
			key := "auto:" + hex.EncodeToString(sum[:])
			_, wasCreated, err := w.Submit(ctx, SubmitRequest{TenantID: tenant, MappingID: mapping.ID, FindingID: f.ID, EngagementID: event.EngagementID, RequestKey: key, PreviewDigest: preview.Digest, Actor: "system:auto_push"})
			if err != nil {
				if autoPushPermanent(err) {
					continue
				}
				retry = true
				break
			}
			if wasCreated {
				created++
			}
		}
		if retry {
			if err := store.DeferAutoPushEvent(ctx, tenant, event, now.Add(time.Minute)); err != nil {
				return created, err
			}
			continue
		}
		if err := store.CompleteAutoPushEvent(ctx, tenant, event, w.clock.Now().UTC()); err != nil {
			return created, err
		}
	}
	return created, nil
}

func autoPushPermanent(err error) bool {
	if errors.Is(err, domain.ErrGroupBusy) {
		return false
	}
	return errors.Is(err, shared.ErrValidation) || errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrForbidden)
}
func (w *Workflow) Reconcile(ctx context.Context, tenant, id shared.ID, version int) (domain.Intent, error) {
	i, err := w.store.GetIntent(ctx, tenant, id)
	if err != nil {
		return domain.Intent{}, err
	}
	if i.State != writeintent.Uncertain || version < 1 || i.Version != version {
		return domain.Intent{}, shared.ErrConflict
	}
	facts, _, err := readTicketSnapshot(i)
	if err != nil {
		return domain.Intent{}, err
	}
	in, err := w.integration(ctx, tenant, i.IntegrationID)
	if err != nil {
		return domain.Intent{}, err
	}
	if in.Endpoint != facts.Endpoint || in.Provider != facts.Provider {
		return domain.Intent{}, fmt.Errorf("%w: restore the original Jira origin before reconciliation", shared.ErrConflict)
	}
	p, err := w.providers.TicketProvider(shared.WithTenant(ctx, tenant), in)
	if err != nil {
		return domain.Intent{}, safeTicketError(err)
	}
	defer closeTicketProvider(p)
	target, err := i.DispatchTarget()
	if err != nil {
		return domain.Intent{}, err
	}
	hits, err := p.SearchTicketMarker(ctx, target.ProjectKey, target.IssueType, i.Marker)
	if err != nil {
		return domain.Intent{}, safeTicketError(err)
	}
	if len(hits) == 0 {
		return i, nil
	}
	change := domain.IntentTransition{Event: writeintent.ReconcileMultiple}
	if len(hits) == 1 {
		if !sameRemoteOrigin(facts.Endpoint, hits[0].URL) {
			return domain.Intent{}, shared.ErrValidation
		}
		change = domain.IntentTransition{Event: writeintent.ReconcileFound, Remote: &hits[0]}
	}
	return w.store.TransitionIntent(ctx, tenant, id, i.Version, change, w.clock.Now().UTC())
}
func (w *Workflow) ListFindingIntents(ctx context.Context, tenant, finding shared.ID, limit int) ([]domain.Intent, error) {
	return w.store.ListFindingIntents(ctx, tenant, finding, limit)
}
func ticketDigest(raw []byte) string {
	var value any
	if json.Unmarshal(raw, &value) == nil {
		raw, _ = json.Marshal(value)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func closeTicketProvider(provider ports.TicketProvider) {
	if closer, ok := provider.(interface{ Close() }); ok {
		closer.Close()
	}
}
func sameRemoteOrigin(endpoint, remote string) bool {
	a, e := url.Parse(endpoint)
	if e != nil {
		return false
	}
	b, e := url.Parse(remote)
	if e != nil {
		return false
	}
	return a.Scheme == "https" && b.Scheme == "https" && strings.EqualFold(a.Host, b.Host) && b.User == nil && b.RawQuery == "" && b.Fragment == "" && strings.HasPrefix(b.Path, strings.TrimRight(a.Path, "/")+"/browse/")
}
func safeTicketError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{shared.ErrValidation, shared.ErrNotFound, shared.ErrConflict, shared.ErrForbidden, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	var provider *ports.TicketProviderError
	if errors.As(err, &provider) {
		return provider
	}
	return fmt.Errorf("%w: Jira is unavailable", shared.ErrValidation)
}
func mappingClass(m domain.Mapping) notification.DataClass {
	if m.DataClass.Valid() {
		return m.DataClass
	}
	return notification.DataClassSummary
}
