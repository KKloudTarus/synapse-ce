package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

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
	IntegrationID       shared.ID              `json:"integration_id"`
	Scope               domain.Scope           `json:"scope"`
	ScopeID             shared.ID              `json:"scope_id"`
	ProjectKey          string                 `json:"project_key"`
	IssueType           string                 `json:"issue_type"`
	Component           string                 `json:"component"`
	Labels              []string               `json:"labels"`
	PriorityMap         map[string]string      `json:"priority_map"`
	SecurityLevel       string                 `json:"security_level"`
	SummaryTemplate     string                 `json:"summary_template"`
	DescriptionTemplate string                 `json:"description_template"`
	FieldValues         map[string]string      `json:"field_values"`
	Transition          string                 `json:"transition_id"`
	DataClass           notification.DataClass `json:"data_class"`
	Locale              string                 `json:"locale"`
	Version             int                    `json:"version"`
	WaiverReason        string                 `json:"waiver_reason"`
	Actor               string                 `json:"-"`
	AllowAdmin          bool                   `json:"-"`
}
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
	if in.SecurityLevel == "" && (!in.AllowAdmin || strings.TrimSpace(in.WaiverReason) == "") {
		return domain.Mapping{}, fmt.Errorf("%w: select an issue security level or record an administrator waiver", shared.ErrValidation)
	}
	if len(in.WaiverReason) > 1024 {
		return domain.Mapping{}, shared.ErrValidation
	}
	in.WaiverReason = ticketAuditText(in.WaiverReason)
	now := w.clock.Now().UTC()
	m := domain.Mapping{ID: id, TenantID: tenant, IntegrationID: in.IntegrationID, Scope: in.Scope, ScopeID: in.ScopeID, ProjectKey: in.ProjectKey, IssueType: in.IssueType, Component: in.Component, Labels: in.Labels, PriorityMap: in.PriorityMap, SecurityLevel: in.SecurityLevel, SummaryTemplate: in.SummaryTemplate, DescriptionTemplate: in.DescriptionTemplate, FieldValues: in.FieldValues, Transition: in.Transition, DataClass: in.DataClass, Locale: in.Locale, WaiverReason: in.WaiverReason, Version: 1, CreatedAt: now, UpdatedAt: now}
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
		action = "ticket.mapping.updated"
	}
	if m.DataClass == notification.DataClassDetail && !in.AllowAdmin {
		return domain.Mapping{}, shared.ErrForbidden
	}
	if err := m.Validate(); err != nil {
		return domain.Mapping{}, err
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
	Provider           integration.Provider   `json:"provider"`
	Endpoint           string                 `json:"endpoint"`
	DataClass          notification.DataClass `json:"data_class"`
	PolicyRevision     int                    `json:"policy_revision"`
	MappingVersion     int                    `json:"mapping_version"`
	ConnectionRevision int                    `json:"connection_revision"`
	CredentialRevision int                    `json:"credential_revision"`
	WaiverReason       string                 `json:"waiver_reason"`
}

// Preview never writes to Jira. Destination/security/policy facts participate in
// the digest; the correlation marker is the only declared provider-field addition.
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
	description, err := provider.FormatTicketDescription(body, links)
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
	payload := map[string]any{"fields": fields, "_synapse": snapshotFacts{Provider: in.Provider, Endpoint: in.Endpoint, DataClass: class, PolicyRevision: policy.Revision, MappingVersion: m.Version, ConnectionRevision: in.ConnectionRevision, CredentialRevision: in.CredentialRevision, WaiverReason: m.WaiverReason}}
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
func (w *Workflow) Submit(ctx context.Context, req SubmitRequest) (domain.Intent, bool, error) {
	if strings.TrimSpace(req.RequestKey) == "" || len(req.RequestKey) > 128 || strings.TrimSpace(req.Actor) == "" {
		return domain.Intent{}, false, shared.ErrValidation
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
	id := w.ids.NewID()
	marker := "synapse-intent-" + id.String()
	labels = append(labels, marker)
	fields["labels"], _ = json.Marshal(labels)
	payload["fields"], _ = json.Marshal(fields)
	raw, _ := json.Marshal(payload)
	now := w.clock.Now().UTC()
	i := domain.Intent{ID: id, TenantID: req.TenantID, IntegrationID: m.IntegrationID, MappingID: m.ID, FindingID: req.FindingID, EngagementID: req.EngagementID, Action: domain.Create, RequestKey: req.RequestKey, PayloadDigest: p.Digest, Marker: marker, State: writeintent.Pending, Version: 1, Snapshot: raw, MappingVersion: facts.MappingVersion, ConnectionRevision: facts.ConnectionRevision, CredentialRevision: facts.CredentialRevision, SecurityLevel: m.SecurityLevel, CreatedAt: now, UpdatedAt: now}
	entry := ports.AuditEntry{Actor: req.Actor, Action: "ticket.intent.created", Target: id.String(), At: now, Metadata: map[string]string{"mapping_id": m.ID.String(), "preview_digest": p.Digest}}
	return w.intentAudit.CreateOrGetIntentAudited(ctx, req.TenantID, i, entry)
}

func (w *Workflow) Tick(ctx context.Context, tenant shared.ID, limit int) (int, error) {
	if tenant.IsZero() || limit < 1 || limit > 100 {
		return 0, shared.ErrValidation
	}
	tenantCtx := shared.WithTenant(ctx, tenant)
	due, err := w.store.ListDueIntents(tenantCtx, tenant, w.clock.Now().UTC(), limit)
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, i := range due {
		if ctx.Err() != nil {
			return completed, ctx.Err()
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
		remote, sendErr := provider.CreateTicket(callCtx, request)
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
			completed++
		}
	}
	return completed, nil
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
