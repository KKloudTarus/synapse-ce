package ticketing

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (w *Workflow) integration(ctx context.Context, tenant, id shared.ID) (integration.Integration, error) {
	if tenant.IsZero() || id.IsZero() {
		return integration.Integration{}, shared.ErrValidation
	}
	item, err := w.integrations.GetIntegration(shared.WithTenant(ctx, tenant), id)
	if err != nil {
		return integration.Integration{}, err
	}
	if item.TenantID != tenant || item.Archived {
		return integration.Integration{}, shared.ErrNotFound
	}
	if item.Provider != "jira-cloud" && item.Provider != "jira-dc" {
		return integration.Integration{}, fmt.Errorf("%w: choose a Jira integration", shared.ErrValidation)
	}
	return item, nil
}
func (w *Workflow) validateScope(ctx context.Context, m domain.Mapping) error {
	ctx = shared.WithTenant(ctx, m.TenantID)
	switch m.Scope {
	case domain.Engagement:
		_, err := w.engagements.GetByIDInTenant(ctx, m.TenantID, m.ScopeID)
		return err
	case domain.Project:
		_, err := w.engagements.GetByProjectID(ctx, m.TenantID, m.ScopeID)
		return err
	default:
		return shared.ErrValidation
	}
}
func (w *Workflow) validateFindingScope(ctx context.Context, m domain.Mapping, engagement shared.ID) error {
	if m.Scope == domain.Engagement {
		if m.ScopeID != engagement {
			return shared.ErrNotFound
		}
		_, err := w.engagements.GetByIDInTenant(ctx, m.TenantID, engagement)
		return err
	}
	if m.Scope != domain.Project {
		return shared.ErrValidation
	}
	e, err := w.engagements.GetByProjectID(shared.WithTenant(ctx, m.TenantID), m.TenantID, m.ScopeID)
	if err != nil {
		return err
	}
	if e == nil || e.ID != engagement {
		return shared.ErrNotFound
	}
	return nil
}
func validateTicketTemplates(m domain.Mapping) error {
	schema, err := msgtemplate.NewSchema(TicketContextSpec)
	if err != nil {
		return err
	}
	for name, source := range map[string]string{"ticket-summary": m.SummaryTemplate, "ticket-description": m.DescriptionTemplate} {
		if source != "" {
			if _, err = msgtemplate.Compile(name, source, schema); err != nil {
				return fmt.Errorf("%w: invalid ticket template", shared.ErrValidation)
			}
		}
	}
	return nil
}
func (w *Workflow) Metadata(ctx context.Context, tenant, integrationID shared.ID, project, typ, issue string) (ports.TicketMetadata, error) {
	item, err := w.integration(ctx, tenant, integrationID)
	if err != nil {
		return ports.TicketMetadata{}, err
	}
	if len(project) > 255 || len(typ) > 255 || len(issue) > 255 {
		return ports.TicketMetadata{}, shared.ErrValidation
	}
	keyBytes, _ := json.Marshal([]any{tenant, item.ID, item.Endpoint, item.ConnectionRevision, item.CredentialRevision, project, typ, issue})
	key := string(keyBytes)
	now := w.clock.Now().UTC()
	w.metadataMu.Lock()
	cached, found := w.metadata[key]
	w.metadataMu.Unlock()
	if found && now.Sub(cached.at) < 30*time.Second {
		return cloneTicketMetadata(cached.value), nil
	}
	result := w.discovery.DoChan(key, func() (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		w.metadataMu.Lock()
		cached, found := w.metadata[key]
		if found && w.clock.Now().UTC().Sub(cached.at) < 30*time.Second {
			w.metadataMu.Unlock()
			return cloneTicketMetadata(cached.value), nil
		}
		if len(w.metadataActive) >= 4 {
			w.metadataMu.Unlock()
			return nil, fmt.Errorf("%w: Jira metadata discovery capacity reached", shared.ErrConflict)
		}
		w.metadataActive[key] = struct{}{}
		w.metadataMu.Unlock()
		defer func() {
			w.metadataMu.Lock()
			delete(w.metadataActive, key)
			w.metadataMu.Unlock()
		}()

		callCtx, cancel := context.WithTimeout(shared.WithTenant(ctx, tenant), 20*time.Second)
		defer cancel()
		provider, e := w.providers.TicketProvider(callCtx, item)
		if e != nil {
			return nil, safeTicketError(e)
		}
		defer closeTicketProvider(provider)
		meta, e := provider.DiscoverTickets(callCtx, project, typ, issue)
		if e != nil {
			return nil, safeTicketError(e)
		}
		raw, e := json.Marshal(meta)
		if e != nil || len(raw) > 256<<10 {
			return nil, fmt.Errorf("%w: Jira metadata exceeds supported bounds", shared.ErrValidation)
		}
		w.metadataMu.Lock()
		defer w.metadataMu.Unlock()
		if len(w.metadata) >= 32 {
			oldest := ""
			var oldestAt time.Time
			for k, v := range w.metadata {
				if oldest == "" || v.at.Before(oldestAt) {
					oldest, oldestAt = k, v.at
				}
			}
			delete(w.metadata, oldest)
		}
		w.metadata[key] = metadataEntry{value: cloneTicketMetadata(meta), at: w.clock.Now().UTC()}
		return meta, nil
	})
	select {
	case <-ctx.Done():
		return ports.TicketMetadata{}, ctx.Err()
	case answer := <-result:
		if answer.Err != nil {
			return ports.TicketMetadata{}, answer.Err
		}
		return cloneTicketMetadata(answer.Val.(ports.TicketMetadata)), nil
	}
}
func cloneTicketMetadata(meta ports.TicketMetadata) ports.TicketMetadata {
	raw, _ := json.Marshal(meta)
	var out ports.TicketMetadata
	_ = json.Unmarshal(raw, &out)
	return out
}

// ticketAuditText applies both the audit sink's URL removal and the shared
// generic credential scrub. Exact configured credentials are rejected before
// persistence by validateTicketLiterals at each relevant write boundary.
func ticketAuditText(value string) string {
	return ticketRenderedText(redact.AuditText(value, nil))
}
func choiceExists(choices []ports.TicketChoice, id string) bool {
	for _, choice := range choices {
		if choice.ID == id {
			return true
		}
	}
	return false
}
func (w *Workflow) validateSelections(m domain.Mapping, meta ports.TicketMetadata) error {
	if !choiceExists(meta.Projects, m.ProjectKey) || !choiceExists(meta.IssueTypes, m.IssueType) {
		return fmt.Errorf("%w: select a discovered Jira project and issue type", shared.ErrValidation)
	}
	if m.SecurityLevel == "" {
		if strings.TrimSpace(m.WaiverReason) == "" {
			return fmt.Errorf("%w: issue security level required", shared.ErrValidation)
		}
	} else if !choiceExists(meta.SecurityLevels, m.SecurityLevel) {
		return fmt.Errorf("%w: issue security level unavailable", shared.ErrValidation)
	}
	if m.Component != "" && !choiceExists(meta.Components, m.Component) {
		return fmt.Errorf("%w: component unavailable", shared.ErrValidation)
	}
	for severity, id := range m.PriorityMap {
		validSeverity := false
		for _, known := range shared.AllSeverities() {
			if severity == string(known) {
				validSeverity = true
				break
			}
		}
		if !validSeverity {
			return fmt.Errorf("%w: priority key must be a finding severity", shared.ErrValidation)
		}
		if !choiceExists(meta.Priorities, id) {
			return fmt.Errorf("%w: priority unavailable", shared.ErrValidation)
		}
	}
	for _, label := range m.Labels {
		if strings.HasPrefix(label, "synapse-intent-") || ticketText(label) != label {
			return fmt.Errorf("%w: label contains reserved or sensitive content", shared.ErrValidation)
		}
	}
	// Initial transitions are discovered on an existing Jira issue, never typed by
	// ID. A create mapping without an issue context cannot safely promise one.
	if m.Transition != "" && !choiceExists(meta.Transitions, m.Transition) {
		return fmt.Errorf("%w: transition unavailable in create context", shared.ErrValidation)
	}
	known := make(map[string]ports.TicketField, len(meta.Fields))
	for _, field := range meta.Fields {
		known[field.ID] = field
	}
	for _, id := range []string{"summary", "description", "labels"} {
		if _, available := known[id]; !available {
			return fmt.Errorf("%w: Jira create screen does not expose %s", shared.ErrValidation, id)
		}
	}
	if m.SecurityLevel != "" {
		if _, available := known["security"]; !available {
			return fmt.Errorf("%w: issue security is unavailable on the Jira create screen", shared.ErrValidation)
		}
	}
	if m.Component != "" {
		if _, available := known["components"]; !available {
			return fmt.Errorf("%w: components are unavailable on the Jira create screen", shared.ErrValidation)
		}
	}
	if len(m.PriorityMap) != 0 {
		if _, available := known["priority"]; !available {
			return fmt.Errorf("%w: priority is unavailable on the Jira create screen", shared.ErrValidation)
		}
	}
	for id, value := range m.FieldValues {
		if reservedTicketField(id) {
			return fmt.Errorf("%w: core ticket fields cannot be overridden", shared.ErrValidation)
		}
		field, ok := known[id]
		if !ok {
			return fmt.Errorf("%w: custom field unavailable", shared.ErrValidation)
		}
		if _, err := ticketFieldValue(field, ticketText(value)); err != nil {
			return err
		}
	}
	for _, field := range meta.Fields {
		if !field.Required || field.HasDefault {
			continue
		}
		switch field.ID {
		case "project", "issuetype", "summary", "description", "labels":
			continue
		case "security":
			if m.SecurityLevel != "" {
				continue
			}
		case "components":
			if m.Component != "" {
				continue
			}
		case "priority":
			if len(m.PriorityMap) >= len(shared.AllSeverities()) {
				continue
			}
		case "reporter":
			if field.Type == "user" && validResolvedReporter(meta.ResolvedReporter) {
				continue
			}
		default:
			if value, ok := m.FieldValues[field.ID]; ok && strings.TrimSpace(value) != "" {
				continue
			}
		}
		return fmt.Errorf("%w: Jira requires another configured field", shared.ErrValidation)
	}
	return nil
}

func validResolvedReporter(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 255
}

func requiredResolvedReporter(meta ports.TicketMetadata) (string, bool) {
	for _, field := range meta.Fields {
		if field.ID == "reporter" && field.Required && !field.HasDefault && field.Type == "user" && validResolvedReporter(meta.ResolvedReporter) {
			return strings.TrimSpace(meta.ResolvedReporter), true
		}
	}
	return "", false
}
func reservedTicketField(id string) bool {
	switch id {
	case "project", "issuetype", "summary", "description", "labels", "security", "priority", "components", "transition", "assignee", "reporter":
		return true
	}
	return false
}
func ticketFieldValue(field ports.TicketField, value string) (any, error) {
	if len(value) > 4096 || strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%w: custom field value required", shared.ErrValidation)
	}
	if len(field.Values) > 0 {
		if !choiceExists(field.Values, value) {
			return nil, fmt.Errorf("%w: choose an allowed custom field value", shared.ErrValidation)
		}
		if field.Type == "array" {
			return []map[string]string{{"id": value}}, nil
		}
		return map[string]string{"id": value}, nil
	}
	switch field.Type {
	case "", "string":
		return value, nil
	case "number":
		n, err := strconv.ParseFloat(value, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, shared.ErrValidation
		}
		return n, nil
	case "boolean":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return nil, shared.ErrValidation
		}
		return b, nil
	case "date":
		if _, err := time.Parse("2006-01-02", value); err != nil {
			return nil, shared.ErrValidation
		}
		return value, nil
	default:
		return nil, fmt.Errorf("%w: custom field type needs a supported value selector", shared.ErrValidation)
	}
}
func readTicketSnapshot(i domain.Intent) (snapshotFacts, json.RawMessage, error) {
	var obj map[string]json.RawMessage
	var facts snapshotFacts
	if json.Unmarshal(i.Snapshot, &obj) != nil || json.Unmarshal(obj["_synapse"], &facts) != nil || !facts.DataClass.Valid() || facts.Endpoint == "" || (facts.Provider != "jira-cloud" && facts.Provider != "jira-dc") || facts.MappingVersion != i.MappingVersion || facts.ConnectionRevision != i.ConnectionRevision || facts.CredentialRevision != i.CredentialRevision {
		return facts, nil, fmt.Errorf("%w: immutable ticket snapshot missing", shared.ErrValidation)
	}
	u, err := url.Parse(facts.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return facts, nil, shared.ErrValidation
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(obj["fields"], &fields) != nil {
		return facts, nil, shared.ErrValidation
	}
	var labels []string
	if json.Unmarshal(fields["labels"], &labels) != nil {
		return facts, nil, shared.ErrValidation
	}
	original := make([]string, 0, len(labels))
	markers := 0
	for _, label := range labels {
		if label == i.Marker {
			markers++
		} else {
			original = append(original, label)
		}
	}
	if markers != 1 {
		return facts, nil, shared.ErrValidation
	}
	fields["labels"], _ = json.Marshal(original)
	base := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		base[k] = v
	}
	base["fields"], _ = json.Marshal(fields)
	raw, _ := json.Marshal(base)
	if ticketDigest(raw) != i.PayloadDigest {
		return facts, nil, fmt.Errorf("%w: ticket snapshot digest mismatch", shared.ErrConflict)
	}
	if i.Action == domain.Update || i.Action == domain.Transition {
		if facts.UpdateRemoteID == "" || facts.UpdateRemoteURL == "" {
			return facts, nil, fmt.Errorf("%w: update ticket target missing", shared.ErrValidation)
		}
		if i.Action == domain.Transition {
			if facts.StatusTransitionID == "" || facts.StatusComment == "" || facts.StatusSource == "" {
				return facts, nil, fmt.Errorf("%w: transition ticket snapshot missing status facts", shared.ErrValidation)
			}
			delete(base, "_synapse")
			request, _ := json.Marshal(base)
			return facts, request, nil
		}
		// A grouped update uses the immutable preview snapshot for authority, but
		// Jira must never receive create-only destination or assignment fields.
		fields["labels"], _ = json.Marshal(labels)
		for _, immutable := range []string{"project", "issuetype", "reporter", "assignee", "id", "key", "self"} {
			delete(fields, immutable)
		}
		if len(fields) == 0 {
			return facts, nil, fmt.Errorf("%w: update ticket fields missing", shared.ErrValidation)
		}
		base["fields"], _ = json.Marshal(fields)
		delete(base, "_synapse")
		request, _ := json.Marshal(base)
		return facts, request, nil
	}
	if facts.UpdateRemoteID != "" || facts.UpdateRemoteURL != "" {
		return facts, nil, fmt.Errorf("%w: create ticket snapshot has update target", shared.ErrValidation)
	}
	delete(obj, "_synapse")
	request, _ := json.Marshal(obj)
	return facts, request, nil
}
func (w *Workflow) executionPreflight(ctx context.Context, i domain.Intent, facts snapshotFacts) (integration.Integration, error) {
	in, m, err := w.executionAuthority(ctx, i, facts)
	if err != nil {
		return in, err
	}
	meta, err := w.Metadata(ctx, i.TenantID, i.IntegrationID, m.ProjectKey, m.IssueType, "")
	if err != nil {
		return in, err
	}
	// Metadata is an external read that can take up to the provider timeout. Re-read
	// all authoritative local state immediately before the provider write so a
	// disable, policy change, scope change, or mapping revision during discovery is
	// still refused. A concurrent external write after this final admission cannot be
	// made atomic with local state and remains covered by the durable intent marker.
	in, m, err = w.executionAuthority(ctx, i, facts)
	if err != nil {
		return in, err
	}
	if err = w.validateSelections(m, meta); err != nil {
		return in, err
	}
	return in, nil
}

func (w *Workflow) executionAuthority(ctx context.Context, i domain.Intent, facts snapshotFacts) (integration.Integration, domain.Mapping, error) {
	in, err := w.integration(ctx, i.TenantID, i.IntegrationID)
	if err != nil {
		return in, domain.Mapping{}, err
	}
	if !in.Enabled || in.Endpoint != facts.Endpoint || in.Provider != facts.Provider || in.ConnectionRevision != facts.ConnectionRevision || in.CredentialRevision != facts.CredentialRevision {
		return in, domain.Mapping{}, shared.ErrConflict
	}
	m, err := w.store.GetMapping(ctx, i.TenantID, i.MappingID)
	if err != nil {
		return in, domain.Mapping{}, err
	}
	if m.Version != facts.MappingVersion || m.SecurityLevel != i.SecurityLevel || m.WaiverReason != facts.WaiverReason {
		return in, domain.Mapping{}, shared.ErrConflict
	}
	if err = w.validateFindingScope(ctx, m, i.EngagementID); err != nil {
		return in, domain.Mapping{}, err
	}
	if _, err = w.findings.GetByEngagementAndID(ctx, i.EngagementID, i.FindingID); err != nil {
		return in, domain.Mapping{}, err
	}
	if i.Action == domain.Transition || (i.Action == domain.Update && facts.StatusSource != "") {
		f, stateErr := w.findings.GetByEngagementAndID(ctx, i.EngagementID, i.FindingID)
		if stateErr != nil {
			return in, domain.Mapping{}, stateErr
		}
		state, source, stateErr := w.ticketSyncStateForTarget(ctx, i.TenantID, ports.TicketStatusTarget{Mapping: m, Intent: i}, f)
		if stateErr != nil || facts.StatusSource != source || m.StatusTransitions[state] == "" || (i.Action == domain.Transition && m.StatusTransitions[state] != facts.StatusTransitionID) {
			return in, domain.Mapping{}, shared.ErrConflict
		}
	}
	if strings.HasPrefix(i.RequestKey, "auto:") {
		f, err := w.findings.GetByEngagementAndID(ctx, i.EngagementID, i.FindingID)
		if err != nil {
			return in, domain.Mapping{}, err
		}
		if !w.autoPushSourceAvailable || !m.AutoPushEnabled || m.AutoPushMinSeverity == "" || f.Status != finding.StatusConfirmed || f.Kind == finding.KindExternal || !f.CanPromote() || shared.SeverityRank(f.Severity) < shared.SeverityRank(m.AutoPushMinSeverity) {
			return in, domain.Mapping{}, shared.ErrForbidden
		}
	}
	if facts.GroupFactsDigest != "" {
		reader, ok := w.store.(ports.TicketGroupFactsReader)
		if !ok {
			return in, domain.Mapping{}, shared.ErrConflict
		}
		current, err := reader.GroupTicketFacts(ctx, i.TenantID, i.MappingID, m.ScopeID, facts.GroupVulnerability, ports.TicketGroupMember{EngagementID: i.EngagementID, FindingID: i.FindingID})
		if err != nil {
			return in, domain.Mapping{}, err
		}
		digest, err := ticketGroupFactsDigest(current)
		if err != nil {
			return in, domain.Mapping{}, err
		}
		if digest != facts.GroupFactsDigest {
			return in, domain.Mapping{}, shared.ErrConflict
		}
		if facts.StatusSource == "" {
			groups, ok := w.store.(ports.TicketGroupStore)
			if !ok {
				return in, domain.Mapping{}, shared.ErrConflict
			}
			group, found, err := groups.GetTicketGroup(ctx, i.TenantID, i.MappingID, m.ScopeID, facts.GroupVulnerability)
			if err != nil {
				return in, domain.Mapping{}, err
			}
			if !found || group.IntentID != i.ID || group.Revision != facts.GroupRevision+1 {
				return in, domain.Mapping{}, shared.ErrConflict
			}
		}
	}
	policy, err := w.policy.GetEngagementNotificationSetting(ctx, i.TenantID, i.EngagementID)
	if err != nil {
		return in, domain.Mapping{}, err
	}
	class, allowed := notification.EffectiveDataClass(mappingClass(m), policy.ExternalNotifications)
	if !allowed || class.Rank() < facts.DataClass.Rank() {
		return in, domain.Mapping{}, shared.ErrForbidden
	}
	return in, m, nil
}

func (w *Workflow) validateTicketLiterals(ctx context.Context, tenant, integrationID shared.ID, raw json.RawMessage) error {
	item, err := w.integration(ctx, tenant, integrationID)
	if err != nil {
		return err
	}
	provider, err := w.providers.TicketProvider(shared.WithTenant(ctx, tenant), item)
	if err != nil {
		return safeTicketError(err)
	}
	defer closeTicketProvider(provider)
	return safeTicketError(provider.ValidateTicketPayload(raw))
}
