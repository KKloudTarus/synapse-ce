package notification

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// errTemplatesUnavailable is returned when no template store is wired; the router does not register
// the template routes then, so it only reaches a caller that bypasses the router.
var errTemplatesUnavailable = errors.New("notification templates are not configured")

// SetTemplateStore wires custom message templates (#1370). Without it the template routes are not
// registered.
func (s *Service) SetTemplateStore(store ports.NotificationTemplateStore) { s.templates = store }

// TemplatesEnabled reports whether a template store is wired.
func (s *Service) TemplatesEnabled() bool { return s != nil && s.templates != nil }

// TemplateInput creates a template: its key, which never changes, a display name and the source of
// each content field of the family.
type TemplateInput struct {
	Name      string                `json:"name"`
	EventType domain.EventType      `json:"event_type"`
	Family    domain.TemplateFamily `json:"family"`
	Locale    tenancy.Locale        `json:"locale"`
	Fields    map[string]string     `json:"fields"`
}

// TemplateUpdateInput appends a version. An empty name keeps the current one.
type TemplateUpdateInput struct {
	Name     string            `json:"name,omitempty"`
	Fields   map[string]string `json:"fields"`
	Revision int               `json:"revision"`
}

// TemplateChangeInput activates, rolls back or archives a template. Version selects the version to
// activate (zero is the latest); rollback requires it and archive ignores it.
type TemplateChangeInput struct {
	Version  int `json:"version,omitempty"`
	Revision int `json:"revision"`
}

// TemplateDetail is a template head with the content of its newest version and, once activated,
// the version that renders.
type TemplateDetail struct {
	domain.Template
	Latest *domain.TemplateVersion `json:"latest,omitempty"`
	Active *domain.TemplateVersion `json:"active,omitempty"`
	// ArchivedTemplateID is the template an activation or rollback archived because it held the
	// same key, or empty.
	ArchivedTemplateID shared.ID `json:"archived_template_id,omitempty"`
}

// BuiltinTemplate is a read-only template shipped with the current build. Fields are copied from
// the catalog so callers cannot mutate the catalog used by notification delivery.
type BuiltinTemplate struct {
	EventType domain.EventType      `json:"event_type"`
	Family    domain.TemplateFamily `json:"family"`
	Locale    tenancy.Locale        `json:"locale"`
	Fields    map[string]string     `json:"fields"`
}

// ListBuiltinTemplates returns the current build's built-in catalog for read-only console use.
func (s *Service) ListBuiltinTemplates() []BuiltinTemplate {
	if s == nil || s.builtins == nil {
		return []BuiltinTemplate{}
	}
	items := s.builtins.List()
	out := make([]BuiltinTemplate, len(items))
	for i, item := range items {
		fields := make(map[string]string, len(item.Fields))
		for field, source := range item.Fields {
			fields[field] = source
		}
		out[i] = BuiltinTemplate{
			EventType: item.EventType,
			Family:    item.Family,
			Locale:    item.Locale,
			Fields:    fields,
		}
	}
	return out
}

// TemplateValidationError is a template field the engine rejected. It names the field, the event
// type it was checked against, the engine code and the line, and never carries the field's source:
// Detail is the engine's capped identifier or parse message only.
type TemplateValidationError struct {
	Field     string           `json:"field"`
	EventType domain.EventType `json:"event_type"`
	Code      msgtemplate.Code `json:"code"`
	Line      int              `json:"line,omitempty"`
	Detail    string           `json:"detail,omitempty"`
	// Path locates the value inside a webhook custom body (#1376), for example $.alert.title.
	Path string `json:"path,omitempty"`
}

func (e *TemplateValidationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "template field %q is invalid for event type %s: %s", e.Field, e.EventType, e.Code)
	if e.Path != "" {
		b.WriteString(" at " + e.Path)
	}
	if e.Line > 0 {
		b.WriteString(" at line " + strconv.Itoa(e.Line))
	}
	if e.Detail != "" {
		b.WriteString(": " + e.Detail)
	}
	return b.String()
}

// Unwrap classifies the rejection as a validation error (HTTP 400).
func (e *TemplateValidationError) Unwrap() error { return shared.ErrValidation }

// templateCatalog is the event catalog templates are validated against. Tests replace it to declare
// variables the production catalog does not have yet.
var templateCatalog = domain.EventCatalog

// templateSchema is the variable schema of one event. The event catalog declares both scalar
// variables and the bounded, flat fields a list item may expose, so templates cannot range over
// undeclared snapshot data.
type templateSchema struct {
	eventType domain.EventType
	schema    *msgtemplate.Schema
}

// templateSchemas returns the schema of every event type a template key can render: its own type,
// or every catalog type for a "*" template, so a wildcard template only uses variables every event
// declares. Schemas are small, so they are built per call.
func templateSchemas(eventType domain.EventType) ([]templateSchema, error) {
	var out []templateSchema
	for _, spec := range templateCatalog() {
		if eventType != domain.AnyEventType && spec.Type != eventType {
			continue
		}
		var vars []string
		lists := make(map[string]msgtemplate.List)
		for _, variable := range spec.Variables {
			if variable.ListCap == 0 {
				vars = append(vars, variable.Name)
				continue
			}
			lists[variable.Name] = msgtemplate.List{Cap: variable.ListCap, Fields: append([]string(nil), variable.ItemFields...)}
		}
		schema, err := msgtemplate.NewSchema(msgtemplate.SchemaSpec{Vars: vars, Lists: lists})
		if err != nil {
			return nil, fmt.Errorf("notification catalog schema for %s: %w", spec.Type, err)
		}
		out = append(out, templateSchema{eventType: spec.Type, schema: schema})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: template event type must be * or a catalog event type", shared.ErrValidation)
	}
	return out, nil
}

// validateTemplateContent checks fields against the family and compiles every non-empty field with
// the template engine for each event type the key can match. The first rejection, in field order
// then event order, is returned so the error is deterministic.
func validateTemplateContent(key domain.TemplateKey, fields map[string]string) error {
	if err := key.Validate(); err != nil {
		return err
	}
	if err := domain.ValidateTemplateFields(key.Family, fields); err != nil {
		return err
	}
	schemas, err := templateSchemas(key.EventType)
	if err != nil {
		return err
	}
	for _, field := range key.Family.Fields() {
		source, ok := fields[field]
		if !ok || source == "" {
			continue
		}
		if key.Family == domain.FamilyWebhook && field == "body" {
			if err := validateWebhookBody(key.EventType, source, schemas); err != nil {
				return err
			}
			continue
		}
		for _, candidate := range schemas {
			eventType, schema := candidate.eventType, candidate.schema
			if _, err := msgtemplate.Compile(field, source, schema); err != nil {
				var rejection *msgtemplate.Error
				if errors.As(err, &rejection) && errors.Is(err, msgtemplate.ErrInvalidTemplate) {
					return &TemplateValidationError{Field: field, EventType: eventType, Code: rejection.Code, Line: rejection.Line, Detail: rejection.Detail}
				}
				return fmt.Errorf("compile notification template field %s: %w", field, err)
			}
		}
	}
	return nil
}

// ListTemplates lists the tenant's templates, ordered by ID.
func (s *Service) ListTemplates(ctx context.Context, q ports.NotificationTemplateQuery) ([]domain.Template, error) {
	if s.templates == nil {
		return nil, errTemplatesUnavailable
	}
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	if q.EventType != "" && q.EventType != domain.AnyEventType && !q.EventType.Valid() {
		return nil, fmt.Errorf("%w: event_type must be * or a catalog event type", shared.ErrValidation)
	}
	if q.Family != "" && !q.Family.Valid() {
		return nil, fmt.Errorf("%w: family must be one of chat, email, pager, ticket, webhook", shared.ErrValidation)
	}
	if q.Locale != "" && q.Locale != domain.AnyLocale && !q.Locale.Valid() {
		return nil, fmt.Errorf("%w: locale must be *, en or vi", shared.ErrValidation)
	}
	if q.Status != "" && !q.Status.Valid() {
		return nil, fmt.Errorf("%w: status must be draft, active or archived", shared.ErrValidation)
	}
	return s.templates.ListNotificationTemplates(ctx, tenant, q)
}

// GetTemplate returns a template with its newest version and the version that renders.
func (s *Service) GetTemplate(ctx context.Context, id shared.ID) (TemplateDetail, error) {
	if s.templates == nil {
		return TemplateDetail{}, errTemplatesUnavailable
	}
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return TemplateDetail{}, err
	}
	head, err := s.templates.GetNotificationTemplate(ctx, tenant, id)
	if err != nil {
		return TemplateDetail{}, err
	}
	return s.templateDetail(ctx, head, nil)
}

// ListTemplateVersions lists a template's versions newest first.
func (s *Service) ListTemplateVersions(ctx context.Context, id shared.ID, before, limit int) ([]domain.TemplateVersion, error) {
	if s.templates == nil {
		return nil, errTemplatesUnavailable
	}
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	if before < 0 || limit < 0 {
		return nil, fmt.Errorf("%w: before and limit must not be negative", shared.ErrValidation)
	}
	return s.templates.ListNotificationTemplateVersions(ctx, tenant, id, before, limit)
}

// CreateTemplate validates and stores a draft template with version 1.
func (s *Service) CreateTemplate(ctx context.Context, actor string, in TemplateInput) (TemplateDetail, error) {
	return mutation(ctx, s, func(ctx context.Context) (TemplateDetail, error) { return s.createTemplate(ctx, actor, in) })
}

// UpdateTemplate validates and appends a version. It does not change what renders.
func (s *Service) UpdateTemplate(ctx context.Context, actor string, id shared.ID, in TemplateUpdateInput) (TemplateDetail, error) {
	return mutation(ctx, s, func(ctx context.Context) (TemplateDetail, error) { return s.updateTemplate(ctx, actor, id, in) })
}

// ActivateTemplate makes a version render (the latest when Version is zero).
func (s *Service) ActivateTemplate(ctx context.Context, actor string, id shared.ID, in TemplateChangeInput) (TemplateDetail, error) {
	return mutation(ctx, s, func(ctx context.Context) (TemplateDetail, error) {
		return s.activateTemplate(ctx, actor, id, in, false)
	})
}

// RollbackTemplate activates an earlier version. Versions are never rewritten.
func (s *Service) RollbackTemplate(ctx context.Context, actor string, id shared.ID, in TemplateChangeInput) (TemplateDetail, error) {
	return mutation(ctx, s, func(ctx context.Context) (TemplateDetail, error) {
		return s.activateTemplate(ctx, actor, id, in, true)
	})
}

// ArchiveTemplate retires a template; the key falls back to the next resolution tier.
func (s *Service) ArchiveTemplate(ctx context.Context, actor string, id shared.ID, in TemplateChangeInput) (TemplateDetail, error) {
	return mutation(ctx, s, func(ctx context.Context) (TemplateDetail, error) { return s.archiveTemplate(ctx, actor, id, in) })
}

func (s *Service) createTemplate(ctx context.Context, actor string, in TemplateInput) (TemplateDetail, error) {
	if s.templates == nil {
		return TemplateDetail{}, errTemplatesUnavailable
	}
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return TemplateDetail{}, err
	}
	key := domain.TemplateKey{EventType: in.EventType, Family: in.Family, Locale: in.Locale}
	if err := validateTemplateContent(key, in.Fields); err != nil {
		return TemplateDetail{}, err
	}
	head := domain.Template{TenantID: tenant, ID: s.ids.NewID(), Name: in.Name, TemplateKey: key, CreatedAt: s.clock.Now().UTC(), CreatedBy: actor}
	created, version, err := s.templates.CreateNotificationTemplate(ctx, head, in.Fields)
	if err != nil {
		return TemplateDetail{}, err
	}
	meta := templateAuditMetadata(created, map[string]string{"to_version": "1", "checksum": version.Checksum, "diff": templateDiff(nil, version.Fields)})
	if err := s.record(ctx, actor, "notification.template.created", created.ID.String(), meta); err != nil {
		return TemplateDetail{}, err
	}
	return TemplateDetail{Template: created, Latest: &version}, nil
}

func (s *Service) updateTemplate(ctx context.Context, actor string, id shared.ID, in TemplateUpdateInput) (TemplateDetail, error) {
	if s.templates == nil {
		return TemplateDetail{}, errTemplatesUnavailable
	}
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return TemplateDetail{}, err
	}
	current, err := s.templates.GetNotificationTemplate(ctx, tenant, id)
	if err != nil {
		return TemplateDetail{}, err
	}
	if in.Revision != current.Revision {
		return TemplateDetail{}, fmt.Errorf("notification template revision is stale: %w", shared.ErrConflict)
	}
	if err := validateTemplateContent(current.TemplateKey, in.Fields); err != nil {
		return TemplateDetail{}, err
	}
	previous, err := s.templates.GetNotificationTemplateVersion(ctx, tenant, id, current.LatestVersion)
	if err != nil {
		return TemplateDetail{}, err
	}
	updated, version, err := s.templates.AppendNotificationTemplateVersion(ctx, ports.NotificationTemplateUpdate{
		TenantID: tenant, ID: id, Name: in.Name, Fields: in.Fields, ExpectedRevision: in.Revision, Actor: actor, At: s.clock.Now().UTC(),
	})
	if err != nil {
		return TemplateDetail{}, err
	}
	meta := templateAuditMetadata(updated, map[string]string{
		"from_version": strconv.Itoa(previous.Version), "to_version": strconv.Itoa(version.Version),
		"checksum": version.Checksum, "diff": templateDiff(previous.Fields, version.Fields),
		"name_changed": strconv.FormatBool(in.Name != "" && in.Name != current.Name),
	})
	if err := s.record(ctx, actor, "notification.template.updated", id.String(), meta); err != nil {
		return TemplateDetail{}, err
	}
	return s.templateDetail(ctx, updated, &version)
}

func (s *Service) activateTemplate(ctx context.Context, actor string, id shared.ID, in TemplateChangeInput, rollback bool) (TemplateDetail, error) {
	if s.templates == nil {
		return TemplateDetail{}, errTemplatesUnavailable
	}
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return TemplateDetail{}, err
	}
	if in.Version < 0 || (rollback && in.Version == 0) {
		return TemplateDetail{}, fmt.Errorf("%w: a positive version is required", shared.ErrValidation)
	}
	current, err := s.templates.GetNotificationTemplate(ctx, tenant, id)
	if err != nil {
		return TemplateDetail{}, err
	}
	if in.Revision != current.Revision {
		return TemplateDetail{}, fmt.Errorf("notification template revision is stale: %w", shared.ErrConflict)
	}
	target := in.Version
	if target == 0 {
		target = current.LatestVersion
	}
	if rollback && current.Status == domain.TemplateActive && target == current.ActiveVersion {
		return TemplateDetail{}, fmt.Errorf("%w: version %d is already the active version", shared.ErrConflict, target)
	}
	version, err := s.templates.GetNotificationTemplateVersion(ctx, tenant, id, target)
	if err != nil {
		return TemplateDetail{}, err
	}
	// The catalog can change between save and activation, so the version is checked again: a
	// version that no longer compiles would only ever render the built-in fallback.
	if err := validateTemplateContent(current.TemplateKey, version.Fields); err != nil {
		return TemplateDetail{}, err
	}
	var from *domain.TemplateVersion
	if current.ActiveVersion > 0 {
		previous, err := s.templates.GetNotificationTemplateVersion(ctx, tenant, id, current.ActiveVersion)
		if err != nil {
			return TemplateDetail{}, err
		}
		from = &previous
	}
	activated, archived, err := s.templates.ActivateNotificationTemplate(ctx, ports.NotificationTemplateChange{
		TenantID: tenant, ID: id, Version: target, ExpectedRevision: in.Revision, Actor: actor, At: s.clock.Now().UTC(),
	})
	if err != nil {
		return TemplateDetail{}, err
	}
	meta := map[string]string{
		"to_version": strconv.Itoa(target), "checksum": version.Checksum,
		"previous_status": string(current.Status), "archived_template_id": archived.String(),
	}
	var fromFields map[string]string
	if from != nil {
		meta["from_version"] = strconv.Itoa(from.Version)
		fromFields = from.Fields
	}
	meta["diff"] = templateDiff(fromFields, version.Fields)
	action := "notification.template.activated"
	if rollback {
		action = "notification.template.rolled_back"
	}
	if err := s.record(ctx, actor, action, id.String(), templateAuditMetadata(activated, meta)); err != nil {
		return TemplateDetail{}, err
	}
	detail, err := s.templateDetail(ctx, activated, nil)
	if err != nil {
		return TemplateDetail{}, err
	}
	detail.ArchivedTemplateID = archived
	return detail, nil
}

func (s *Service) archiveTemplate(ctx context.Context, actor string, id shared.ID, in TemplateChangeInput) (TemplateDetail, error) {
	if s.templates == nil {
		return TemplateDetail{}, errTemplatesUnavailable
	}
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return TemplateDetail{}, err
	}
	current, err := s.templates.GetNotificationTemplate(ctx, tenant, id)
	if err != nil {
		return TemplateDetail{}, err
	}
	if current.Status == domain.TemplateArchived {
		return TemplateDetail{}, fmt.Errorf("%w: notification template is already archived", shared.ErrConflict)
	}
	archived, err := s.templates.ArchiveNotificationTemplate(ctx, ports.NotificationTemplateChange{
		TenantID: tenant, ID: id, ExpectedRevision: in.Revision, Actor: actor, At: s.clock.Now().UTC(),
	})
	if err != nil {
		return TemplateDetail{}, err
	}
	meta := templateAuditMetadata(archived, map[string]string{"previous_status": string(current.Status), "active_version": strconv.Itoa(current.ActiveVersion)})
	if err := s.record(ctx, actor, "notification.template.archived", id.String(), meta); err != nil {
		return TemplateDetail{}, err
	}
	return s.templateDetail(ctx, archived, nil)
}

// templateDetail loads the newest and the active version of head. latest, when not nil, is the
// newest version the caller already holds.
func (s *Service) templateDetail(ctx context.Context, head domain.Template, latest *domain.TemplateVersion) (TemplateDetail, error) {
	detail := TemplateDetail{Template: head, Latest: latest}
	if detail.Latest == nil {
		version, err := s.templates.GetNotificationTemplateVersion(ctx, head.TenantID, head.ID, head.LatestVersion)
		if err != nil {
			return TemplateDetail{}, err
		}
		detail.Latest = &version
	}
	if head.ActiveVersion > 0 {
		if head.ActiveVersion == detail.Latest.Version {
			detail.Active = detail.Latest
		} else {
			version, err := s.templates.GetNotificationTemplateVersion(ctx, head.TenantID, head.ID, head.ActiveVersion)
			if err != nil {
				return TemplateDetail{}, err
			}
			detail.Active = &version
		}
	}
	return detail, nil
}

// templateAuditMetadata is the metadata every template audit entry carries: the key, the name and
// the resulting status and versions, plus extra. It never carries template source.
func templateAuditMetadata(t domain.Template, extra map[string]string) map[string]string {
	meta := map[string]string{
		"name": t.Name, "event_type": string(t.EventType), "family": string(t.Family), "locale": string(t.Locale),
		"status": string(t.Status), "latest_version": strconv.Itoa(t.LatestVersion), "active_version": strconv.Itoa(t.ActiveVersion),
	}
	for k, v := range extra {
		if v != "" {
			meta[k] = v
		}
	}
	return meta
}

// templateDiff summarizes how the fields changed from before to after without quoting any source:
// one "field:+added/-removed" entry per changed field, in field-name order, where the counts are
// lines added and removed (a multiset difference of the field's lines). A field that appears is all
// additions and a field that disappears all removals. "none" means nothing changed.
func templateDiff(before, after map[string]string) string {
	names := map[string]bool{}
	for name := range before {
		names[name] = true
	}
	for name := range after {
		names[name] = true
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	var parts []string
	for _, name := range sorted {
		old, hadOld := before[name]
		next, hasNext := after[name]
		if hadOld == hasNext && old == next {
			continue
		}
		added, removed := lineDelta(old, next)
		parts = append(parts, name+":+"+strconv.Itoa(added)+"/-"+strconv.Itoa(removed))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func lineDelta(before, after string) (added, removed int) {
	counts := map[string]int{}
	for _, line := range splitLines(before) {
		counts[line]--
	}
	for _, line := range splitLines(after) {
		counts[line]++
	}
	for _, n := range counts {
		if n > 0 {
			added += n
		} else {
			removed -= n
		}
	}
	return added, removed
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}
