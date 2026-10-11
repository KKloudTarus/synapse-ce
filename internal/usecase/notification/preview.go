package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PreviewEventLimit is how many of the tenant's recent events of one type a preview can pick from.
const PreviewEventLimit = 20

// PreviewSource is where a preview's sample event comes from.
type PreviewSource string

const (
	// PreviewFromFixture renders against the published fixture of the event type (#1411).
	PreviewFromFixture PreviewSource = "fixture"
	// PreviewFromEvent renders against one of the tenant's stored events.
	PreviewFromEvent PreviewSource = "event"
)

var (
	errPreviewEventsUnavailable   = fmt.Errorf("%w: previewing a stored event is not available on this server", shared.ErrValidation)
	errPreviewFixturesUnavailable = errors.New("notification event fixtures are not configured")
)

// SetEventFixtures wires the published event fixtures the preview renders against by default. The
// composition root passes the embedded docs/guide/schemas/events files.
func (s *Service) SetEventFixtures(fixtures fs.FS) { s.fixtures = fixtures }

// SetEventReader lets the preview pick one of the tenant's stored events. Without it only fixtures
// can be previewed.
func (s *Service) SetEventReader(reader ports.NotificationEventReader) { s.eventReader = reader }

// PreviewEvent is one stored event a preview can render against. It names the event and never
// carries its data or template context: those are rendered at the channel's class, not listed.
type PreviewEvent struct {
	ID           shared.ID        `json:"id"`
	EventType    domain.EventType `json:"event_type"`
	OccurredAt   time.Time        `json:"occurred_at"`
	EngagementID shared.ID        `json:"engagement_id,omitempty"`
	Severity     shared.Severity  `json:"severity,omitempty"`
	SubjectKind  string           `json:"subject_kind,omitempty"`
}

func previewEvent(e domain.Event) PreviewEvent {
	return PreviewEvent{ID: e.ID, EventType: e.Type, OccurredAt: e.OccurredAt, EngagementID: e.EngagementID, Severity: e.Severity, SubjectKind: e.SubjectKind}
}

// ListPreviewEvents returns the caller's tenant's most recent events of one type, newest first, at
// most PreviewEventLimit. Row-level security keeps every other tenant's events out.
func (s *Service) ListPreviewEvents(ctx context.Context, eventType domain.EventType) ([]PreviewEvent, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	if !eventType.Valid() {
		return nil, fmt.Errorf("%w: event_type must be a catalog event type", shared.ErrValidation)
	}
	if s.eventReader == nil {
		return nil, errPreviewEventsUnavailable
	}
	events, err := s.eventReader.ListRecentNotificationEvents(ctx, tenant, eventType, PreviewEventLimit)
	if err != nil {
		return nil, err
	}
	out := make([]PreviewEvent, 0, len(events))
	for _, e := range events {
		out = append(out, previewEvent(e))
	}
	return out, nil
}

// PreviewInput asks to render a template for one channel and event type without sending.
//
//   - EventID picks a stored event; empty renders against the event type's fixture.
//   - TemplateID previews that template instead of the one resolution would pick; Version picks
//     one of its versions (0 is the latest).
//   - Fields previews unsaved text: alone it is a new template for the event type and the
//     channel's family, with TemplateID it is an unsaved edit of that template.
type PreviewInput struct {
	ChannelID  shared.ID         `json:"channel_id"`
	EventType  domain.EventType  `json:"event_type"`
	EventID    shared.ID         `json:"event_id,omitempty"`
	TemplateID shared.ID         `json:"template_id,omitempty"`
	Version    int               `json:"version,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
}

// PreviewChannel names the channel a preview renders for.
type PreviewChannel struct {
	ID     shared.ID             `json:"id"`
	Name   string                `json:"name"`
	Type   domain.ChannelType    `json:"type"`
	Family domain.TemplateFamily `json:"family"`
}

// PreviewSample names the event a preview renders against.
type PreviewSample struct {
	Source PreviewSource `json:"source"`
	PreviewEvent
}

// PreviewDraft names the template text a preview renders instead of resolving: a saved version of
// TemplateID, or unsaved text (Unsaved), which has no version.
type PreviewDraft struct {
	TemplateID shared.ID `json:"template_id,omitempty"`
	Version    int       `json:"version,omitempty"`
	Unsaved    bool      `json:"unsaved,omitempty"`
}

// TemplatePreview is the answer to a preview. Exactly one of Resolution and Draft is set.
//
// Rendered stays false until the send-time renderer (#1365) lands: the preview then hands the
// prepared channel, event and draft to the same RenderMessage that deliveries use, so preview and
// send can never render differently, and the response gains the suppressed state and the message.
type TemplatePreview struct {
	Channel    PreviewChannel      `json:"channel"`
	Sample     PreviewSample       `json:"sample"`
	Resolution *TemplateResolution `json:"resolution,omitempty"`
	Draft      *PreviewDraft       `json:"draft,omitempty"`
	Rendered   bool                `json:"rendered"`

	// prepared is the render input #1365 will consume. It holds the event's template context and
	// the draft's text, so it is never serialized.
	prepared preparedPreview
}

type preparedPreview struct {
	channel domain.Channel
	event   domain.Event
	draft   *domain.TemplateVersion
}

// PreviewTemplate prepares a template preview: it loads the channel, takes the sample event (the
// fixture or a stored event, projected through the event's builder), and picks the template text
// (the draft or what resolution would choose). Unsaved text goes through the same engine checks
// as a save, so a broken template is reported here with its field and line, never rendered.
// Nothing is sent and nothing is written.
func (s *Service) PreviewTemplate(ctx context.Context, in PreviewInput) (TemplatePreview, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return TemplatePreview{}, err
	}
	if !in.EventType.Valid() {
		return TemplatePreview{}, fmt.Errorf("%w: event_type must be a catalog event type", shared.ErrValidation)
	}
	if in.Version < 0 {
		return TemplatePreview{}, fmt.Errorf("%w: version must not be negative", shared.ErrValidation)
	}
	if in.Version > 0 && in.TemplateID.IsZero() {
		return TemplatePreview{}, fmt.Errorf("%w: version needs a template_id", shared.ErrValidation)
	}
	if in.Version > 0 && in.Fields != nil {
		return TemplatePreview{}, fmt.Errorf("%w: version and fields cannot be combined; fields is the text to preview", shared.ErrValidation)
	}
	if (!in.TemplateID.IsZero() || in.Fields != nil) && s.templates == nil {
		return TemplatePreview{}, errTemplatesUnavailable
	}
	channel, err := s.repo.GetChannel(ctx, tenant, in.ChannelID)
	if err != nil {
		return TemplatePreview{}, err
	}
	if channel.DeletedAt != nil {
		return TemplatePreview{}, fmt.Errorf("notification channel: %w", shared.ErrNotFound)
	}
	family, ok := domain.FamilyForChannelType(channel.Type)
	if !ok {
		return TemplatePreview{}, fmt.Errorf("%w: channel type %q has no template family", shared.ErrValidation, channel.Type)
	}

	event, source, err := s.previewSample(ctx, tenant, in)
	if err != nil {
		return TemplatePreview{}, err
	}
	out := TemplatePreview{
		Channel: PreviewChannel{ID: channel.ID, Name: channel.Name, Type: channel.Type, Family: family},
		Sample:  PreviewSample{Source: source, PreviewEvent: previewEvent(event)},
	}
	out.prepared = preparedPreview{channel: channel, event: event}

	if in.TemplateID.IsZero() && in.Fields == nil {
		resolution, err := s.resolveForChannel(ctx, tenant, channel, in.EventType)
		if err != nil {
			return TemplatePreview{}, err
		}
		out.Resolution = &resolution
		return out, nil
	}
	draft, named, err := s.previewDraft(ctx, tenant, in, family)
	if err != nil {
		return TemplatePreview{}, err
	}
	out.Draft, out.prepared.draft = &named, &draft
	return out, nil
}

// previewSample loads the event a preview renders against and projects it through the event's
// builder, so a stored event captured before its builder existed still has a template context.
func (s *Service) previewSample(ctx context.Context, tenant shared.ID, in PreviewInput) (domain.Event, PreviewSource, error) {
	var (
		event  domain.Event
		source PreviewSource
		err    error
	)
	if in.EventID.IsZero() {
		source = PreviewFromFixture
		if event, err = s.fixtureEvent(tenant, in.EventType); err != nil {
			return domain.Event{}, "", err
		}
	} else {
		source = PreviewFromEvent
		if s.eventReader == nil {
			return domain.Event{}, "", errPreviewEventsUnavailable
		}
		if event, err = s.eventReader.GetNotificationEvent(ctx, tenant, in.EventID); err != nil {
			return domain.Event{}, "", err
		}
		if event.Type != in.EventType {
			return domain.Event{}, "", fmt.Errorf("%w: event %s is a %s event, not %s", shared.ErrValidation, in.EventID, event.Type, in.EventType)
		}
	}
	projected, err := s.events.Project(ctx, event)
	if err != nil {
		return domain.Event{}, "", fmt.Errorf("project preview event: %w", err)
	}
	return projected, source, nil
}

// fixtureEvent reads the published fixture of an event type as an event of the caller's tenant.
// A fixture's engagement is illustrative and belongs to no tenant, so it is dropped: an engagement
// override only ever applies to a real event.
func (s *Service) fixtureEvent(tenant shared.ID, eventType domain.EventType) (domain.Event, error) {
	if s.fixtures == nil {
		return domain.Event{}, errPreviewFixturesUnavailable
	}
	raw, err := fs.ReadFile(s.fixtures, string(eventType)+".v1.fixture.json")
	if err != nil {
		return domain.Event{}, fmt.Errorf("read %s fixture: %w", eventType, err)
	}
	var event domain.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return domain.Event{}, fmt.Errorf("decode %s fixture: %w", eventType, err)
	}
	if event.Type != eventType {
		return domain.Event{}, fmt.Errorf("%s fixture declares type %s", eventType, event.Type)
	}
	event.TenantID, event.EngagementID = tenant, ""
	return event, nil
}

// previewDraft picks the text a preview renders instead of resolving: a saved version of a
// template, an unsaved edit of it, or unsaved text for a new template. The template must be of the
// channel's family and cover the event type, as a binding would require.
func (s *Service) previewDraft(ctx context.Context, tenant shared.ID, in PreviewInput, family domain.TemplateFamily) (domain.TemplateVersion, PreviewDraft, error) {
	key := domain.TemplateKey{EventType: in.EventType, Family: family, Locale: domain.AnyLocale}
	var version domain.TemplateVersion
	named := PreviewDraft{Unsaved: in.Fields != nil}
	if !in.TemplateID.IsZero() {
		template, err := s.templates.GetNotificationTemplate(ctx, tenant, in.TemplateID)
		if err != nil {
			return domain.TemplateVersion{}, PreviewDraft{}, err
		}
		if template.Family != family {
			return domain.TemplateVersion{}, PreviewDraft{}, fmt.Errorf("%w: template family %s does not match the channel family %s", shared.ErrValidation, template.Family, family)
		}
		if !template.Covers(in.EventType) {
			return domain.TemplateVersion{}, PreviewDraft{}, fmt.Errorf("%w: template is for %s, not %s", shared.ErrValidation, template.EventType, in.EventType)
		}
		key = template.TemplateKey
		named.TemplateID = template.ID
		if in.Fields == nil {
			number := in.Version
			if number == 0 {
				number = template.LatestVersion
			}
			if version, err = s.templates.GetNotificationTemplateVersion(ctx, tenant, template.ID, number); err != nil {
				return domain.TemplateVersion{}, PreviewDraft{}, err
			}
			named.Version = version.Version
			return version, named, nil
		}
	}
	// Unsaved text is checked exactly as a save would check it. A "*" template is checked against
	// every catalog event, so text that only fits the previewed event is still reported.
	if err := validateTemplateContent(key, in.Fields); err != nil {
		return domain.TemplateVersion{}, PreviewDraft{}, err
	}
	return domain.TemplateVersion{TenantID: tenant, TemplateID: in.TemplateID, Fields: in.Fields}, named, nil
}
