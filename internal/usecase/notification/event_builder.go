package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// EventBuilders holds one builder per event type (#1344). A builder owns what used to be spread
// over SQL and adapters: the subject an event is about, the template variables it exposes, and
// the re-check that tells the worker whether a queued delivery still describes the source.
type EventBuilders struct {
	builders map[domain.EventType]eventBuilder
}

// eventBuilder is the per-type part. Every field is optional.
type eventBuilder struct {
	// subjectKey names the data key that holds the subject ID.
	subjectKey string
	// data composes the event's data from the source facts when a captured record carries only its
	// identity (#1344). The result is the webhook body's data object, a public contract (#1411).
	data func(e domain.Event, facts sourceFacts) map[string]any
	// vars returns the type's own variables; the common ones are added by Project.
	vars func(e domain.Event, data eventData, facts sourceFacts) map[string]string
	// relevant re-checks a queued delivery against the source; nil means always relevant.
	relevant func(ctx context.Context, facts ports.NotificationRelevance, work ports.NotificationWork, data eventData) (bool, error)
}

var _ ports.NotificationEventProjector = (*EventBuilders)(nil)

// NewEventBuilders returns the builders of every catalog event type.
func NewEventBuilders() *EventBuilders {
	return &EventBuilders{builders: eventBuilders()}
}

// Project names the event's subject and takes its template context snapshot. A producer passes what
// it read from the source row as the variables of e.Context: the builder composes the data from
// them when the capture recorded identity only, keeps them over derived variables, and the catalog
// then decides which survive (domain.EventSpec.Snapshot).
func (b *EventBuilders) Project(_ context.Context, e domain.Event) (domain.Event, error) {
	spec, ok := domain.LookupEvent(e.Type)
	if !ok {
		return e, fmt.Errorf("%w: unknown notification event type", shared.ErrValidation)
	}
	seed, err := domain.DecodeTemplateContext(e.Context)
	if err != nil {
		return e, err
	}
	facts := sourceFacts(seed.Vars)
	builder := b.builders[e.Type]
	data := decodeEventData(e.Data)
	if builder.data != nil && len(data) == 0 {
		if e.Data, err = json.Marshal(builder.data(e, facts)); err != nil {
			return e, err
		}
		data = decodeEventData(e.Data)
	}
	vars := commonVars(spec, e, data)
	if builder.vars != nil {
		for name, value := range builder.vars(e, data, facts) {
			vars[name] = value
		}
	}
	for name, value := range seed.Vars {
		if value != "" {
			vars[name] = value
		}
	}
	for name, value := range vars {
		vars[name] = scrubSecrets(value)
	}
	if e.Context, err = spec.Snapshot(vars).Encode(); err != nil {
		return e, err
	}
	if e.SubjectKind == "" {
		e.SubjectKind = spec.SubjectKind
	}
	if e.SubjectID == "" && builder.subjectKey != "" {
		e.SubjectID = data.text(builder.subjectKey)
	}
	return e, nil
}

// StillRelevant reports whether a queued delivery's source still holds. An event whose type has no
// re-check is always relevant.
func (b *EventBuilders) StillRelevant(ctx context.Context, facts ports.NotificationRelevance, work ports.NotificationWork) (bool, error) {
	builder := b.builders[work.Event.Type]
	if builder.relevant == nil {
		return true, nil
	}
	return builder.relevant(ctx, facts, work, decodeEventData(work.Event.Data))
}

// commonVars are the variables every event declares (domain commonVariables).
func commonVars(spec domain.EventSpec, e domain.Event, data eventData) map[string]string {
	return map[string]string{
		"event_type":  string(e.Type),
		"event_label": spec.Label,
		"occurred_at": formatTime(e.OccurredAt),
		"title":       data.text("title"),
		"summary":     data.text("summary"),
	}
}

// eventData is an event's data object. Producers write it, so every read is lenient: a missing or
// mistyped key reads as empty rather than failing the projection.
type eventData map[string]any

func decodeEventData(raw json.RawMessage) eventData {
	var data eventData
	if err := json.Unmarshal(raw, &data); err != nil || data == nil {
		return eventData{}
	}
	return data
}

func (d eventData) text(key string) string {
	switch v := d[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

// time reads an RFC 3339 value; ok is false when the key is missing or malformed.
func (d eventData) time(key string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, d.text(key))
	return t, err == nil
}

// scrubSecrets removes secrets a scanner or a producer left in a value (#1361): keyed assignments
// such as password=, bearer tokens, AWS access key IDs, PEM private keys and URL credentials. It
// runs before the snapshot, so no template ever sees them.
//
// It scrubs twice. The raw pass sees a PEM block while its line breaks still mark its lines. The
// snapshot then removes invisible characters, which can rejoin a key a scanner split (pass, a zero
// width space, word=), so the value is sanitized here and scrubbed again: the snapshot stores the
// text the second pass saw. Scrubbing a scrubbed value changes nothing, so projecting an event
// again stores the same snapshot.
func scrubSecrets(value string) string {
	value = scrubPatterns(value)
	return scrubPatterns(strings.TrimSpace(msgtemplate.Sanitize(value)))
}

func scrubPatterns(value string) string {
	return redact.URLCreds(privacy.ScrubSecretPatterns(value))
}

// sourceFacts are the values a producer read from the source row, passed as context variables.
// Names that are not catalog variables (identifiers, raw values a builder cleans) never reach the
// snapshot.
type sourceFacts map[string]string

func (f sourceFacts) get(name string) string { return strings.TrimSpace(f[name]) }

// formatTime is the stored form of every time variable: RFC 3339 in UTC, so the send-time render
// can present it in the tenant's zone (#1365).
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
