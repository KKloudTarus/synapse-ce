package notification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

// TemplateFamily groups channel types that render the same content fields (EPIC #1327 D5). A
// template is written once per family, and every channel of that family formats its output.
type TemplateFamily string

const (
	FamilyChat    TemplateFamily = "chat"
	FamilyEmail   TemplateFamily = "email"
	FamilyPager   TemplateFamily = "pager"
	FamilyTicket  TemplateFamily = "ticket"
	FamilyWebhook TemplateFamily = "webhook"
)

// familyFields lists the content fields each family renders. It matches the family CHECK on
// notification_templates (0195); adding a family is a code change plus that CHECK.
var familyFields = map[TemplateFamily][]string{
	FamilyChat:    {"title", "body"},
	FamilyEmail:   {"subject", "body"},
	FamilyPager:   {"summary"},
	FamilyTicket:  {"summary", "description"},
	FamilyWebhook: {"body"},
}

// TemplateFamilies lists every family in display order.
func TemplateFamilies() []TemplateFamily {
	return []TemplateFamily{FamilyChat, FamilyEmail, FamilyPager, FamilyTicket, FamilyWebhook}
}

// Valid reports whether f is a known family.
func (f TemplateFamily) Valid() bool { _, ok := familyFields[f]; return ok }

// Fields returns the content fields the family renders, in display order.
func (f TemplateFamily) Fields() []string { return append([]string(nil), familyFields[f]...) }

// TemplateStatus is the lifecycle of a tenant template. Only an active template is resolved at
// send time; a draft has never been activated, and an archived one was retired or replaced.
type TemplateStatus string

const (
	TemplateDraft    TemplateStatus = "draft"
	TemplateActive   TemplateStatus = "active"
	TemplateArchived TemplateStatus = "archived"
)

// Valid reports whether s is a known status.
func (s TemplateStatus) Valid() bool {
	return s == TemplateDraft || s == TemplateActive || s == TemplateArchived
}

// AnyEventType and AnyLocale are the wildcards of a template key. A "*" event template applies to
// every event of its family that has no event-specific template; a "*" locale template applies to
// every locale that has no locale-specific one (resolution order, #1371).
const (
	AnyEventType EventType      = "*"
	AnyLocale    tenancy.Locale = "*"
)

// Bounds shared with the CHECKs in 0195.
const (
	// MaxTemplateNameRunes caps a template's display name.
	MaxTemplateNameRunes = 200
	// MaxTemplateIDBytes caps a template ID.
	MaxTemplateIDBytes = 128
	// MaxTemplateActorBytes caps the recorded actor.
	MaxTemplateActorBytes = 200
	// MaxTemplateFieldBytes caps one field's source; it is the engine's source limit, so a field
	// the store accepts is never refused by msgtemplate for its size.
	MaxTemplateFieldBytes = msgtemplate.MaxSourceBytes
)

// TemplateKey is what resolution looks a tenant template up by. At most one template per key is
// active, enforced by a partial unique index.
type TemplateKey struct {
	EventType EventType      `json:"event_type"`
	Family    TemplateFamily `json:"family"`
	Locale    tenancy.Locale `json:"locale"`
}

// Validate checks the key. The event type must be "*" or declared in the catalog, so a template
// can never be saved for an event that is never produced.
func (k TemplateKey) Validate() error {
	if k.EventType != AnyEventType && !k.EventType.Valid() {
		return fmt.Errorf("%w: template event type must be * or a catalog event type", shared.ErrValidation)
	}
	if !k.Family.Valid() {
		return fmt.Errorf("%w: template family must be one of chat, email, pager, ticket, webhook", shared.ErrValidation)
	}
	if k.Locale != AnyLocale && !k.Locale.Valid() {
		return fmt.Errorf("%w: template locale must be *, en or vi", shared.ErrValidation)
	}
	return nil
}

// Template is the mutable head of a tenant template. Its content lives in append-only
// TemplateVersions; the head points at the newest one and, once activated, at the one that
// renders. The key never changes after creation.
type Template struct {
	TenantID shared.ID `json:"tenant_id"`
	ID       shared.ID `json:"id"`
	Name     string    `json:"name"`
	TemplateKey
	Status TemplateStatus `json:"status"`
	// LatestVersion is the newest version. Appending a version never changes what renders.
	LatestVersion int `json:"latest_version"`
	// ActiveVersion is the version that renders while Status is active, and the last one that
	// rendered after the template is archived. Zero means the template was never activated.
	ActiveVersion int `json:"active_version"`
	// Revision guards concurrent edits of the head.
	Revision  int       `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// ValidateNew checks what a caller supplies when creating a template.
func (t Template) ValidateNew() error {
	if t.TenantID.IsZero() {
		return fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	if err := ValidateTemplateID(t.ID); err != nil {
		return err
	}
	if err := ValidateTemplateName(t.Name); err != nil {
		return err
	}
	if err := t.Validate(); err != nil {
		return err
	}
	if t.CreatedAt.IsZero() {
		return fmt.Errorf("%w: template creation time is required", shared.ErrValidation)
	}
	return ValidateTemplateActor(t.CreatedBy)
}

// ValidateTemplateID bounds a template ID.
func ValidateTemplateID(id shared.ID) error {
	if id.IsZero() || len(id) > MaxTemplateIDBytes || !printable(id.String()) {
		return fmt.Errorf("%w: template id must be 1 to %d printable bytes", shared.ErrValidation, MaxTemplateIDBytes)
	}
	return nil
}

// ValidateTemplateName bounds a display name. Surrounding space is rejected, not trimmed, so the
// stored name is exactly what the caller sent.
func ValidateTemplateName(name string) error {
	if strings.TrimSpace(name) != name || name == "" || !utf8.ValidString(name) ||
		utf8.RuneCountInString(name) > MaxTemplateNameRunes || !printable(name) {
		return fmt.Errorf("%w: template name must be 1 to %d printable characters without surrounding space", shared.ErrValidation, MaxTemplateNameRunes)
	}
	return nil
}

// ValidateTemplateActor bounds the recorded actor.
func ValidateTemplateActor(actor string) error {
	if actor == "" || len(actor) > MaxTemplateActorBytes || !utf8.ValidString(actor) || !printable(actor) {
		return fmt.Errorf("%w: template actor must be 1 to %d printable bytes", shared.ErrValidation, MaxTemplateActorBytes)
	}
	return nil
}

// TemplateVersion is one immutable revision of a template's content: the source of each content
// field of the family. Rows are append-only; a rollback activates an earlier version rather than
// rewriting one.
type TemplateVersion struct {
	TenantID   shared.ID         `json:"tenant_id"`
	TemplateID shared.ID         `json:"template_id"`
	Version    int               `json:"version"`
	Fields     map[string]string `json:"fields"`
	// Checksum is TemplateChecksum(Fields), computed by the store, so a delivery's pinned
	// (template, version) can be checked against the text that rendered it.
	Checksum  string    `json:"checksum"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// ValidateTemplateFields checks a version's fields against the family: every key is a field of
// the family, every value is valid UTF-8 without NUL and at most MaxTemplateFieldBytes, and at
// least one field is not blank. It does not compile the source; the API does that with the event's
// variable schema before saving (#1370).
func ValidateTemplateFields(family TemplateFamily, fields map[string]string) error {
	allowed := familyFields[family]
	if allowed == nil {
		return fmt.Errorf("%w: template family must be one of chat, email, pager, ticket, webhook", shared.ErrValidation)
	}
	if len(fields) == 0 {
		return fmt.Errorf("%w: template needs at least one field", shared.ErrValidation)
	}
	blank := true
	for key, value := range fields {
		if !contains(allowed, key) {
			return fmt.Errorf("%w: field %q is not a %s field (allowed: %s)", shared.ErrValidation, key, family, strings.Join(allowed, ", "))
		}
		if len(value) > MaxTemplateFieldBytes {
			return fmt.Errorf("%w: field %q exceeds %d bytes", shared.ErrValidation, key, MaxTemplateFieldBytes)
		}
		if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return fmt.Errorf("%w: field %q must be UTF-8 text without NUL", shared.ErrValidation, key)
		}
		if strings.TrimSpace(value) != "" {
			blank = false
		}
	}
	if blank {
		return fmt.Errorf("%w: template needs at least one non-blank field", shared.ErrValidation)
	}
	return nil
}

// TemplateChecksum is the hex SHA-256 of the fields encoded as JSON with sorted keys.
func TemplateChecksum(fields map[string]string) string {
	encoded, err := json.Marshal(fields) // map keys are sorted; string values cannot fail
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// CloneFields copies a field map so a stored version cannot be changed through the caller's map.
func CloneFields(fields map[string]string) map[string]string {
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	return out
}

func printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && r != ' ' {
			return false
		}
	}
	return true
}
