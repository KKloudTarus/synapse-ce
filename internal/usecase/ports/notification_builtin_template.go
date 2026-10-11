package ports

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

// BuiltinTemplate is one template shipped with the build (#1366): the fourth resolution tier,
// below every tenant template and above the raw fallback. Its key uses the same wildcards as a
// tenant template.
type BuiltinTemplate struct {
	// Ref identifies the template and the build that shipped it, recorded on an attempt, for
	// example "builtin:scan.completed:chat:en@<build>".
	Ref string
	notification.TemplateKey
	// Fields holds the source of each content field of the family.
	Fields map[string]string
}

// BuiltinTemplates is the catalog of built-in templates (#1366). Builtin looks up exactly one key
// and reports found=false when the build ships none for it; wildcard and locale fallback belong to
// the resolver (#1371), which calls it once per step. List returns every built-in, for the console.
//
// Until #1366 lands the composition root wires NoBuiltinTemplates, so resolution goes straight
// from the tenant tiers to the fallback.
type BuiltinTemplates interface {
	Builtin(eventType notification.EventType, family notification.TemplateFamily, locale tenancy.Locale) (BuiltinTemplate, bool)
	List() []BuiltinTemplate
}

// NoBuiltinTemplates is the empty catalog.
type NoBuiltinTemplates struct{}

// Builtin implements BuiltinTemplates.
func (NoBuiltinTemplates) Builtin(notification.EventType, notification.TemplateFamily, tenancy.Locale) (BuiltinTemplate, bool) {
	return BuiltinTemplate{}, false
}

// List implements BuiltinTemplates.
func (NoBuiltinTemplates) List() []BuiltinTemplate { return nil }
