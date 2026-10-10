// Package notificationbuiltin adapts the domain-owned shipped template assets to the notification
// usecase port.
package notificationbuiltin

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification/builtin"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Catalog struct{ assets *builtin.Catalog }

var _ ports.BuiltinTemplates = (*Catalog)(nil)

func New() *Catalog { return &Catalog{assets: builtin.New()} }

func (c *Catalog) Builtin(event notification.EventType, family notification.TemplateFamily, locale tenancy.Locale) (ports.BuiltinTemplate, bool) {
	template, ok := c.assets.Builtin(event, family, locale)
	if !ok {
		return ports.BuiltinTemplate{}, false
	}
	return ports.BuiltinTemplate{Ref: template.Ref, TemplateKey: template.TemplateKey, Fields: cloneFields(template.Fields)}, true
}

func (c *Catalog) List() []ports.BuiltinTemplate {
	assets := c.assets.List()
	out := make([]ports.BuiltinTemplate, len(assets))
	for i, template := range assets {
		out[i] = ports.BuiltinTemplate{Ref: template.Ref, TemplateKey: template.TemplateKey, Fields: cloneFields(template.Fields)}
	}
	return out
}

func cloneFields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
