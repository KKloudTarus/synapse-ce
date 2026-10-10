package notification

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TemplateContext is the snapshot of an event's template variables (EPIC #1327 D5), stored with
// the event at projection. It has the shape msgtemplate.Data renders: flat string variables and
// lists of string maps. Templates never see the raw event.
type TemplateContext struct {
	Vars  map[string]string              `json:"vars"`
	Lists map[string][]map[string]string `json:"lists,omitempty"`
}

const maxScanCompletedContextBytes = 16 * 1024

// Data returns the context as the template engine's input.
func (c TemplateContext) Data() msgtemplate.Data {
	return msgtemplate.Data{Vars: c.Vars, Lists: c.Lists}
}

// Snapshot keeps only the variables the event type declares, drops any declared above the type's
// maximum data class, and sanitizes and bounds every value, so a snapshot never carries a variable
// the catalog does not describe or a value a template could not safely interpolate. Empty values
// are dropped: a template reads a missing variable as empty.
func (s EventSpec) Snapshot(vars map[string]string) TemplateContext {
	return s.SnapshotWithLists(vars, nil)
}

// SnapshotWithLists keeps only declared scalar and list values at the event's
// maximum class. List item fields are whitelisted by the catalog and bounded by
// the declaration, so a producer cannot add arbitrary structured data.
func (s EventSpec) SnapshotWithLists(vars map[string]string, lists map[string][]map[string]string) TemplateContext {
	out := TemplateContext{Vars: map[string]string{}}
	limit := s.MaxDataClass.Rank()
	for _, v := range s.Variables {
		if v.ListCap != 0 || v.Class.Rank() > limit {
			continue
		}
		value := boundRunes(snapshotString(vars[v.Name]), msgtemplate.DefaultMaxValueRunes)
		if value != "" {
			out.Vars[v.Name] = value
		}
	}
	for _, v := range s.Variables {
		if v.ListCap == 0 || v.Class.Rank() > limit {
			continue
		}
		items := lists[v.Name]
		if len(items) > v.ListCap {
			items = items[:v.ListCap]
		}
		for _, item := range items {
			outItem := make(map[string]string, len(v.ItemFields))
			for _, field := range v.ItemFields {
				if value := boundRunes(snapshotString(item[field]), msgtemplate.DefaultMaxValueRunes); value != "" {
					outItem[field] = value
				}
			}
			if len(outItem) != 0 {
				if out.Lists == nil {
					out.Lists = map[string][]map[string]string{}
				}
				out.Lists[v.Name] = append(out.Lists[v.Name], outItem)
			}
		}
	}
	if s.Type == EventScanCompleted {
		out = out.withinByteLimit(maxScanCompletedContextBytes)
	}
	return out
}

// Scrub complete values before truncating: a partial PEM or URL loses the
// delimiters needed to recognize it. Sanitize then scrub again for split keys.
func snapshotString(value string) string {
	value = privacy.ScrubURLCredentials(privacy.ScrubSecretPatterns(value))
	return privacy.ScrubURLCredentials(privacy.ScrubSecretPatterns(strings.TrimSpace(msgtemplate.Sanitize(value))))
}

// withinByteLimit deterministically removes list tail items until the encoded
// context fits. Scan findings are ordered by severity before reaching this
// method, so this preserves the highest-signal entries and all scalar counts.
func (c TemplateContext) withinByteLimit(limit int) TemplateContext {
	for {
		raw, err := json.Marshal(c)
		if err != nil || len(raw) <= limit {
			return c
		}
		name := ""
		for candidate, items := range c.Lists {
			if len(items) != 0 && (name == "" || candidate > name) {
				name = candidate
			}
		}
		if name == "" {
			// The scan aggregate values are generated as small decimal counts. If
			// a producer supplied oversized ancillary scalars, drop those before
			// weakening the aggregate signal.
			for candidate := range c.Vars {
				if !scanContextCountVariable(candidate) && (name == "" || candidate > name) {
					name = candidate
				}
			}
			if name == "" {
				return c
			}
			delete(c.Vars, name)
			continue
		}
		items := c.Lists[name]
		if len(items) == 1 {
			delete(c.Lists, name)
			if len(c.Lists) == 0 {
				c.Lists = nil
			}
			continue
		}
		c.Lists[name] = items[:len(items)-1]
	}
}

func scanContextCountVariable(name string) bool {
	switch name {
	case "total_count", "critical_count", "high_count", "medium_count", "low_count", "info_count", "new_count", "fixed_count", "unchanged_count", "delta_available":
		return true
	}
	return false
}

// Encode returns the snapshot as the JSON object stored with the event.
func (c TemplateContext) Encode() (json.RawMessage, error) {
	if c.Vars == nil {
		c.Vars = map[string]string{}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxContextBytes {
		return nil, fmt.Errorf("%w: notification template context is too large", shared.ErrValidation)
	}
	return raw, nil
}

// DecodeTemplateContext reads a stored snapshot. An empty or {} snapshot, which every event
// projected before its builder existed carries, decodes to an empty context.
func DecodeTemplateContext(raw json.RawMessage) (TemplateContext, error) {
	var c TemplateContext
	if len(strings.TrimSpace(string(raw))) != 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return TemplateContext{}, fmt.Errorf("%w: notification template context is not valid", shared.ErrValidation)
		}
	}
	if c.Vars == nil {
		c.Vars = map[string]string{}
	}
	return c, nil
}

func boundRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
