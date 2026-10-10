// Package builtin supplies the versioned message template assets bundled with Synapse.
package builtin

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

// contentVersion changes only when shipped message content changes. Delivery attempts retain
// this reference for pin resolution and audit history.
const contentVersion = "v1"

// Catalog is an immutable built-in template catalog. It returns copies because callers may use a
// returned field map while rendering and must not be able to mutate the catalog for other sends.
type Catalog struct {
	byKey map[notification.TemplateKey]Template
	list  []Template
}

// Template is a domain-owned built-in asset. The adapter translates it to the usecase port.
type Template struct {
	Ref string
	notification.TemplateKey
	Fields map[string]string
}

// New builds the shipped catalog for every routable event and both supported locales. A wildcard
// entry for each family keeps a new event useful at signal class until it gets event-specific copy.
func New() *Catalog {
	c := &Catalog{byKey: make(map[notification.TemplateKey]Template)}
	events := []notification.EventType{
		notification.EventVulnerabilityAction,
		notification.EventScanCompleted,
		notification.EventQualityGateFailed,
		notification.EventSLAApproaching,
		notification.EventFleetAgentOffline,
		notification.EventIncidentCreated,
		notification.EventOwnershipChanged,
	}
	families := []notification.TemplateFamily{
		notification.FamilyChat,
		notification.FamilyEmail,
		notification.FamilyPager,
		notification.FamilyWebhook,
	}
	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		for _, family := range families {
			c.add(notification.AnyEventType, family, locale, fields(notification.AnyEventType, family, locale))
		}
		for _, event := range events {
			for _, family := range families {
				c.add(event, family, locale, fields(event, family, locale))
			}
		}
	}
	sort.Slice(c.list, func(i, j int) bool { return c.list[i].Ref < c.list[j].Ref })
	return c
}

func (c *Catalog) add(event notification.EventType, family notification.TemplateFamily, locale tenancy.Locale, content map[string]string) {
	key := notification.TemplateKey{EventType: event, Family: family, Locale: locale}
	template := Template{
		Ref:         fmt.Sprintf("builtin:%s:%s:%s@%s", event, family, locale, contentVersion),
		TemplateKey: key,
		Fields:      cloneFields(content),
	}
	c.byKey[key] = template
	c.list = append(c.list, template)
}

// Builtin returns the exact key the resolver requests; wildcard and locale fallbacks belong to
// the resolver so its precedence remains identical for tenant and shipped templates.
func (c *Catalog) Builtin(event notification.EventType, family notification.TemplateFamily, locale tenancy.Locale) (Template, bool) {
	template, ok := c.byKey[notification.TemplateKey{EventType: event, Family: family, Locale: locale}]
	if !ok {
		return Template{}, false
	}
	template.Fields = cloneFields(template.Fields)
	return template, true
}

// List returns copies in stable reference order for pin resolution and the console listing.
func (c *Catalog) List() []Template {
	out := make([]Template, len(c.list))
	for i, template := range c.list {
		template.Fields = cloneFields(template.Fields)
		out[i] = template
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

func fields(event notification.EventType, family notification.TemplateFamily, locale tenancy.Locale) map[string]string {
	title, body := copyFor(event, locale)
	switch family {
	case notification.FamilyChat:
		return map[string]string{"title": title, "body": body}
	case notification.FamilyEmail:
		return map[string]string{"subject": title, "body": body}
	case notification.FamilyPager:
		return map[string]string{"summary": title + ": " + pagerDetail(event, locale)}
	case notification.FamilyWebhook:
		return map[string]string{"body": webhookBody(event)}
	default:
		return nil
	}
}

func copyFor(event notification.EventType, locale tenancy.Locale) (string, string) {
	if locale == tenancy.LocaleVietnamese {
		switch event {
		case notification.EventVulnerabilityAction:
			return "Hành động rủi ro lỗ hổng", "Mức độ: {{.severity}}\nHành động: {{.action_type}}\nThời gian: {{.occurred_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}"
		case notification.EventScanCompleted:
			return "Quét đã hoàn tất", "Loại quét: {{.scan_kind}}\n{{if .total_count}}Tổng phát hiện: {{.total_count}}{{if .critical_count}} (nghiêm trọng {{.critical_count}}, cao {{.high_count}}, trung bình {{.medium_count}}, thấp {{.low_count}}, thông tin {{.info_count}}){{end}}{{else}}Tổng phát hiện: chưa có dữ liệu{{end}}\n{{if and (eq .delta_available \"true\") .new_count .fixed_count .unchanged_count}}Thay đổi: {{.new_count}} mới, {{.fixed_count}} đã xử lý, {{.unchanged_count}} không đổi{{else}}Thay đổi: chưa có dữ liệu so sánh{{end}}\nThời gian: {{.occurred_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}{{if .target}}\nMục tiêu: {{.target}}{{end}}{{range .findings}}\n- [{{.severity}}] {{.title}} ({{.status}}){{end}}"
		case notification.EventQualityGateFailed:
			return "Chất lượng không đạt", "Điều kiện không đạt: {{.failed_conditions}}\nThời gian: {{.occurred_at}}{{if .project_name}}\nDự án: {{.project_name}}{{end}}"
		case notification.EventSLAApproaching:
			return "SLA sắp đến hạn", "Mức SLA: {{.tier}}\nHạn xử lý: {{.deadline}}{{if .lead_time_hours}}\nCòn lại: {{.lead_time_hours}} giờ{{end}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}{{if .finding_title}}\nPhát hiện: {{.finding_title}}{{end}}"
		case notification.EventFleetAgentOffline:
			return "Agent không kết nối", "Lần cuối hoạt động: {{.last_seen_at}}{{if .agent_name}}\nAgent: {{.agent_name}}{{end}}"
		case notification.EventIncidentCreated:
			return "Sự cố mới", "Mức độ: {{.severity}}\nThời gian: {{.occurred_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}{{if .asset_name}}\nTài sản: {{.asset_name}}{{end}}"
		case notification.EventOwnershipChanged:
			return "Thay đổi người phụ trách phát hiện", "Sự kiện: {{.event_type}}\nThời gian: {{.occurred_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}{{if .finding_title}}\nPhát hiện: {{.finding_title}}{{end}}{{if .old_team}}\nNhóm cũ: {{.old_team}}{{end}}{{if .new_team}}\nNhóm mới: {{.new_team}}{{end}}{{if .old_assignee}}\nNgười phụ trách cũ: {{.old_assignee}}{{end}}{{if .new_assignee}}\nNgười phụ trách mới: {{.new_assignee}}{{end}}{{if .actor}}\nNgười thay đổi: {{.actor}}{{end}}{{if .reason}}\nLý do: {{.reason}}{{end}}"
		default:
			return "Thông báo Synapse", "Sự kiện: {{.event_label}}\nThời gian: {{.occurred_at}}"
		}
	}
	switch event {
	case notification.EventVulnerabilityAction:
		return "Vulnerability risk action", "Severity: {{.severity}}\nAction: {{.action_type}}\nOccurred: {{.occurred_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}"
	case notification.EventScanCompleted:
		return "Scan completed", "Scan type: {{.scan_kind}}\n{{if .total_count}}Findings: {{.total_count}}{{if .critical_count}} (critical {{.critical_count}}, high {{.high_count}}, medium {{.medium_count}}, low {{.low_count}}, info {{.info_count}}){{end}}{{else}}Findings: unavailable{{end}}\n{{if and (eq .delta_available \"true\") .new_count .fixed_count .unchanged_count}}Changes: {{.new_count}} new, {{.fixed_count}} fixed, {{.unchanged_count}} unchanged{{else}}Changes: comparison unavailable{{end}}\nOccurred: {{.occurred_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}{{if .target}}\nTarget: {{.target}}{{end}}{{range .findings}}\n- [{{.severity}}] {{.title}} ({{.status}}){{end}}"
	case notification.EventQualityGateFailed:
		return "Quality gate failed", "Failed conditions: {{.failed_conditions}}\nOccurred: {{.occurred_at}}{{if .project_name}}\nProject: {{.project_name}}{{end}}"
	case notification.EventSLAApproaching:
		return "SLA approaching deadline", "SLA tier: {{.tier}}\nDeadline: {{.deadline}}{{if .lead_time_hours}}\nTime remaining: {{.lead_time_hours}} hours{{end}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}{{if .finding_title}}\nFinding: {{.finding_title}}{{end}}"
	case notification.EventFleetAgentOffline:
		return "Fleet agent offline", "Last heartbeat: {{.last_seen_at}}{{if .agent_name}}\nAgent: {{.agent_name}}{{end}}"
	case notification.EventIncidentCreated:
		return "Incident created", "Severity: {{.severity}}\nOccurred: {{.occurred_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}{{if .asset_name}}\nAsset: {{.asset_name}}{{end}}"
	case notification.EventOwnershipChanged:
		return "Finding ownership changed", "Event: {{.event_type}}\nOccurred: {{.occurred_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}{{if .finding_title}}\nFinding: {{.finding_title}}{{end}}{{if .old_team}}\nPrevious team: {{.old_team}}{{end}}{{if .new_team}}\nNew team: {{.new_team}}{{end}}{{if .old_assignee}}\nPrevious assignee: {{.old_assignee}}{{end}}{{if .new_assignee}}\nNew assignee: {{.new_assignee}}{{end}}{{if .actor}}\nChanged by: {{.actor}}{{end}}{{if .reason}}\nReason: {{.reason}}{{end}}"
	default:
		return "Synapse notification", "Event: {{.event_label}}\nOccurred: {{.occurred_at}}"
	}
}

func pagerDetail(event notification.EventType, locale tenancy.Locale) string {
	_, body := copyFor(event, locale)
	return body
}

func webhookBody(event notification.EventType) string {
	// This body is used only for an explicit custom-body binding. The normal webhook delivery is
	// a versioned envelope built from the filtered context by the renderer.
	return `{"event_type":"{{.event_type}}","occurred_at":"{{.occurred_at}}","kind":"` + string(event) + `"}`
}
