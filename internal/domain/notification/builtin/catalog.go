// Package builtin supplies the versioned message template assets bundled with Synapse.
package builtin

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

// contentVersion is the version for unchanged shipped assets. Delivery attempts retain their
// exact asset reference for pin resolution and audit history.
const contentVersion = "v1"

const scanPagerContentVersion = "v2"

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
		notification.EventDigest,
		notification.EventVulnerabilityAction,
		notification.EventScanCompleted,
		notification.EventQualityGateFailed,
		notification.EventSLAApproaching,
		notification.EventFleetAgentOffline,
		notification.EventIncidentCreated,
		notification.EventOwnershipChanged,
		notification.EventFindingCreated, notification.EventFindingStatusChanged, notification.EventFindingRetestCompleted,
		notification.EventScanFailed, notification.EventDASTRunFinished, notification.EventReconRunFinished, notification.EventCSPMRunFinished,
		notification.EventSLABreached, notification.EventRiskAcceptanceCreated, notification.EventRiskAcceptanceExpiring, notification.EventRiskAcceptanceExpired,
		notification.EventEngagementCreated, notification.EventEngagementStatusChanged, notification.EventEngagementWindowStarting, notification.EventEngagementWindowEnding,
		notification.EventFindingCommented, notification.EventFindingMentioned,
		notification.EventApprovalRequested, notification.EventApprovalDecided, notification.EventApprovalTimedOut,
		notification.EventIncidentUpdated, notification.EventResponseFinished, notification.EventEvidenceChainBroken,
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
		Ref:         fmt.Sprintf("builtin:%s:%s:%s@%s", event, family, locale, assetVersion(event, family)),
		TemplateKey: key,
		Fields:      cloneFields(content),
	}
	c.byKey[key] = template
	c.list = append(c.list, template)
}

func assetVersion(event notification.EventType, family notification.TemplateFamily) string {
	if event == notification.EventScanCompleted && family == notification.FamilyPager {
		return scanPagerContentVersion
	}
	return contentVersion
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
	if event == notification.EventDigest && family == notification.FamilyPager {
		return map[string]string{"summary": title + ": {{.item_count}} ({{.cadence}})"}
	}
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
	if event == notification.EventDigest {
		if locale == tenancy.LocaleVietnamese {
			return "Tổng hợp thông báo", "Chu kỳ: {{.cadence}} · {{.item_count}} sự kiện\n{{.window_start}} → {{.window_end}}{{range .items}}\n- {{.event_type}}{{if .severity}} [{{.severity}}]{{end}}{{if .title}} {{.title}}{{end}}{{if .target}} · {{.target}}{{end}}{{end}}{{if ne .omitted_count \"0\"}}\nCòn {{.omitted_count}} sự kiện trong cửa sổ này.{{end}}"
		}
		return "Notification digest", "Cadence: {{.cadence}} · {{.item_count}} events\n{{.window_start}} → {{.window_end}}{{range .items}}\n- {{.event_type}}{{if .severity}} [{{.severity}}]{{end}}{{if .title}} {{.title}}{{end}}{{if .target}} · {{.target}}{{end}}{{end}}{{if ne .omitted_count \"0\"}}\n{{.omitted_count}} more events in this window.{{end}}"
	}

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
		case notification.EventFindingCreated:
			return "Phát hiện mới", "Mức độ: {{.severity}}\nLoại: {{.finding_kind}}\nTrạng thái: {{.status}}\nThời gian: {{.occurred_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}{{if .finding_title}}\nPhát hiện: {{.finding_title}}{{end}}"
		case notification.EventFindingStatusChanged:
			return "Trạng thái phát hiện đã đổi", "Mức độ: {{.severity}}\n{{.from_status}} → {{.to_status}}\nThời gian: {{.occurred_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}{{if .finding_title}}\nPhát hiện: {{.finding_title}}{{end}}"
		case notification.EventFindingRetestCompleted:
			return "Kiểm tra lại hoàn tất", "Mức độ: {{.severity}}\nKết quả: {{.result}}\nTrạng thái: {{.status}}\nThời gian: {{.occurred_at}}{{if .finding_title}}\nPhát hiện: {{.finding_title}}{{end}}"
		case notification.EventScanFailed, notification.EventDASTRunFinished, notification.EventReconRunFinished, notification.EventCSPMRunFinished:
			return "Lần quét đã hoàn tất", "Loại: {{.scan_kind}}\nKết quả: {{.outcome}}\nNhà cung cấp: {{.provider}}{{if .error_code}}\nMã lỗi: {{.error_code}}{{end}}{{if eq .counts_available \"true\"}}\nTổng phát hiện: {{.total_count}}{{if eq .severity_counts_available \"true\"}} (nghiêm trọng {{.critical_count}}, cao {{.high_count}}, trung bình {{.medium_count}}, thấp {{.low_count}}, thông tin {{.info_count}}){{end}}{{else}}\nTổng phát hiện: chưa có dữ liệu{{end}}\nThời gian: {{.occurred_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}{{if .target}}\nMục tiêu: {{.target}}{{end}}"
		case notification.EventSLABreached:
			return "SLA đã quá hạn", "Mức độ: {{.severity}}\nMức SLA: {{.tier}}\nHạn xử lý: {{.deadline}}\nThời gian: {{.occurred_at}}{{if .finding_title}}\nPhát hiện: {{.finding_title}}{{end}}"
		case notification.EventRiskAcceptanceCreated, notification.EventRiskAcceptanceExpiring, notification.EventRiskAcceptanceExpired:
			title := "Chấp nhận rủi ro mới"
			if event == notification.EventRiskAcceptanceExpiring {
				title = "Chấp nhận rủi ro sắp hết hạn"
			} else if event == notification.EventRiskAcceptanceExpired {
				title = "Chấp nhận rủi ro đã hết hạn"
			}
			return title, "Mức độ: {{.severity}}\nMức: {{.tier}}\nHết hạn: {{.expires_at}}{{if .lead_time_hours}}\nCòn lại: {{.lead_time_hours}} giờ{{end}}\nThời gian: {{.occurred_at}}{{if .finding_title}}\nPhát hiện: {{.finding_title}}{{end}}"
		case notification.EventEngagementCreated:
			return "Đợt đánh giá mới", "Trạng thái: {{.status}}\nĐược phép từ: {{.authorized_from}}\nĐến: {{.authorized_to}}{{if .timezone}}\nMúi giờ: {{.timezone}}{{end}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}{{if .actor}}\nNgười thực hiện: {{.actor}}{{end}}"
		case notification.EventEngagementStatusChanged:
			return "Trạng thái đợt đánh giá đã đổi", "{{.from_status}} → {{.to_status}}{{if .status}}\nTrạng thái: {{.status}}{{end}}\nThời gian: {{.occurred_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}{{if .actor}}\nNgười thực hiện: {{.actor}}{{end}}"
		case notification.EventEngagementWindowStarting, notification.EventEngagementWindowEnding:
			title := "Cửa sổ đánh giá sắp bắt đầu"
			if event == notification.EventEngagementWindowEnding {
				title = "Cửa sổ đánh giá sắp kết thúc"
			}
			return title, "Mốc ủy quyền: {{.boundary}}{{if .lead_time_hours}}\nCòn lại: {{.lead_time_hours}} giờ{{end}}\nBắt đầu: {{.authorized_from}}\nKết thúc: {{.authorized_to}}{{if .timezone}}\nMúi giờ: {{.timezone}}{{end}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}"
		case notification.EventFindingCommented:
			return "Bình luận mới về phát hiện", "Mức độ: {{.severity}}\nTrạng thái: {{.status}}{{if .actor}}\nNgười bình luận: {{.actor}}{{end}}{{if .comment_excerpt}}\nNội dung: {{.comment_excerpt}}{{end}}\nThời gian: {{.occurred_at}}"
		case notification.EventFindingMentioned:
			return "Bạn được nhắc đến trong phát hiện", "Mức độ: {{.severity}}\nTrạng thái: {{.status}}\nThời gian: {{.occurred_at}}"
		case notification.EventApprovalRequested:
			return "Yêu cầu phê duyệt", "Loại: {{.kind}}\nTrạng thái: {{.status}}\nHết hạn: {{.expires_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}"
		case notification.EventApprovalDecided:
			return "Phê duyệt đã được quyết định", "Loại: {{.kind}}\nQuyết định: {{.decision}}\nTrạng thái: {{.status}}{{if .actor}}\nNgười quyết định: {{.actor}}{{end}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}"
		case notification.EventApprovalTimedOut:
			return "Phê duyệt đã hết hạn", "Loại: {{.kind}}\nTrạng thái: {{.status}}\nHết hạn: {{.expires_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}"
		case notification.EventIncidentUpdated:
			return "Sự cố đã cập nhật", "Mức độ: {{.severity}}\nCập nhật: {{.update_kind}}\nTrạng thái: {{.status}}{{if .disposition}}\nPhân loại: {{.disposition}}{{end}}{{if .incident_title}}\nSự cố: {{.incident_title}}{{end}}{{if .owner}}\nPhụ trách: {{.owner}}{{end}}{{if .actor}}\nNgười cập nhật: {{.actor}}{{end}}"
		case notification.EventResponseFinished:
			return "Phản hồi đã hoàn tất", "Kết quả: {{.outcome}}\nHành động: {{.action_kind}}{{if .target}}\nMục tiêu: {{.target}}{{end}}{{if .actor}}\nNgười thực hiện: {{.actor}}{{end}}"
		case notification.EventEvidenceChainBroken:
			return "Chuỗi bằng chứng không hợp lệ", "Mức độ: {{.severity}}\nLý do: {{.reason_code}}\nThời gian: {{.occurred_at}}{{if .engagement_name}}\nĐợt đánh giá: {{.engagement_name}}{{end}}"
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
	case notification.EventFindingCreated:
		return "Finding created", "Severity: {{.severity}}\nKind: {{.finding_kind}}\nStatus: {{.status}}\nOccurred: {{.occurred_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}{{if .finding_title}}\nFinding: {{.finding_title}}{{end}}"
	case notification.EventFindingStatusChanged:
		return "Finding status changed", "Severity: {{.severity}}\n{{.from_status}} → {{.to_status}}\nOccurred: {{.occurred_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}{{if .finding_title}}\nFinding: {{.finding_title}}{{end}}"
	case notification.EventFindingRetestCompleted:
		return "Finding retest completed", "Severity: {{.severity}}\nResult: {{.result}}\nStatus: {{.status}}\nOccurred: {{.occurred_at}}{{if .finding_title}}\nFinding: {{.finding_title}}{{end}}"
	case notification.EventScanFailed, notification.EventDASTRunFinished, notification.EventReconRunFinished, notification.EventCSPMRunFinished:
		return "Scan run finished", "Kind: {{.scan_kind}}\nOutcome: {{.outcome}}\nProvider: {{.provider}}{{if .error_code}}\nError: {{.error_code}}{{end}}{{if eq .counts_available \"true\"}}\nFindings: {{.total_count}}{{if eq .severity_counts_available \"true\"}} (critical {{.critical_count}}, high {{.high_count}}, medium {{.medium_count}}, low {{.low_count}}, info {{.info_count}}){{end}}{{else}}\nFindings: unavailable{{end}}\nOccurred: {{.occurred_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}{{if .target}}\nTarget: {{.target}}{{end}}"
	case notification.EventSLABreached:
		return "Remediation SLA breached", "Severity: {{.severity}}\nSLA tier: {{.tier}}\nDeadline: {{.deadline}}\nOccurred: {{.occurred_at}}{{if .finding_title}}\nFinding: {{.finding_title}}{{end}}"
	case notification.EventRiskAcceptanceCreated, notification.EventRiskAcceptanceExpiring, notification.EventRiskAcceptanceExpired:
		title := "Risk acceptance created"
		if event == notification.EventRiskAcceptanceExpiring {
			title = "Risk acceptance expiring"
		} else if event == notification.EventRiskAcceptanceExpired {
			title = "Risk acceptance expired"
		}
		return title, "Severity: {{.severity}}\nTier: {{.tier}}\nExpires: {{.expires_at}}{{if .lead_time_hours}}\nTime remaining: {{.lead_time_hours}} hours{{end}}\nOccurred: {{.occurred_at}}{{if .finding_title}}\nFinding: {{.finding_title}}{{end}}"
	case notification.EventEngagementCreated:
		return "Engagement created", "Status: {{.status}}\nAuthorized from: {{.authorized_from}}\nAuthorized to: {{.authorized_to}}{{if .timezone}}\nTime zone: {{.timezone}}{{end}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}{{if .actor}}\nCreated by: {{.actor}}{{end}}"
	case notification.EventEngagementStatusChanged:
		return "Engagement status changed", "{{.from_status}} → {{.to_status}}{{if .status}}\nStatus: {{.status}}{{end}}\nOccurred: {{.occurred_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}{{if .actor}}\nChanged by: {{.actor}}{{end}}"
	case notification.EventEngagementWindowStarting, notification.EventEngagementWindowEnding:
		title := "Engagement window starting"
		if event == notification.EventEngagementWindowEnding {
			title = "Engagement window ending"
		}
		return title, "Authorization boundary: {{.boundary}}{{if .lead_time_hours}}\nTime remaining: {{.lead_time_hours}} hours{{end}}\nStarts: {{.authorized_from}}\nEnds: {{.authorized_to}}{{if .timezone}}\nTime zone: {{.timezone}}{{end}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}"
	case notification.EventFindingCommented:
		return "Finding comment added", "Severity: {{.severity}}\nStatus: {{.status}}{{if .actor}}\nCommented by: {{.actor}}{{end}}{{if .comment_excerpt}}\nComment: {{.comment_excerpt}}{{end}}\nOccurred: {{.occurred_at}}"
	case notification.EventFindingMentioned:
		return "You were mentioned on a finding", "Severity: {{.severity}}\nStatus: {{.status}}\nOccurred: {{.occurred_at}}"
	case notification.EventApprovalRequested:
		return "Approval requested", "Kind: {{.kind}}\nStatus: {{.status}}\nExpires: {{.expires_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}"
	case notification.EventApprovalDecided:
		return "Approval decided", "Kind: {{.kind}}\nDecision: {{.decision}}\nStatus: {{.status}}{{if .actor}}\nDecided by: {{.actor}}{{end}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}"
	case notification.EventApprovalTimedOut:
		return "Approval timed out", "Kind: {{.kind}}\nStatus: {{.status}}\nExpired: {{.expires_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}"
	case notification.EventIncidentUpdated:
		return "Incident updated", "Severity: {{.severity}}\nUpdate: {{.update_kind}}\nStatus: {{.status}}{{if .disposition}}\nDisposition: {{.disposition}}{{end}}{{if .incident_title}}\nIncident: {{.incident_title}}{{end}}{{if .owner}}\nOwner: {{.owner}}{{end}}{{if .actor}}\nUpdated by: {{.actor}}{{end}}"
	case notification.EventResponseFinished:
		return "Response finished", "Outcome: {{.outcome}}\nAction: {{.action_kind}}{{if .target}}\nTarget: {{.target}}{{end}}{{if .actor}}\nActor: {{.actor}}{{end}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}"
	case notification.EventEvidenceChainBroken:
		return "Evidence chain broken", "Severity: {{.severity}}\nReason: {{.reason_code}}\nOccurred: {{.occurred_at}}{{if .engagement_name}}\nEngagement: {{.engagement_name}}{{end}}"
	default:
		return "Synapse notification", "Event: {{.event_label}}\nOccurred: {{.occurred_at}}"
	}
}

func pagerDetail(event notification.EventType, locale tenancy.Locale) string {
	if event == notification.EventScanCompleted {
		if locale == tenancy.LocaleVietnamese {
			return `Thay đổi: {{if and (eq .delta_available "true") .new_count .fixed_count .unchanged_count}}{{.new_count}} mới, {{.fixed_count}} đã xử lý, {{.unchanged_count}} không đổi{{else}}chưa có dữ liệu so sánh{{end}}; Tổng: {{if .total_count}}{{.total_count}}{{if .critical_count}} (nghiêm trọng {{.critical_count}}, cao {{.high_count}}, TB {{.medium_count}}, thấp {{.low_count}}, TT {{.info_count}}){{end}}{{else}}chưa có dữ liệu{{end}}`
		}
		return `Changes: {{if and (eq .delta_available "true") .new_count .fixed_count .unchanged_count}}{{.new_count}} new, {{.fixed_count}} fixed, {{.unchanged_count}} unchanged{{else}}comparison unavailable{{end}}; Findings: {{if .total_count}}{{.total_count}}{{if .critical_count}} (critical {{.critical_count}}, high {{.high_count}}, medium {{.medium_count}}, low {{.low_count}}, info {{.info_count}}){{end}}{{else}}unavailable{{end}}`
	}
	_, body := copyFor(event, locale)
	return body
}

func webhookBody(event notification.EventType) string {
	// This body is used only for an explicit custom-body binding. The normal webhook delivery is
	// a versioned envelope built from the filtered context by the renderer.
	return `{"event_type":"{{.event_type}}","occurred_at":"{{.occurred_at}}","kind":"` + string(event) + `"}`
}
