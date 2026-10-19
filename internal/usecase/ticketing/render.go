package ticketing

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/consolelink"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxTicketSummaryRunes = 255
	maxTicketBodyBytes    = 16 << 10
	maxTicketBodyRunes    = 12000
)

// TicketContextSpec is the fixed, flat template surface for a Jira ticket. Values above the
// effective data class are present as empty strings, so one approved template can be used under a
// stricter engagement policy without gaining access to the suppressed content.
var TicketContextSpec = msgtemplate.SchemaSpec{
	Vars:          []string{"finding_id", "title", "severity", "description", "remediation", "status", "console_url"},
	MaxValueRunes: msgtemplate.DefaultMaxValueRunes,
}

// RenderTicket renders a bounded, class-filtered ticket subject and description. Links are made
// only from the operator-controlled public console origin; templates receive no arbitrary URL.
func RenderTicket(m domain.Mapping, f finding.Finding, class notification.DataClass, locale, publicBase string) (summary, body string, links []ports.RenderedLink, err error) {
	if class != notification.DataClassSignal && class != notification.DataClassSummary && class != notification.DataClassDetail {
		return "", "", nil, fmt.Errorf("%w: ticket data class is invalid", shared.ErrValidation)
	}
	builder, err := consolelink.NewBuilder(publicBase)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: configure a trusted HTTPS public console URL before previewing Jira tickets", shared.ErrValidation)
	}
	link, err := builder.Finding(f.EngagementID, f.ID)
	if err != nil {
		return "", "", nil, err
	}
	return renderTicketWithLink(m, f, class, locale, link)
}

// renderTicket preserves the established engagement route except when the
// mapping's Project owns the hidden analysis context. In that case it resolves
// the stable project key from the repository and never accepts it from the
// request or mapping payload.
func (w *Workflow) renderTicket(ctx context.Context, m domain.Mapping, f finding.Finding, class notification.DataClass) (summary, body string, links []ports.RenderedLink, err error) {
	if m.Scope != domain.Project {
		return RenderTicket(m, f, class, m.Locale, w.publicBase)
	}
	if w.projects == nil {
		// Existing runtimes may carry Project mappings before composition has
		// wired Project links. Preserve their frozen legacy rendering; new
		// Project-source wiring always supplies the repository.
		return RenderTicket(m, f, class, m.Locale, w.publicBase)
	}
	builder, err := consolelink.NewBuilder(w.publicBase)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: configure a trusted HTTPS public console URL before previewing Jira tickets", shared.ErrValidation)
	}
	p, err := w.projects.GetByID(ctx, m.TenantID, m.ScopeID)
	if err != nil || p == nil {
		if err == nil {
			err = shared.ErrNotFound
		}
		return "", "", nil, err
	}
	link, err := builder.ProjectSourceFinding(p.Key, f.ID)
	if err != nil {
		return "", "", nil, err
	}
	return renderTicketWithLink(m, f, class, m.Locale, link)
}

func renderTicketWithLink(m domain.Mapping, f finding.Finding, class notification.DataClass, locale string, link consolelink.Link) (summary, body string, links []ports.RenderedLink, err error) {
	if class != notification.DataClassSignal && class != notification.DataClassSummary && class != notification.DataClassDetail {
		return "", "", nil, fmt.Errorf("%w: ticket data class is invalid", shared.ErrValidation)
	}
	links = []ports.RenderedLink{{Label: "Open finding", URL: link.Href()}}
	vars := ticketContext(f, class, link.Href(), normalizedLocale(locale))
	summarySource, bodySource := m.SummaryTemplate, m.DescriptionTemplate
	if strings.TrimSpace(summarySource) == "" || strings.TrimSpace(bodySource) == "" {
		defaultSummary, defaultBody := ticketBuiltins(normalizedLocale(locale), class)
		if strings.TrimSpace(summarySource) == "" {
			summarySource = defaultSummary
		}
		if strings.TrimSpace(bodySource) == "" {
			bodySource = defaultBody
		}
	}
	schema, err := msgtemplate.NewSchema(TicketContextSpec)
	if err != nil {
		return "", "", nil, err
	}
	summaryTemplate, err := msgtemplate.Compile("ticket-summary", summarySource, schema)
	if err != nil {
		return "", "", nil, err
	}
	bodyTemplate, err := msgtemplate.Compile("ticket-description", bodySource, schema)
	if err != nil {
		return "", "", nil, err
	}
	summaryOutput, err := summaryTemplate.Render(msgtemplate.Data{Vars: vars}, maxTicketSummaryRunes)
	if err != nil {
		return "", "", nil, err
	}
	bodyOutput, err := bodyTemplate.Render(msgtemplate.Data{Vars: vars}, maxTicketBodyRunes)
	if err != nil {
		return "", "", nil, err
	}
	// Template literals are administrator-provided but still leave this boundary. Scrub the
	// complete rendered result so a copied token or credential in a literal cannot reach Jira.
	// Summary fields are plain Jira text, so remove the Markdown escapes msgtemplate applied to
	// interpolated finding values; Jira does not parse those escapes and would show them verbatim.
	summary = strings.TrimSpace(boundRunes(ticketRenderedText(unescapeTicketSummary(summaryOutput.Text)), maxTicketSummaryRunes))
	body = strings.TrimSpace(boundUTF8Bytes(ticketRenderedText(bodyOutput.Text), maxTicketBodyBytes))
	if summary == "" || body == "" {
		return "", "", nil, fmt.Errorf("%w: ticket template rendered empty content", shared.ErrValidation)
	}
	return summary, body, links, nil
}

func ticketContext(f finding.Finding, class notification.DataClass, consoleURL, locale string) map[string]string {
	vars := map[string]string{
		"finding_id":  ticketText(f.ID.String()),
		"severity":    ticketText(localSeverity(f.Severity, locale)),
		"status":      ticketText(localStatus(f.Status, locale)),
		"console_url": ticketText(consoleURL),
		"title":       "", "description": "", "remediation": "",
	}
	if class.Rank() >= notification.DataClassSummary.Rank() {
		vars["title"] = ticketText(f.Title)
	}
	if class == notification.DataClassDetail {
		vars["description"] = ticketText(f.Description)
		// Finding has no remediation field in the current persisted model. Keep the stable
		// template variable empty until that model becomes available; it never falls back to
		// an unbounded custom value from the mapping.
		vars["remediation"] = ""
	}
	return vars
}

func ticketText(value string) string {
	value = privacy.ScrubURLCredentials(privacy.ScrubSecretPatterns(value))
	value = redact.String(value, nil)
	value = msgtemplate.Sanitize(value)
	value = privacy.ScrubURLCredentials(privacy.ScrubSecretPatterns(value))
	return strings.TrimSpace(value)
}

func ticketRenderedText(value string) string {
	value = privacy.ScrubURLCredentials(privacy.ScrubSecretPatterns(value))
	value = redact.String(value, nil)
	value = sanitizeTicketRenderedText(value)
	return privacy.ScrubURLCredentials(privacy.ScrubSecretPatterns(value))
}

// sanitizeTicketRenderedText closes invisible-character redaction bypasses
// without changing the deliberate line layout of an operator's template.
func sanitizeTicketRenderedText(value string) string {
	var out strings.Builder
	for len(value) > 0 {
		index := strings.IndexAny(value, "\n\r\t")
		if index < 0 {
			out.WriteString(msgtemplate.Sanitize(value))
			break
		}
		out.WriteString(msgtemplate.Sanitize(value[:index]))
		out.WriteByte(value[index])
		value = value[index+1:]
	}
	return out.String()
}

// msgtemplate escapes interpolated values for a CommonMark sink. Jira summaries are plain fields,
// not CommonMark, so undo only the exact punctuation escapes it introduces.
func unescapeTicketSummary(value string) string {
	const punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	var out strings.Builder
	out.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) && strings.IndexByte(punctuation, value[i+1]) >= 0 {
			continue
		}
		out.WriteByte(value[i])
	}
	return out.String()
}

func normalizedLocale(locale string) string {
	if strings.EqualFold(strings.TrimSpace(locale), "vi") || strings.EqualFold(strings.TrimSpace(locale), "vi-vn") {
		return "vi"
	}
	return "en"
}

func ticketBuiltins(locale string, class notification.DataClass) (string, string) {
	if locale == "vi" {
		switch class {
		case notification.DataClassSignal:
			return "Phát hiện bảo mật ({{.severity}}): {{.status}}", "Mã phát hiện: {{.finding_id}}\nMức độ: {{.severity}}\nTrạng thái: {{.status}}"
		case notification.DataClassSummary:
			return "Phát hiện {{.severity}}: {{.title}}", "Phát hiện: {{.title}}\nMã: {{.finding_id}}\nMức độ: {{.severity}}\nTrạng thái: {{.status}}"
		default:
			return "Phát hiện {{.severity}}: {{.title}}", "Phát hiện: {{.title}}\nMã: {{.finding_id}}\nMức độ: {{.severity}}\nTrạng thái: {{.status}}\n\nMô tả:\n{{.description}}{{if .remediation}}\n\nKhắc phục:\n{{.remediation}}{{end}}"
		}
	}
	switch class {
	case notification.DataClassSignal:
		return "Security finding ({{.severity}}): {{.status}}", "Finding ID: {{.finding_id}}\nSeverity: {{.severity}}\nStatus: {{.status}}"
	case notification.DataClassSummary:
		return "{{.severity}} finding: {{.title}}", "Finding: {{.title}}\nID: {{.finding_id}}\nSeverity: {{.severity}}\nStatus: {{.status}}"
	default:
		return "{{.severity}} finding: {{.title}}", "Finding: {{.title}}\nID: {{.finding_id}}\nSeverity: {{.severity}}\nStatus: {{.status}}\n\nDescription:\n{{.description}}{{if .remediation}}\n\nRemediation:\n{{.remediation}}{{end}}"
	}
}

func localSeverity(value shared.Severity, locale string) string {
	if locale != "vi" {
		return string(value)
	}
	switch value {
	case shared.SeverityCritical:
		return "nghiêm trọng"
	case shared.SeverityHigh:
		return "cao"
	case shared.SeverityMedium:
		return "trung bình"
	case shared.SeverityLow:
		return "thấp"
	case shared.SeverityInfo:
		return "thông tin"
	default:
		return "không xác định"
	}
}

func localStatus(value finding.Status, locale string) string {
	if locale != "vi" {
		return string(value)
	}
	switch value {
	case finding.StatusOpen:
		return "mở"
	case finding.StatusTriage:
		return "đang phân loại"
	case finding.StatusConfirmed:
		return "đã xác nhận"
	case finding.StatusFalsePos:
		return "dương tính giả"
	case finding.StatusRemediated:
		return "đã khắc phục"
	default:
		return "không xác định"
	}
}

func boundUTF8Bytes(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit < utf8.RuneLen('…') {
		return ""
	}
	limit -= utf8.RuneLen('…')
	for len(value) > limit {
		_, size := utf8.DecodeLastRuneInString(value)
		value = value[:len(value)-size]
	}
	return value + "…"
}

func boundRunes(value string, limit int) string {
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	if limit < 1 {
		return ""
	}
	end := 0
	for count := 0; end < len(value) && count < limit-1; count++ {
		_, size := utf8.DecodeRuneInString(value[end:])
		end += size
	}
	return value[:end] + "…"
}
