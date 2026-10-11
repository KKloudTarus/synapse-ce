package notificationsender

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	pagerDutyEventsUS = "https://events.pagerduty.com/v2/enqueue"
	pagerDutyEventsEU = "https://events.eu.pagerduty.com/v2/enqueue"
	jsmAlertsURL      = "https://api.atlassian.com/jsm/ops/integration/v2/alerts"
)

type pagerDutyDriver struct{ s *Sender }

func (pagerDutyDriver) ChannelType() notification.ChannelType { return notification.ChannelPagerDuty }
func (d pagerDutyDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.PagerDutyChannelConfig)
	if !ok || strings.TrimSpace(cfg.RoutingKey) == "" {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	target := pagerDutyEventsUS
	if cfg.Region == "events.eu.pagerduty.com" {
		target = pagerDutyEventsEU
	} else if cfg.Region != "events.pagerduty.com" {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	summary, links, fallback, ok := pagerContent(w, messageformat.PagerDutySummaryRunes)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	dedup, ok := d.s.pagerDedupKey(w)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "pager_key_unavailable", TemplateFallback: fallback}
	}
	if w.SubjectResolved && strings.TrimSpace(w.SubjectAnchor) == "" {
		// A close without an acknowledged trigger could close an unrelated alert if the provider
		// happens to have the same alias. The worker persists pager aliases as RemoteRef only after
		// a successful attempt, so a nonempty anchor proves the matching trigger was accepted.
		return ports.NotificationSendResult{ErrorCode: "pager_resolve_unpaired", TemplateFallback: fallback}
	}
	action := "trigger"
	if w.SubjectResolved {
		action = "resolve"
	}
	payload, err := json.Marshal(map[string]any{"routing_key": cfg.RoutingKey, "event_action": action, "dedup_key": dedup, "payload": map[string]any{"summary": summary, "source": "synapse", "severity": "error", "custom_details": map[string]any{"links": links}}})
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "request_invalid", TemplateFallback: fallback}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "synapse-notifications/1")
	result := d.s.do(req)
	result.TemplateFallback = fallback
	if result.ErrorCode == "" && result.StatusCode >= http.StatusOK && result.StatusCode < http.StatusMultipleChoices {
		result.RemoteRef = dedup
	}
	return result
}

type jsmDriver struct{ s *Sender }

func (jsmDriver) ChannelType() notification.ChannelType { return notification.ChannelJSM }
func (d jsmDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.JSMChannelConfig)
	if !ok || strings.TrimSpace(cfg.APIKey) == "" {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	summary, links, fallback, ok := pagerContent(w, messageformat.JSMMessageRunes)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	alias, ok := d.s.pagerDedupKey(w)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "pager_key_unavailable", TemplateFallback: fallback}
	}
	if w.SubjectResolved && strings.TrimSpace(w.SubjectAnchor) == "" {
		return ports.NotificationSendResult{ErrorCode: "pager_resolve_unpaired", TemplateFallback: fallback}
	}
	target := jsmAlertsURL
	payload := map[string]any{"message": summary, "alias": alias, "source": "synapse", "details": jsmLinkDetails(links)}
	if w.SubjectResolved {
		target += "/" + url.PathEscape(alias) + "/close?identifierType=alias"
		payload = map[string]any{"source": "synapse"}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "request_invalid", TemplateFallback: fallback}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "GenieKey "+cfg.APIKey)
	req.Header.Set("User-Agent", "synapse-notifications/1")
	result, response := d.s.doRead(req)
	result.TemplateFallback = fallback
	if result.ErrorCode != "" {
		return result
	}
	if result.StatusCode != http.StatusAccepted {
		result.ErrorCode, result.Retryable = "jsm_request_unconfirmed", true
		return result
	}
	var accepted struct {
		RequestID string `json:"requestId"`
	}
	if json.Unmarshal(response, &accepted) != nil || accepted.RequestID == "" {
		return ports.NotificationSendResult{StatusCode: http.StatusAccepted, ErrorCode: "jsm_request_unconfirmed", Retryable: true, TemplateFallback: fallback}
	}
	statusRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, jsmAlertsURL+"/requests/"+url.PathEscape(accepted.RequestID), nil)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "request_invalid", TemplateFallback: fallback}
	}
	statusRequest.Header.Set("Accept", "application/json")
	statusRequest.Header.Set("Authorization", "GenieKey "+cfg.APIKey)
	statusRequest.Header.Set("User-Agent", "synapse-notifications/1")
	status, statusBody := d.s.doRead(statusRequest)
	status.TemplateFallback = fallback
	if status.ErrorCode != "" {
		return status
	}
	var finished struct {
		Data struct {
			IsSuccess *bool `json:"isSuccess"`
		} `json:"data"`
	}
	if json.Unmarshal(statusBody, &finished) != nil {
		return ports.NotificationSendResult{StatusCode: status.StatusCode, ErrorCode: "jsm_request_unconfirmed", Retryable: true, TemplateFallback: fallback}
	}
	if finished.Data.IsSuccess == nil {
		return ports.NotificationSendResult{StatusCode: status.StatusCode, ErrorCode: "jsm_request_unconfirmed", Retryable: true, TemplateFallback: fallback}
	}
	if !*finished.Data.IsSuccess {
		return ports.NotificationSendResult{StatusCode: status.StatusCode, ErrorCode: "jsm_request_failed", TemplateFallback: fallback}
	}
	return ports.NotificationSendResult{StatusCode: http.StatusAccepted, TemplateFallback: fallback, RemoteRef: alias}
}

func pagerContent(w ports.NotificationWork, summaryRunes int) (string, []map[string]string, bool, bool) {
	var raw []byte
	fallback := false
	if w.Formatted != nil && len(w.Formatted.Body) > 0 {
		raw = w.Formatted.Body
	} else {
		// Direct sender callers do not pass through RenderMessage. Clamp the fallback here too, so
		// pager providers cannot regain summary/detail values through a high-class channel.
		fallbackWork := w
		fallbackWork.Channel.DataClass = notification.DataClassSignal
		summary, _, fallbackEvent := eventText(fallbackWork)
		fallback = fallbackEvent
		message, err := (messageformat.PagerDutyFormatter{}).Format(ports.RenderedMessage{Fields: map[string]string{"summary": summary}})
		if err != nil {
			return "", nil, fallback, false
		}
		raw = message.Body
	}
	var value struct {
		Summary string              `json:"summary"`
		Links   []map[string]string `json:"links"`
	}
	if json.Unmarshal(raw, &value) != nil || strings.TrimSpace(value.Summary) == "" {
		return "", nil, fallback, false
	}
	return strings.TrimSpace(limit(value.Summary, summaryRunes)), value.Links, fallback, true
}

// jsmLinkDetails keeps the JSM ExtraProperties contract string-only. URLs are already checked by
// the formatter; labels and rendered event content do not enter details.
func jsmLinkDetails(links []map[string]string) map[string]string {
	details := make(map[string]string, len(links))
	for i, link := range links {
		if target := strings.TrimSpace(link["url"]); target != "" {
			details["link_"+strconv.Itoa(i+1)] = target
		}
	}
	return details
}

func (s *Sender) pagerDedupKey(w ports.NotificationWork) (string, bool) {
	tenant := w.Delivery.TenantID
	if tenant.IsZero() {
		tenant = w.Event.TenantID
	}
	if len(s.pagerKey) == 0 || tenant.IsZero() || w.Channel.ID.IsZero() {
		return "", false
	}
	// SubjectKind/SubjectID are trusted source identities. SubjectAnchor is deliberately absent:
	// it is an acknowledgement from the provider, not a source identity. Events without a subject
	// use their own immutable event ID, preventing unrelated subject-less events from aggregating.
	subjectKind, subjectID := strings.TrimSpace(w.Event.SubjectKind), strings.TrimSpace(w.Event.SubjectID)
	if subjectKind == "" || subjectID == "" {
		subjectKind, subjectID = "event", w.Event.ID.String()
	}
	if subjectID == "" {
		return "", false
	}
	mac := hmac.New(sha256.New, s.pagerKey)
	_, _ = mac.Write([]byte(tenant.String()))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(w.Channel.ID.String()))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(strconv.Itoa(w.Channel.SecretVersion)))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(subjectKind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(subjectID))
	return hex.EncodeToString(mac.Sum(nil)), true
}
