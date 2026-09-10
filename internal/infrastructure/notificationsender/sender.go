// Package notificationsender delivers one durable notification attempt. Retry
// scheduling belongs to synapse-worker; this adapter never sleeps or retries.
package notificationsender

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type SMTPConfig struct {
	Host       string
	Port       int
	From       string
	Username   string
	Password   string
	RequireTLS bool
}

type Sender struct {
	http    *http.Client
	smtp    SMTPConfig
	now     func() time.Time
	timeout time.Duration
}

var _ ports.NotificationSender = (*Sender)(nil)

func New(smtpConfig SMTPConfig, timeout time.Duration) *Sender {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if smtpConfig.Port == 0 {
		smtpConfig.Port = 587
	}
	return &Sender{http: safehttp.New(timeout, false), smtp: smtpConfig, now: time.Now, timeout: timeout}
}

func (s *Sender) Send(ctx context.Context, work ports.NotificationWork, cfg ports.NotificationChannelConfig) ports.NotificationSendResult {
	switch work.Channel.Type {
	case notification.ChannelWebhook:
		return s.sendWebhook(ctx, work, cfg)
	case notification.ChannelSlack:
		return s.sendSlack(ctx, work, cfg)
	case notification.ChannelEmail:
		return s.sendEmail(ctx, work, cfg)
	default:
		return ports.NotificationSendResult{ErrorCode: "unsupported_channel"}
	}
}

func (s *Sender) sendWebhook(ctx context.Context, w ports.NotificationWork, cfg ports.NotificationChannelConfig) ports.NotificationSendResult {
	body, err := json.Marshal(w.Event)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "encode_failed"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "request_invalid"}
	}
	timestamp := strconv.FormatInt(s.now().UTC().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(cfg.Secret))
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "synapse-notifications/1")
	req.Header.Set("X-Synapse-Timestamp", timestamp)
	req.Header.Set("X-Synapse-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Synapse-Event-ID", w.Event.ID.String())
	req.Header.Set("X-Synapse-Delivery-ID", w.Delivery.ID.String())
	return s.do(req)
}

func (s *Sender) sendSlack(ctx context.Context, w ports.NotificationWork, cfg ports.NotificationChannelConfig) ports.NotificationSendResult {
	title, summary := eventText(w)
	body, _ := json.Marshal(map[string]any{"text": title, "blocks": []map[string]any{{"type": "header", "text": map[string]string{"type": "plain_text", "text": limit(title, 150)}}, {"type": "section", "text": map[string]string{"type": "mrkdwn", "text": escapeSlack(limit(summary, 2500))}}, {"type": "context", "elements": []map[string]string{{"type": "mrkdwn", "text": "Event `" + string(w.Event.Type) + "` · `" + w.Event.ID.String() + "`"}}}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "request_invalid"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "synapse-notifications/1")
	return s.do(req)
}

func (s *Sender) do(req *http.Request) ports.NotificationSendResult {
	resp, err := s.http.Do(req)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "network_error", Retryable: true}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	result := ports.NotificationSendResult{StatusCode: resp.StatusCode}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return result
	}
	switch {
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		result.Retryable = true
		result.ErrorCode = "http_" + strconv.Itoa(resp.StatusCode)
		if resp.StatusCode == http.StatusTooManyRequests {
			result.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), s.now())
		}
	default:
		result.ErrorCode = "http_" + strconv.Itoa(resp.StatusCode)
	}
	return result
}

func (s *Sender) sendEmail(ctx context.Context, w ports.NotificationWork, _ ports.NotificationChannelConfig) ports.NotificationSendResult {
	if strings.TrimSpace(s.smtp.Host) == "" || strings.TrimSpace(s.smtp.From) == "" {
		return ports.NotificationSendResult{ErrorCode: "smtp_not_configured"}
	}
	from, err := mail.ParseAddress(s.smtp.From)
	if err != nil || strings.ContainsAny(from.Address, "\r\n") {
		return ports.NotificationSendResult{ErrorCode: "smtp_sender_invalid"}
	}
	title, summary := eventText(w)
	messageID := "<" + w.Delivery.ID.String() + "@synapse.local>"
	body := "From: " + from.Address + "\r\nTo: " + w.Delivery.Recipient + "\r\nSubject: " + safeHeader(title) + "\r\nMessage-ID: " + messageID + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + limit(summary, 64<<10) + "\r\n"
	address := net.JoinHostPort(s.smtp.Host, strconv.Itoa(s.smtp.Port))
	dialer := net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "smtp_connect", Retryable: true}
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	client, err := smtp.NewClient(conn, s.smtp.Host)
	if err != nil {
		return smtpResult(err)
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err = client.StartTLS(&tls.Config{ServerName: s.smtp.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return smtpResult(err)
		}
	} else if s.smtp.RequireTLS {
		return ports.NotificationSendResult{ErrorCode: "smtp_tls_required"}
	}
	if s.smtp.Username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return ports.NotificationSendResult{ErrorCode: "smtp_auth_unavailable"}
		}
		if err = client.Auth(smtp.PlainAuth("", s.smtp.Username, s.smtp.Password, s.smtp.Host)); err != nil {
			return smtpResult(err)
		}
	}
	if err = client.Mail(from.Address); err != nil {
		return smtpResult(err)
	}
	if err = client.Rcpt(w.Delivery.Recipient); err != nil {
		return smtpResult(err)
	}
	writer, err := client.Data()
	if err != nil {
		return smtpResult(err)
	}
	if _, err = writer.Write([]byte(body)); err == nil {
		err = writer.Close()
	}
	if err != nil {
		return smtpResult(err)
	}
	// DATA's final 250 is the relay's acknowledgement. A disconnect during
	// QUIT must not cause a duplicate of an already accepted message.
	_ = client.Quit()
	return ports.NotificationSendResult{StatusCode: 250}
}

func smtpResult(err error) ports.NotificationSendResult {
	result := ports.NotificationSendResult{ErrorCode: "smtp_error", Retryable: true}
	var proto *textproto.Error
	if errors.As(err, &proto) {
		result.StatusCode = proto.Code
		result.ErrorCode = "smtp_" + strconv.Itoa(proto.Code)
		result.Retryable = proto.Code >= 400 && proto.Code < 500
	}
	return result
}
func parseRetryAfter(v string, now time.Time) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && seconds > 0 {
		return time.Duration(min(seconds, 3600)) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}
func eventText(w ports.NotificationWork) (string, string) {
	var data map[string]any
	_ = json.Unmarshal(w.Event.Data, &data)
	title := fmt.Sprint(data["title"])
	if title == "<nil>" || strings.TrimSpace(title) == "" {
		title = "Synapse: " + string(w.Event.Type)
	}
	summary := fmt.Sprint(data["summary"])
	if summary == "<nil>" || strings.TrimSpace(summary) == "" {
		summary = "A " + string(w.Event.Type) + " event occurred at " + w.Event.OccurredAt.UTC().Format(time.RFC3339)
	}
	return safeHeader(title), summary
}
func safeHeader(v string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(limit(v, 180)))
}
func escapeSlack(v string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(v)
}
func limit(v string, n int) string {
	runes := []rune(v)
	if len(runes) > n {
		return string(runes[:n])
	}
	return v
}
