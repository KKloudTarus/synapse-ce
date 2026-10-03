package notificationsender

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// emailDriver sends one message per delivery recipient through the operator's SMTP relay. The
// channel's configuration only lists recipients; the relay is process configuration.
type emailDriver struct{ s *Sender }

func (emailDriver) ChannelType() notification.ChannelType { return notification.ChannelEmail }

func (d emailDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	if _, ok := config.(ports.EmailChannelConfig); !ok {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	title, summary, fallback := eventText(w)
	result := d.s.sendSMTP(ctx, w.Delivery.Recipient, title, summary, w.Delivery.ID)
	result.TemplateFallback = fallback
	return result
}

// SendContactVerification shares the SMTP transport and retry classification with
// notification delivery, but the code is never put into a persisted event, rule,
// delivery attempt, or job payload.
func (s *Sender) SendContactVerification(ctx context.Context, recipient, code string, challengeID shared.ID) ports.NotificationSendResult {
	return s.sendSMTP(ctx, recipient, "Verify your Synapse email address", "Your verification code is "+code+". It expires in 10 minutes. If you did not request this, ignore this email.", challengeID)
}

func (s *Sender) SendPersonalNotice(ctx context.Context, recipient, title, summary string, messageID shared.ID) ports.NotificationSendResult {
	return s.sendSMTP(ctx, recipient, title, summary, messageID)
}

// SendIdentityRecoveryAlert deliberately bypasses notification rules and preferences. Its
// persisted obligation contains no recipient address or activation value; this transport receives
// only the resolved destination at delivery time.
func (s *Sender) SendIdentityRecoveryAlert(ctx context.Context, recipient string, sessionID shared.ID) ports.NotificationSendResult {
	return s.sendSMTP(ctx, recipient, "Emergency recovery session issued", "An emergency identity recovery session was issued. If you did not initiate recovery, contact an organization administrator immediately.", sessionID)
}

func (s *Sender) sendSMTP(ctx context.Context, destination, title, summary string, messageID shared.ID) ports.NotificationSendResult {
	if strings.TrimSpace(s.smtp.Host) == "" || strings.TrimSpace(s.smtp.From) == "" {
		return ports.NotificationSendResult{ErrorCode: "smtp_not_configured"}
	}
	from, err := mail.ParseAddress(s.smtp.From)
	if err != nil || strings.ContainsAny(from.Address, "\r\n") {
		return ports.NotificationSendResult{ErrorCode: "smtp_sender_invalid"}
	}
	recipient, err := mail.ParseAddress(destination)
	if err != nil || recipient.Address != destination || strings.ContainsAny(destination, "\r\n") {
		return ports.NotificationSendResult{ErrorCode: "smtp_recipient_invalid"}
	}
	mailID := "<" + messageID.String() + "@synapse.local>"
	body := "From: " + from.Address + "\r\nTo: " + destination + "\r\nSubject: " + safeHeader(title) + "\r\nMessage-ID: " + mailID + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + limit(summary, 64<<10) + "\r\n"
	address := net.JoinHostPort(s.smtp.Host, strconv.Itoa(s.smtp.Port))
	conn, err := s.dial(ctx, "tcp", address)
	if errors.Is(err, safehttp.ErrBlockedDestination) {
		return ports.NotificationSendResult{ErrorCode: "smtp_destination_blocked"}
	}
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "smtp_connect", Retryable: true}
	}
	defer func() { _ = conn.Close() }()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	client, err := smtp.NewClient(conn, s.smtp.Host)
	if err != nil {
		return smtpResult(err)
	}
	defer func() { _ = client.Close() }()
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
	if err = client.Rcpt(destination); err != nil {
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
