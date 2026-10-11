// Package syslog sends redacted records as RFC 5424 messages over RFC 5425 TLS.
package syslog

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type connection interface {
	io.Writer
	Close() error
	HandshakeContext(context.Context) error
	SetDeadline(time.Time) error
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

// Client is an RFC 5424-over-TLS SIEM driver.
type Client struct {
	dial    dialFunc
	timeout time.Duration
	now     func() time.Time
	wrapTLS func(net.Conn, *tls.Config) connection
}

// New creates a client whose TCP connections pass through the shared SSRF-safe dialer.
func New(timeout time.Duration) *Client {
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 5 * time.Second
	}
	dialer := safehttp.NewDialer(safehttp.Policy{}, timeout)
	return &Client{
		dial: dialer.DialContext, timeout: timeout, now: time.Now,
		wrapTLS: func(conn net.Conn, config *tls.Config) connection { return tls.Client(conn, config) },
	}
}

// Deliver writes each record as one complete octet-counted frame. A completed
// transport write is the only acknowledgement available from syslog TLS.
func (c *Client) Deliver(ctx context.Context, req siem.Delivery) (siem.DeliveryResult, error) {
	if c == nil || c.dial == nil || c.wrapTLS == nil {
		return siem.DeliveryResult{}, fmt.Errorf("syslog client is not configured")
	}
	if req.AckMode != siem.AckTransportWrite {
		return blockedAll(len(req.Records), "syslog acknowledgement mode must be transport write"), nil
	}
	if !validAppName(req.Target) {
		return blockedAll(len(req.Records), "syslog app name is invalid"), nil
	}
	origin, err := siem.ParseOriginFor(siem.ProviderSyslogTLS, req.Origin)
	if err != nil {
		return blockedAll(len(req.Records), "syslog origin is invalid"), nil
	}
	tlsConfig, err := credentials(req.Secret, origin.Host)
	if err != nil {
		return blockedAll(len(req.Records), "syslog TLS credential is invalid"), nil
	}
	frames := make([][]byte, len(req.Records))
	for i, record := range req.Records {
		frames[i], err = frame(c.clock().UTC(), req.Target, record)
		if err != nil {
			return blockedAll(len(req.Records), "syslog record is invalid"), nil
		}
	}
	raw, err := c.dial(ctx, "tcp", net.JoinHostPort(origin.Host, origin.Port))
	if err != nil {
		if errors.Is(err, safehttp.ErrBlockedDestination) {
			return blockedAll(len(req.Records), "syslog destination is blocked"), nil
		}
		return retryFrom(len(req.Records), 0, "syslog connection failed"), nil
	}
	conn := c.wrapTLS(raw, tlsConfig)
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(c.duration())
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return retryFrom(len(req.Records), 0, "syslog connection deadline failed"), nil
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		if certificateVerificationFailed(err) {
			return blockedAll(len(req.Records), "syslog TLS certificate verification failed"), nil
		}
		return retryFrom(len(req.Records), 0, "syslog TLS handshake failed"), nil
	}
	result := siem.DeliveryResult{Items: make([]siem.DeliveryItem, len(frames))}
	for i, frame := range frames {
		if err := writeFull(conn, frame); err != nil {
			for j := i; j < len(result.Items); j++ {
				result.Items[j] = retryItem("syslog frame write failed")
			}
			return result, nil
		}
		result.Items[i].Disposition = siem.ItemAcked
	}
	return result, nil
}

func certificateVerificationFailed(err error) bool {
	var verificationError *tls.CertificateVerificationError
	var hostnameError x509.HostnameError
	var unknownAuthority x509.UnknownAuthorityError
	var invalidCertificate x509.CertificateInvalidError
	return errors.As(err, &verificationError) || errors.As(err, &hostnameError) ||
		errors.As(err, &unknownAuthority) || errors.As(err, &invalidCertificate)
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Client) duration() time.Duration {
	if c.timeout > 0 {
		return c.timeout
	}
	return 5 * time.Second
}

type credential struct {
	CAPEM         string `json:"ca_pem"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
}

func credentials(secret, host string) (*tls.Config, error) {
	var value credential
	decoder := json.NewDecoder(strings.NewReader(secret))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode credential")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("decode credential")
	}
	if (value.ClientCertPEM == "") != (value.ClientKeyPEM == "") {
		return nil, fmt.Errorf("client certificate and key must be paired")
	}
	config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if value.CAPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(value.CAPEM)) {
			return nil, fmt.Errorf("CA certificate is invalid")
		}
		config.RootCAs = roots
	}
	if value.ClientCertPEM != "" {
		certificate, err := tls.X509KeyPair([]byte(value.ClientCertPEM), []byte(value.ClientKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("client certificate is invalid")
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

func frame(timestamp time.Time, app string, record siem.DeliveryRecord) ([]byte, error) {
	if !json.Valid(record.Body) {
		return nil, fmt.Errorf("body is not JSON")
	}
	recordID := messageID(record.ID)
	message := fmt.Sprintf(`<134>1 %s - %s - %s - `, timestamp.Format(time.RFC3339Nano), app, recordID) + "\ufeff" + string(record.Body)
	if len(message) > siem.MaxRecordBytes {
		return nil, fmt.Errorf("message exceeds the byte cap")
	}
	return append([]byte(strconv.Itoa(len(message))+" "), []byte(message)...), nil
}

func validAppName(value string) bool {
	if len(value) == 0 || len(value) > 48 {
		return false
	}
	for _, r := range value {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func messageID(recordID string) string {
	sum := sha256.Sum256([]byte(recordID))
	return fmt.Sprintf("syn-%x", sum[:14])
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func blockedAll(n int, reason string) siem.DeliveryResult {
	items := make([]siem.DeliveryItem, n)
	for i := range items {
		items[i] = siem.DeliveryItem{Disposition: siem.ItemFailed, Blocked: true, Diagnostic: reason}
	}
	return siem.DeliveryResult{Items: items}
}

func retryFrom(n, start int, reason string) siem.DeliveryResult {
	items := make([]siem.DeliveryItem, n)
	for i := range items {
		if i < start {
			items[i].Disposition = siem.ItemAcked
		} else {
			items[i] = retryItem(reason)
		}
	}
	return siem.DeliveryResult{Items: items}
}

func retryItem(reason string) siem.DeliveryItem {
	return siem.DeliveryItem{Disposition: siem.ItemFailed, Retryable: true, Diagnostic: reason}
}

var _ ports.SIEMDriver = (*Client)(nil)
