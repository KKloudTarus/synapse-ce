package notificationsender

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxDocumentPDFBytes = 10 << 20
const maxDocumentMIMEBytes = 16 << 20

var documentMailIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var documentFilenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,122}\.pdf$`)
var _ ports.DocumentPDFSender = (*Sender)(nil)

// SendDocumentPDF shares WS3's dial, TLS, authentication and SMTP envelope. An
// unacknowledged DATA write is uncertain; its scheduler must not retry it blindly.
func (s *Sender) SendDocumentPDF(ctx context.Context, document ports.DocumentPDFMail) ports.DocumentEmailResult {
	if document.BeforeData == nil || !documentMailIDPattern.MatchString(document.MessageID.String()) || !documentFilenamePattern.MatchString(document.Filename) || len(document.PDF) < 5 || len(document.PDF) > maxDocumentPDFBytes || !bytes.HasPrefix(document.PDF, []byte("%PDF-")) || !utf8.ValidString(document.Subject) || len(document.Subject) > 1024 || len(document.Text) > 64<<10 || len(document.HTML) > 64<<10 || !utf8.ValidString(document.Text) || !utf8.ValidString(document.HTML) {
		return ports.DocumentEmailResult{ErrorCode: "document_email_invalid"}
	}
	relay := s.smtp
	if document.Relay != nil {
		relay = smtpConfigFromRelay(*document.Relay, s.smtp)
	}
	secrets := []string{relay.Password, relay.OAuthClientSecret, relay.OAuthRefreshToken}
	for _, literal := range []string{document.Subject, document.Text, document.HTML, document.Filename, string(document.PDF)} {
		if redact.String(literal, secrets) != literal {
			return ports.DocumentEmailResult{ErrorCode: "credential_in_document_email"}
		}
	}
	ambiguous := false
	result := s.sendSMTPMessageWithConfig(ctx, relay, document.Recipient, document.Subject, document.Text, document.HTML, "", document.MessageID, &document, &ambiguous)
	return ports.DocumentEmailResult{Accepted: result.StatusCode == 250 && result.ErrorCode == "", Ambiguous: ambiguous, Retryable: result.Retryable && !ambiguous, ErrorCode: result.ErrorCode}
}

func attachDocumentPDF(raw []byte, document ports.DocumentPDFMail) ([]byte, error) {
	if len(document.PDF) < 5 || len(document.PDF) > maxDocumentPDFBytes || !documentFilenamePattern.MatchString(document.Filename) {
		return nil, errors.New("invalid PDF attachment")
	}
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	for _, header := range []string{"From", "To", "Subject", "Date", "Message-ID", "MIME-Version"} {
		value := message.Header.Get(header)
		if value == "" || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("invalid document envelope")
		}
		fmt.Fprintf(&body, "%s: %s\r\n", header, value)
	}
	var content bytes.Buffer
	writer := multipart.NewWriter(&content)
	sum := sha256.Sum256([]byte(document.MessageID.String()))
	if err := writer.SetBoundary("synapse-mixed-" + hex.EncodeToString(sum[:16])); err != nil {
		return nil, err
	}
	fmt.Fprintf(&body, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", writer.Boundary())
	textHeader := textproto.MIMEHeader{}
	textHeader.Set("Content-Type", message.Header.Get("Content-Type"))
	if transfer := message.Header.Get("Content-Transfer-Encoding"); transfer != "" {
		textHeader.Set("Content-Transfer-Encoding", transfer)
	}
	textPart, err := writer.CreatePart(textHeader)
	if err != nil {
		return nil, err
	}
	text, readErr := io.ReadAll(io.LimitReader(message.Body, (512<<10)+1))
	if readErr != nil || len(text) > 512<<10 {
		return nil, errors.New("document email body exceeds bounds")
	}
	if _, err = textPart.Write(text); err != nil {
		return nil, err
	}
	attachmentHeader := textproto.MIMEHeader{}
	attachmentHeader.Set("Content-Type", mime.FormatMediaType("application/pdf", map[string]string{"name": document.Filename}))
	attachmentHeader.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": document.Filename}))
	attachmentHeader.Set("Content-Transfer-Encoding", "base64")
	attachmentPart, err := writer.CreatePart(attachmentHeader)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(document.PDF)
	for len(encoded) > 0 {
		n := min(len(encoded), 76)
		if _, err = io.WriteString(attachmentPart, encoded[:n]+"\r\n"); err != nil {
			return nil, err
		}
		encoded = encoded[n:]
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	if body.Len()+content.Len() > maxDocumentMIMEBytes {
		return nil, errors.New("encoded document email exceeds bounds")
	}
	body.Write(content.Bytes())
	return body.Bytes(), nil
}
