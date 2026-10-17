package notificationsender

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"
)

func documentMailFixture() ports.DocumentPDFMail {
	return ports.DocumentPDFMail{Recipient: "recipient@example.test", Subject: "Báo cáo bảo mật", Text: "Đánh giá đã hoàn tất", HTML: "<p>Đánh giá đã hoàn tất</p>", Filename: "report.pdf", PDF: []byte("%PDF-1.7\nverified immutable artifact"), MessageID: "scheduled-report", BeforeData: func(context.Context) error { return nil }}
}

func TestDocumentPDFMixedMIMEPreservesPDFAndVietnameseAlternative(t *testing.T) {
	document := documentMailFixture()
	raw, err := smtpMessage("sender@example.test", document.Recipient, document.Subject, document.Text, document.HTML, "", "<scheduled-report@synapse.local>", time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := attachDocumentPDF(raw, document)
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	kind, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/mixed" {
		t.Fatalf("MIME kind=%q err=%v", kind, err)
	}
	mixed := multipart.NewReader(message.Body, params["boundary"])
	text, err := mixed.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	kind, params, err = mime.ParseMediaType(text.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/alternative" {
		t.Fatalf("missing alternative: %s %v", kind, err)
	}
	alternatives := multipart.NewReader(text, params["boundary"])
	for _, want := range []string{document.Text, document.HTML} {
		part, err := alternatives.NextRawPart()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(quotedprintable.NewReader(part))
		if err != nil || string(decoded) != want {
			t.Fatalf("Vietnamese body=%q err=%v", decoded, err)
		}
	}
	attachment, err := mixed.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	kind, params, err = mime.ParseMediaType(attachment.Header.Get("Content-Disposition"))
	if err != nil || kind != "attachment" || params["filename"] != "report.pdf" {
		t.Fatalf("attachment metadata=%q %v", attachment.Header, err)
	}
	pdf, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, attachment))
	if err != nil || !bytes.Equal(pdf, document.PDF) {
		t.Fatalf("PDF changed err=%v", err)
	}
	if _, err = mixed.NextPart(); err != io.EOF {
		t.Fatalf("unexpected MIME part: %v", err)
	}
}

func TestDocumentPDFRejectsOversizeInjectionAndConfiguredSecretBeforeDial(t *testing.T) {
	for _, scenario := range []string{"oversize", "filename", "message_id", "pdf", "secret", "guard"} {
		t.Run(scenario, func(t *testing.T) {
			sender := New(SMTPConfig{Host: "smtp.example.test", Port: 587, From: "sender@example.test", Password: "configured-secret"}, time.Second)
			sender.dial = func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("invalid document reached network")
				return nil, errors.New("unexpected dial")
			}
			document := documentMailFixture()
			switch scenario {
			case "oversize":
				document.PDF = bytes.Repeat([]byte("x"), maxDocumentPDFBytes+1)
			case "filename":
				document.Filename = "report.pdf\r\nBcc: attacker@example.test"
			case "message_id":
				document.MessageID = "id\r\nBcc: attacker"
			case "pdf":
				document.PDF = []byte("<script>html</script>")
			case "secret":
				document.Text = "configured-secret"
			case "guard":
				document.BeforeData = nil
			}
			result := sender.SendDocumentPDF(context.Background(), document)
			if result.Accepted || result.Ambiguous || result.ErrorCode == "" {
				t.Fatalf("invalid document result=%+v", result)
			}
		})
	}
}

func TestDocumentPDFSMTPAcknowledgementAndBeforeDataGuard(t *testing.T) {
	for _, scenario := range []string{"accepted", "lost_ack", "guard_denied"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			messages := make(chan string, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = fmt.Fprint(conn, "220 report relay\r\n")
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"), strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
						_, _ = fmt.Fprint(conn, "250 accepted\r\n")
					case strings.HasPrefix(line, "DATA"):
						_, _ = fmt.Fprint(conn, "354 send body\r\n")
						var body strings.Builder
						for {
							line, err = reader.ReadString('\n')
							if err != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
							body.WriteString(line)
						}
						messages <- body.String()
						if scenario == "accepted" {
							_, _ = fmt.Fprint(conn, "250 accepted\r\n")
						}
						return
					default:
						return
					}
				}
			}()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			number, _ := strconv.Atoi(port)
			sender := New(SMTPConfig{Host: host, Port: number, From: "sender@example.test"}, time.Second)
			document := documentMailFixture()
			guardCalls := 0
			document.BeforeData = func(context.Context) error {
				guardCalls++
				if scenario == "guard_denied" {
					return errors.New("current authority revoked")
				}
				return nil
			}
			result := sender.SendDocumentPDF(context.Background(), document)
			if guardCalls != 1 {
				t.Fatalf("release guard calls=%d", guardCalls)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("SMTP fixture did not stop")
			}
			switch scenario {
			case "accepted":
				if !result.Accepted || result.Ambiguous || result.ErrorCode != "" {
					t.Fatalf("ack result=%+v", result)
				}
				body := <-messages
				if !strings.Contains(body, "multipart/mixed") || !strings.Contains(body, "Message-ID: <scheduled-report@synapse.local>") {
					t.Fatal("missing bounded PDF MIME or stable Message-ID")
				}
			case "lost_ack":
				if result.Accepted || !result.Ambiguous || result.Retryable {
					t.Fatalf("unacknowledged DATA may duplicate: %+v", result)
				}
			case "guard_denied":
				if result.Accepted || result.Ambiguous || result.ErrorCode != "release_authority_changed" {
					t.Fatalf("guard result=%+v", result)
				}
				select {
				case <-messages:
					t.Fatal("PDF sent after guard refusal")
				default:
				}
			}
		})
	}
}
