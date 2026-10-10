package notificationsender

import (
	"bufio"
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSMTPControlledRelay(t *testing.T) {
	for _, tc := range []struct {
		code      int
		formatted bool
	}{{250, false}, {250, true}, {450, false}, {550, false}} {
		name := strconv.Itoa(tc.code)
		if tc.formatted {
			name += "_formatted"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			messages := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = fmt.Fprint(conn, "220 test relay\r\n")
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						_, _ = fmt.Fprint(conn, "250 test relay\r\n")
					case strings.HasPrefix(line, "MAIL"):
						_, _ = fmt.Fprint(conn, "250 sender ok\r\n")
					case strings.HasPrefix(line, "RCPT"):
						_, _ = fmt.Fprintf(conn, "%d recipient result\r\n", tc.code)
					case strings.HasPrefix(line, "DATA"):
						_, _ = fmt.Fprint(conn, "354 send data\r\n")
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
						_, _ = fmt.Fprint(conn, "250 accepted\r\n")
						// Disconnect before QUIT: the accepted message is still successful.
						return
					default:
						return
					}
				}
			}()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			number, _ := strconv.Atoi(port)
			sender := New(SMTPConfig{Host: host, Port: number, From: "synapse@example.com", UnsubscribeURL: "https://mail.example/unsubscribe"}, time.Second)
			work := testWork(notification.ChannelEmail)
			work.Delivery.Recipient = "recipient@example.com"
			if tc.formatted {
				work.Formatted = &ports.FormattedMessage{Subject: "Rendered", Body: []byte("plain"), HTMLBody: []byte("<p>rich</p>")}
			}
			result := sender.Send(context.Background(), work, ports.EmailChannelConfig{})
			if tc.code == 250 {
				if result.StatusCode != 250 || result.ErrorCode != "" {
					t.Fatalf("%+v", result)
				}
				body := <-messages
				if !strings.Contains(body, "Message-ID: <delivery@synapse.local>") || !strings.Contains(body, "To: recipient@example.com") || !strings.Contains(body, "List-Unsubscribe: <https://mail.example/unsubscribe>") {
					t.Fatalf("missing headers: %s", body)
				}
			} else if result.Retryable != (tc.code == 450) || result.StatusCode != tc.code {
				t.Fatalf("%+v", result)
			}
		})
	}
}

func TestSMTPMultipartAlternativeUsesSafeHeaders(t *testing.T) {
	raw, err := smtpMessage("sender@example.com", "recipient@example.com", "Cảnh báo\r\nBcc: attacker@example.com", "plain <text>", "<p>safe &amp; escaped</p>", "https://mail.example/unsubscribe", "<delivery@synapse.local>")
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if got := message.Header.Get("Bcc"); got != "" {
		t.Fatalf("injected Bcc header = %q", got)
	}
	if got := message.Header.Get("List-Unsubscribe"); got != "<https://mail.example/unsubscribe>" || message.Header.Get("List-Unsubscribe-Post") != "" {
		t.Fatalf("unsubscribe headers = %q / %q", got, message.Header.Get("List-Unsubscribe-Post"))
	}
	if !strings.HasPrefix(message.Header.Get("Subject"), "=?UTF-8?q?") {
		t.Fatalf("subject was not encoded: %q", message.Header.Get("Subject"))
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" || params["boundary"] == "" {
		t.Fatalf("content type = %q (%v)", message.Header.Get("Content-Type"), err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	var parts []string
	for {
		part, readErr := reader.NextPart()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		body, readErr := io.ReadAll(part)
		if readErr != nil {
			t.Fatal(readErr)
		}
		parts = append(parts, part.Header.Get("Content-Type")+":"+string(body))
	}
	if len(parts) != 2 || !strings.Contains(parts[0], "plain <text>") || !strings.Contains(parts[1], "<p>safe &amp; escaped</p>") {
		t.Fatalf("multipart parts = %#v", parts)
	}
}

func TestSMTPPlainTextUsesQuotedPrintableUTF8(t *testing.T) {
	raw, err := smtpMessage("sender@example.com", "recipient@example.com", "Thông báo", "Cảnh báo: đã hoàn tất", "", "", "<delivery@synapse.local>")
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if got := message.Header.Get("Content-Transfer-Encoding"); got != "quoted-printable" {
		t.Fatalf("Content-Transfer-Encoding = %q", got)
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(message.Body))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(decoded); got != "Cảnh báo: đã hoàn tất\r\n" {
		t.Fatalf("decoded body = %q", got)
	}
}

func TestSMTPFoldsLongUnicodeSubject(t *testing.T) {
	title := strings.Repeat("🚨 cảnh báo bảo mật ", 20)
	raw, err := smtpMessage("sender@example.com", "recipient@example.com", title, "body", "", "", "<delivery@synapse.local>")
	if err != nil {
		t.Fatal(err)
	}
	inHeaders := true
	for _, line := range strings.Split(string(raw), "\r\n") {
		if line == "" {
			inHeaders = false
		}
		if inHeaders && len(line) > 78 {
			t.Fatalf("header line is %d bytes: %q", len(line), line)
		}
	}
	message, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || decoded != safeHeader(title) {
		t.Fatalf("decoded Subject = %q, %v", decoded, err)
	}
}

func TestContactVerificationUsesExistingSMTPTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	mail := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = fmt.Fprint(conn, "220 test relay\r\n")
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				_, _ = fmt.Fprint(conn, "250 test relay\r\n")
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				_, _ = fmt.Fprint(conn, "250 accepted\r\n")
			case strings.HasPrefix(line, "DATA"):
				_, _ = fmt.Fprint(conn, "354 data\r\n")
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
				mail <- body.String()
				_, _ = fmt.Fprint(conn, "250 accepted\r\n")
				return
			default:
				return
			}
		}
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	sender := New(SMTPConfig{Host: host, Port: number, From: "synapse@example.com", UnsubscribeURL: "https://mail.example/unsubscribe"}, time.Second)
	result := sender.SendContactVerification(context.Background(), "alice@example.com", "01234567", shared.ID("challenge-1"))
	if result.StatusCode != 250 || result.ErrorCode != "" {
		t.Fatalf("SMTP result: %+v", result)
	}
	body := <-mail
	for _, expected := range []string{"To: alice@example.com", "Message-ID: <challenge-1@synapse.local>", "01234567", "Verify your Synapse email address"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("SMTP message missing %q", expected)
		}
	}
	if strings.Contains(body, "List-Unsubscribe:") {
		t.Fatalf("contact verification must not carry channel unsubscribe header: %s", body)
	}
	if result := sender.SendContactVerification(context.Background(), "alice@example.com\r\nBcc: attacker@example.com", "01234567", shared.ID("challenge-2")); result.ErrorCode != "smtp_recipient_invalid" {
		t.Fatalf("unsafe recipient accepted: %+v", result)
	}
}

func TestTransportTimeoutAndHTTPClassification(t *testing.T) {
	for _, kind := range []notification.ChannelType{notification.ChannelWebhook, notification.ChannelSlack} {
		for _, code := range []int{204, 302, 400, 408, 429, 500} {
			t.Run(string(kind)+strconv.Itoa(code), func(t *testing.T) {
				receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body); w.WriteHeader(code) }))
				defer receiver.Close()
				sender := New(SMTPConfig{}, time.Second)
				sender.http = receiver.Client()
				result := sender.Send(context.Background(), testWork(kind), channelConfig(kind, receiver.URL, "test-key"))
				if result.StatusCode != code || result.Retryable != (code == 408 || code == 429 || code >= 500) {
					t.Fatalf("%+v", result)
				}
			})
		}
	}
	release := make(chan struct{})
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer receiver.Close()
	defer close(release)
	sender := New(SMTPConfig{}, 20*time.Millisecond)
	sender.http = receiver.Client()
	sender.http.Timeout = 20 * time.Millisecond
	if result := sender.Send(context.Background(), testWork(notification.ChannelWebhook), ports.WebhookChannelConfig{URL: receiver.URL}); !result.Retryable {
		t.Fatalf("%+v", result)
	}
}

func TestPublicTransportBlocksPrivateDestinations(t *testing.T) {
	for _, endpoint := range []string{"https://127.0.0.1:1", "https://[::1]:1", "https://169.254.169.254", "https://10.0.0.1", "https://[fd00:ec2::254]"} {
		result := New(SMTPConfig{}, 50*time.Millisecond).Send(context.Background(), testWork(notification.ChannelWebhook), ports.WebhookChannelConfig{URL: endpoint})
		// A refused destination does not change on retry, so it must not burn the retry budget.
		if result.ErrorCode != "destination_blocked" || result.Retryable {
			t.Fatalf("%s: result = %+v, want a non-retryable destination_blocked", endpoint, result)
		}
	}
}

func TestSMTPRelayRefusesMetadataEndpoints(t *testing.T) {
	for _, host := range []string{"169.254.169.254", "fd00:ec2::254", "100.100.100.200"} {
		work := testWork(notification.ChannelEmail)
		work.Delivery.Recipient = "recipient@example.com"
		result := New(SMTPConfig{Host: host, Port: 25, From: "synapse@example.com"}, time.Second).Send(context.Background(), work, ports.EmailChannelConfig{})
		if result.ErrorCode != "smtp_destination_blocked" || result.Retryable {
			t.Fatalf("relay %s: result = %+v, want a non-retryable smtp_destination_blocked", host, result)
		}
	}
}

func TestSMTPTimeoutAndRequiredTLS(t *testing.T) {
	for _, silent := range []bool{true, false} {
		t.Run(fmt.Sprint("silent=", silent), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			release := make(chan struct{})
			defer close(release)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if silent {
					<-release
					return
				}
				_, _ = fmt.Fprint(conn, "220 relay\r\n")
				_, _ = bufio.NewReader(conn).ReadString('\n')
				_, _ = fmt.Fprint(conn, "250 relay without TLS\r\n")
				<-release
			}()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			number, _ := strconv.Atoi(port)
			sender := New(SMTPConfig{Host: host, Port: number, From: "sender@example.com", RequireTLS: true}, 100*time.Millisecond)
			work := testWork(notification.ChannelEmail)
			work.Delivery.Recipient = "recipient@example.com"
			result := sender.Send(context.Background(), work, ports.EmailChannelConfig{})
			if silent {
				if !result.Retryable {
					t.Fatalf("timeout: %+v", result)
				}
			} else if result.Retryable || result.ErrorCode != "smtp_tls_required" {
				t.Fatalf("TLS policy: %+v", result)
			}
		})
	}
}
