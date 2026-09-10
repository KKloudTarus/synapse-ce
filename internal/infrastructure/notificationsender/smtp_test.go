package notificationsender

import (
	"bufio"
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSMTPControlledRelay(t *testing.T) {
	for _, code := range []int{250, 450, 550} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
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
						_, _ = fmt.Fprintf(conn, "%d recipient result\r\n", code)
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
			sender := New(SMTPConfig{Host: host, Port: number, From: "synapse@example.com"}, time.Second)
			work := testWork(notification.ChannelEmail)
			work.Delivery.Recipient = "recipient@example.com"
			result := sender.Send(context.Background(), work, ports.NotificationChannelConfig{})
			if code == 250 {
				if result.StatusCode != 250 || result.ErrorCode != "" {
					t.Fatalf("%+v", result)
				}
				body := <-messages
				if !strings.Contains(body, "Message-ID: <delivery@synapse.local>") || !strings.Contains(body, "To: recipient@example.com") {
					t.Fatalf("missing headers: %s", body)
				}
			} else if result.Retryable != (code == 450) || result.StatusCode != code {
				t.Fatalf("%+v", result)
			}
		})
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
				result := sender.Send(context.Background(), testWork(kind), ports.NotificationChannelConfig{URL: receiver.URL, Secret: "test-key"})
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
	if result := sender.Send(context.Background(), testWork(notification.ChannelWebhook), ports.NotificationChannelConfig{URL: receiver.URL}); !result.Retryable {
		t.Fatalf("%+v", result)
	}
}

func TestPublicTransportBlocksPrivateDestinations(t *testing.T) {
	for _, endpoint := range []string{"https://127.0.0.1:1", "https://[::1]:1", "https://169.254.169.254", "https://10.0.0.1"} {
		result := New(SMTPConfig{}, 50*time.Millisecond).Send(context.Background(), testWork(notification.ChannelWebhook), ports.NotificationChannelConfig{URL: endpoint})
		if result.ErrorCode == "" {
			t.Fatalf("allowed private destination %s", endpoint)
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
			result := sender.Send(context.Background(), work, ports.NotificationChannelConfig{})
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
