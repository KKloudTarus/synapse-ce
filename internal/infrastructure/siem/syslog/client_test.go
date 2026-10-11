package syslog

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

func TestDeliverRFC5424OverTLS(t *testing.T) {
	listener, origin, ca := tlsListener(t, tls.VersionTLS12, tls.VersionTLS13)
	frames := make(chan string, 2)
	go readFrames(listener, frames)
	client := testClient(listener.Addr().String())
	req := delivery(origin, fmt.Sprintf(`{"ca_pem":%q}`, ca), "synapse", []siem.DeliveryRecord{
		{ID: `rec-1]"\\`, Body: []byte(`{"action":"login"}`)},
		{ID: "rec-2", Body: []byte(`{"action":"logout"}`)},
	})
	result, err := client.Deliver(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range result.Items {
		if item.Disposition != siem.ItemAcked {
			t.Fatalf("item %d = %+v", i, item)
		}
	}
	wantPrefix := `<134>1 2025-01-01T20:04:05Z - synapse - ` + messageID(`rec-1]"\\`) + ` - `
	if got := <-frames; got != wantPrefix+"\ufeff"+`{"action":"login"}` {
		t.Fatalf("message = %q", got)
	}
	if got := <-frames; !strings.HasSuffix(got, "\ufeff"+`{"action":"logout"}`) {
		t.Fatalf("second message = %q", got)
	}
}

func TestDeliverRejectsBadTLSAndCredential(t *testing.T) {
	t.Run("hostname", func(t *testing.T) {
		listener, _, ca := tlsListener(t, tls.VersionTLS12, tls.VersionTLS13)
		go acceptAndHandshake(listener)
		result, err := testClient(listener.Addr().String()).Deliver(context.Background(), delivery("tls://wrong.example:6514", fmt.Sprintf(`{"ca_pem":%q}`, ca), "synapse", oneRecord()))
		if err != nil || !result.Items[0].Blocked || result.Items[0].Retryable {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("TLS 1.1", func(t *testing.T) {
		listener, origin, ca := tlsListener(t, tls.VersionTLS11, tls.VersionTLS11)
		go acceptAndHandshake(listener)
		result, err := testClient(listener.Addr().String()).Deliver(context.Background(), delivery(origin, fmt.Sprintf(`{"ca_pem":%q}`, ca), "synapse", oneRecord()))
		if err != nil || !result.Items[0].Retryable {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	for _, secret := range []string{`not-json-secret`, `{"client_cert_pem":"secret-cert"}`, `{"client_key_pem":"secret-key"}`, `{"ca_pem":"secret-ca"}`} {
		result, err := testClient("unused").Deliver(context.Background(), delivery("tls://localhost:6514", secret, "synapse", oneRecord()))
		if err != nil || !result.Items[0].Blocked || strings.Contains(fmt.Sprint(result, err), secret) || strings.Contains(fmt.Sprint(result, err), "secret-") {
			t.Fatalf("secret=%q result=%+v err=%v", secret, result, err)
		}
	}
}

func TestBlockedDestinationIsNotRetried(t *testing.T) {
	client := &Client{
		dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, fmt.Errorf("policy: %w", safehttp.ErrBlockedDestination)
		},
		now: fixedNow,
		wrapTLS: func(net.Conn, *tls.Config) connection {
			t.Fatal("TLS must not start for a blocked destination")
			return nil
		},
	}
	result, err := client.Deliver(context.Background(), delivery("tls://syslog.example:6514", `{}`, "synapse", oneRecord()))
	if err != nil || !result.Items[0].Blocked || result.Items[0].Retryable {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if errors.Is(err, safehttp.ErrBlockedDestination) {
		t.Fatal("policy detail escaped the driver")
	}
}

func TestDeliverRejectsHeaderInjectionAndSanitizesRecordID(t *testing.T) {
	result, err := testClient("unused").Deliver(context.Background(), delivery("tls://localhost:6514", `{}`, "bad\r\napp", oneRecord()))
	if err != nil || !result.Items[0].Blocked {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	listener, origin, ca := tlsListener(t, tls.VersionTLS12, tls.VersionTLS13)
	frames := make(chan string, 1)
	go readFrames(listener, frames)
	records := []siem.DeliveryRecord{{ID: strings.Repeat("x", 200) + "\r\n", Body: []byte(`{}`)}}
	result, err = testClient(listener.Addr().String()).Deliver(context.Background(), delivery(origin, fmt.Sprintf(`{"ca_pem":%q}`, ca), "synapse", records))
	if err != nil || result.Items[0].Disposition != siem.ItemAcked {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	message := <-frames
	if strings.ContainsAny(message, "\r\n") || !strings.Contains(message, messageID(records[0].ID)) {
		t.Fatalf("unsafe message = %q", message)
	}
}

func TestMessageIDDoesNotCollideOnLongCommonPrefix(t *testing.T) {
	prefix := strings.Repeat("same-prefix-", 8)
	left, right := messageID(prefix+"left"), messageID(prefix+"right")
	if left == right || len(left) != 32 || len(right) != 32 {
		t.Fatalf("message IDs = %q, %q", left, right)
	}
}

func TestCompletedFramesOnlyAreAcknowledged(t *testing.T) {
	conn := &failingConn{writesLeft: 1}
	client := &Client{dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }, now: fixedNow}
	// The test connection is already post-handshake; exercise the framing/write boundary directly.
	client.wrapTLS = func(net.Conn, *tls.Config) connection { return conn }
	result, err := client.Deliver(context.Background(), delivery("tls://syslog.example:6514", `{}`, "synapse", []siem.DeliveryRecord{{ID: "1", Body: []byte(`{}`)}, {ID: "2", Body: []byte(`{}`)}}))
	if err != nil || result.Items[0].Disposition != siem.ItemAcked || !result.Items[1].Retryable {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func testClient(address string) *Client {
	return &Client{
		dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
		now:     fixedNow,
		wrapTLS: func(conn net.Conn, cfg *tls.Config) connection { return tls.Client(conn, cfg) },
	}
}

func fixedNow() time.Time { return time.Date(2025, 1, 2, 3, 4, 5, 0, time.FixedZone("test", 7*3600)) }

func delivery(origin, secret, target string, records []siem.DeliveryRecord) siem.Delivery {
	return siem.Delivery{Origin: origin, Secret: secret, Target: target, AckMode: siem.AckTransportWrite, Records: records}
}

func oneRecord() []siem.DeliveryRecord {
	return []siem.DeliveryRecord{{ID: "rec-1", Body: []byte(`{}`)}}
}

func tlsListener(t *testing.T, min, max uint16) (net.Listener, string, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	cert := server.TLS.Certificates[0]
	leaf := server.Certificate()
	server.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: min, MaxVersion: max})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	return listener, "tls://example.com:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), ca
}

func readFrames(listener net.Listener, out chan<- string) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for i := 0; i < cap(out); i++ {
		sizeText, err := reader.ReadString(' ')
		if err != nil {
			return
		}
		size, err := strconv.Atoi(strings.TrimSpace(sizeText))
		if err != nil {
			return
		}
		payload := make([]byte, size)
		if _, err = io.ReadFull(reader, payload); err != nil {
			return
		}
		out <- string(payload)
	}
}

func acceptAndHandshake(listener net.Listener) {
	conn, err := listener.Accept()
	if err == nil {
		if tlsConn, ok := conn.(*tls.Conn); ok {
			_ = tlsConn.Handshake()
		}
		_ = conn.Close()
	}
}

type failingConn struct{ writesLeft int }

func (c *failingConn) Write(p []byte) (int, error) {
	if c.writesLeft == 0 {
		return 0, io.ErrClosedPipe
	}
	c.writesLeft--
	return len(p), nil
}
func (*failingConn) Read([]byte) (int, error)               { return 0, io.EOF }
func (*failingConn) Close() error                           { return nil }
func (*failingConn) LocalAddr() net.Addr                    { return dummyAddr("local") }
func (*failingConn) RemoteAddr() net.Addr                   { return dummyAddr("remote") }
func (*failingConn) SetDeadline(time.Time) error            { return nil }
func (*failingConn) SetReadDeadline(time.Time) error        { return nil }
func (*failingConn) SetWriteDeadline(time.Time) error       { return nil }
func (*failingConn) HandshakeContext(context.Context) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
