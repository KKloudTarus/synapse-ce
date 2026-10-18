package syslog

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
)

// rfc5424Frame is the grammar this driver has to produce, transcribed from RFC 5424 section 6 and
// RFC 5425 section 4.3:
//
//	SYSLOG-MSG  = HEADER SP STRUCTURED-DATA [SP MSG]
//	HEADER      = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
//	TIMESTAMP   = NILVALUE / FULL-DATE "T" FULL-TIME
//	TIME-SECFRAC= "." 1*6DIGIT
//	MSGID       = NILVALUE / 1*32PRINTUSASCII
//	frame       = MSG-LEN SP SYSLOG-MSG
//
// The fraction is capped at six digits, which is the part time.RFC3339Nano gets wrong.
var rfc5424Frame = regexp.MustCompile(`^(\d+) <(\d{1,3})>(\d) (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})) (\S+) (\S+) (\S+) (\S+) (-|\[.*\]) \x{feff}(.*)$`)

// parseFrame splits one octet-counted frame into its RFC 5424 fields and fails the test when the
// frame does not match the grammar above.
func parseFrame(t *testing.T, raw string) (length int, pri, version, timestamp, host, app, procID, msgID, structured, message string) {
	t.Helper()
	groups := rfc5424Frame.FindStringSubmatch(raw)
	if groups == nil {
		t.Fatalf("frame does not match the RFC 5424 grammar: %q", raw)
	}
	length, err := strconv.Atoi(groups[1])
	if err != nil {
		t.Fatalf("frame length %q: %v", groups[1], err)
	}
	return length, groups[2], groups[3], groups[4], groups[5], groups[6], groups[7], groups[8], groups[9], groups[10]
}

// TestFrameMatchesRFC5424 drives a delivery and checks every header field of the frame that
// reaches the wire, including the octet count that RFC 5425 framing depends on.
func TestFrameMatchesRFC5424(t *testing.T) {
	listener, origin, ca := tlsListener(t, tls.VersionTLS12, tls.VersionTLS13)
	frames := make(chan string, 1)
	go readRawFrames(listener, frames)
	client := testClient(listener.Addr().String())

	body := `{"action":"user.login","tenant_id":"tenant-a"}`
	record := siem.DeliveryRecord{ID: "siem:tenant-a:audit:4711", Body: []byte(body)}
	result, err := client.Deliver(context.Background(), delivery(origin, fmt.Sprintf(`{"ca_pem":%q}`, ca), "synapse", []siem.DeliveryRecord{record}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Items[0].Disposition != siem.ItemAcked {
		t.Fatalf("item = %+v", result.Items[0])
	}

	raw := <-frames
	length, pri, version, timestamp, host, app, procID, msgID, structured, message := parseFrame(t, raw)

	// RFC 5425: the count is the octet length of the message that follows the space.
	payload := raw[strings.Index(raw, " ")+1:]
	if length != len(payload) {
		t.Errorf("frame length = %d, want %d octets", length, len(payload))
	}
	// Facility 16 (local0) times eight plus severity 6 (informational).
	if pri != "134" {
		t.Errorf("PRI = %s, want 134", pri)
	}
	if version != "1" {
		t.Errorf("VERSION = %s, want 1", version)
	}
	if host != "-" || procID != "-" || structured != "-" {
		t.Errorf("HOSTNAME/PROCID/STRUCTURED-DATA = %q/%q/%q, want the nil value in each", host, procID, structured)
	}
	if app != "synapse" {
		t.Errorf("APP-NAME = %q, want the sink target", app)
	}
	if msgID != messageID(record.ID) || len(msgID) > 32 {
		t.Errorf("MSGID = %q (%d chars), want the record digest within 32 characters", msgID, len(msgID))
	}
	for _, r := range msgID {
		if r < 33 || r > 126 {
			t.Errorf("MSGID carries a character outside PRINTUSASCII: %q", msgID)
			break
		}
	}
	if message != body {
		t.Errorf("MSG = %q, want the record body after the BOM", message)
	}
	if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
		t.Errorf("TIMESTAMP %q is not RFC 3339: %v", timestamp, err)
	}
}

// TestTimestampFractionStaysWithinSixDigits is the RFC 5424 bound on TIME-SECFRAC. A clock with
// nanosecond resolution, which time.Now has on Linux, used to produce nine digits here.
func TestTimestampFractionStaysWithinSixDigits(t *testing.T) {
	for _, tc := range []struct {
		name string
		ns   int
		want string
	}{
		{name: "no fraction", ns: 0, want: "2026-10-18T13:45:01Z"},
		{name: "microseconds are kept", ns: 123_456_000, want: "2026-10-18T13:45:01.123456Z"},
		{name: "nanoseconds are truncated", ns: 123_456_789, want: "2026-10-18T13:45:01.123456Z"},
		{name: "the largest fraction is truncated", ns: 999_999_999, want: "2026-10-18T13:45:01.999999Z"},
		{name: "a sub-microsecond fraction is dropped", ns: 1, want: "2026-10-18T13:45:01Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stamp := time.Date(2026, 10, 18, 13, 45, 1, tc.ns, time.UTC)
			built, err := frame(stamp, "synapse", siem.DeliveryRecord{ID: "rec-1", Body: []byte(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, timestamp, _, _, _, _, _, _ := parseFrame(t, string(built))
			if timestamp != tc.want {
				t.Errorf("TIMESTAMP = %q, want %q", timestamp, tc.want)
			}
			if fraction := strings.SplitN(timestamp, ".", 2); len(fraction) == 2 {
				digits := strings.TrimSuffix(fraction[1], "Z")
				if len(digits) > 6 {
					t.Errorf("TIME-SECFRAC has %d digits, RFC 5424 allows at most six: %q", len(digits), timestamp)
				}
			}
		})
	}
}

// TestFrameRefusesInputItCannotEncode pins the records the driver will not put on the wire. A
// frame that lies about its own length or splits into two messages is worse than a dropped record.
func TestFrameRefusesInputItCannotEncode(t *testing.T) {
	for _, tc := range []struct{ name, id, body string }{
		{name: "a body that is not json", id: "rec-1", body: `not json`},
		{name: "a body that is empty", id: "rec-1", body: ``},
		{name: "a body over the record cap", id: "rec-1", body: `{"x":"` + strings.Repeat("y", siem.MaxRecordBytes) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := frame(time.Unix(0, 0).UTC(), "synapse", siem.DeliveryRecord{ID: tc.id, Body: []byte(tc.body)}); err == nil {
				t.Fatalf("%s was encoded", tc.name)
			}
		})
	}

	t.Run("a multi-line body cannot split the frame", func(t *testing.T) {
		// A newline inside a JSON string is escaped, so this is valid JSON with a literal \n in
		// the value. Octet counting carries it, and the frame length must still be exact.
		built, err := frame(time.Unix(0, 0).UTC(), "synapse", siem.DeliveryRecord{ID: "rec-1", Body: []byte(`{"text":"first\nsecond"}`)})
		if err != nil {
			t.Fatal(err)
		}
		raw := string(built)
		length, _, _, _, _, _, _, _, _, _ := parseFrame(t, raw)
		if payload := raw[strings.Index(raw, " ")+1:]; length != len(payload) {
			t.Errorf("frame length = %d, want %d octets", length, len(payload))
		}
	})
}

// TestAppNameFollowsRFC5424 pins the APP-NAME rule: one to 48 printable US-ASCII characters. A
// name outside that set would break the receiver's parse of every following field.
func TestAppNameFollowsRFC5424(t *testing.T) {
	for _, tc := range []struct {
		name  string
		app   string
		valid bool
	}{
		{name: "a plain name", app: "synapse", valid: true},
		{name: "the longest name", app: strings.Repeat("a", 48), valid: true},
		{name: "punctuation is printable", app: "synapse-siem_1.0", valid: true},
		{name: "empty", app: ""},
		{name: "too long", app: strings.Repeat("a", 49)},
		{name: "a space", app: "synapse siem"},
		{name: "a newline", app: "synapse\nsiem"},
		{name: "a tab", app: "synapse\tsiem"},
		{name: "a control character", app: "synapse\x01"},
		{name: "delete", app: "synapse\x7f"},
		{name: "beyond ascii", app: "synapseé"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validAppName(tc.app) != tc.valid {
				t.Errorf("validAppName(%q) = %v, want %v", tc.app, !tc.valid, tc.valid)
			}
			if tc.valid {
				return
			}
			// An invalid name blocks the batch without dialing.
			client := &Client{
				dial:    func(context.Context, string, string) (net.Conn, error) { t.Fatal("dialed"); return nil, nil },
				now:     fixedNow,
				wrapTLS: func(conn net.Conn, cfg *tls.Config) connection { return tls.Client(conn, cfg) },
			}
			result, err := client.Deliver(context.Background(), delivery("tls://receiver.example:6514", `{}`, tc.app, oneRecord()))
			if err != nil {
				t.Fatal(err)
			}
			for i, item := range result.Items {
				if item.Disposition != siem.ItemFailed || !item.Blocked || item.Retryable {
					t.Errorf("item %d: %+v, want blocked and not retryable", i, item)
				}
			}
		})
	}
}

// TestCredentialShapesAreValidated pins the sealed TLS credential. The pairing rule matters: a
// certificate without its key would silently fall back to no client certificate.
func TestCredentialShapesAreValidated(t *testing.T) {
	_, _, ca := tlsListener(t, tls.VersionTLS12, tls.VersionTLS13)
	for _, tc := range []struct {
		name   string
		secret string
		valid  bool
	}{
		{name: "the system trust store", secret: `{}`, valid: true},
		{name: "a private CA", secret: fmt.Sprintf(`{"ca_pem":%q}`, ca), valid: true},
		{name: "not json", secret: `ca_pem`},
		{name: "two objects", secret: `{}{}`},
		{name: "an unknown field", secret: `{"ca_pem":"","verify":false}`},
		{name: "a CA that is not a certificate", secret: `{"ca_pem":"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"}`},
		{name: "a certificate without its key", secret: fmt.Sprintf(`{"client_cert_pem":%q}`, ca)},
		{name: "a key without its certificate", secret: `{"client_key_pem":"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"}`},
		{name: "a certificate and key that do not pair", secret: fmt.Sprintf(`{"client_cert_pem":%q,"client_key_pem":"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"}`, ca)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := credentials(tc.secret, "receiver.example")
			if (err == nil) != tc.valid {
				t.Fatalf("credentials(%s) error = %v, want valid=%v", tc.name, err, tc.valid)
			}
			if !tc.valid {
				return
			}
			config, _ := credentials(tc.secret, "receiver.example")
			if config.ServerName != "receiver.example" {
				t.Errorf("ServerName = %q, want the origin host so hostname verification applies", config.ServerName)
			}
			if config.MinVersion != tls.VersionTLS12 {
				t.Errorf("MinVersion = %x, want TLS 1.2", config.MinVersion)
			}
			if config.InsecureSkipVerify {
				t.Error("verification is disabled")
			}
		})
	}
}

// TestDeliveryIsRefusedBeforeDialing covers the inputs that must not reach a receiver at all.
func TestDeliveryIsRefusedBeforeDialing(t *testing.T) {
	refuse := func(t *testing.T, req siem.Delivery) siem.DeliveryResult {
		t.Helper()
		client := &Client{
			dial:    func(context.Context, string, string) (net.Conn, error) { t.Fatal("dialed"); return nil, nil },
			now:     fixedNow,
			wrapTLS: func(conn net.Conn, cfg *tls.Config) connection { return tls.Client(conn, cfg) },
		}
		result, err := client.Deliver(context.Background(), req)
		if err != nil {
			t.Fatalf("delivery returned an error instead of a classified batch: %v", err)
		}
		return result
	}

	for _, tc := range []struct {
		name string
		req  siem.Delivery
	}{
		{name: "another acknowledgement mode", req: siem.Delivery{
			Origin: "tls://receiver.example:6514", Secret: `{}`, Target: "synapse",
			AckMode: siem.AckHECAcceptance, Records: oneRecord(),
		}},
		{name: "an http origin", req: delivery("https://receiver.example:6514", `{}`, "synapse", oneRecord())},
		{name: "an origin without a port", req: delivery("tls://receiver.example", `{}`, "synapse", oneRecord())},
		{name: "an origin with a path", req: delivery("tls://receiver.example:6514/ingest", `{}`, "synapse", oneRecord())},
		{name: "an invalid credential", req: delivery("tls://receiver.example:6514", `{`, "synapse", oneRecord())},
		{name: "a record that cannot be framed", req: delivery("tls://receiver.example:6514", `{}`, "synapse",
			[]siem.DeliveryRecord{{ID: "rec-1", Body: []byte(`not json`)}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := refuse(t, tc.req)
			if len(result.Items) != len(tc.req.Records) {
				t.Fatalf("items = %d, want one per record", len(result.Items))
			}
			for i, item := range result.Items {
				if item.Disposition != siem.ItemFailed || !item.Blocked || item.Retryable {
					t.Errorf("item %d: %+v, want blocked and not retryable", i, item)
				}
			}
		})
	}
}

// TestUnconfiguredClientIsAnError keeps a half-wired composition root from looking like a
// destination failure.
func TestUnconfiguredClientIsAnError(t *testing.T) {
	var nilClient *Client
	if _, err := nilClient.Deliver(context.Background(), delivery("tls://receiver.example:6514", `{}`, "synapse", oneRecord())); err == nil {
		t.Error("a nil client delivered")
	}
	if _, err := (&Client{}).Deliver(context.Background(), delivery("tls://receiver.example:6514", `{}`, "synapse", oneRecord())); err == nil {
		t.Error("a client without a dialer delivered")
	}
}

// TestNewClampsTheTimeout keeps a sink from holding a worker slot for an arbitrary time.
func TestNewClampsTheTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero falls back", 0, 5 * time.Second},
		{"negative falls back", -time.Second, 5 * time.Second},
		{"too long falls back", time.Minute, 5 * time.Second},
		{"a sane value is kept", 2 * time.Second, 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := New(tc.in).duration(); got != tc.want {
				t.Errorf("New(%v) timeout = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// readRawFrames reads octet-counted frames and reports each one including its length prefix, so a
// test can assert on the framing rather than only on the message.
func readRawFrames(listener net.Listener, out chan<- string) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
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
		if _, err := readFull(reader, payload); err != nil {
			return
		}
		out <- strings.TrimSpace(sizeText) + " " + string(payload)
	}
}

func readFull(reader *bufio.Reader, payload []byte) (int, error) {
	read := 0
	for read < len(payload) {
		n, err := reader.Read(payload[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}
