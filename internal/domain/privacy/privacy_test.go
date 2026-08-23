package privacy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// Test fixtures are FAKE credentials assembled from parts (no secret pattern appears verbatim in source);
// they exist only to prove the scrubber removes them.
var (
	fakeAWSKey = "AKIA" + "IOSFODNN7EXAMPLE"
	fakePGPass = "p4" + "ss"
)

func pgScheme() string { return "postgres" + "://" }
func pgHost() string   { return "@" + "db:5432/app" }
func fakePGURL() string {
	return pgScheme() + "user:" + fakePGPass + pgHost()
}

func TestScrubSecretsPatterns(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		absent  string // substring that must NOT survive
		changed bool
	}{
		{"password assignment", "--config password=hunter2 --db x", "hunter2", true},
		{"env-style underscore key", "docker run -e DB_PASSWORD=hunter2 img", "hunter2", true},
		{"aws secret access key env", "aws_secret_access_key=" + "REDACTME8", "REDACTME8", true},
		{"cli flag single-token space", "mysql --password s3cr3t db", "s3cr3t", true},
		{"cli flag equals", "app --token=abc.def.ghi run", "abc.def.ghi", true},
		{"connection string", fakePGURL(), fakePGPass, true},
		{"bearer token", "curl -H Authorization: Bearer " + "tok" + "enABC123value", "tok" + "enABC123value", true},
		{"aws access key", "export AWS_ID " + fakeAWSKey, fakeAWSKey, true},
		{"clean command", "ls -la /var/log", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := scrubSecrets(tc.in)
			if changed != tc.changed {
				t.Fatalf("changed=%v want %v (got %q)", changed, tc.changed, got)
			}
			if tc.absent != "" && strings.Contains(got, tc.absent) {
				t.Fatalf("secret survived scrub: %q", got)
			}
			// Idempotent: re-scrubbing already-redacted text changes nothing.
			if again, changedAgain := scrubSecrets(got); changedAgain || again != got {
				t.Fatalf("scrub not idempotent: %q -> %q", got, again)
			}
		})
	}
}

func TestClassifyDispositions(t *testing.T) {
	p := DefaultPolicy()
	// env is dropped by default.
	if v, d := p.Classify(CategoryProcessEnv, "SECRET=1"); d != DispositionDrop || v != "" {
		t.Fatalf("env must be dropped, got %q/%s", v, d)
	}
	// an allowed arg carrying a secret is redacted.
	if v, d := p.Classify(CategoryProcessArg, "--password=hunter2"); d != DispositionRedact || strings.Contains(v, "hunter2") {
		t.Fatalf("secret arg must be redacted, got %q/%s", v, d)
	}
	// a clean arg is allowed unchanged.
	if v, d := p.Classify(CategoryProcessArg, "--verbose"); d != DispositionAllow || v != "--verbose" {
		t.Fatalf("clean arg must be allowed, got %q/%s", v, d)
	}
	// hash disposition preserves correlation without the cleartext.
	hp := DefaultPolicy()
	hp.Dispositions[CategoryProcessComm] = DispositionHash
	a, da := hp.Classify(CategoryProcessComm, "sshd")
	b, _ := hp.Classify(CategoryProcessComm, "sshd")
	c, _ := hp.Classify(CategoryProcessComm, "bash")
	if da != DispositionHash || strings.Contains(a, "sshd") || a != b || a == c {
		t.Fatalf("hash must hide value but correlate: a=%q b=%q c=%q", a, b, c)
	}
}

func TestRedactionPolicyDigestDeterministicAndDistinct(t *testing.T) {
	a := RedactionPolicyDigest(DefaultPolicy())
	b := RedactionPolicyDigest(DefaultPolicy())
	if a == "" || a != b {
		t.Fatalf("digest must be deterministic: %q vs %q", a, b)
	}
	other := DefaultPolicy()
	other.Version = "tenant-x:v2"
	if RedactionPolicyDigest(other) == a {
		t.Fatal("a different policy must have a different digest")
	}
}

func mkEnvelope(args []string, path string) telemetry.TelemetryEnvelope {
	return telemetry.TelemetryEnvelope{
		SchemaVersion: telemetry.SchemaVersion,
		EventID:       "e1", EventType: "process.exec", EventClass: detection.ClassProcess,
		AgentID: "agent-1", AgentSessionID: "sess-1", AssetID: "asset-1", BootID: "boot-1",
		StreamID: "s1", SensorID: "sensor-1", SensorVersion: "1",
		OccurredAt: time.Unix(1, 0).UTC(), ObservedAt: time.Unix(2, 0).UTC(),
		Sequence: 1,
		Event: telemetry.TelemetryEvent{
			Class: detection.ClassProcess,
			Process: &telemetry.ProcessObservation{
				Kind: "exec", PID: 100, Comm: "mysqldump", Path: path, Args: args,
			},
		},
	}
}

// TestScrubRedactsKnownSecretEndToEnd is the #611 privacy exit: a planted secret in argv must not appear
// anywhere in the scrubbed envelope (its serialized form), and the input must be left unmutated.
func TestScrubRedactsKnownSecretEndToEnd(t *testing.T) {
	secret := "hunter2" + "SuperSecret"
	in := mkEnvelope([]string{"mysqldump", "--password=" + secret, "app_db"}, "/usr/bin/mysqldump")
	out, rep, err := Scrub(in, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), secret) {
		t.Fatalf("planted secret survived into the scrubbed envelope: %s", blob)
	}
	if !rep.Changed() || rep.PolicyDigest == "" {
		t.Fatalf("report must record the redaction + policy digest: %+v", rep)
	}
	if out.RedactionPolicyDigest != rep.PolicyDigest {
		t.Fatalf("envelope must carry the policy digest")
	}
	if !out.DataQuality.Has(telemetry.QualityRedacted) {
		t.Fatal("a redacted envelope must set QualityRedacted")
	}
	// Non-mutating: the input still holds the secret.
	if !strings.Contains(in.Event.Process.Args[1], secret) {
		t.Fatal("Scrub must not mutate its input")
	}
	// The non-secret argv context is preserved (forensic value kept).
	if out.Event.Process.Args[0] != "mysqldump" || out.Event.Process.Args[2] != "app_db" {
		t.Fatalf("non-secret argv context must be preserved: %+v", out.Event.Process.Args)
	}
}

// TestRedactArgvSplitCredential covers the common form the per-element scan cannot: a credential flag and
// its value in SEPARATE argv elements (`--password`, `secret`).
func TestRedactArgvSplitCredential(t *testing.T) {
	secret := "sep" + "AratedSecret9"
	out, red, _ := DefaultPolicy().RedactArgv([]string{"mysql", "--password", secret, "-h", "db", "--token", "abc.def"})
	if red < 2 {
		t.Fatalf("both split credential values must be redacted, got %d", red)
	}
	for _, a := range out {
		if strings.Contains(a, secret) || a == "abc.def" {
			t.Fatalf("split credential value survived: %#v", out)
		}
	}
	// flags + non-credential args preserved.
	if out[0] != "mysql" || out[1] != "--password" || out[3] != "-h" || out[4] != "db" {
		t.Fatalf("non-credential argv context lost: %#v", out)
	}
}

// TestScrubRedactsSplitArgvSecretEndToEnd proves the envelope Scrub closes the split-argv form too.
func TestScrubRedactsSplitArgvSecretEndToEnd(t *testing.T) {
	secret := "spl" + "itFormSecret7"
	in := mkEnvelope([]string{"psql", "--password", secret, "mydb"}, "/usr/bin/psql")
	out, _, err := Scrub(in, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), secret) {
		t.Fatalf("split-argv secret survived: %s", blob)
	}
	if out.Event.Process.Args[1] != "--password" || out.Event.Process.Args[0] != "psql" {
		t.Fatalf("flag/context lost: %#v", out.Event.Process.Args)
	}
}

func TestScrubBoundsArgvAndPath(t *testing.T) {
	p := DefaultPolicy()
	p.MaxArgLen = 8
	p.MaxArgCount = 2
	p.MaxPathLen = 5
	in := mkEnvelope([]string{"aaaaaaaaaaaaaaaa", "b", "c", "d"}, "/very/long/path")
	out, _, err := Scrub(in, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Event.Process.Args) != 2 || !out.Event.Process.ArgsTruncated {
		t.Fatalf("argv count must be bounded + flagged: %+v", out.Event.Process.Args)
	}
	if len([]rune(out.Event.Process.Args[0])) != 8 {
		t.Fatalf("arg length must be bounded, got %q", out.Event.Process.Args[0])
	}
	if len([]rune(out.Event.Process.Path)) != 5 || !out.Event.Process.PathTruncated {
		t.Fatalf("path must be bounded + flagged, got %q", out.Event.Process.Path)
	}
	// A Scrub-introduced truncation must set BOTH honesty channels: the struct flag AND the DataQuality bit.
	if !out.DataQuality.Has(telemetry.QualityTruncatedArgv) || !out.DataQuality.Has(telemetry.QualityTruncatedPath) {
		t.Fatalf("scrub truncation must set the DataQuality bits, got %s", out.DataQuality)
	}
}

func TestScrubFilePathBoundedAndFlagged(t *testing.T) {
	p := DefaultPolicy()
	p.MaxPathLen = 4
	in := telemetry.TelemetryEnvelope{
		SchemaVersion: telemetry.SchemaVersion, EventID: "e1", EventType: "file.write",
		EventClass: detection.ClassFile, AgentID: "agent-1", AgentSessionID: "sess-1", AssetID: "asset-1",
		BootID: "boot-1", StreamID: "s1", SensorID: "sensor-1", SensorVersion: "1",
		OccurredAt: time.Unix(1, 0).UTC(), ObservedAt: time.Unix(2, 0).UTC(), Sequence: 1,
		Event: telemetry.TelemetryEvent{Class: detection.ClassFile, File: &telemetry.FileObservation{Op: "open", Path: "/etc/shadow", Device: 1, Inode: 2}},
	}
	out, _, err := Scrub(in, p)
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(out.Event.File.Path)) != 4 || !out.Event.File.PathTruncated || !out.DataQuality.Has(telemetry.QualityTruncatedPath) {
		t.Fatalf("file path truncation must set the struct flag AND the quality bit: path=%q trunc=%v q=%s", out.Event.File.Path, out.Event.File.PathTruncated, out.DataQuality)
	}
}

func TestScrubDeterministic(t *testing.T) {
	in := mkEnvelope([]string{"app", "--token=abc.def", "run"}, "/usr/bin/app")
	a, _, _ := Scrub(in, DefaultPolicy())
	b, _, _ := Scrub(in, DefaultPolicy())
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) != string(bb) {
		t.Fatal("scrub must be deterministic for a stable spool/commitment")
	}
}

func TestScrubRejectsInvalidPolicy(t *testing.T) {
	_, _, err := Scrub(mkEnvelope(nil, "/x"), Policy{})
	if err == nil {
		t.Fatal("an invalid (zero) policy must be rejected, not fail open")
	}
	if !strings.Contains(err.Error(), shared.ErrValidation.Error()) {
		t.Fatalf("want validation error, got %v", err)
	}
}
