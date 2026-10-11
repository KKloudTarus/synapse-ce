package siem

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
)

func TestDataClassMatchesNotificationVocabulary(t *testing.T) {
	pairs := []struct {
		got  DataClass
		want notification.DataClass
	}{
		{ClassSignal, notification.DataClassSignal},
		{ClassSummary, notification.DataClassSummary},
		{ClassDetail, notification.DataClassDetail},
	}
	for _, pair := range pairs {
		got, ok := pair.got.NotificationClass()
		if !ok || got != pair.want || string(pair.got) != string(pair.want) {
			t.Fatalf("%s drifted from notification class %s", pair.got, pair.want)
		}
	}
	if _, ok := ClassNone.NotificationClass(); ok {
		t.Fatal("none is not a notification class")
	}
}

func TestParseOriginRejectsUnsafeDestinations(t *testing.T) {
	rejected := []string{
		"http://splunk.example",
		"https://user:secret@splunk.example",
		"https://splunk.example/services",
		"https://splunk.example/hec?token=1",
		"https://169.254.169.254",
		"https://127.0.0.1",
		"https://10.1.2.3",
		"https://[fd00:ec2::254]",
		"https://metadata.google.internal",
		"https://192.0.2.1:99999",
	}
	for _, raw := range rejected {
		if _, err := ParseOrigin(raw); err == nil {
			t.Fatalf("accepted unsafe origin %s", raw)
		}
	}
	origin, err := ParseOrigin("https://splunk.example:8088/")
	if err != nil {
		t.Fatal(err)
	}
	if origin.String() != "https://splunk.example:8088" {
		t.Fatalf("origin = %s", origin.String())
	}
	if err := HostAllowed(origin.Host, []string{"other.example"}); err == nil {
		t.Fatal("host outside the allowlist was accepted")
	}
	if err := HostAllowed("10.0.0.5", nil); err == nil {
		t.Fatal("private literal was accepted without an allowlist")
	}
}

func TestIndexerAckIsNotImplied(t *testing.T) {
	if AckIndexer.ValidFor(ProviderSplunk, false) {
		t.Fatal("indexer ack was accepted without an explicit capability")
	}
	if !AckHECAcceptance.ValidFor(ProviderSplunk, false) {
		t.Fatal("hec acceptance should be valid")
	}
	if AckBulkItem.ValidFor(ProviderSplunk, true) {
		t.Fatal("bulk item ack is not a splunk mode")
	}
	if !ProviderMicrosoftSentinel.Valid() || !AckIngestionAcceptance.ValidFor(ProviderMicrosoftSentinel, false) {
		t.Fatal("microsoft sentinel ingestion acceptance is not valid")
	}
	if AckHECAcceptance.ValidFor(ProviderMicrosoftSentinel, false) {
		t.Fatal("splunk acceptance is not a sentinel mode")
	}
	if !validSentinelOriginHost("example.eastus-1.ingest.monitor.azure.com") {
		t.Fatal("valid microsoft sentinel ingestion host was rejected")
	}
	for _, host := range []string{"ingest.monitor.azure.com", "monitor.azure.com", "ingest.monitor.azure.com.evil.example", "evil.example"} {
		if validSentinelOriginHost(host) {
			t.Fatalf("invalid microsoft sentinel ingestion host accepted: %s", host)
		}
	}
	sink := Sink{
		ID: "sink-sentinel", TenantID: "tenant-a", Name: "Sentinel", Provider: ProviderMicrosoftSentinel,
		Origin: "https://example.eastus-1.ingest.monitor.azure.com:8443",
		Target: "dcr-0123456789abcdef0123456789abcdef/Custom-SynapseSIEM",
		DataClass: ClassSignal, AckMode: AckIngestionAcceptance, Enabled: true,
		Generation: 1, SecretVersion: 1, Version: 1, Channel: "channel-1",
	}
	if err := sink.Validate(); err == nil {
		t.Fatal("microsoft sentinel custom HTTPS port was accepted")
	}
	sink.Origin = "https://example.eastus-1.ingest.monitor.azure.com:443"
	if err := sink.Validate(); err != nil {
		t.Fatalf("microsoft sentinel explicit HTTPS port 443 was rejected: %v", err)
	}
	if !validSentinelTarget("dcr-0123456789abcdef0123456789abcdef/Custom-SynapseSIEM") {
		t.Fatal("valid microsoft sentinel target was rejected")
	}
	for _, target := range []string{"", "dcr-short/Custom-SynapseSIEM", "dcr-0123456789abcdef0123456789abcdef/Custom-", "dcr-0123456789ABCDEF0123456789abcdef/Custom-SynapseSIEM", "dcr-0123456789abcdef0123456789abcdef/SynapseSIEM", " dcr-0123456789abcdef0123456789abcdef/Custom-SynapseSIEM ", "dcr-0123456789abcdef0123456789abcdef/a/b"} {
		if validSentinelTarget(target) {
			t.Fatalf("invalid microsoft sentinel target accepted: %s", target)
		}
	}
	if validIndex(".hidden") || validIndex("_all") || validIndex("Logs") || validIndex("a/b") {
		t.Fatal("unsafe index name accepted")
	}
	if !validIndex("synapse-siem") {
		t.Fatal("normal index rejected")
	}
}

func TestSyslogTLSContract(t *testing.T) {
	if !ProviderSyslogTLS.Valid() {
		t.Fatal("syslog TLS provider is not valid")
	}
	if !AckTransportWrite.ValidFor(ProviderSyslogTLS, false) {
		t.Fatal("syslog TLS must acknowledge a completed transport write")
	}
	if AckTransportWrite.ValidFor(ProviderSplunk, false) {
		t.Fatal("transport-write acknowledgement leaked to an HTTPS provider")
	}
	origin, err := ParseOriginFor(ProviderSyslogTLS, "tls://syslog.example:6514")
	if err != nil || origin.String() != "tls://syslog.example:6514" {
		t.Fatalf("syslog origin = %+v, %v", origin, err)
	}
	origin, err = ParseOriginFor(ProviderSyslogTLS, "tls://[2001:4860:4860::8888]:6514")
	if err != nil || origin.String() != "tls://[2001:4860:4860::8888]:6514" {
		t.Fatalf("syslog IPv6 origin = %+v, %v", origin, err)
	}
	for _, raw := range []string{"tls://syslog.example", "https://syslog.example:6514"} {
		if _, err := ParseOriginFor(ProviderSyslogTLS, raw); err == nil {
			t.Fatalf("accepted invalid syslog origin %q", raw)
		}
	}
	if _, err := ParseOriginFor(ProviderSplunk, "tls://splunk.example:8088"); err == nil {
		t.Fatal("TLS origin weakened HTTPS provider validation")
	}
	if err := validateTarget(ProviderSyslogTLS, "synapse"); err != nil {
		t.Fatalf("normal syslog app name rejected: %v", err)
	}
	if err := validateTarget(ProviderSyslogTLS, "bad app"); err == nil {
		t.Fatal("invalid syslog app name accepted")
	}
}

func TestAuditHolesAreNotGapsAndBreaksStop(t *testing.T) {
	at := time.UnixMicro(1_700_000_000_000_000).UTC()
	meta := map[string]string{"severity": "high"}
	firstHash := audit.ComputeHash("", "ada", "finding.created", "asset-1", meta, at)
	secondHash := audit.ComputeHash(firstHash, "ada", "finding.updated", "asset-1", meta, at)
	rows := []AuditFact{
		{ID: 4, Actor: "ada", Action: "finding.created", Target: "asset-1", AtUnixMicro: at.UnixMicro(), Hash: firstHash, HashVersion: 2, Severity: "high"},
		{ID: 9, Actor: "ada", Action: "finding.updated", Target: "asset-1", AtUnixMicro: at.UnixMicro(), Hash: secondHash, PreviousHash: firstHash, HashVersion: 2, Severity: "high"},
	}
	accepted, problem := VerifyAuditContent(Position{Source: SourceAudit}, rows, []map[string]string{meta, meta}, AuditAnchor{})
	if !problem.None() || len(accepted) != 2 {
		t.Fatalf("id hole was treated as a break: %+v (%d)", problem, len(accepted))
	}
	broken := append([]AuditFact(nil), rows...)
	broken[1].PreviousHash = "not-the-parent"
	accepted, problem = VerifyAuditContent(Position{Source: SourceAudit}, broken, []map[string]string{meta, meta}, AuditAnchor{})
	if problem.Kind != "broken" || len(accepted) != 1 {
		t.Fatalf("unlinked row = %+v accepted %d", problem, len(accepted))
	}
	legacy := rows[0]
	legacy.PreviousHash = "v1-head"
	_, problem = VerifyAuditContent(Position{Source: SourceAudit}, []AuditFact{legacy}, []map[string]string{meta}, AuditAnchor{})
	if problem.Kind != "broken" {
		t.Fatalf("non-genesis v2 start = %+v", problem)
	}
	cursor := Position{Source: SourceAudit, AuditID: 4, AuditHash: firstHash, HashVersion: 2}
	anchor := AuditAnchor{CursorID: 4, CursorHash: firstHash, CursorFound: true, HeadID: 4, HeadHash: firstHash}
	_, problem = VerifyAuditContent(cursor, nil, nil, anchor)
	if !problem.None() {
		t.Fatalf("caught-up cursor = %+v", problem)
	}
	anchor.CursorFound = false
	_, problem = VerifyAuditContent(cursor, nil, nil, anchor)
	if problem.Kind != "broken" {
		t.Fatalf("missing anchor = %+v", problem)
	}
}

func TestIncidentSequenceHoleIsAGap(t *testing.T) {
	rows := []IncidentFact{{StreamSeq: 1, IncidentID: "i1", EventSeq: 1}, {StreamSeq: 3, IncidentID: "i1", EventSeq: 2}}
	accepted, problem := VerifyIncidentPage(Position{Source: SourceIncidentLive}, rows)
	if problem.Kind != "gap" || len(accepted) != 1 {
		t.Fatalf("hole = %+v accepted %d", problem, len(accepted))
	}
}

func TestHandledPrefixDoesNotPassAFailure(t *testing.T) {
	items := []BatchItem{
		{Ordinal: 0, Disposition: ItemAcked, Position: Position{Source: SourceAudit, AuditID: 1, AuditHash: "a", HashVersion: 2}},
		{Ordinal: 1, Disposition: ItemFailed, Position: Position{Source: SourceAudit, AuditID: 2, AuditHash: "b", HashVersion: 2}},
		{Ordinal: 2, Disposition: ItemAcked, Position: Position{Source: SourceAudit, AuditID: 3, AuditHash: "c", HashVersion: 2}},
	}
	pos, ok := AdvancePosition(items)
	if !ok || pos.AuditID != 1 {
		t.Fatalf("cursor jumped the failure: %+v ok=%v", pos, ok)
	}
	if NextState(items, false) != BatchPartial {
		t.Fatalf("state = %s", NextState(items, false))
	}
	if NextState(items, true) != BatchBlocked {
		t.Fatal("block did not win")
	}
}

func TestEffectiveClassFailsClosed(t *testing.T) {
	class, reason, err := EffectiveClass(ClassDetail, "eng-1", EngagementCeiling{})
	if err != nil || class != ClassSignal || reason != "engagement_unknown" {
		t.Fatalf("unknown engagement = %s %s %v", class, reason, err)
	}
	class, reason, err = EffectiveClass(ClassDetail, "", EngagementCeiling{Known: true, Class: ClassDetail})
	if err != nil || class != ClassSignal || reason != "unscoped" {
		t.Fatalf("unscoped = %s %s %v", class, reason, err)
	}
	class, _, err = EffectiveClass(ClassDetail, "eng-1", EngagementCeiling{Known: true, Class: ClassNone})
	if err != nil || class != ClassNone {
		t.Fatalf("none = %s %v", class, err)
	}
	class, _, err = EffectiveClass(ClassSummary, "eng-1", EngagementCeiling{Known: true, Class: ClassDetail})
	if err != nil || class != ClassSummary {
		t.Fatalf("min = %s %v", class, err)
	}
}

func TestLeaseFenceAndRetry(t *testing.T) {
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	lease := Lease{SinkID: "s", TenantID: "t", Source: SourceAudit, Owner: "w1", Token: 3, Generation: 1, ExpiresAt: now.Add(time.Second)}
	if err := lease.Holds("w1", 3, 1, now); err != nil {
		t.Fatal(err)
	}
	if err := lease.Holds("w1", 2, 1, now); err == nil {
		t.Fatal("stale token was accepted")
	}
	if err := lease.Holds("w1", 3, 1, now.Add(time.Second)); err == nil {
		t.Fatal("expired lease was accepted")
	}
	if Claimable(lease, now) {
		t.Fatal("live lease was claimable")
	}
	if !Claimable(lease, now.Add(time.Second)) {
		t.Fatal("expired lease was not claimable")
	}
	next := RetryAt(now, 1, 2*time.Second, func() float64 { return 0 })
	if !next.Equal(now.Add(2 * time.Second)) {
		t.Fatalf("retry-after ignored: %s", next.Sub(now))
	}
	capped := RetryAt(now, 30, 0, func() float64 { return 1 })
	if capped.Sub(now) > MaxRetry {
		t.Fatalf("delay %s exceeds cap", capped.Sub(now))
	}
}

func TestSafeDiagnosticStripsSecrets(t *testing.T) {
	got := SafeDiagnostic("post https://user:token@splunk.example/services failed bearer abcdefgh token")
	if strings.Contains(got, "token@") || strings.Contains(got, "abcdefgh") || strings.Contains(got, "https://") {
		t.Fatalf("diagnostic leaked: %s", got)
	}
}
