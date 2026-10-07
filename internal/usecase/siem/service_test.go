package siemuc

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/siem/ocsf"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID {
	s.n++
	return shared.ID("id-" + itoa(s.n))
}

type vaultSealer struct{ cipher *vault.Cipher }

func (v vaultSealer) Seal(_ context.Context, plaintext, aad []byte) (string, error) {
	return v.cipher.Seal(plaintext, aad)
}
func (v vaultSealer) Open(_ context.Context, ciphertext string, aad []byte) ([]byte, error) {
	return v.cipher.Open(ciphertext, aad)
}

type memAudit struct{ entries []ports.AuditEntry }

func (m *memAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	m.entries = append(m.entries, entry)
	return nil
}

type scriptDriver struct {
	mu    sync.Mutex
	calls int
	seen  [][]byte
	fn    func(call int, req siem.Delivery) (siem.DeliveryResult, error)
}

type delayedAckDriver struct {
	posts int
	polls int
}

type secretValidatingDriver struct {
	scriptDriver
}

func (d *secretValidatingDriver) ValidateSecret(secret string) error {
	if secret != "valid-provider-secret" {
		return invalid("provider secret")
	}
	return nil
}

type captureSIEMMetrics struct {
	items   map[siem.ItemDisposition]int
	backlog map[string]int
}

func (m *captureSIEMMetrics) Batch(string, string) {}
func (m *captureSIEMMetrics) Retry(string)         {}
func (m *captureSIEMMetrics) Gap(string)           {}
func (m *captureSIEMMetrics) Backlog(source string, _ float64, count int) {
	if m.backlog == nil {
		m.backlog = map[string]int{}
	}
	m.backlog[source] = count
}
func (m *captureSIEMMetrics) Blocked(string) {}
func (m *captureSIEMMetrics) Items(_ string, disposition string, n int) {
	m.items[siem.ItemDisposition(disposition)] += n
}

func TestCommittedItemMetricsSeparateDispositionsAndDoNotRecount(t *testing.T) {
	svc, store, _, _, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	sink, err := svc.Create(ctx, "ada", SinkInput{Name: "Metrics", Provider: siem.ProviderSplunk,
		Origin: "https://splunk.example:8088", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Claim(ctx, "worker", sink, siem.SourceAudit, clock.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]siem.BatchItem, 4)
	for i, disposition := range []siem.ItemDisposition{siem.ItemAcked, siem.ItemQuarantined, siem.ItemSuppressed, siem.ItemAcked} {
		items[i] = siem.BatchItem{Ordinal: i, RecordID: itoa(i + 1), Position: siem.Position{
			Source: siem.SourceAudit, AuditID: int64(i + 1), AuditHash: itoa(i + 1), HashVersion: 2},
			Disposition: disposition, PayloadDigest: "digest", DataClass: siem.ClassSignal}
	}
	batch := siem.Batch{ID: "batch-metrics", TenantID: sink.TenantID, SinkID: sink.ID, Source: siem.SourceAudit,
		Generation: sink.Generation, LeaseToken: lease.Token, State: siem.BatchAcked,
		PolicyVersion: "signal/v1", MappingVersion: "v1", Items: items, CreatedAt: clock.now, UpdatedAt: clock.now}
	metrics := &captureSIEMMetrics{items: map[siem.ItemDisposition]int{}}
	svc.SetMetrics(metrics)
	if err := svc.finish(ctx, lease, batch, sink.Provider, clock.now); err != nil {
		t.Fatal(err)
	}
	if err := svc.finish(ctx, lease, batch, sink.Provider, clock.now); err != nil {
		t.Fatal(err)
	}
	if metrics.items[siem.ItemAcked] != 2 || metrics.items[siem.ItemQuarantined] != 1 || metrics.items[siem.ItemSuppressed] != 1 {
		t.Fatalf("metrics counted cumulative prefix or wrong disposition: %+v", metrics.items)
	}
}

func TestTickPublishesBacklogForAllSources(t *testing.T) {
	svc, _, _, _, _ := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	if _, err := svc.Create(ctx, "ada", SinkInput{Name: "Metrics", Provider: siem.ProviderSplunk,
		Origin: "https://splunk.example:8088", Secret: "splunk-token"}); err != nil {
		t.Fatal(err)
	}
	metrics := &captureSIEMMetrics{items: map[siem.ItemDisposition]int{}}
	svc.SetMetrics(metrics)
	if _, err := svc.Tick(ctx, "worker", TickBudget{MaxPartitions: 3}); err != nil {
		t.Fatal(err)
	}
	for _, source := range partitions() {
		if _, found := metrics.backlog[string(source)]; !found {
			t.Fatalf("missing backlog metric for %s: %+v", source, metrics.backlog)
		}
	}
}

func TestCreateSyslogTLSDefaultsTransportContract(t *testing.T) {
	svc, _, _, _, _ := testService(t)
	sink, err := svc.Create(shared.WithTenant(context.Background(), "tenant-a"), "ada", SinkInput{
		Name: "Syslog", Provider: siem.ProviderSyslogTLS, Origin: "tls://syslog.example:6514", Secret: `{}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sink.Target != "synapse" || sink.AckMode != siem.AckTransportWrite {
		t.Fatalf("syslog defaults = target %q, ack %q", sink.Target, sink.AckMode)
	}
}

func TestSyslogTLSAllowsSystemTrustCredential(t *testing.T) {
	svc, _, _, _, _ := testService(t)
	_, err := svc.Create(shared.WithTenant(context.Background(), "tenant-a"), "ada", SinkInput{
		Name: "Syslog", Provider: siem.ProviderSyslogTLS, Origin: "tls://syslog.example:6514", Secret: `{}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(shared.WithTenant(context.Background(), "tenant-a"), "ada", SinkInput{
		Name: "Splunk", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: `{}`,
	}); err == nil {
		t.Fatal("HTTPS provider accepted an undersized credential")
	}
}

func TestTickRotatesSinksUnderPartitionBudget(t *testing.T) {
	svc, store, driver, _, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	for i := 0; i < 4; i++ {
		if _, err := svc.Create(ctx, "ada", SinkInput{Name: "Sink " + itoa(i),
			Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"}); err != nil {
			t.Fatal(err)
		}
	}
	fact := chain("ada", "user.login", "console", "", clock.now, nil)
	fact.ID = 1
	store.AddAudit("tenant-a", fact, nil)
	for i := 0; i < 4; i++ {
		if _, err := svc.Tick(ctx, "worker", TickBudget{MaxPartitions: 3}); err != nil {
			t.Fatal(err)
		}
	}
	if driver.calls != 4 {
		sinks, _ := store.ListSinks(ctx)
		for _, sink := range sinks {
			cp, ok, _ := store.Checkpoint(ctx, sink.ID, siem.SourceAudit)
			t.Logf("sink %s cursor %+v found=%v", sink.Name, cp.Position, ok)
		}
		t.Fatalf("fourth sink starved under budget: calls=%d", driver.calls)
	}
}

func TestReplayHeadUsesLastIncidentBeyondFirstPage(t *testing.T) {
	svc, store, _, _, _ := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	sink, err := svc.Create(ctx, "ada", SinkInput{Name: "Replay", Provider: siem.ProviderSplunk,
		Origin: "https://old.example", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	for seq := 1; seq <= 150; seq++ {
		store.AddIncident("tenant-a", siem.IncidentFact{Phase: siem.PhaseLive, StreamSeq: int64(seq),
			IncidentID: "incident-" + itoa(seq), EventSeq: 1, Kind: "created"})
	}
	if _, err := svc.ChangeOrigin(ctx, "ada", sink.ID, OriginInput{
		Origin: "https://new.example", Secret: "new-token", Replay: siem.ReplayHead, Version: sink.Version,
	}); err != nil {
		t.Fatal(err)
	}
	cp, found, err := store.Checkpoint(ctx, sink.ID, siem.SourceIncidentLive)
	if err != nil || !found || cp.Position.StreamSeq != 150 {
		t.Fatalf("head stopped at first page: %+v found=%v err=%v", cp, found, err)
	}
}

func (d *delayedAckDriver) Deliver(_ context.Context, _ siem.Delivery) (siem.DeliveryResult, error) {
	d.posts++
	id := int64(0)
	return siem.DeliveryResult{IndexerAckID: &id}, nil
}

func (d *delayedAckDriver) PollAck(_ context.Context, _ siem.Delivery, id int64) (bool, time.Duration, error) {
	if id != 0 {
		return false, 0, invalid("wrong receipt")
	}
	d.polls++
	return d.polls >= 3, 0, nil
}

func TestIndexerReceiptSurvivesRetryAndRestartWithoutRepost(t *testing.T) {
	svc, store, _, auditLog, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	driver := &delayedAckDriver{}
	svc.drivers[siem.ProviderSplunk] = driver
	sink, err := svc.Create(ctx, "ada", SinkInput{
		Name: "Indexer", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088",
		AckMode: siem.AckIndexer, IndexerAckSupported: true, Secret: "splunk-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	fact := chain("ada", "user.login", "console", "", clock.now, nil)
	fact.ID = 1
	store.AddAudit("tenant-a", fact, nil)
	if _, err := svc.Tick(ctx, "worker-a", TickBudget{MaxPartitions: 3}); err != nil {
		t.Fatal(err)
	}
	batch, _, found, err := store.OpenBatch(ctx, sink.ID, siem.SourceAudit)
	if err != nil || !found || batch.State != siem.BatchAwaitingAck || batch.IndexerAckID == nil || *batch.IndexerAckID != 0 {
		t.Fatalf("receipt was not persisted: %+v %v", batch, err)
	}
	for i := 1; i <= 3; i++ {
		restarted, err := NewService(store, store, store, svc.sealer,
			map[siem.Provider]ports.SIEMDriver{siem.ProviderSplunk: driver}, auditLog,
			fakeClock{now: clock.now.Add(time.Duration(i) * time.Minute)}, &seqIDs{n: 10}, testSchema(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := restarted.Tick(ctx, "worker-b", TickBudget{MaxPartitions: 3}); err != nil {
			t.Fatal(err)
		}
	}
	cp, found, err := store.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if err != nil || !found || cp.Position.AuditID != 1 || driver.posts != 1 || driver.polls != 3 {
		t.Fatalf("receipt was reposted or lost: cp=%+v found=%v posts=%d polls=%d err=%v", cp, found, driver.posts, driver.polls, err)
	}
}

func (d *scriptDriver) Deliver(_ context.Context, req siem.Delivery) (siem.DeliveryResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	for _, record := range req.Records {
		d.seen = append(d.seen, append([]byte(nil), record.Body...))
		if json.Valid(record.Body) == false {
			return siem.DeliveryResult{}, errNotJSON
		}
	}
	return d.fn(d.calls, req)
}

var errNotJSON = invalid("driver saw a non-JSON body")

func ackAll(req siem.Delivery) siem.DeliveryResult {
	items := make([]siem.DeliveryItem, len(req.Records))
	for i := range items {
		items[i].Disposition = siem.ItemAcked
	}
	return siem.DeliveryResult{Items: items}
}

func testService(t *testing.T) (*Service, *Memory, *scriptDriver, *memAudit, fakeClock) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := vault.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemory()
	driver := &scriptDriver{fn: func(_ int, req siem.Delivery) (siem.DeliveryResult, error) { return ackAll(req), nil }}
	auditLog := &memAudit{}
	clock := fakeClock{now: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	svc, err := NewService(store, store, store, vaultSealer{cipher}, map[siem.Provider]ports.SIEMDriver{siem.ProviderSplunk: driver}, auditLog, clock, &seqIDs{}, testSchema(t))
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, driver, auditLog, clock
}

func TestProviderSecretValidatorRunsOnCreateRotateAndOriginChange(t *testing.T) {
	svc, _, _, _, _ := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	driver := &secretValidatingDriver{scriptDriver: scriptDriver{fn: func(_ int, req siem.Delivery) (siem.DeliveryResult, error) {
		return ackAll(req), nil
	}}}
	svc.drivers[siem.ProviderMicrosoftSentinel] = driver

	base := SinkInput{
		Name: "Sentinel", Provider: siem.ProviderMicrosoftSentinel,
		Origin: "https://example.eastus-1.ingest.monitor.azure.com",
		Target: "dcr-0123456789abcdef0123456789abcdef/Custom-SynapseSIEM",
	}
	if _, err := svc.Create(ctx, "ada", SinkInput{
		Name: base.Name, Provider: base.Provider, Origin: base.Origin, Target: base.Target,
		Secret: "invalid-provider-secret",
	}); err == nil {
		t.Fatal("create accepted provider-invalid secret")
	}
	sink, err := svc.Create(ctx, "ada", SinkInput{
		Name: base.Name, Provider: base.Provider, Origin: base.Origin, Target: base.Target,
		Secret: "valid-provider-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RotateSecret(ctx, "ada", sink.ID, "invalid-provider-secret", sink.Version); err == nil {
		t.Fatal("rotate accepted provider-invalid secret")
	}
	if _, err := svc.ChangeOrigin(ctx, "ada", sink.ID, OriginInput{
		Origin: "https://other.eastus-1.ingest.monitor.azure.com",
		Secret: "invalid-provider-secret", Replay: siem.ReplayCursor, Version: sink.Version,
	}); err == nil {
		t.Fatal("origin change accepted provider-invalid secret")
	}
}

func TestUpdateMergesOnlyPresentFields(t *testing.T) {
	svc, _, _, _, _ := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	created, err := svc.Create(ctx, "ada", SinkInput{
		Name: "Main", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088",
		DataClass: siem.ClassSummary, AllowHosts: []string{"splunk.example"}, Secret: "splunk-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.Update(ctx, "ada", created.ID, SinkInput{Name: "Renamed", Version: created.Version})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Renamed" || updated.Origin != created.Origin || updated.Target != created.Target ||
		updated.DataClass != created.DataClass || updated.AckMode != created.AckMode ||
		len(updated.AllowHosts) != 1 || updated.AllowHosts[0] != "splunk.example" {
		t.Fatalf("rename changed omitted fields: %+v", updated)
	}
	cleared, err := svc.Update(ctx, "ada", created.ID, SinkInput{
		Version: updated.Version, AllowHostsPresent: true, AllowHosts: []string{},
	})
	if err != nil || len(cleared.AllowHosts) != 0 {
		t.Fatalf("explicit empty allowlist: %+v, %v", cleared, err)
	}
	if _, err := svc.Update(ctx, "ada", created.ID, SinkInput{
		Version: cleared.Version, Provider: siem.ProviderElasticsearch,
	}); err == nil {
		t.Fatal("provider change was silently accepted")
	}
}

func chain(actor, action, target, prev string, at time.Time, meta map[string]string) siem.AuditFact {
	if meta == nil {
		meta = map[string]string{}
	}
	hash := audit.ComputeHash(prev, actor, action, target, meta, at)
	return siem.AuditFact{
		Actor: actor, Action: action, Target: target, AtUnixMicro: at.UnixMicro(),
		Hash: hash, PreviousHash: prev, HashVersion: 2, Severity: meta["severity"],
		EngagementID: meta["engagement_id"], AdvisoryID: meta["advisory_id"], Title: meta["title"],
	}
}

func TestCreateRejectsMachineAndTickExportsWithoutAuditingTheBatch(t *testing.T) {
	svc, store, driver, auditLog, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	if _, err := svc.Create(ctx, "mcp", SinkInput{Name: "Main", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"}); err == nil {
		t.Fatal("machine principal created a sink")
	}
	sink, err := svc.Create(ctx, "ada", SinkInput{Name: "Main", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	at := clock.now
	meta := map[string]string{"severity": "high"}
	first := chain("ada", "user.login", "console", "", at, meta)
	first.ID = 4
	second := chain("ada", "user.login", "console", first.Hash, at, meta)
	second.ID = 11
	store.AddAudit("tenant-a", first, meta)
	store.AddAudit("tenant-a", second, meta)
	stats, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 4, Deadline: clock.now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Sent == 0 || driver.calls == 0 {
		t.Fatalf("stats %+v calls %d", stats, driver.calls)
	}
	body := string(driver.seen[0])
	if body == "" || contains(body, "splunk-token") {
		t.Fatalf("payload leaked or empty: %s", body)
	}
	cp, ok, err := store.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if err != nil || !ok || cp.Position.AuditID != 11 {
		t.Fatalf("checkpoint %+v ok %v err %v", cp, ok, err)
	}
	before := len(auditLog.entries)
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 4}); err != nil {
		t.Fatal(err)
	}
	if driver.calls != 1 {
		t.Fatalf("caught-up tick sent again: %d", driver.calls)
	}
	if len(auditLog.entries) != before {
		t.Fatal("export wrote an audit event")
	}
}

func TestBrokenChainDoesNotAdvanceAndPartialAckResumes(t *testing.T) {
	svc, store, driver, _, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	sink, err := svc.Create(ctx, "ada", SinkInput{Name: "Main", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	at := clock.now
	meta := map[string]string{}
	good := chain("ada", "user.login", "console", "", at, meta)
	good.ID = 1
	bad := chain("ada", "user.login", "console", good.Hash, at, meta)
	bad.ID = 2
	bad.Hash = "tampered"
	store.AddAudit("tenant-a", good, meta)
	store.AddAudit("tenant-a", bad, meta)
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	cp, ok, err := store.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if err != nil || !ok || cp.Position.AuditID != 1 {
		t.Fatalf("cursor passed the break: %+v", cp)
	}
	fresh, err := svc.Get(ctx, "ada", sink.ID)
	if err != nil || fresh.BlockedReason == "" {
		t.Fatalf("break was not blocked: %+v %v", fresh, err)
	}

	store2 := NewMemory()
	driver.calls = 0
	driver.fn = func(call int, req siem.Delivery) (siem.DeliveryResult, error) {
		if call == 1 {
			return siem.DeliveryResult{Items: []siem.DeliveryItem{
				{Disposition: siem.ItemAcked},
				{Disposition: siem.ItemFailed, Retryable: true},
				{Disposition: siem.ItemAcked},
			}}, nil
		}
		return ackAll(req), nil
	}
	cipher, _ := vault.NewCipher(bytesKey())
	svc, err = NewService(store2, store2, store2, vaultSealer{cipher}, map[siem.Provider]ports.SIEMDriver{siem.ProviderSplunk: driver}, &memAudit{}, clock, &seqIDs{}, testSchema(t))
	if err != nil {
		t.Fatal(err)
	}
	sink, err = svc.Create(ctx, "ada", SinkInput{Name: "Partial", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	var prev string
	for id := int64(1); id <= 3; id++ {
		row := chain("ada", "user.login", "console", prev, at, meta)
		row.ID = id
		prev = row.Hash
		store2.AddAudit("tenant-a", row, meta)
	}
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	cp, _, _ = store2.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if cp.Position.AuditID != 1 {
		t.Fatalf("partial cursor = %d", cp.Position.AuditID)
	}
	svc.clock = fakeClock{now: clock.now.Add(time.Minute)}
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	cp, _, _ = store2.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if cp.Position.AuditID != 3 {
		t.Fatalf("resumed cursor = %d", cp.Position.AuditID)
	}
	if driver.calls != 2 {
		t.Fatalf("calls = %d", driver.calls)
	}
}

func TestTimeoutThenSuccessIsAtLeastOnce(t *testing.T) {
	svc, store, driver, _, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	driver.fn = func(call int, req siem.Delivery) (siem.DeliveryResult, error) {
		if call == 1 {
			return siem.DeliveryResult{}, context.DeadlineExceeded
		}
		return ackAll(req), nil
	}
	sink, err := svc.Create(ctx, "ada", SinkInput{Name: "Retry", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	row := chain("ada", "user.login", "console", "", clock.now, map[string]string{})
	row.ID = 1
	store.AddAudit("tenant-a", row, map[string]string{})
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	cp, ok, _ := store.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if ok && cp.Position.AuditID != 0 {
		t.Fatalf("timeout advanced the cursor: %+v", cp)
	}
	svc.clock = fakeClock{now: clock.now.Add(time.Minute)}
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	cp, ok, _ = store.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if !ok || cp.Position.AuditID != 1 || driver.calls != 2 {
		t.Fatalf("retry cursor %+v ok %v calls %d", cp, ok, driver.calls)
	}
}

func TestTwoWorkersCannotBothCommit(t *testing.T) {
	svc, store, driver, _, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	if _, err := svc.Create(ctx, "ada", SinkInput{Name: "Race", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"}); err != nil {
		t.Fatal(err)
	}
	row := chain("ada", "user.login", "console", "", clock.now, nil)
	row.ID = 1
	store.AddAudit("tenant-a", row, map[string]string{})
	var wg sync.WaitGroup
	wg.Add(2)
	for _, worker := range []string{"siem-worker-1", "siem-worker-2"} {
		go func(worker string) {
			defer wg.Done()
			_, _ = svc.Tick(ctx, worker, TickBudget{MaxPartitions: 1})
		}(worker)
	}
	wg.Wait()
	if driver.calls != 1 {
		t.Fatalf("workers sent %d times", driver.calls)
	}
}

func bytesKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func contains(s, part string) bool {
	return len(part) > 0 && len(s) >= len(part) && (s == part || len(s) > len(part) && indexOf(s, part) >= 0)
}

func indexOf(s, part string) int {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return i
		}
	}
	return -1
}

func testSchema(t *testing.T) ports.SIEMOCSFValidator {
	t.Helper()
	schema, err := ocsf.New()
	if err != nil {
		t.Fatal(err)
	}
	return schema
}
