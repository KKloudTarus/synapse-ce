package siemuc

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
)

// Memory is the in-process twin of the Postgres store. Lease compare-and-swap
// and the single open batch rule match the SQL constraints.
type Memory struct {
	mu          sync.Mutex
	sinks       map[string]siem.Sink
	secrets     map[string]map[int64]string
	leases      map[string]siem.Lease
	batches     map[string]storedBatch
	open        map[string]string
	checkpoints map[string]siem.Checkpoint
	audits      map[string][]storedAudit
	incidents   map[string][]siem.IncidentFact
	pendingHist map[string][]siem.IncidentFact
}

type storedBatch struct {
	batch  siem.Batch
	sealed []string
}

type storedAudit struct {
	fact siem.AuditFact
	meta map[string]string
}

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{
		sinks: map[string]siem.Sink{}, secrets: map[string]map[int64]string{},
		leases: map[string]siem.Lease{}, batches: map[string]storedBatch{},
		open: map[string]string{}, checkpoints: map[string]siem.Checkpoint{},
		audits: map[string][]storedAudit{}, incidents: map[string][]siem.IncidentFact{},
		pendingHist: map[string][]siem.IncidentFact{},
	}
}

func (m *Memory) AddAudit(tenant shared.ID, fact siem.AuditFact, meta map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenant.String()
	m.audits[key] = append(m.audits[key], storedAudit{fact: fact, meta: cloneMeta(meta)})
}

func (m *Memory) AddIncident(tenant shared.ID, fact siem.IncidentFact) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenant.String() + "\x00" + string(fact.Phase)
	m.incidents[key] = append(m.incidents[key], fact)
}

func (m *Memory) QueueHistorical(tenant shared.ID, fact siem.IncidentFact) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fact.Phase = siem.PhaseHistorical
	m.pendingHist[tenant.String()] = append(m.pendingHist[tenant.String()], fact)
}

func (m *Memory) CreateSink(ctx context.Context, sink siem.Sink, sealed string) error {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if sink.TenantID != tenant {
		return errTenant
	}
	key := idKey(tenant, sink.ID)
	if _, ok := m.sinks[key]; ok {
		return conflict("sink exists")
	}
	for _, existing := range m.sinks {
		if existing.TenantID == tenant && existing.Name == sink.Name {
			return conflict("sink name exists")
		}
	}
	m.sinks[key] = sink
	m.secrets[key] = map[int64]string{sink.SecretVersion: sealed}
	return nil
}

func (m *Memory) UpdateSink(ctx context.Context, sink siem.Sink, expected int64) error {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := idKey(tenant, sink.ID)
	current, ok := m.sinks[key]
	if !ok {
		return missing("sink")
	}
	if current.Version != expected {
		return conflict("sink version")
	}
	m.sinks[key] = sink
	return nil
}

func (m *Memory) GetSink(ctx context.Context, id shared.ID) (siem.Sink, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return siem.Sink{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sink, ok := m.sinks[idKey(tenant, id)]
	if !ok {
		return siem.Sink{}, missing("sink")
	}
	return sink, nil
}

func (m *Memory) ListSinks(ctx context.Context) ([]siem.Sink, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []siem.Sink
	for _, sink := range m.sinks {
		if sink.TenantID == tenant {
			out = append(out, sink)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) PutSecret(ctx context.Context, sinkID shared.ID, version int64, sealed string) error {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := idKey(tenant, sinkID)
	if _, ok := m.sinks[key]; !ok {
		return missing("sink")
	}
	if m.secrets[key] == nil {
		m.secrets[key] = map[int64]string{}
	}
	m.secrets[key][version] = sealed
	return nil
}

func (m *Memory) LatestSecret(ctx context.Context, sinkID shared.ID) (int64, string, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return 0, "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	versions := m.secrets[idKey(tenant, sinkID)]
	var best int64
	var sealed string
	for version, value := range versions {
		if version >= best {
			best = version
			sealed = value
		}
	}
	if best == 0 {
		return 0, "", missing("secret")
	}
	return best, sealed, nil
}

func (m *Memory) GetSecret(ctx context.Context, sinkID shared.ID, version int64) (string, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sealed, ok := m.secrets[idKey(tenant, sinkID)][version]
	if !ok {
		return "", missing("secret")
	}
	return sealed, nil
}

func (m *Memory) Claim(ctx context.Context, owner string, sink siem.Sink, source siem.Source, now time.Time, ttl time.Duration) (siem.Lease, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return siem.Lease{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := partKey(tenant, sink.ID, source)
	current := m.leases[key]
	if current.Owner == owner && now.Before(current.ExpiresAt) && current.Generation == sink.Generation {
		current.ExpiresAt = now.Add(ttl)
		m.leases[key] = current
		return current, nil
	}
	if current.Owner != "" && !siem.Claimable(current, now) {
		return siem.Lease{}, siem.ErrStaleLease
	}
	token := current.Token + 1
	lease := siem.Lease{
		SinkID: sink.ID, TenantID: tenant, Source: source, Owner: owner,
		Token: token, Generation: sink.Generation, ExpiresAt: now.Add(ttl),
	}
	if err := lease.Validate(); err != nil {
		return siem.Lease{}, err
	}
	m.leases[key] = lease
	if id, ok := m.open[key]; ok {
		stored := m.batches[id]
		if stored.batch.Generation == sink.Generation {
			stored.batch.LeaseToken = lease.Token
			m.batches[id] = stored
		}
	}
	return lease, nil
}

func (m *Memory) Release(ctx context.Context, lease siem.Lease) error {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := partKey(tenant, lease.SinkID, lease.Source)
	current, ok := m.leases[key]
	if ok && current.Token == lease.Token && current.Owner == lease.Owner {
		current.Owner = ""
		current.ExpiresAt = time.Time{}
		m.leases[key] = current
	}
	return nil
}

func (m *Memory) SaveBatch(ctx context.Context, batch siem.Batch, sealed []string) error {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return err
	}
	if batch.TenantID != tenant {
		return errTenant
	}
	if err := batch.Validate(); err != nil && batch.State != siem.BatchInvalid {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := partKey(tenant, batch.SinkID, batch.Source)
	lease, held := m.leases[key]
	sink, exists := m.sinks[idKey(tenant, batch.SinkID)]
	if !held || lease.Token != batch.LeaseToken || !exists || sink.Generation != batch.Generation {
		return siem.ErrStaleLease
	}
	if old, exists := m.batches[batch.ID.String()]; exists && !old.batch.State.Open() {
		return siem.ErrStaleLease
	}
	if batch.State.Open() {
		if id, ok := m.open[key]; ok && id != batch.ID.String() {
			return conflict("open batch")
		}
		m.open[key] = batch.ID.String()
	} else if m.open[key] == batch.ID.String() {
		delete(m.open, key)
	}
	copied := append([]string(nil), sealed...)
	m.batches[batch.ID.String()] = storedBatch{batch: batch, sealed: copied}
	return nil
}

func (m *Memory) OpenBatch(ctx context.Context, sinkID shared.ID, source siem.Source) (siem.Batch, []string, bool, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return siem.Batch{}, nil, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.open[partKey(tenant, sinkID, source)]
	if !ok {
		return siem.Batch{}, nil, false, nil
	}
	stored, ok := m.batches[id]
	if !ok || !stored.batch.State.Open() {
		return siem.Batch{}, nil, false, nil
	}
	return stored.batch, append([]string(nil), stored.sealed...), true, nil
}

func (m *Memory) Checkpoint(ctx context.Context, sinkID shared.ID, source siem.Source) (siem.Checkpoint, bool, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return siem.Checkpoint{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp, ok := m.checkpoints[partKey(tenant, sinkID, source)]
	return cp, ok, nil
}

func (m *Memory) Commit(ctx context.Context, lease siem.Lease, batch siem.Batch, checkpoint siem.Checkpoint, now time.Time) error {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	held, ok := m.leases[partKey(tenant, lease.SinkID, lease.Source)]
	if !ok {
		return siem.ErrStaleLease
	}
	if err := held.Holds(lease.Owner, lease.Token, lease.Generation, now); err != nil {
		return err
	}
	if batch.LeaseToken != held.Token || batch.Generation != held.Generation {
		return siem.ErrStaleLease
	}
	currentSink, ok := m.sinks[idKey(tenant, batch.SinkID)]
	if !ok || currentSink.Generation != batch.Generation || checkpoint.Generation != batch.Generation {
		return siem.ErrStaleLease
	}
	if old, ok := m.checkpoints[partKey(tenant, batch.SinkID, batch.Source)]; ok {
		if old.Generation != batch.Generation || memoryPositionRegresses(checkpoint.Position, old.Position) {
			return siem.ErrStaleLease
		}
	}
	stored := m.batches[batch.ID.String()]
	stored.batch = batch
	m.batches[batch.ID.String()] = stored
	if batch.State.Open() {
		m.open[partKey(tenant, batch.SinkID, batch.Source)] = batch.ID.String()
	} else {
		delete(m.open, partKey(tenant, batch.SinkID, batch.Source))
	}
	if !checkpoint.Position.Zero() || checkpoint.ChainHead != "" {
		checkpoint.TenantID = tenant
		m.checkpoints[partKey(tenant, checkpoint.SinkID, checkpoint.Source)] = checkpoint
	}
	return nil
}

func memoryPositionRegresses(next, current siem.Position) bool {
	if current.Source == siem.SourceAudit {
		return next.AuditID < current.AuditID
	}
	return next.StreamSeq < current.StreamSeq
}

func (m *Memory) ResetPartition(ctx context.Context, sink siem.Sink, source siem.Source, checkpoint siem.Checkpoint) error {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := partKey(tenant, sink.ID, source)
	if lease, ok := m.leases[key]; ok {
		lease.Token++
		lease.Owner = ""
		lease.ExpiresAt = time.Time{}
		m.leases[key] = lease
	}
	if id, ok := m.open[key]; ok {
		stored := m.batches[id]
		stored.batch.State = siem.BatchInvalid
		stored.sealed = nil
		m.batches[id] = stored
		delete(m.open, key)
	}
	checkpoint.TenantID = tenant
	checkpoint.SinkID = sink.ID
	checkpoint.Source = source
	checkpoint.Generation = sink.Generation
	m.checkpoints[key] = checkpoint
	return nil
}

func (m *Memory) Prune(ctx context.Context, before time.Time) error {
	if _, err := tenantOf(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, stored := range m.batches {
		if stored.batch.State == siem.BatchAcked && stored.batch.UpdatedAt.Before(before) {
			for i := range stored.sealed {
				stored.sealed[i] = ""
			}
			m.batches[id] = stored
		}
	}
	return nil
}

func (m *Memory) AggregateBacklog(ctx context.Context) (map[siem.Source]siem.BacklogAggregate, error) {
	sinks, err := m.ListSinks(ctx)
	if err != nil {
		return nil, err
	}
	result := map[siem.Source]siem.BacklogAggregate{}
	for _, sink := range sinks {
		if !sink.Enabled {
			continue
		}
		for _, source := range partitions() {
			cp, _, err := m.Checkpoint(ctx, sink.ID, source)
			if err != nil {
				return nil, err
			}
			var count int
			var oldest int64
			if source == siem.SourceAudit {
				count, oldest, err = m.CountAudit(ctx, cp.Position.AuditID)
			} else {
				phase := siem.PhaseLive
				if source == siem.SourceIncidentHistorical {
					phase = siem.PhaseHistorical
				}
				count, oldest, err = m.CountIncident(ctx, phase, cp.Position.StreamSeq)
			}
			if err != nil {
				return nil, err
			}
			value := result[source]
			value.Records += count
			if oldest > 0 && (value.OldestUnixMicro == 0 || oldest < value.OldestUnixMicro) {
				value.OldestUnixMicro = oldest
			}
			result[source] = value
		}
	}
	return result, nil
}

func (m *Memory) ReadAudit(ctx context.Context, afterID int64, limit int) ([]siem.AuditFact, []map[string]string, siem.AuditAnchor, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return nil, nil, siem.AuditAnchor{}, err
	}
	if limit <= 0 || limit > siem.MaxBatchRecords {
		limit = siem.MaxBatchRecords
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.audits[tenant.String()]
	anchor := siem.AuditAnchor{}
	if afterID > 0 {
		for _, row := range rows {
			if row.fact.ID == afterID {
				anchor.CursorID = row.fact.ID
				anchor.CursorHash = row.fact.Hash
				anchor.CursorFound = true
			}
		}
	}
	var facts []siem.AuditFact
	var meta []map[string]string
	for _, row := range rows {
		if row.fact.ID > anchor.HeadID {
			anchor.HeadID = row.fact.ID
			anchor.HeadHash = row.fact.Hash
		}
		if row.fact.HashVersion == 1 {
			anchor.V1Present = true
			continue
		}
		if row.fact.ID <= afterID || len(facts) >= limit {
			continue
		}
		facts = append(facts, siem.AuditWithMetadata(row.fact, row.meta))
		meta = append(meta, cloneMeta(row.meta))
	}
	return facts, meta, anchor, nil
}

func (m *Memory) CountAudit(ctx context.Context, afterID int64) (int, int64, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return 0, 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	var oldest int64
	for _, row := range m.audits[tenant.String()] {
		if row.fact.HashVersion != 2 || row.fact.ID <= afterID {
			continue
		}
		count++
		if oldest == 0 || row.fact.AtUnixMicro < oldest {
			oldest = row.fact.AtUnixMicro
		}
	}
	return count, oldest, nil
}

func (m *Memory) ReadIncident(ctx context.Context, phase siem.Phase, afterSeq int64, limit int) ([]siem.IncidentFact, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > siem.MaxBatchRecords {
		limit = siem.MaxBatchRecords
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []siem.IncidentFact
	for _, fact := range m.incidents[tenant.String()+"\x00"+string(phase)] {
		if fact.StreamSeq <= afterSeq {
			continue
		}
		out = append(out, fact)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *Memory) HeadIncident(ctx context.Context, phase siem.Phase) (siem.IncidentFact, bool, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return siem.IncidentFact{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.incidents[tenant.String()+"\x00"+string(phase)]
	if len(rows) == 0 {
		return siem.IncidentFact{}, false, nil
	}
	return rows[len(rows)-1], true, nil
}

func (m *Memory) CountIncident(ctx context.Context, phase siem.Phase, afterSeq int64) (int, int64, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return 0, 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.incidents[tenant.String()+"\x00"+string(phase)]
	count := 0
	var oldest int64
	for _, row := range rows {
		if row.StreamSeq <= afterSeq {
			continue
		}
		count++
		if oldest == 0 || row.AtUnixMicro < oldest {
			oldest = row.AtUnixMicro
		}
	}
	return count, oldest, nil
}

func (m *Memory) BackfillIncidents(ctx context.Context, limit int) (int, error) {
	tenant, err := tenantOf(ctx)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pending := m.pendingHist[tenant.String()]
	if len(pending) == 0 || limit <= 0 {
		return 0, nil
	}
	if limit > len(pending) {
		limit = len(pending)
	}
	key := tenant.String() + "\x00" + string(siem.PhaseHistorical)
	existing := map[string]bool{}
	var maxSeq int64
	for _, fact := range m.incidents[key] {
		existing[fact.IncidentID+":"+itoa(fact.EventSeq)] = true
		if fact.StreamSeq > maxSeq {
			maxSeq = fact.StreamSeq
		}
	}
	written := 0
	rest := pending[:0]
	for i, fact := range pending {
		id := fact.IncidentID + ":" + itoa(fact.EventSeq)
		if i >= limit {
			rest = append(rest, fact)
			continue
		}
		if existing[id] {
			continue
		}
		maxSeq++
		fact.Phase = siem.PhaseHistorical
		fact.StreamSeq = maxSeq
		m.incidents[key] = append(m.incidents[key], fact)
		existing[id] = true
		written++
	}
	m.pendingHist[tenant.String()] = append([]siem.IncidentFact(nil), rest...)
	return written, nil
}

func (m *Memory) TenantIDs(context.Context) ([]shared.ID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[shared.ID]bool{}
	var out []shared.ID
	for _, sink := range m.sinks {
		if !seen[sink.TenantID] {
			seen[sink.TenantID] = true
			out = append(out, sink.TenantID)
		}
	}
	return out, nil
}

func tenantOf(ctx context.Context) (shared.ID, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return "", errTenant
	}
	return tenant, nil
}

func idKey(tenant, id shared.ID) string { return tenant.String() + "\x00" + id.String() }

func partKey(tenant, sink shared.ID, source siem.Source) string {
	return tenant.String() + "\x00" + sink.String() + "\x00" + string(source)
}

func cloneMeta(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
