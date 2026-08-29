package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryStore is the in-memory columnar-tier twin used inline/in dev and in tests. It upholds the same
// contract as the Postgres tier: tenant-bucketed, tiered retention (hot -> warm-at-reduced-resolution ->
// expiry), sampling recorded with the data, and sequence-gap visibility. It is reached only through
// ports.TelemetryStore.
type TelemetryStore struct {
	mu     sync.Mutex
	rows   map[shared.ID][]telemetryRow        // tenant -> rows
	losses map[shared.ID][]ports.TelemetryLoss // tenant -> first-class loss records (A0.6)
	hot    time.Duration
	warm   time.Duration
}

type telemetryRow struct {
	host, asset, agent shared.ID
	class              detection.Class
	seq                uint64
	idx                int // event index within its batch, for idempotency + deterministic downsample
	sampleRate         int
	event              detection.Event
	warm               bool
}

var _ ports.TelemetryStore = (*TelemetryStore)(nil)

// NewTelemetryStore constructs the store with the hot/warm tier boundaries (the config in ADR 0001).
func NewTelemetryStore(hot, warm time.Duration) *TelemetryStore {
	return &TelemetryStore{rows: map[shared.ID][]telemetryRow{}, losses: map[shared.ID][]ports.TelemetryLoss{}, hot: hot, warm: warm}
}

// RecordLoss persists a Truncated/Dropped loss record for the ctx tenant, idempotent on
// (host, class, seq, disposition) so a re-ingest of the same over-budget batch records one loss.
func normalizeTelemetryLoss(loss ports.TelemetryLoss) ports.TelemetryLoss {
	loss.FromAt = loss.FromAt.UTC().Truncate(time.Microsecond)
	loss.ToAt = loss.ToAt.UTC().Truncate(time.Microsecond)
	return loss
}

func sameTelemetryLoss(a, b ports.TelemetryLoss) bool {
	a = normalizeTelemetryLoss(a)
	b = normalizeTelemetryLoss(b)
	return a.HostID == b.HostID &&
		a.AssetID == b.AssetID &&
		a.Class == b.Class &&
		a.Sequence == b.Sequence &&
		a.Disposition == b.Disposition &&
		a.ObservedCount == b.ObservedCount &&
		a.KeptCount == b.KeptCount &&
		a.DroppedCount == b.DroppedCount &&
		a.Reason == b.Reason &&
		a.FromAt.Equal(b.FromAt) &&
		a.ToAt.Equal(b.ToAt)
}

func (s *TelemetryStore) RecordLoss(ctx context.Context, loss ports.TelemetryLoss) error {
	if err := loss.Validate(); err != nil {
		return err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	loss = normalizeTelemetryLoss(loss)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.losses[tenant] {
		if existing.HostID != loss.HostID || existing.Class != loss.Class || existing.Sequence != loss.Sequence || existing.Disposition != loss.Disposition {
			continue
		}
		if sameTelemetryLoss(existing, loss) {
			return nil
		}
		return fmt.Errorf("%w: telemetry loss identity is already committed to different immutable facts", shared.ErrConflict)
	}
	s.losses[tenant] = append(s.losses[tenant], loss)
	return nil
}

// Ingest appends the batch's events, idempotent on (host, class, seq, event index). The bucket is the
// AUTHENTICATED ctx tenant (fail-closed), never the wire batch's self-declared tenant.
func (s *TelemetryStore) Ingest(ctx context.Context, batch ports.TelemetryBatch) error {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := make(map[string]struct{}, len(s.rows[tenant]))
	for _, r := range s.rows[tenant] {
		existing[rowKey(r.host, r.class, r.seq, r.idx)] = struct{}{}
	}
	for i, ev := range batch.Events {
		if _, dup := existing[rowKey(batch.HostID, batch.Class, batch.Sequence, i)]; dup {
			continue
		}
		s.rows[tenant] = append(s.rows[tenant], telemetryRow{
			host: batch.HostID, asset: batch.AssetID, agent: batch.AgentID, class: batch.Class,
			seq: batch.Sequence, idx: i, sampleRate: batch.SampleRate, event: ev,
		})
	}
	return nil
}

// LastSequence returns the highest sequence stored for a (host, class) in the ctx tenant.
func (s *TelemetryStore) LastSequence(ctx context.Context, hostID shared.ID, class detection.Class) (uint64, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var last uint64
	for _, r := range s.rows[tenant] {
		if r.host == hostID && r.class == class && r.seq > last {
			last = r.seq
		}
	}
	return last, nil
}

// Query runs a retro-hunt over the window and reports completeness honestly.
func (s *TelemetryStore) Query(ctx context.Context, q ports.HuntQuery) (ports.HuntResult, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.HuntResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var res ports.HuntResult
	res.MaxSampleRate = 1
	seqsByHostClass := map[string]map[uint64]struct{}{}
	for _, r := range s.rows[tenant] {
		if !matchesQuery(r, q) {
			continue
		}
		res.Events = append(res.Events, r.event)
		if r.sampleRate > 1 {
			res.Sampled = true
			if r.sampleRate > res.MaxSampleRate {
				res.MaxSampleRate = r.sampleRate
			}
		}
		k := r.host.String() + "\x00" + string(r.class)
		if seqsByHostClass[k] == nil {
			seqsByHostClass[k] = map[uint64]struct{}{}
		}
		seqsByHostClass[k][r.seq] = struct{}{}
	}
	res.SequenceGaps = detectSeqGaps(seqsByHostClass)
	// First-class losses intersecting the window (by host/asset/class/time, like the events). Any loss
	// makes the window incomplete — including on an asset pivot, since losses carry an AssetID.
	for _, l := range s.losses[tenant] {
		if matchesLossQuery(l, q) {
			res.Losses = append(res.Losses, l)
		}
	}
	sort.Slice(res.Losses, func(i, j int) bool { return res.Losses[i].FromAt.Before(res.Losses[j].FromAt) })
	res.Complete = !res.Sampled && len(res.SequenceGaps) == 0 && len(res.Losses) == 0
	res.RowsScanned = len(res.Events) // rows matched/returned, consistent with the Postgres twin
	sort.Slice(res.Events, func(i, j int) bool { return res.Events[i].At.Before(res.Events[j].At) })
	if q.Limit > 0 && len(res.Events) > q.Limit {
		res.Events = res.Events[:q.Limit]
	}
	return res, nil
}

// RetentionSweep down-samples the warm window (reduced resolution) and expires past-warm rows for the
// ctx tenant (tenant-scoped, matching the RLS-scoped Postgres tier).
func (s *TelemetryStore) RetentionSweep(ctx context.Context, now time.Time) (ports.SweepReport, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.SweepReport{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hotCut := now.Add(-s.hot)
	warmCut := now.Add(-s.warm)
	rep := ports.SweepReport{At: now}
	{
		rows := s.rows[tenant]
		kept := rows[:0]
		for _, r := range rows {
			switch {
			case !r.event.At.After(warmCut):
				rep.Expired++ // past the warm window -> expired
				continue
			case !r.event.At.After(hotCut):
				// Entered the warm window: reduce resolution by dropping every other event (deterministic
				// by index), and mark the survivors warm.
				if !r.warm && r.idx%2 == 1 {
					rep.WarmDownsampled++
					continue
				}
				r.warm = true
			}
			kept = append(kept, r)
		}
		s.rows[tenant] = kept
	}
	return rep, nil
}

// Footprint reports the GLOBAL store size (all tenants) — an operator spend metric, not a per-tenant
// figure — with an approximate byte estimate (the Postgres tier reports real on-disk bytes). It carries
// only counts/bytes, never tenant data, so a global scope leaks nothing.
func (s *TelemetryStore) Footprint(_ context.Context) (ports.TelemetryFootprint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var rows int64
	for _, rs := range s.rows {
		rows += int64(len(rs))
	}
	return ports.TelemetryFootprint{Rows: rows, Bytes: rows * 256}, nil
}

func matchesQuery(r telemetryRow, q ports.HuntQuery) bool {
	if q.HostID != "" && r.host != q.HostID {
		return false
	}
	if q.AssetID != "" && r.asset != q.AssetID {
		return false
	}
	if q.Class != "" && r.class != q.Class {
		return false
	}
	if !q.Since.IsZero() && r.event.At.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && r.event.At.After(q.Until) {
		return false
	}
	return true
}

// matchesLossQuery windows a loss record by the hunt's host/asset/class/time — the SAME dimensions the
// events matcher uses, so an asset-pivot hunt surfaces losses (a truncated/dropped window is never
// presented as complete on an asset pivot). Losses carry an AssetID for exactly this reason.
func matchesLossQuery(l ports.TelemetryLoss, q ports.HuntQuery) bool {
	if q.HostID != "" && l.HostID != q.HostID {
		return false
	}
	if q.AssetID != "" && l.AssetID != q.AssetID {
		return false
	}
	if q.Class != "" && l.Class != q.Class {
		return false
	}
	// Overlap, not point containment: the loss surfaces if its dropped-event span [FromAt, ToAt] intersects
	// the hunt window — so a window starting INSIDE the span still sees the loss.
	if !q.Since.IsZero() && l.ToAt.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && l.FromAt.After(q.Until) {
		return false
	}
	return true
}

func detectSeqGaps(seqsByHostClass map[string]map[uint64]struct{}) []ports.TelemetrySequenceGap {
	var gaps []ports.TelemetrySequenceGap
	for k, set := range seqsByHostClass {
		var seqs []uint64
		for s := range set {
			seqs = append(seqs, s)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		host, class := splitHostClass(k)
		for i := 1; i < len(seqs); i++ {
			if seqs[i] > seqs[i-1]+1 {
				gaps = append(gaps, ports.TelemetrySequenceGap{
					HostID: host, Class: class, Missing: seqs[i] - seqs[i-1] - 1, LastSeen: seqs[i-1], Incoming: seqs[i],
				})
			}
		}
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].LastSeen < gaps[j].LastSeen })
	return gaps
}

func rowKey(host shared.ID, class detection.Class, seq uint64, idx int) string {
	return host.String() + "\x00" + string(class) + "\x00" + fmtUint(seq) + "\x00" + fmtInt(idx)
}

func splitHostClass(k string) (shared.ID, detection.Class) {
	for i := 0; i < len(k); i++ {
		if k[i] == 0 {
			return shared.ID(k[:i]), detection.Class(k[i+1:])
		}
	}
	return shared.ID(k), ""
}

// requireTelemetryTenant binds the tenant from the authenticated context and fails closed if absent —
// matching the Postgres twin's WithContextTenant, so neither backend silently serves the default bucket.
func requireTelemetryTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: telemetry operation requires a tenant in context", shared.ErrValidation)
}

func fmtUint(u uint64) string { return fmtInt(int(u)) }
func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
