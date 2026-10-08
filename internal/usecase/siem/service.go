package siemuc

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service manages tenant SIEM sinks and the fenced export tick.
type Service struct {
	schema       ports.SIEMOCSFValidator
	store        ports.SIEMStore
	sources      ports.SIEMSources
	directory    ports.SIEMDirectory
	sealer       ports.SIEMSealer
	drivers      map[siem.Provider]ports.SIEMDriver
	policy       ports.SIEMEngagementPolicy
	metrics      ports.SIEMMetrics
	audit        ports.AuditLogger
	transactions ports.TenantTransactionRunner
	clock        ports.Clock
	ids          ports.IDGenerator
	rng          func() float64
	publicBase   string
	turn         atomic.Uint64
}

// SinkInput is an operator write. Secret is write-only.
type SinkInput struct {
	Name                string
	NamePresent         bool
	Provider            siem.Provider
	ProviderPresent     bool
	Origin              string
	OriginPresent       bool
	Target              string
	TargetPresent       bool
	DataClass           siem.DataClass
	DataClassPresent    bool
	AckMode             siem.AckMode
	AckModePresent      bool
	IndexerAckSupported bool
	IndexerAckPresent   bool
	AllowHosts          []string
	AllowHostsPresent   bool
	Secret              string
	Version             int64
}

// OriginInput changes the destination and chooses the next cursor explicitly.
type OriginInput struct {
	Origin  string
	Secret  string
	Replay  siem.Replay
	Version int64
}

// PartitionView is the operator-visible cursor and lag for one source.
type PartitionView struct {
	Source       siem.Source `json:"source"`
	CaughtUp     bool        `json:"caught_up"`
	LagRecords   int         `json:"lag_records"`
	BacklogAgeS  float64     `json:"backlog_age_seconds"`
	Cursor       string      `json:"cursor"`
	Blocked      string      `json:"blocked,omitempty"`
	Guarantee    string      `json:"guarantee"`
	LegacyV1     bool        `json:"legacy_v1"`
	CoverageNote string      `json:"coverage_note"`
}

// Status is the sink plus its partitions. Secrets are absent.
type Status struct {
	Sink       siem.Sink       `json:"sink"`
	Partitions []PartitionView `json:"partitions"`
}

// NewService wires the export service. Drivers may be empty in tests that
// only exercise configuration; a tick then blocks that provider.
func NewService(store ports.SIEMStore, sources ports.SIEMSources, directory ports.SIEMDirectory, sealer ports.SIEMSealer, drivers map[siem.Provider]ports.SIEMDriver, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator, schema ports.SIEMOCSFValidator) (*Service, error) {
	if schema == nil || store == nil || sources == nil || directory == nil || sealer == nil || clock == nil || ids == nil {
		return nil, invalid("siem service dependencies are required")
	}
	if drivers == nil {
		drivers = map[siem.Provider]ports.SIEMDriver{}
	}
	return &Service{
		schema: schema, store: store, sources: sources, directory: directory, sealer: sealer,
		drivers: drivers, audit: audit, clock: clock, ids: ids,
		rng: func() float64 { return 0.5 }, metrics: noopMetrics{},
	}, nil
}

// SetEngagementPolicy installs the shared ceiling. Without it, engagement
// scoped records stay at signal.
func (s *Service) SetEngagementPolicy(policy ports.SIEMEngagementPolicy) { s.policy = policy }

// SetTransactions makes configuration, cursor resets, secrets and audit one
// tenant-local commit. It must be wired with the same pool as the SIEM store.
func (s *Service) SetTransactions(runner ports.TenantTransactionRunner) { s.transactions = runner }

func (s *Service) write(ctx context.Context, fn func(context.Context) (siem.Sink, error)) (siem.Sink, error) {
	if s.transactions == nil {
		return fn(ctx)
	}
	tenant, err := tenantOf(ctx)
	if err != nil {
		return siem.Sink{}, err
	}
	var result siem.Sink
	err = s.transactions.Run(ctx, tenant, func(txCtx context.Context) error {
		var callErr error
		result, callErr = fn(txCtx)
		return callErr
	})
	return result, err
}

// SetMetrics installs the operational recorder.
func (s *Service) SetMetrics(metrics ports.SIEMMetrics) {
	if metrics != nil {
		s.metrics = metrics
	}
}

// SetPublicBase stores the console origin used for deep links. An invalid
// value is rejected. An empty value omits links.
func (s *Service) SetPublicBase(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		s.publicBase = ""
		return nil
	}
	origin, err := siem.ParseOrigin(raw)
	if err != nil {
		return err
	}
	s.publicBase = origin.String()
	return nil
}

// SetRNG replaces the jitter source. Tests pass a deterministic function.
func (s *Service) SetRNG(rng func() float64) {
	if rng != nil {
		s.rng = rng
	}
}

// Create stores a sink and its first sealed secret.
func (s *Service) Create(ctx context.Context, actor string, in SinkInput) (siem.Sink, error) {
	return s.write(ctx, func(txCtx context.Context) (siem.Sink, error) { return s.create(txCtx, actor, in) })
}

func (s *Service) create(ctx context.Context, actor string, in SinkInput) (siem.Sink, error) {
	if err := s.human(actor); err != nil {
		return siem.Sink{}, err
	}
	tenant, err := tenantOf(ctx)
	if err != nil {
		return siem.Sink{}, err
	}
	sink, sealed, err := s.newSink(ctx, tenant, in)
	if err != nil {
		return siem.Sink{}, err
	}
	if err := s.store.CreateSink(ctx, sink, sealed); err != nil {
		return siem.Sink{}, err
	}
	if err := s.record(ctx, actor, "siem.sink.create", sink); err != nil {
		return siem.Sink{}, err
	}
	return sink, nil
}

// Update changes settings that keep the origin and cursor. Host changes use
// ChangeOrigin. Raising the data class is allowed for the tenant admin and
// still passes through the engagement ceiling at send time.
func (s *Service) Update(ctx context.Context, actor string, id shared.ID, in SinkInput) (siem.Sink, error) {
	return s.write(ctx, func(txCtx context.Context) (siem.Sink, error) { return s.update(txCtx, actor, id, in) })
}

func (s *Service) update(ctx context.Context, actor string, id shared.ID, in SinkInput) (siem.Sink, error) {
	if err := s.human(actor); err != nil {
		return siem.Sink{}, err
	}
	current, err := s.store.GetSink(ctx, id)
	if err != nil {
		return siem.Sink{}, err
	}
	if in.Version != current.Version {
		return siem.Sink{}, conflict("sink version")
	}
	if in.OriginPresent || in.Origin != "" {
		origin, err := siem.NormalizeOriginFor(current.Provider, in.Origin)
		if err != nil {
			return siem.Sink{}, err
		}
		if origin != current.Origin {
			return siem.Sink{}, invalid("host changes require an explicit replay choice")
		}
	}
	updated := current
	if in.ProviderPresent && in.Provider == "" {
		return siem.Sink{}, invalid("sink provider cannot be cleared")
	}
	if in.Provider != "" && in.Provider != current.Provider {
		return siem.Sink{}, invalid("sink provider cannot be changed")
	}
	if in.NamePresent || in.Name != "" {
		updated.Name = strings.TrimSpace(in.Name)
	}
	if in.TargetPresent || in.Target != "" {
		updated.Target = in.Target
	}
	if in.DataClassPresent || in.DataClass != "" {
		updated.DataClass = in.DataClass
	}
	if in.AckModePresent || in.AckMode != "" {
		updated.AckMode = in.AckMode
	}
	if in.IndexerAckPresent {
		updated.IndexerAckSupported = in.IndexerAckSupported
	}
	if in.AllowHostsPresent || in.AllowHosts != nil {
		updated.AllowHosts = append([]string{}, in.AllowHosts...)
	}
	updated.Version++
	updated.UpdatedAt = s.clock.Now().UTC()
	if err := updated.Validate(); err != nil {
		return siem.Sink{}, err
	}
	if err := s.store.UpdateSink(ctx, updated, current.Version); err != nil {
		return siem.Sink{}, err
	}
	if err := s.record(ctx, actor, "siem.sink.update", updated); err != nil {
		return siem.Sink{}, err
	}
	return updated, nil
}

// RotateSecret keeps the cursor and generation. The previous secret version
// remains sealed so an in-flight batch can still be explained, but sends use
// the latest version.
func (s *Service) RotateSecret(ctx context.Context, actor string, id shared.ID, secret string, version int64) (siem.Sink, error) {
	return s.write(ctx, func(txCtx context.Context) (siem.Sink, error) {
		return s.rotateSecret(txCtx, actor, id, secret, version)
	})
}

func (s *Service) rotateSecret(ctx context.Context, actor string, id shared.ID, secret string, version int64) (siem.Sink, error) {
	if err := s.human(actor); err != nil {
		return siem.Sink{}, err
	}
	current, err := s.store.GetSink(ctx, id)
	if err != nil {
		return siem.Sink{}, err
	}
	if err := validateSecretFor(current.Provider, secret); err != nil {
		return siem.Sink{}, err
	}
	if version != current.Version {
		return siem.Sink{}, conflict("sink version")
	}
	if err := s.validateProviderSecret(current.Provider, secret); err != nil {
		return siem.Sink{}, err
	}
	current.SecretVersion++
	current.Version++
	current.UpdatedAt = s.clock.Now().UTC()
	sealed, err := s.sealSecret(ctx, current, secret)
	if err != nil {
		return siem.Sink{}, err
	}
	if err := s.store.PutSecret(ctx, current.ID, current.SecretVersion, sealed); err != nil {
		return siem.Sink{}, err
	}
	if err := s.store.UpdateSink(ctx, current, version); err != nil {
		return siem.Sink{}, err
	}
	if err := s.record(ctx, actor, "siem.sink.rotate_secret", current); err != nil {
		return siem.Sink{}, err
	}
	return current, nil
}

// ChangeOrigin pauses the sink, invalidates prepared batches, and starts a
// new generation at the chosen cursor. The new secret is required.
func (s *Service) ChangeOrigin(ctx context.Context, actor string, id shared.ID, in OriginInput) (siem.Sink, error) {
	return s.write(ctx, func(txCtx context.Context) (siem.Sink, error) { return s.changeOrigin(txCtx, actor, id, in) })
}

func (s *Service) changeOrigin(ctx context.Context, actor string, id shared.ID, in OriginInput) (siem.Sink, error) {
	if err := s.human(actor); err != nil {
		return siem.Sink{}, err
	}
	if !in.Replay.Valid() {
		return siem.Sink{}, invalid("replay must be cursor or head")
	}
	current, err := s.store.GetSink(ctx, id)
	if err != nil {
		return siem.Sink{}, err
	}
	if err := validateSecretFor(current.Provider, in.Secret); err != nil {
		return siem.Sink{}, err
	}
	if in.Version != current.Version {
		return siem.Sink{}, conflict("sink version")
	}
	if err := s.validateProviderSecret(current.Provider, in.Secret); err != nil {
		return siem.Sink{}, err
	}
	origin, err := siem.NormalizeOriginFor(current.Provider, in.Origin)
	if err != nil {
		return siem.Sink{}, err
	}
	current.Origin = origin
	current.Generation++
	current.SecretVersion++
	current.Version++
	current.Paused = true
	current.BlockedReason = ""
	current.Channel, err = newChannel()
	if err != nil {
		return siem.Sink{}, err
	}
	current.UpdatedAt = s.clock.Now().UTC()
	if err := current.Validate(); err != nil {
		return siem.Sink{}, err
	}
	sealed, err := s.sealSecret(ctx, current, in.Secret)
	if err != nil {
		return siem.Sink{}, err
	}
	if err := s.store.PutSecret(ctx, current.ID, current.SecretVersion, sealed); err != nil {
		return siem.Sink{}, err
	}
	for _, source := range partitions() {
		cp, err := s.checkpointForReplay(ctx, current, source, in.Replay)
		if err != nil {
			return siem.Sink{}, err
		}
		if err := s.store.ResetPartition(ctx, current, source, cp); err != nil {
			return siem.Sink{}, err
		}
	}
	if err := s.store.UpdateSink(ctx, current, in.Version); err != nil {
		return siem.Sink{}, err
	}
	if err := s.record(ctx, actor, "siem.sink.change_origin", current); err != nil {
		return siem.Sink{}, err
	}
	return current, nil
}

// Pause stops new sends without moving cursors.
func (s *Service) Pause(ctx context.Context, actor string, id shared.ID, version int64) (siem.Sink, error) {
	return s.write(ctx, func(txCtx context.Context) (siem.Sink, error) {
		return s.setPaused(txCtx, actor, id, version, true, "siem.sink.pause")
	})
}

// Resume clears an operator pause and a blocked reason. A still-broken
// source chain blocks again on the next tick instead of skipping.
func (s *Service) Resume(ctx context.Context, actor string, id shared.ID, version int64) (siem.Sink, error) {
	return s.write(ctx, func(txCtx context.Context) (siem.Sink, error) {
		return s.setPaused(txCtx, actor, id, version, false, "siem.sink.resume")
	})
}

// Get returns one sink without its secret.
func (s *Service) Get(ctx context.Context, actor string, id shared.ID) (siem.Sink, error) {
	if err := s.human(actor); err != nil {
		return siem.Sink{}, err
	}
	return s.store.GetSink(ctx, id)
}

// List returns the tenant's sinks.
func (s *Service) List(ctx context.Context, actor string) ([]siem.Sink, error) {
	if err := s.human(actor); err != nil {
		return nil, err
	}
	return s.store.ListSinks(ctx)
}

// Status reports cursors, lag, and the selected guarantee. Legacy v1 audit
// rows are visible as uncovered, not as a verified prefix.
func (s *Service) Status(ctx context.Context, actor string, id shared.ID) (Status, error) {
	if err := s.human(actor); err != nil {
		return Status{}, err
	}
	sink, err := s.store.GetSink(ctx, id)
	if err != nil {
		return Status{}, err
	}
	status := Status{Sink: sink}
	for _, source := range partitions() {
		view, err := s.partitionView(ctx, sink, source)
		if err != nil {
			return Status{}, err
		}
		status.Partitions = append(status.Partitions, view)
	}
	return status, nil
}

// Test sends one synthetic record. It does not move a cursor or trust the
// remote body as configuration.
func (s *Service) Test(ctx context.Context, actor string, id shared.ID) (string, error) {
	if err := s.human(actor); err != nil {
		return "", err
	}
	sink, err := s.store.GetSink(ctx, id)
	if err != nil {
		return "", err
	}
	driver := s.drivers[sink.Provider]
	if driver == nil {
		return "", invalid("siem provider is not wired")
	}
	secret, err := s.openSecret(ctx, sink)
	if err != nil {
		return "", err
	}
	fact := siem.AuditFact{ID: 0, Action: "siem.connection_test", Severity: "info", AtUnixMicro: s.clock.Now().UTC().UnixMicro(), HashVersion: 2}
	exported := siem.ExportAudit(sink.TenantID.String(), fact, siem.ClassSignal, []string{secret}, "")
	result, err := driver.Deliver(ctx, siem.Delivery{
		Origin: sink.Origin, Secret: secret, Target: sink.Target, Channel: sink.Channel,
		AckMode: sink.AckMode, Records: []siem.DeliveryRecord{{ID: exported.RecordID, Body: exported.Body}},
	})
	if err != nil {
		return "", invalid(siem.SafeDiagnostic(err.Error()))
	}
	if result.IndexerAckID != nil {
		poller, ok := driver.(ports.SIEMAckDriver)
		if !ok {
			return "", invalid("indexer acknowledgement is not supported by the provider")
		}
		confirmed, _, pollErr := poller.PollAck(ctx, siem.Delivery{
			Origin: sink.Origin, Secret: secret, Target: sink.Target, Channel: sink.Channel,
			AckMode: sink.AckMode,
		}, *result.IndexerAckID)
		if pollErr != nil || !confirmed {
			return "", invalid("connection test indexer acknowledgement was not confirmed")
		}
		result.Items = []siem.DeliveryItem{{Disposition: siem.ItemAcked}}
	}
	if len(result.Items) != 1 || result.Items[0].Disposition != siem.ItemAcked {
		reason := "connection test was not accepted"
		if len(result.Items) == 1 {
			reason = result.Items[0].Diagnostic
		}
		return "", invalid(siem.SafeDiagnostic(reason))
	}
	if err := s.record(ctx, actor, "siem.sink.test", sink); err != nil {
		return "", err
	}
	return string(sink.AckMode), nil
}

func (s *Service) newSink(ctx context.Context, tenant shared.ID, in SinkInput) (siem.Sink, string, error) {
	provider := in.Provider
	if err := validateSecretFor(provider, in.Secret); err != nil {
		return siem.Sink{}, "", err
	}
	if err := s.validateProviderSecret(provider, in.Secret); err != nil {
		return siem.Sink{}, "", err
	}
	origin, err := siem.NormalizeOriginFor(provider, in.Origin)
	if err != nil {
		return siem.Sink{}, "", err
	}
	channel, err := newChannel()
	if err != nil {
		return siem.Sink{}, "", err
	}
	now := s.clock.Now().UTC()
	sink := siem.Sink{
		ID: s.ids.NewID(), TenantID: tenant, Name: strings.TrimSpace(in.Name), Provider: provider,
		Origin: origin, Target: defaultTarget(provider, in.Target), DataClass: defaultClass(in.DataClass),
		AckMode: defaultAck(provider, in.AckMode), IndexerAckSupported: in.IndexerAckSupported,
		AllowHosts: append([]string(nil), in.AllowHosts...), Enabled: true, Generation: 1,
		SecretVersion: 1, Version: 1, Channel: channel, CreatedAt: now, UpdatedAt: now,
	}
	if err := sink.Validate(); err != nil {
		return siem.Sink{}, "", err
	}
	sealed, err := s.sealSecret(ctx, sink, in.Secret)
	if err != nil {
		return siem.Sink{}, "", err
	}
	return sink, sealed, nil
}

func (s *Service) sealSecret(ctx context.Context, sink siem.Sink, secret string) (string, error) {
	return s.sealer.Seal(ctx, []byte(secret), secretAAD(sink))
}

func (s *Service) openSecret(ctx context.Context, sink siem.Sink) (string, error) {
	sealed, err := s.store.GetSecret(ctx, sink.ID, sink.SecretVersion)
	if err != nil {
		return "", err
	}
	plain, err := s.sealer.Open(ctx, sealed, secretAAD(sink))
	if err != nil {
		return "", invalid("stored siem secret could not be opened")
	}
	return string(plain), nil
}

func secretAAD(sink siem.Sink) []byte {
	return []byte(sink.TenantID.String() + "|" + sink.ID.String() + "|" + string(sink.Provider) + "|" + fmt.Sprintf("%d", sink.SecretVersion))
}

func (s *Service) setPaused(ctx context.Context, actor string, id shared.ID, version int64, paused bool, action string) (siem.Sink, error) {
	if err := s.human(actor); err != nil {
		return siem.Sink{}, err
	}
	sink, err := s.store.GetSink(ctx, id)
	if err != nil {
		return siem.Sink{}, err
	}
	if version != sink.Version {
		return siem.Sink{}, conflict("sink version")
	}
	sink.Paused = paused
	if !paused {
		sink.BlockedReason = ""
	}
	sink.Version++
	sink.UpdatedAt = s.clock.Now().UTC()
	if err := s.store.UpdateSink(ctx, sink, version); err != nil {
		return siem.Sink{}, err
	}
	if err := s.record(ctx, actor, action, sink); err != nil {
		return siem.Sink{}, err
	}
	return sink, nil
}

func (s *Service) checkpointForReplay(ctx context.Context, sink siem.Sink, source siem.Source, replay siem.Replay) (siem.Checkpoint, error) {
	cp := siem.Checkpoint{SinkID: sink.ID, TenantID: sink.TenantID, Source: source, Generation: sink.Generation, UpdatedAt: s.clock.Now().UTC()}
	if replay == siem.ReplayCursor {
		current, ok, err := s.store.Checkpoint(ctx, sink.ID, source)
		if err != nil {
			return siem.Checkpoint{}, err
		}
		if ok {
			cp.Position = current.Position
			cp.ChainHead = current.ChainHead
		}
		return cp, nil
	}
	switch source {
	case siem.SourceAudit:
		_, _, anchor, err := s.sources.ReadAudit(ctx, 0, 1)
		if err != nil {
			return siem.Checkpoint{}, err
		}
		if anchor.HeadID > 0 {
			cp.Position = siem.Position{Source: source, AuditID: anchor.HeadID, AuditHash: anchor.HeadHash, HashVersion: 2}
			cp.ChainHead = anchor.HeadHash
		}
	default:
		phase := siem.PhaseLive
		if source == siem.SourceIncidentHistorical {
			phase = siem.PhaseHistorical
		}
		last, found, err := s.sources.HeadIncident(ctx, phase)
		if err != nil {
			return siem.Checkpoint{}, err
		}
		if found {
			cp.Position = siem.Position{Source: source, StreamSeq: last.StreamSeq, IncidentID: last.IncidentID, EventSeq: last.EventSeq, Phase: phase}
		}
	}
	return cp, nil
}

func (s *Service) partitionView(ctx context.Context, sink siem.Sink, source siem.Source) (PartitionView, error) {
	cp, _, err := s.store.Checkpoint(ctx, sink.ID, source)
	if err != nil {
		return PartitionView{}, err
	}
	view := PartitionView{
		Source: source, Guarantee: string(sink.AckMode), Blocked: sink.BlockedReason,
		CoverageNote: "v2 tenant audit and captured incident events; legacy v1 audit is not exported",
		Cursor:       cursorText(cp.Position),
	}
	var count int
	var oldest int64
	switch source {
	case siem.SourceAudit:
		count, oldest, err = s.sources.CountAudit(ctx, cp.Position.AuditID)
		_, _, anchor, anchorErr := s.sources.ReadAudit(ctx, cp.Position.AuditID, 1)
		if anchorErr == nil {
			view.LegacyV1 = anchor.V1Present
		}
	case siem.SourceIncidentLive:
		count, oldest, err = s.sources.CountIncident(ctx, siem.PhaseLive, cp.Position.StreamSeq)
	default:
		count, oldest, err = s.sources.CountIncident(ctx, siem.PhaseHistorical, cp.Position.StreamSeq)
	}
	if err != nil {
		return PartitionView{}, err
	}
	view.LagRecords = count
	view.CaughtUp = count == 0 && sink.BlockedReason == ""
	if oldest > 0 {
		view.BacklogAgeS = s.clock.Now().Sub(time.UnixMicro(oldest)).Seconds()
		if view.BacklogAgeS < 0 {
			view.BacklogAgeS = 0
		}
	}
	return view, nil
}

func (s *Service) record(ctx context.Context, actor, action string, sink siem.Sink) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: action, Target: sink.ID.String(), At: s.clock.Now().UTC(),
		Metadata: map[string]string{
			"provider": string(sink.Provider), "origin": sink.Origin, "generation": fmt.Sprintf("%d", sink.Generation),
			"data_class": string(sink.DataClass), "ack_mode": string(sink.AckMode),
		},
	})
}

func (s *Service) human(actor string) error {
	if shared.IsMachineActor(actor) {
		return forbidden("siem settings require a human admin")
	}
	return nil
}

func (s *Service) ceiling(ctx context.Context, engagementID string) siem.EngagementCeiling {
	if s.policy == nil || engagementID == "" {
		return siem.EngagementCeiling{}
	}
	ceiling, err := s.policy.Ceiling(ctx, engagementID)
	if err != nil {
		return siem.EngagementCeiling{}
	}
	return ceiling
}

func partitions() []siem.Source {
	return []siem.Source{siem.SourceAudit, siem.SourceIncidentLive, siem.SourceIncidentHistorical}
}

func defaultClass(class siem.DataClass) siem.DataClass {
	if class == "" {
		return siem.ClassSignal
	}
	return class
}

func defaultAck(provider siem.Provider, mode siem.AckMode) siem.AckMode {
	if mode != "" {
		return mode
	}
	if provider == siem.ProviderElasticsearch {
		return siem.AckBulkItem
	}
	if provider == siem.ProviderSyslogTLS {
		return siem.AckTransportWrite
	}
	if provider == siem.ProviderMicrosoftSentinel {
		return siem.AckIngestionAcceptance
	}
	return siem.AckHECAcceptance
}

func defaultTarget(provider siem.Provider, target string) string {
	if strings.TrimSpace(target) != "" {
		return strings.TrimSpace(target)
	}
	if provider == siem.ProviderSplunk {
		return "/services/collector/event"
	}
	if provider == siem.ProviderSyslogTLS {
		return "synapse"
	}
	return target
}

func (s *Service) validateProviderSecret(provider siem.Provider, secret string) error {
	driver := s.drivers[provider]
	validator, ok := driver.(ports.SIEMSecretValidator)
	if !ok {
		return nil
	}
	if err := validator.ValidateSecret(secret); err != nil {
		return invalid("siem provider credential is invalid")
	}
	return nil
}

func validateSecretFor(provider siem.Provider, secret string) error {
	minimum := 8
	if provider == siem.ProviderSyslogTLS {
		minimum = 2 // `{}` selects the system trust store without client credentials.
	}
	if len(secret) < minimum || len(secret) > 4096 {
		return invalid("siem secret length is invalid")
	}
	if strings.ContainsAny(secret, "\r\n") {
		return invalid("siem secret must be a single line")
	}
	return nil
}

func cursorText(position siem.Position) string {
	if position.Zero() {
		return "start"
	}
	if position.Source == siem.SourceAudit {
		return fmt.Sprintf("audit:%d", position.AuditID)
	}
	return fmt.Sprintf("%s:%d", position.Phase, position.StreamSeq)
}

func newChannel() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:]), nil
}

type noopMetrics struct{}

func (noopMetrics) Batch(string, string)         {}
func (noopMetrics) Items(string, string, int)    {}
func (noopMetrics) Retry(string)                 {}
func (noopMetrics) Gap(string)                   {}
func (noopMetrics) Backlog(string, float64, int) {}
func (noopMetrics) Blocked(string)               {}
