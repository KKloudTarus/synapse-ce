package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	telemetryShipMaxRecords = 256
	telemetryShipMaxBytes   = 1 << 20
	telemetryShipIdle       = 500 * time.Millisecond
	telemetryShipBackoff    = time.Second
)

type telemetryTransport interface {
	RegisterTelemetrySigningKey(context.Context, string, fleetagent.AgentSigningKey, string) error
	ShipTelemetry(context.Context, string, fleetclient.TelemetryIngestRequest) (fleetclient.TelemetryShipResponse, error)
}

type telemetryProtocolError struct{ message string }

func (e *telemetryProtocolError) Error() string { return e.message }

func closedTelemetryWorker() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func (r *runner) startTelemetryShipper(ctx context.Context, durable *spool.Spool, cred fleetclient.Credential) <-chan struct{} {
	api, ok := r.api.(telemetryTransport)
	if !ok {
		return closedTelemetryWorker()
	}
	if cred.AgentID == "" || cred.AssetID == "" {
		log.Printf("telemetry transport disabled: canonical agent/asset binding is incomplete")
		return closedTelemetryWorker()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.telemetryShipLoop(ctx, durable, api, cred)
	}()
	return done
}

func (r *runner) telemetryShipLoop(ctx context.Context, durable *spool.Spool, api telemetryTransport, cred fleetclient.Credential) {
	journal := newTelemetryBatchJournalStore(r.cfg.stateDir)
	var signer fleetclient.TelemetrySigner
	for {
		registered, err := r.ensureTelemetrySignerRegistered(ctx, api, cred, signer)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			retry, wait := telemetryRegistrationRetry(err)
			if !retry {
				log.Printf("telemetry signing-key registration rejected; transport disabled with WAL retained: %v", err)
				return
			}
			log.Printf("telemetry signing-key registration failed (will retry): %v", err)
			if !sleepContext(ctx, wait) {
				return
			}
			continue
		}
		signer = registered

		progress := false
		for _, priority := range []fleetagent.DeliveryPriority{fleetagent.PriorityP2, fleetagent.PriorityP3} {
			shipped, retryAfter, err := r.shipTelemetryPriority(ctx, durable, api, cred, signer, journal, priority)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				retry, wait := telemetryDeliveryRetry(err, retryAfter)
				if !retry {
					log.Printf("telemetry %s transport stopped with WAL retained: %v", priority, err)
					return
				}
				log.Printf("telemetry %s ship failed (will retry): %v", priority, err)
				if !sleepContext(ctx, wait) {
					return
				}
				break
			}
			progress = progress || shipped
		}
		if progress {
			continue
		}
		if !sleepContext(ctx, telemetryShipIdle) {
			return
		}
	}
}

func (r *runner) ensureTelemetrySignerRegistered(ctx context.Context, api telemetryTransport, cred fleetclient.Credential, current fleetclient.TelemetrySigner) (fleetclient.TelemetrySigner, error) {
	now := time.Now().UTC()
	if !current.NeedsRotation(now) {
		return current, nil
	}
	signer, err := r.store.EnsureTelemetrySigner(cred.AgentID, now)
	if err != nil {
		return fleetclient.TelemetrySigner{}, err
	}
	proof := fleetagent.ProveKeyPossession(signer.PrivateKey, signer.Key)
	if err := api.RegisterTelemetrySigningKey(ctx, cred.Token, signer.Key, proof); err != nil {
		return fleetclient.TelemetrySigner{}, err
	}
	return signer, nil
}

func telemetryRegistrationRetry(err error) (bool, time.Duration) {
	if err == nil || errors.Is(err, context.Canceled) {
		return false, 0
	}
	var protocol *telemetryProtocolError
	if errors.As(err, &protocol) {
		return false, 0
	}
	var status *fleetclient.HTTPStatusError
	if errors.As(err, &status) {
		if !status.Retryable() {
			return false, 0
		}
		wait := telemetryShipBackoff
		if status.RetryAfter > wait {
			wait = status.RetryAfter
		}
		return true, wait
	}
	return true, telemetryShipBackoff
}

func telemetryDeliveryRetry(err error, retryAfter time.Duration) (bool, time.Duration) {
	if err == nil || errors.Is(err, context.Canceled) {
		return false, 0
	}
	var protocol *telemetryProtocolError
	if errors.As(err, &protocol) {
		return false, 0
	}
	var status *fleetclient.HTTPStatusError
	if errors.As(err, &status) && !status.Retryable() {
		return false, 0
	}
	wait := telemetryShipBackoff
	if retryAfter > wait {
		wait = retryAfter
	}
	return true, wait
}

func (r *runner) shipTelemetryPriority(
	ctx context.Context,
	durable *spool.Spool,
	api telemetryTransport,
	cred fleetclient.Credential,
	signer fleetclient.TelemetrySigner,
	journal *telemetryBatchJournalStore,
	priority fleetagent.DeliveryPriority,
) (bool, time.Duration, error) {
	state, err := journal.Load(priority)
	if err != nil {
		return false, 0, &telemetryProtocolError{message: err.Error()}
	}
	if state.Pending != nil {
		if state.Pending.Acked {
			if err := finalizeTelemetryPendingBatch(ctx, durable, journal, &state); err != nil {
				return false, 0, err
			}
			return true, 0, nil
		}
		return sendTelemetryPendingBatch(ctx, durable, api, cred, journal, &state)
	}

	records, err := durable.PeekPriority(ctx, priority, ports.PeekSpoolRequest{
		MaxRecords: telemetryShipMaxRecords,
		MaxBytes:   telemetryShipMaxBytes,
	})
	if err != nil {
		return false, 0, err
	}
	if len(records) == 0 {
		return false, 0, nil
	}
	batchRecords, err := telemetryBatchPrefix(records)
	if err != nil {
		return false, 0, &telemetryProtocolError{message: err.Error()}
	}
	first := batchRecords[0]
	if state.Epoch == 0 || state.Epoch < first.Position.Epoch {
		state.Epoch = first.Position.Epoch
		state.LastCommitted = 0
	}
	if state.Epoch != first.Position.Epoch {
		return false, 0, &telemetryProtocolError{message: fmt.Sprintf(
			"telemetry %s journal epoch %d is ahead of oldest WAL epoch %d", priority, state.Epoch, first.Position.Epoch,
		)}
	}
	batchSequence := state.LastCommitted + 1
	request, err := buildTelemetryIngestRequest(cred, signer, batchRecords, batchSequence)
	if err != nil {
		return false, 0, &telemetryProtocolError{message: err.Error()}
	}
	state.Pending = &telemetryPendingBatch{
		Epoch:      first.Position.Epoch,
		Sequence:   batchSequence,
		WALFrom:    first.Position.Sequence,
		WALThrough: batchRecords[len(batchRecords)-1].Position.Sequence,
		Request:    request,
	}
	// Persist the exact signed request BEFORE the network send. This is the point
	// at which the batch sequence becomes issued; after it returns, every crash path
	// can retransmit the same sequence/content rather than accidentally reusing it.
	if err := journal.Save(state); err != nil {
		return false, 0, err
	}
	return sendTelemetryPendingBatch(ctx, durable, api, cred, journal, &state)
}

func sendTelemetryPendingBatch(
	ctx context.Context,
	durable *spool.Spool,
	api telemetryTransport,
	cred fleetclient.Credential,
	journal *telemetryBatchJournalStore,
	state *telemetryBatchLaneState,
) (bool, time.Duration, error) {
	pending := state.Pending
	if pending == nil || pending.Acked {
		return false, 0, &telemetryProtocolError{message: "telemetry pending batch state is inconsistent"}
	}
	resp, err := api.ShipTelemetry(ctx, cred.Token, pending.Request)
	if err != nil {
		var status *fleetclient.HTTPStatusError
		if errors.As(err, &status) && status.Retryable() {
			return false, status.RetryAfter, err
		}
		return false, 0, err
	}
	// The agent issues at most one uncommitted batch per lane and never skips a
	// batch sequence. Therefore a valid success must acknowledge exactly this
	// sequence. Treat the response as untrusted input: never convert a stale/ahead
	// ACK into deletion of unrelated WAL records.
	if resp.ACK != pending.Sequence {
		return false, 0, &telemetryProtocolError{message: fmt.Sprintf(
			"server telemetry ACK %d does not match pending batch sequence %d", resp.ACK, pending.Sequence,
		)}
	}
	pending.Acked = true
	if err := journal.Save(*state); err != nil {
		return false, 0, err
	}
	if err := finalizeTelemetryPendingBatch(ctx, durable, journal, state); err != nil {
		return false, 0, err
	}
	return true, 0, nil
}

func finalizeTelemetryPendingBatch(ctx context.Context, durable *spool.Spool, journal *telemetryBatchJournalStore, state *telemetryBatchLaneState) error {
	pending := state.Pending
	if pending == nil || !pending.Acked {
		return &telemetryProtocolError{message: "telemetry pending batch is not durably acknowledged"}
	}
	if _, err := durable.Ack(ctx, ports.SpoolACK{
		Priority: state.Priority,
		Epoch:    pending.Epoch,
		Through:  pending.WALThrough,
	}); err != nil {
		return fmt.Errorf("apply telemetry WAL ACK: %w", err)
	}
	// The WAL ACK is idempotent. Clear the pending journal only afterwards; a
	// crash between these two operations replays the local ACK on restart and is
	// therefore safe, while the opposite order could lose the only WAL mapping.
	state.LastCommitted = pending.Sequence
	state.Pending = nil
	return journal.Save(*state)
}

func telemetryBatchPrefix(records []ports.SpoolRecord) ([]ports.SpoolRecord, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("telemetry batch requires records")
	}
	first := records[0]
	if first.Kind != ports.SpoolRecordTelemetry {
		return nil, fmt.Errorf("unexpected %s record in raw telemetry lane %s", first.Kind, first.Position.Priority)
	}
	out := records[:1]
	for i := 1; i < len(records); i++ {
		previous := out[len(out)-1]
		current := records[i]
		if current.Kind != ports.SpoolRecordTelemetry ||
			current.SchemaVersion != first.SchemaVersion ||
			current.Position.Priority != first.Position.Priority ||
			current.Position.Epoch != first.Position.Epoch ||
			current.Position.Session != first.Position.Session ||
			current.Position.Boot != first.Position.Boot ||
			current.Position.Sequence != previous.Position.Sequence+1 {
			break
		}
		out = append(out, current)
	}
	return out, nil
}

const telemetryEnvelopeContentType = "application/vnd.synapse.telemetry-envelope+json;version=1"

func telemetryRecordTruncated(record ports.SpoolRecord) (bool, error) {
	if record.ContentType != telemetryEnvelopeContentType {
		return false, fmt.Errorf("telemetry record has unexpected content type %q", record.ContentType)
	}
	var envelope telemetry.TelemetryEnvelope
	if err := json.Unmarshal(record.Payload, &envelope); err != nil {
		return false, fmt.Errorf("decode telemetry envelope: %w", err)
	}
	if err := envelope.Validate(); err != nil {
		return false, fmt.Errorf("validate telemetry envelope: %w", err)
	}
	if envelope.EventID != record.EventID ||
		envelope.EventClass != record.EventClass ||
		envelope.SchemaVersion != record.SchemaVersion ||
		!envelope.ObservedAt.Equal(record.ObservedAt) {
		return false, fmt.Errorf("telemetry envelope metadata disagrees with WAL record")
	}
	return envelope.DataQuality.Has(telemetry.QualityTruncatedArgv) ||
		envelope.DataQuality.Has(telemetry.QualityTruncatedPath), nil
}

func buildTelemetryIngestRequest(
	cred fleetclient.Credential,
	signer fleetclient.TelemetrySigner,
	records []ports.SpoolRecord,
	batchSequence uint64,
) (fleetclient.TelemetryIngestRequest, error) {
	if len(records) == 0 || batchSequence == 0 {
		return fleetclient.TelemetryIngestRequest{}, fmt.Errorf("telemetry batch requires records and a positive batch sequence")
	}
	agentID := shared.ID(cred.AgentID)
	assetID := shared.ID(cred.AssetID)
	if agentID.IsZero() || assetID.IsZero() {
		return fleetclient.TelemetryIngestRequest{}, fmt.Errorf("telemetry batch requires canonical agent and asset identity")
	}
	session := fleetagent.CanonicalSessionID(agentID)
	if session == "" {
		return fleetclient.TelemetryIngestRequest{}, fmt.Errorf("telemetry batch cannot derive canonical agent session")
	}
	first := records[0]
	if first.Position.Session != session {
		return fleetclient.TelemetryIngestRequest{}, fmt.Errorf("telemetry WAL session %q is not canonical session %q", first.Position.Session, session)
	}
	streamID, err := fleetagent.TelemetryDeliveryStreamID(agentID, session, first.Position.Priority)
	if err != nil {
		return fleetclient.TelemetryIngestRequest{}, err
	}
	refs := make([]fleetagent.EventRef, 0, len(records))
	events := make([]fleetclient.TelemetryEventPayload, 0, len(records))
	minAt, maxAt := first.ObservedAt.UTC(), first.ObservedAt.UTC()
	previousSequence := first.Position.Sequence
	truncatedCount := 0
	for i, record := range records {
		if err := record.Validate(); err != nil {
			return fleetclient.TelemetryIngestRequest{}, fmt.Errorf("telemetry WAL record %d: %w", i, err)
		}
		if record.Kind != ports.SpoolRecordTelemetry ||
			record.SchemaVersion != first.SchemaVersion ||
			record.Position.Priority != first.Position.Priority ||
			record.Position.Epoch != first.Position.Epoch ||
			record.Position.Session != session ||
			record.Position.Boot != first.Position.Boot {
			return fleetclient.TelemetryIngestRequest{}, fmt.Errorf("telemetry batch records cross schema/lane/incarnation boundary")
		}
		if i > 0 && record.Position.Sequence != previousSequence+1 {
			return fleetclient.TelemetryIngestRequest{}, fmt.Errorf("telemetry batch WAL records are not contiguous")
		}
		previousSequence = record.Position.Sequence
		truncated, err := telemetryRecordTruncated(record)
		if err != nil {
			return fleetclient.TelemetryIngestRequest{}, fmt.Errorf("telemetry WAL record %d: %w", i, err)
		}
		if truncated {
			truncatedCount++
		}
		digest := fleetagent.TelemetryEventDigest(record.Payload, assetID)
		refs = append(refs, fleetagent.EventRef{ID: record.EventID, Digest: digest})
		events = append(events, fleetclient.TelemetryEventPayload{
			EventID:    record.EventID,
			Class:      record.EventClass,
			Payload:    append([]byte(nil), record.Payload...),
			ObservedAt: record.ObservedAt.UTC(),
		})
		at := record.ObservedAt.UTC()
		if at.Before(minAt) {
			minAt = at
		}
		if at.After(maxAt) {
			maxAt = at
		}
	}
	policyDigest, err := fleetagent.SamplingPolicyDigest(
		fleetagent.NoSamplingAlgorithm,
		fleetagent.NoSamplingPolicyID,
		"",
		fleetagent.NoSamplingVersion,
	)
	if err != nil {
		return fleetclient.TelemetryIngestRequest{}, err
	}
	payloadDigest := fleetagent.TelemetryPayloadDigest(refs)
	manifest := fleetagent.TelemetryBatchManifest{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		SchemaVersion:   first.SchemaVersion,
		BatchID:         telemetryBatchID(agentID, streamID, first.Position.Epoch, batchSequence, payloadDigest),
		AgentID:         agentID,
		HostID:          agentID,
		AssetID:         assetID,
		StreamID:        streamID,
		Position: fleetagent.StreamPosition{
			Priority: first.Position.Priority,
			Epoch:    first.Position.Epoch,
			Sequence: batchSequence,
			Session:  session,
			Boot:     first.Position.Boot,
		},
		PreviousSequence:     batchSequence - 1,
		EventTimeMin:         minAt,
		EventTimeMax:         maxAt,
		ObservedCount:        len(records),
		KeptCount:            len(records),
		TruncatedCount:       truncatedCount,
		SamplingPolicyDigest: policyDigest,
		Events:               refs,
		PayloadDigest:        payloadDigest,
		KeyID:                signer.Key.KeyID,
	}
	manifest.Signature = fleetagent.SignTelemetryManifest(signer.PrivateKey, manifest)
	if err := manifest.Validate(); err != nil {
		return fleetclient.TelemetryIngestRequest{}, err
	}
	return fleetclient.TelemetryIngestRequest{Manifest: manifest, Events: events}, nil
}

func telemetryBatchID(agentID, streamID shared.ID, epoch, sequence uint64, payloadDigest string) shared.ID {
	h := sha256.New()
	writeBatchIDField := func(value string) {
		_, _ = h.Write([]byte(strconv.Itoa(len(value))))
		_, _ = h.Write([]byte{':'})
		_, _ = h.Write([]byte(value))
	}
	writeBatchIDField("synapse-telemetry-batch-id:v1")
	writeBatchIDField(agentID.String())
	writeBatchIDField(streamID.String())
	writeBatchIDField(strconv.FormatUint(epoch, 10))
	writeBatchIDField(strconv.FormatUint(sequence, 10))
	writeBatchIDField(payloadDigest)
	sum := h.Sum(nil)
	return shared.ID("tb_" + hex.EncodeToString(sum[:16]))
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
