// Command seed-fleet-detections emulates a real EDR agent end-to-end so the incident flow can be
// demonstrated with genuine (non-mock) data. It performs the ACTUAL two-phase signed protocol:
//
//	admit+activate a source-redaction policy → per host: enrol agent, report host inventory (binds the
//	agent to a server-authoritative asset), register telemetry + detection signing keys, ship a SIGNED
//	telemetry batch (so its events become durable), then ship a SIGNED detection batch whose telemetry
//	references point at those exact durable events → the detection seals → correlate folds the sealed
//	detections into an incident per asset.
//
// It reuses the production fleetclient + fleetagent/telemetry/privacy domain, so what it sends is what a
// real agent sends. Dev/seed only.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

var (
	baseURL    = flag.String("url", "http://localhost:8080", "control-plane base URL")
	engagement = flag.String("engagement", "", "engagement id the detections belong to")
	adminToken = os.Getenv("SYNAPSE_API_TOKEN")
)

// hostSpec is one emulated host: a name and the four aligned telemetry/detection scenarios it reports.
type hostSpec struct {
	name     string
	hostname string
	machine  string
}

func main() {
	flag.Parse()
	if *engagement == "" {
		fatalf("need -engagement")
	}
	if adminToken == "" {
		fatalf("need SYNAPSE_API_TOKEN in env")
	}
	ctx := context.Background()
	cli := fleetclient.New(*baseURL, 30*time.Second)

	// 1) Admit + activate the default source-redaction policy for the tenant. The telemetry a real agent
	//    ships is scrubbed under an authorized policy; the control plane refuses events whose redaction
	//    policy is not admitted for the tenant, so we establish it first.
	pol := privacy.DefaultPolicy()
	policyDigest := admitAndActivatePolicy(ctx, pol)
	fmt.Printf("policy admitted+activated digest=%s\n", policyDigest)

	// A stable-per-run suffix keeps host natural keys unique across re-runs (a host natural key is owned by
	// the agent that first reported it, so a fresh agent cannot take it over — see the takeover guard).
	run := os.Getenv("SEED_RUN")
	if run == "" {
		run = fmt.Sprintf("%d", time.Now().Unix())
	}
	hosts := []hostSpec{
		{name: "edr-web-01-" + run, hostname: "web01-" + run, machine: "mid-web-" + run},
		{name: "edr-db-01-" + run, hostname: "db01-" + run, machine: "mid-db-" + run},
		{name: "edr-worker-01-" + run, hostname: "worker01-" + run, machine: "mid-worker-" + run},
	}

	sealed := 0
	for _, h := range hosts {
		sealed += seedHost(ctx, cli, h, policyDigest)
	}

	// 5) Correlate the engagement's sealed detections into incidents.
	correlate(ctx)
	fmt.Printf("DONE: %d detections sealed across %d hosts; correlate run — check GET /api/v1/fleet/incidents\n", sealed, len(hosts))
}

// seedHost runs the full agent lifecycle for one host and returns how many detections it shipped.
func seedHost(ctx context.Context, cli *fleetclient.Client, h hostSpec, policyDigest string) int {
	now := time.Now().UTC()

	// a) Enrol.
	enrolTok := mintEnrolToken(ctx)
	er, err := cli.Enrol(ctx, enrolTok, fleetclient.EnrolRequest{
		Name: h.name, Platform: "linux", OSVersion: "6.8.0", AgentVersion: "0.1.0",
		Capabilities: []string{"detect.process", "detect.file", "detect.network", "detect.privilege"},
	})
	must(err, h.name+": enrol")
	agentID := shared.ID(er.AgentID)

	// b) Report host inventory — this binds the agent to a server-authoritative asset id (which the
	//    telemetry manifest must name; the agent never invents its own asset id).
	asset := reportHostInventory(ctx, cli, er.Token, h)
	fmt.Printf("[%s] agent=%s asset=%s\n", h.name, agentID, asset)

	// c) Register the telemetry + detection signing keys (proof-of-possession; private key never leaves).
	telPub, telPriv, _ := ed25519.GenerateKey(rand.Reader)
	telKey, err := fleetagent.NewSigningKey(agentID, fleetagent.PurposeTelemetryBatch, telPub, now, now.Add(2000*time.Hour))
	must(err, "telemetry key")
	must(cli.RegisterTelemetrySigningKey(ctx, er.Token, telKey, fleetagent.ProveKeyPossession(telPriv, telKey)), "register telemetry key")

	detPub, detPriv, _ := ed25519.GenerateKey(rand.Reader)
	detKey, err := fleetagent.NewSigningKey(agentID, fleetagent.PurposeDetectionBatch, detPub, now, now.Add(2000*time.Hour))
	must(err, "detection key")
	must(cli.RegisterDetectionKey(ctx, er.Token, detKey, fleetagent.ProveKeyPossession(detPriv, detKey)), "register detection key")

	// d) Server-derived incarnation coordinates. The manifest session is NOT free-form: the control plane
	//    recomputes it from the authenticated agent and refuses any mismatch. The delivery STREAM is
	//    per-priority-lane (a class maps to a fixed lane), so events are grouped by lane below.
	session := fleetagent.CanonicalSessionID(agentID)
	const boot = shared.ID("boot-1")
	const srcStream = shared.ID("edr-sensor-stream")

	// e) Build the four aligned telemetry envelopes (the raw signals) for this host.
	observed := now.Truncate(time.Second)
	scenarios := telemetryScenarios(agentID, asset, session, boot, srcStream, observed, policyDigest)

	// f) Group events by their class-derived delivery-priority lane and ship one signed batch per lane
	//    (a batch may not mix lanes). Each lane is its own delivery stream; remember which stream sealed
	//    each event so the detection reference can point at the exact durable coordinate.
	streamOf := map[shared.ID]shared.ID{} // eventID -> delivery stream
	byLane := map[fleetagent.DeliveryPriority][]int{}
	for i, sc := range scenarios {
		pri, perr := fleetagent.TelemetryPriority(sc.class)
		must(perr, "telemetry priority")
		byLane[pri] = append(byLane[pri], i)
	}
	total := 0
	for pri, idxs := range byLane {
		stream, serr := fleetagent.TelemetryDeliveryStreamID(agentID, session, pri)
		must(serr, "derive stream")
		events := make([]fleetclient.TelemetryEventPayload, len(idxs))
		refs := make([]fleetagent.EventRef, len(idxs))
		for j, i := range idxs {
			sc := scenarios[i]
			events[j] = fleetclient.TelemetryEventPayload{EventID: sc.eventID, Class: sc.class, Payload: sc.payload, ObservedAt: observed}
			refs[j] = fleetagent.EventRef{ID: sc.eventID, Digest: fleetagent.TelemetryEventDigest(sc.payload, asset)}
			streamOf[sc.eventID] = stream
		}
		manifest := fleetagent.TelemetryBatchManifest{
			ProtocolVersion: fleetagent.TelemetryProtocolVersion, SchemaVersion: telemetry.SchemaVersion,
			BatchID: shared.ID(fmt.Sprintf("tbatch-%s-p%d", h.name, int(pri))), AgentID: agentID, HostID: agentID, AssetID: asset, StreamID: stream,
			Position:         fleetagent.StreamPosition{Priority: pri, Epoch: 1, Sequence: 1, Session: session, Boot: fleetagent.BootID(boot)},
			PreviousSequence: 0,
			EventTimeMin:     observed, EventTimeMax: observed,
			ObservedCount:    len(idxs), KeptCount: len(idxs),
			SamplingPolicyDigest: strings.Repeat("d", 64),
			Events:               refs,
			KeyID:                telKey.KeyID,
		}
		manifest.PayloadDigest = fleetagent.TelemetryPayloadDigest(manifest.Events)
		manifest.Signature = fleetagent.SignTelemetryManifest(telPriv, manifest)
		if os.Getenv("SEED_DEBUG") == "1" {
			debugShipTelemetry(ctx, er.Token, fleetclient.TelemetryIngestRequest{Manifest: manifest, Events: events})
		}
		tresp, terr := cli.ShipTelemetry(ctx, er.Token, fleetclient.TelemetryIngestRequest{Manifest: manifest, Events: events})
		must(terr, h.name+": ship telemetry")
		if !tresp.Accepted {
			fatalf("[%s] telemetry lane P%d not accepted: %+v", h.name, int(pri), tresp)
		}
		total += len(events)
	}
	fmt.Printf("[%s] telemetry accepted (%d durable events across %d lanes)\n", h.name, total, len(byLane))

	// g) Sign + ship the detection batch. Each detection references its durable telemetry event by the
	//    exact (stream, epoch, sequence, event id, digest) coordinate, so it seals on ingest.
	items := make([]fleetagent.DetectionBatchItemV2, len(scenarios))
	drefs := make([]fleetagent.DetectionRefV2, len(scenarios))
	for i, sc := range scenarios {
		items[i] = fleetagent.DetectionBatchItemV2{
			ID:        shared.ID(fmt.Sprintf("det-%s-%d", h.name, i)),
			Detection: sc.detection,
			AssetID:   asset,
			TelemetryRefs: []fleetagent.TelemetryReference{{
				StreamID: streamOf[sc.eventID], Epoch: 1, Sequence: 1, EventID: sc.eventID,
				Digest: fleetagent.TelemetryEventDigest(sc.payload, asset),
			}},
			Rulepack:              fleetagent.RulepackReference{ID: "builtin", Version: 1, Digest: strings.Repeat("b", 64)},
			RedactionPolicyDigest: policyDigest,
		}
		ref, err := items[i].Reference()
		must(err, "detection item reference")
		drefs[i] = ref
	}
	batch := fleetagent.AgentBatchV2{
		Context: "synapse-agent-detection-batch:v2", Version: 2,
		AgentID: agentID, EngagementID: shared.ID(*engagement), Sequence: 1, KeyID: detKey.KeyID,
		Detections: drefs,
	}
	batch.Signature = fleetagent.SignBatchV2(detPriv, batch)
	must(cli.SendDetectionBatchV2(ctx, er.Token, batch, items), h.name+": ship detections")
	fmt.Printf("[%s] shipped %d detections\n", h.name, len(items))
	return len(items)
}

// scenario pairs one raw telemetry signal (envelope payload) with the detection that fired on it.
type scenario struct {
	eventID   shared.ID
	class     detection.Class
	payload   []byte
	detection detection.Detection
}

// telemetryScenarios builds the four aligned raw-signal + detection pairs for one host.
func telemetryScenarios(agentID, asset shared.ID, session fleetagent.SessionID, boot, srcStream shared.ID, observed time.Time, policyDigest string) []scenario {
	occurred := observed.Add(-time.Millisecond)
	mkEnvelope := func(id shared.ID, seq uint64, ev telemetry.TelemetryEvent) []byte {
		env := telemetry.TelemetryEnvelope{
			SchemaVersion: telemetry.SchemaVersion,
			EventID:       id, EventType: ev.EventType(), EventClass: ev.Class,
			AgentID: agentID, AgentSessionID: shared.ID(session), AssetID: asset, BootID: boot,
			StreamID: srcStream, SensorID: "edr-sensor", SensorVersion: "1",
			OccurredAt: occurred, ObservedAt: observed, Sequence: seq,
			RedactionPolicyDigest: policyDigest,
			Event:                 ev,
		}
		payload, err := json.Marshal(env)
		must(err, "marshal envelope")
		return payload
	}
	mkDetection := func(ruleID string, ev detection.Event) detection.Detection {
		r, ok := detection.Lookup(ruleID)
		if !ok {
			fatalf("unknown rule %s", ruleID)
		}
		d, err := detection.NewDetection(r, asset, agentID, []detection.Event{ev}, observed)
		must(err, "new detection "+ruleID)
		return d
	}

	return []scenario{
		{
			eventID: "ev-proc", class: detection.ClassProcess,
			payload: mkEnvelope("ev-proc", 1, telemetry.TelemetryEvent{
				Class:   detection.ClassProcess,
				Process: &telemetry.ProcessObservation{Kind: "exec", PID: 4021, EntityID: "proc-ps", Comm: "ps", Path: "/usr/bin/ps"},
			}),
			detection: mkDetection("det.process_enumeration", detection.Event{
				Class: detection.ClassProcess, At: observed, Host: asset,
				Process: &detection.ProcessEvent{PID: 4021, Comm: "ps", Path: "/usr/bin/ps"},
			}),
		},
		{
			eventID: "ev-file", class: detection.ClassFile,
			payload: mkEnvelope("ev-file", 2, telemetry.TelemetryEvent{
				Class: detection.ClassFile,
				File:  &telemetry.FileObservation{Op: "open", Path: "/etc/shadow", Comm: "cat"},
			}),
			detection: mkDetection("det.credential_file_access", detection.Event{
				Class: detection.ClassFile, At: observed, Host: asset,
				File: &detection.FileEvent{Path: "/etc/shadow", Op: "read", Comm: "cat"},
			}),
		},
		{
			eventID: "ev-net", class: detection.ClassNetwork,
			payload: mkEnvelope("ev-net", 3, telemetry.TelemetryEvent{
				Class:   detection.ClassNetwork,
				Network: &telemetry.NetworkObservation{Kind: "connect", Proto: "udp", Direction: "egress", RemoteAddr: "185.220.101.7", RemotePort: 53},
			}),
			detection: mkDetection("det.suspicious_dns_beacon", detection.Event{
				Class: detection.ClassNetwork, At: observed, Host: asset,
				Network: &detection.NetworkEvent{Proto: "udp", RemoteAddr: "185.220.101.7", RemotePort: 53, Direction: "egress"},
			}),
		},
		{
			eventID: "ev-priv", class: detection.ClassPrivilege,
			payload: mkEnvelope("ev-priv", 4, telemetry.TelemetryEvent{
				Class:     detection.ClassPrivilege,
				Privilege: &telemetry.PrivilegeObservation{Kind: "capset", PID: 1234, Cap: "CAP_SYS_ADMIN", Comm: "sudo"},
			}),
			detection: mkDetection("det.privilege_escalation_to_root", detection.Event{
				Class: detection.ClassPrivilege, At: observed, Host: asset,
				Privilege: &detection.PrivilegeEvent{Comm: "sudo", Cap: "CAP_SYS_ADMIN"},
			}),
		},
	}
}

// --- admin HTTP helpers (operator plane; bearer token) ---

func admitAndActivatePolicy(ctx context.Context, pol privacy.Policy) string {
	dispositions := make(map[string]string, len(pol.Dispositions))
	for cat, d := range pol.Dispositions {
		dispositions[string(cat)] = string(d)
	}
	admitBody := map[string]any{"policy": map[string]any{
		"dispositions": dispositions, "redact_secrets": pol.RedactSecrets,
		"max_arg_len": pol.MaxArgLen, "max_arg_count": pol.MaxArgCount, "max_path_len": pol.MaxPathLen,
		"hash_salt": pol.HashSalt, "version": pol.Version,
	}}
	// The policy digest is deterministic over its redaction content, so we can compute it locally and the
	// admit/activate calls are idempotent — a 409 means it was already established, which is fine.
	digest := privacy.RedactionPolicyDigest(pol)
	adminPostTolerant(ctx, "/api/v1/fleet/privacy-policies", admitBody)
	opID := fmt.Sprintf("seed-activate-%d", time.Now().UnixNano())
	adminPostTolerant(ctx, "/api/v1/fleet/privacy-policies/activate", map[string]any{"digest": digest, "operation_id": opID})
	return digest
}

func mintEnrolToken(ctx context.Context) string {
	var resp struct {
		Token string `json:"enrolment_token"`
	}
	adminPost(ctx, "/api/v1/agents/enrolment-tokens", map[string]any{"ttl_seconds": 3600}, &resp)
	if resp.Token == "" {
		fatalf("mint enrol token returned empty")
	}
	return resp.Token
}

func reportHostInventory(ctx context.Context, cli *fleetclient.Client, agentToken string, h hostSpec) shared.ID {
	inv := map[string]any{
		"facts":    map[string]any{"hostname": h.hostname, "os": "linux", "os_version": "12", "machine_id": h.machine},
		"complete": true,
	}
	resp, err := cli.SendHostInventoryResolved(ctx, agentToken, inv)
	must(err, h.name+": host inventory")
	if resp.AssetID == "" {
		fatalf("[%s] host inventory returned no asset id", h.name)
	}
	return shared.ID(resp.AssetID)
}

func correlate(ctx context.Context) {
	var resp map[string]any
	adminPost(ctx, "/api/v1/fleet/engagements/"+*engagement+"/correlate", map[string]any{}, &resp)
	fmt.Printf("correlate: %v\n", resp)
}

// debugShipTelemetry replays the exact telemetry request the fleet client would send (gzip'd JSON) but
// prints the server's status + body, which the production client deliberately discards.
func debugShipTelemetry(ctx context.Context, token string, in fleetclient.TelemetryIngestRequest) {
	raw, _ := json.Marshal(in)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, *baseURL+"/api/v1/fleet/telemetry", bytes.NewReader(gz.Bytes()))
	req.Header.Set("X-Synapse-Fleet-Proto", "1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("DEBUG telemetry err: %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Printf("DEBUG telemetry status=%d body=%s\n", resp.StatusCode, string(b))
}

// adminPostTolerant posts and accepts any 2xx or 409 (already-established) without failing.
func adminPostTolerant(ctx context.Context, path string, body any) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, *baseURL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	must(err, "do "+path)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusConflict {
		fatalf("%s -> %d", path, resp.StatusCode)
	}
}

func adminPost(ctx context.Context, path string, body any, out any) {
	b, err := json.Marshal(body)
	must(err, "marshal "+path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *baseURL+path, bytes.NewReader(b))
	must(err, "request "+path)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	must(err, "do "+path)
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fatalf("%s -> %d: %s", path, resp.StatusCode, string(raw))
	}
	if out != nil && len(raw) > 0 {
		must(json.Unmarshal(raw, out), "decode "+path)
	}
}

func must(err error, what string) {
	if err != nil {
		fatalf("%s: %v", what, err)
	}
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
