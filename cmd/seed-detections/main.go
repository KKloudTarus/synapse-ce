// Command seed-detections enrols a fleet agent, registers a detection signing key, and ships a few
// SIGNED detection batches (real v2 wire contract) so the incident/fleet flow can be demonstrated with
// data. It reuses the production fleetclient + fleetagent signing, so what it sends is what a real agent
// sends. Dev/seed only.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

func main() {
	url := flag.String("url", "http://localhost:8080", "control-plane base URL")
	enrolToken := flag.String("enrol-token", "", "one-time enrolment token")
	engagement := flag.String("engagement", "", "engagement id the detections belong to")
	name := flag.String("name", "edr-sensor-01", "agent name")
	flag.Parse()
	if *enrolToken == "" || *engagement == "" {
		fmt.Fprintln(os.Stderr, "need -enrol-token and -engagement")
		os.Exit(2)
	}

	ctx := context.Background()
	cli := fleetclient.New(*url, 30*time.Second)

	// 1) Enrol.
	er, err := cli.Enrol(ctx, *enrolToken, fleetclient.EnrolRequest{
		Name: *name, Platform: "linux", OSVersion: "6.8.0", AgentVersion: "0.1.0",
		Capabilities: []string{"detect.process", "detect.file", "detect.network", "detect.privilege"},
	})
	must(err, "enrol")
	agentID := shared.ID(er.AgentID)
	fmt.Printf("enrolled agent=%s\n", agentID)

	// 2) Register a detection signing key (with proof-of-possession).
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	key, err := fleetagent.NewSigningKey(agentID, fleetagent.PurposeDetectionBatch, pub, now, now.Add(90*24*time.Hour))
	must(err, "new signing key")
	must(cli.RegisterDetectionKey(ctx, er.Token, key, fleetagent.ProveKeyPossession(priv, key)), "register key")
	fmt.Printf("registered key=%s\n", key.KeyID)

	// 3) Build + ship signed detection batches. Multiple detections on the SAME asset correlate into an
	//    incident, so group by asset. Vary the rule/class for a realistic mix.
	assets := []string{"host-web-01", "host-db-01", "host-worker-01"}
	digest := strings.Repeat("a", 64)
	var seq uint64
	total := 0
	for ai, asset := range assets {
		var items []fleetagent.DetectionBatchItemV2
		var refs []fleetagent.DetectionRefV2
		for di, spec := range detectionMix(agentID, shared.ID(asset)) {
			item := fleetagent.DetectionBatchItemV2{
				ID:                    shared.ID(fmt.Sprintf("det-%d-%d", ai, di)),
				Detection:             spec,
				AssetID:               shared.ID(asset),
				TelemetryRefs:         []fleetagent.TelemetryReference{{StreamID: shared.ID("stream-" + asset), Epoch: 1, Sequence: uint64(di + 1), EventID: shared.ID(fmt.Sprintf("ev-%d-%d", ai, di)), Digest: digest}},
				Rulepack:              fleetagent.RulepackReference{ID: "builtin", Version: 1, Digest: strings.Repeat("b", 64)},
				RedactionPolicyDigest: strings.Repeat("c", 64),
			}
			ref, err := item.Reference()
			must(err, "item reference")
			items = append(items, item)
			refs = append(refs, ref)
		}
		seq++
		batch := fleetagent.AgentBatchV2{
			Context: "synapse-agent-detection-batch:v2", Version: 2,
			AgentID: agentID, EngagementID: shared.ID(*engagement), Sequence: seq, KeyID: key.KeyID,
			Detections: refs,
		}
		batch.Signature = fleetagent.SignBatchV2(priv, batch)
		must(cli.SendDetectionBatchV2(ctx, er.Token, batch, items), "send batch "+asset)
		total += len(items)
		fmt.Printf("shipped %d detections for asset=%s\n", len(items), asset)
	}
	fmt.Printf("DONE: %d detections across %d assets\n", total, len(assets))
}

// detectionMix builds a small, varied set of valid detections for one asset.
func detectionMix(agent, host shared.ID) []detection.Detection {
	mk := func(ruleID string, ev detection.Event) detection.Detection {
		r, ok := detection.Lookup(ruleID)
		if !ok {
			panic("unknown rule " + ruleID)
		}
		d, err := detection.NewDetection(r, host, agent, []detection.Event{ev}, time.Now().UTC())
		must(err, "new detection "+ruleID)
		return d
	}
	now := time.Now().UTC()
	return []detection.Detection{
		mk("det.process_enumeration", detection.Event{Class: detection.ClassProcess, At: now, Host: host, Process: &detection.ProcessEvent{PID: 4021, Comm: "ps", Path: "/usr/bin/ps"}}),
		mk("det.credential_file_access", detection.Event{Class: detection.ClassFile, At: now, Host: host, File: &detection.FileEvent{Path: "/etc/shadow", Op: "read", Comm: "cat"}}),
		mk("det.suspicious_dns_beacon", detection.Event{Class: detection.ClassNetwork, At: now, Host: host, Network: &detection.NetworkEvent{Proto: "udp", RemoteAddr: "185.220.101.7", RemotePort: 53, Direction: "egress"}}),
		mk("det.privilege_escalation_to_root", detection.Event{Class: detection.ClassPrivilege, At: now, Host: host, Privilege: &detection.PrivilegeEvent{Comm: "sudo", Cap: "CAP_SYS_ADMIN"}}),
	}
}

func must(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(1)
	}
}
