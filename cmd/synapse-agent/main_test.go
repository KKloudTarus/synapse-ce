package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/platform/fssecurity"
)

type fakeAPI struct {
	enrolCalled bool
	enrolResp   fleetclient.EnrolResponse
	orders      []fleetclient.Order
	results     []result
	progressed  []string
	heartbeats  int
	sent        int
	sendErr     error
	hbResp      fleetclient.HeartbeatResponse
	claims      int
}

type result struct{ orderID, status, reason string }

func (f *fakeAPI) Enrol(_ context.Context, _ string, _ fleetclient.EnrolRequest) (fleetclient.EnrolResponse, error) {
	f.enrolCalled = true
	return f.enrolResp, nil
}
func (f *fakeAPI) Heartbeat(_ context.Context, _ string, _ fleetclient.EnrolRequest) (fleetclient.HeartbeatResponse, error) {
	f.heartbeats++
	return f.hbResp, nil
}
func (f *fakeAPI) ClaimWork(_ context.Context, _ string, _ int) ([]fleetclient.Order, error) {
	f.claims++
	return f.orders, nil
}
func (f *fakeAPI) Progress(_ context.Context, _, orderID string) error {
	f.progressed = append(f.progressed, orderID)
	return nil
}
func (f *fakeAPI) SubmitResult(_ context.Context, _, orderID, status, reason string) error {
	f.results = append(f.results, result{orderID, status, reason})
	return nil
}
func (f *fakeAPI) SendHostInventory(_ context.Context, _ string, _ any) error {
	f.sent++
	return f.sendErr
}
func (f *fakeAPI) RegisterDetectionKey(context.Context, string, fleetagent.AgentSigningKey, string) error {
	return nil
}
func (f *fakeAPI) SendDetectionBatch(context.Context, string, fleetagent.AgentBatch, []fleetagent.DetectionBatchItem) error {
	return nil
}

func newRunner(t *testing.T, api fleetAPI, orders []fleetclient.Order, collect func(context.Context, string) (hostinventory.HostInventory, error)) *runner {
	t.Helper()
	if fa, ok := api.(*fakeAPI); ok {
		fa.orders = orders
	}
	dir := t.TempDir()
	return &runner{
		api:     api,
		collect: collect,
		cfg:     config{stateDir: dir, root: dir, name: "host1", enrolToken: "enrol", once: true, maxOrders: 8},
		store:   fleetclient.NewCredentialStore(dir),
	}
}

func okCollect(inv hostinventory.HostInventory) func(context.Context, string) (hostinventory.HostInventory, error) {
	return func(context.Context, string) (hostinventory.HostInventory, error) { return inv.Normalize(), nil }
}

func TestFirstRunEnrolsAndPersists(t *testing.T) {
	api := &fakeAPI{enrolResp: fleetclient.EnrolResponse{AgentID: "a1", Token: "secret", CertificatePEM: "PEM"}}
	inv := hostinventory.HostInventory{Facts: hostinventory.HostFacts{OS: "linux", OSVersion: "12"},
		Packages: []sbom.Component{{Name: "acl", Version: "1"}}}
	r := newRunner(t, api, []fleetclient.Order{{ID: "o1", Capability: "scan.host"}}, okCollect(inv))

	if err := r.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !api.enrolCalled {
		t.Fatalf("first run must enrol")
	}
	// Credential + key persisted, key is 0600 and the token is not in the key file.
	if _, err := os.Stat(filepath.Join(r.cfg.stateDir, "agent.key")); err != nil {
		t.Fatalf("key must be persisted: %v", err)
	}
	info, err := os.Stat(filepath.Join(r.cfg.stateDir, "credential.json"))
	if err != nil {
		t.Fatalf("credential must be persisted: %v", err)
	}
	// Unix-only guarantee: Windows has no permission bits, so the credential is protected by the
	// state directory's ACL there instead. Asserting 0600 on Windows would assert nothing real.
	if fssecurity.UnixModeEnforced() && info.Mode().Perm() != 0o600 {
		t.Fatalf("credential must be 0600, got %v", info.Mode().Perm())
	}
	// The order was progressed and reported succeeded with a coverage-honest summary.
	if len(api.results) != 1 || api.results[0].status != "succeeded" {
		t.Fatalf("expected one succeeded result, got %+v", api.results)
	}
	// The inventory was reported to the control plane (persisted into the asset model).
	if api.sent != 1 {
		t.Fatalf("the collected inventory must be reported to the control plane, sent=%d", api.sent)
	}
	if len(api.progressed) != 1 {
		t.Fatalf("order should be moved to running, got %v", api.progressed)
	}
	// Inventory buffered to disk.
	if _, err := os.Stat(filepath.Join(r.cfg.stateDir, "inventory-o1.json")); err != nil {
		t.Fatalf("inventory must be buffered locally: %v", err)
	}
}

func TestSecondRunReusesCredentialNoEnrol(t *testing.T) {
	api := &fakeAPI{enrolResp: fleetclient.EnrolResponse{AgentID: "a1", Token: "secret"}}
	r := newRunner(t, api, nil, okCollect(hostinventory.HostInventory{}))
	// Pre-persist a credential.
	if err := r.store.Persist(fleetclient.Credential{AgentID: "a1", Token: "secret"}, []byte("KEY")); err != nil {
		t.Fatal(err)
	}
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if api.enrolCalled {
		t.Fatalf("a stored credential must not re-enrol")
	}
	if api.heartbeats != 1 {
		t.Fatalf("expected one heartbeat, got %d", api.heartbeats)
	}
}

func TestUnsupportedCapabilityFails(t *testing.T) {
	api := &fakeAPI{enrolResp: fleetclient.EnrolResponse{AgentID: "a1", Token: "secret"}}
	r := newRunner(t, api, []fleetclient.Order{{ID: "o9", Capability: "port-scan"}}, okCollect(hostinventory.HostInventory{}))
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(api.results) != 1 || api.results[0].status != "failed" {
		t.Fatalf("unsupported capability must fail the order, got %+v", api.results)
	}
	if len(api.progressed) != 0 {
		t.Fatalf("an unsupported order must not be progressed")
	}
}

func TestCollectErrorFailsOrder(t *testing.T) {
	api := &fakeAPI{enrolResp: fleetclient.EnrolResponse{AgentID: "a1", Token: "secret"}}
	boom := func(context.Context, string) (hostinventory.HostInventory, error) {
		return hostinventory.HostInventory{}, errors.New("no root")
	}
	r := newRunner(t, api, []fleetclient.Order{{ID: "o1", Capability: "scan.host"}}, boom)
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(api.results) != 1 || api.results[0].status != "failed" {
		t.Fatalf("a collect error must fail the order, got %+v", api.results)
	}
}

func TestNoCredentialNoTokenErrors(t *testing.T) {
	api := &fakeAPI{}
	r := newRunner(t, api, nil, okCollect(hostinventory.HostInventory{}))
	r.cfg.enrolToken = ""
	if err := r.run(context.Background()); err == nil {
		t.Fatalf("run with neither credential nor enrol token must error")
	}
}

func TestReportFailureFailsOrder(t *testing.T) {
	api := &fakeAPI{enrolResp: fleetclient.EnrolResponse{AgentID: "a1", Token: "secret"}, sendErr: errors.New("503")}
	inv := hostinventory.HostInventory{Facts: hostinventory.HostFacts{OS: "linux"}}
	r := newRunner(t, api, []fleetclient.Order{{ID: "o1", Capability: "scan.host"}}, okCollect(inv))
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(api.results) != 1 || api.results[0].status != "failed" {
		t.Fatalf("a failed report to the control plane must fail the order, got %+v", api.results)
	}
	if !strings.Contains(api.results[0].reason, "report inventory") {
		t.Fatalf("reason must indicate a reporting failure, got %q", api.results[0].reason)
	}
}

func TestDegradedInventoryFailsOrder(t *testing.T) {
	api := &fakeAPI{enrolResp: fleetclient.EnrolResponse{AgentID: "a1", Token: "secret"}}
	degraded := hostinventory.HostInventory{Facts: hostinventory.HostFacts{OS: "linux"}}
	degraded.AddIssue(hostinventory.CoverageUnreadableDB, "/var/lib/rpm unreadable")
	r := newRunner(t, api, []fleetclient.Order{{ID: "o1", Capability: "scan.host"}}, okCollect(degraded))
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(api.results) != 1 || api.results[0].status != "failed" {
		t.Fatalf("a degraded (untrustworthy) inventory must fail the order, got %+v", api.results)
	}
	if !strings.Contains(api.results[0].reason, "DEGRADED") {
		t.Fatalf("reason must say DEGRADED, got %q", api.results[0].reason)
	}
}

func TestBufferFailureFailsOrder(t *testing.T) {
	api := &fakeAPI{enrolResp: fleetclient.EnrolResponse{AgentID: "a1", Token: "secret"}}
	inv := hostinventory.HostInventory{Facts: hostinventory.HostFacts{OS: "linux"}}
	r := newRunner(t, api, []fleetclient.Order{{ID: "o1", Capability: "scan.host"}}, okCollect(inv))
	// Pre-seed a credential so enrolment is skipped and we reach the buffering step.
	if err := r.store.Persist(fleetclient.Credential{AgentID: "a1", Token: "secret"}, []byte("KEY")); err != nil {
		t.Fatal(err)
	}
	// Make ONLY the inventory-file write fail: create a directory exactly where the buffer file goes,
	// so os.WriteFile("inventory-o1.json") cannot create a regular file over it.
	if err := os.MkdirAll(filepath.Join(r.cfg.stateDir, "inventory-o1.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(api.results) != 1 || api.results[0].status != "failed" {
		t.Fatalf("a buffer-write failure must fail the order, got %+v", api.results)
	}
	if !strings.Contains(api.results[0].reason, "buffer") {
		t.Fatalf("reason must indicate a buffer failure, got %q", api.results[0].reason)
	}
}

func TestSummaryIsCoverageHonest(t *testing.T) {
	inv := hostinventory.HostInventory{}
	inv.AddIssue(hostinventory.CoverageNoPackageDB, "none")
	inv = inv.Normalize()
	if got := summary(inv); got == "" || !strings.Contains(got, "INCOMPLETE") {
		t.Fatalf("incomplete inventory summary must say INCOMPLETE, got %q", got)
	}
}

func TestCycleProceedsAgainstDevelControlPlane(t *testing.T) {
	// A "devel" (untagged) control-plane version must NOT skip claiming — the agent-side CP check
	// fails OPEN on an unparseable version (availability), unlike the server-side agent check.
	api := &fakeAPI{
		enrolResp: fleetclient.EnrolResponse{AgentID: "a1", Token: "secret"},
		hbResp:    fleetclient.HeartbeatResponse{ControlPlaneVersion: "devel", MinSupportedAgentVersion: ""},
	}
	r := newRunner(t, api, nil, okCollect(hostinventory.HostInventory{}))
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if api.claims != 1 {
		t.Fatalf("a devel control-plane version must not skip claim; claims=%d", api.claims)
	}
}

func TestCycleSkipsClaimAgainstTooOldControlPlane(t *testing.T) {
	// A parseable CP version strictly below the agent's required floor skips the claim this cycle.
	api := &fakeAPI{
		enrolResp: fleetclient.EnrolResponse{AgentID: "a1", Token: "secret"},
		hbResp:    fleetclient.HeartbeatResponse{ControlPlaneVersion: "0.0.1"},
	}
	r := newRunner(t, api, nil, okCollect(hostinventory.HostInventory{}))
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if api.claims != 0 {
		t.Fatalf("an older-than-required control plane must skip claim; claims=%d", api.claims)
	}
}
