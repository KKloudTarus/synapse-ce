package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/platform/fssecurity"
)

type fakeAPI struct {
	enrolCalled       bool
	activated         int
	enrolResp         fleetclient.EnrolResponse
	orders            []fleetclient.Order
	results           []result
	progressed        []string
	progressErr       error
	heartbeats        int
	heartbeatRequests []fleetclient.EnrolRequest
	sent              int
	sendErr           error
	hbResp            fleetclient.HeartbeatResponse
	claims            int
	policyResp        fleetclient.PrivacyPolicyResponse
	policyErr         error
	responseResults   []fleetclient.ResponseResultRequest
	responseResultErr error
}

type result struct{ orderID, status, reason string }

func (f *fakeAPI) Enrol(_ context.Context, _ string, _ fleetclient.EnrolRequest) (fleetclient.EnrolResponse, error) {
	f.enrolCalled = true
	return f.enrolResp, nil
}
func (f *fakeAPI) ActivateCredential(fleetclient.Credential, []byte) error {
	f.activated++
	return nil
}
func (f *fakeAPI) Heartbeat(_ context.Context, _ string, request fleetclient.EnrolRequest) (fleetclient.HeartbeatResponse, error) {
	f.heartbeats++
	f.heartbeatRequests = append(f.heartbeatRequests, request)
	return f.hbResp, nil
}
func (f *fakeAPI) ActivePrivacyPolicy(context.Context, string) (fleetclient.PrivacyPolicyResponse, error) {
	if f.policyErr != nil {
		return fleetclient.PrivacyPolicyResponse{}, f.policyErr
	}
	if f.policyResp.Assignment.TenantID == "" {
		return fleetclient.PrivacyPolicyResponse{}, errors.New("privacy policy unavailable")
	}
	return f.policyResp, nil
}
func (f *fakeAPI) ClaimWork(_ context.Context, _ string, _ int) ([]fleetclient.Order, error) {
	f.claims++
	for i := range f.orders {
		if f.orders[i].LeaseID == "" {
			f.orders[i].LeaseID = "lease-1"
		}
		if f.orders[i].LeaseUntil.IsZero() {
			f.orders[i].LeaseUntil = time.Now().Add(time.Minute)
		}
	}
	return f.orders, nil
}
func (f *fakeAPI) Progress(_ context.Context, _, orderID, _ string) error {
	f.progressed = append(f.progressed, orderID)
	return f.progressErr
}
func (f *fakeAPI) SubmitResult(_ context.Context, _, orderID, _ string, status, reason string) error {
	f.results = append(f.results, result{orderID, status, reason})
	return nil
}

type fakeResponseExecutor struct {
	calls        int
	err          error
	pending      []fleetagent.ResponseExecutionJournalEntry
	acked        int
	halts        []int64
	haltCommands int
}

func (e *fakeResponseExecutor) Execute(_ context.Context, command fleetagent.ResponseCommand, leaseID string, _ time.Time) (fleetagent.ResponseExecutionResult, error) {
	e.calls++
	return fleetagent.ResponseExecutionResult{
		AttemptKey: command.AttemptKey, CommandDigest: fleetagent.ResponseCommandDigest(command), LeaseID: leaseID,
		State: fleetagent.ResponseExecutionApplied, ObservedRadius: "state_changing", AffectedCount: 1,
		CompletedAt: time.Now().UTC(),
	}, e.err
}
func (e *fakeResponseExecutor) ExecuteHaltCommand(context.Context, fleetagent.ResponseHaltCommand, string, time.Time) error {
	e.haltCommands++
	return nil
}
func (e *fakeResponseExecutor) Halt(_ context.Context, generation int64) error {
	e.halts = append(e.halts, generation)
	return nil
}
func (e *fakeResponseExecutor) PendingResults(context.Context) ([]fleetagent.ResponseExecutionJournalEntry, error) {
	return append([]fleetagent.ResponseExecutionJournalEntry(nil), e.pending...), nil
}
func (e *fakeResponseExecutor) AcknowledgeResult(_ context.Context, attemptKey, digest string) error {
	for i, entry := range e.pending {
		if entry.Command.AttemptKey == attemptKey && entry.CommandDigest == digest {
			e.pending = append(e.pending[:i], e.pending[i+1:]...)
			e.acked++
			return nil
		}
	}
	return nil
}
func (f *fakeAPI) SubmitResponseResult(_ context.Context, _ string, orderID string, request fleetclient.ResponseResultRequest) error {
	if f.responseResultErr != nil {
		return f.responseResultErr
	}
	f.responseResults = append(f.responseResults, request)
	f.results = append(f.results, result{orderID, request.Status, request.Reason})
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

func privacyPolicyResponse(t *testing.T) fleetclient.PrivacyPolicyResponse {
	t.Helper()
	assignment, err := privacy.NewAssignment(
		"tenant-1",
		privacy.DefaultPolicy(),
		"operator",
		time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("NewAssignment() error = %v", err)
	}
	dispositions := make(map[string]string, len(assignment.Policy.Dispositions))
	for category, disposition := range assignment.Policy.Dispositions {
		dispositions[string(category)] = string(disposition)
	}
	return fleetclient.PrivacyPolicyResponse{Assignment: fleetclient.PrivacyPolicyAssignment{
		TenantID: assignment.TenantID.String(),
		Policy: fleetclient.PrivacyPolicy{
			Dispositions:  dispositions,
			RedactSecrets: assignment.Policy.RedactSecrets,
			MaxArgLen:     assignment.Policy.MaxArgLen,
			MaxArgCount:   assignment.Policy.MaxArgCount,
			MaxPathLen:    assignment.Policy.MaxPathLen,
			HashSalt:      assignment.Policy.HashSalt,
			Version:       assignment.Policy.Version,
		},
		Digest:    assignment.Digest,
		CreatedBy: assignment.CreatedBy,
		CreatedAt: assignment.CreatedAt,
	}}
}

func TestResolvePrivacyPolicyUsesValidatedCacheOnlyForTransientFailure(t *testing.T) {
	response := privacyPolicyResponse(t)
	api := &fakeAPI{policyResp: response}
	r := newRunner(t, api, nil, nil)
	r.cfg.baseURL = "https://control.example/api/"
	cred := fleetclient.Credential{AgentID: "agent-1", Token: "token"}

	first, err := r.resolvePrivacyPolicy(t.Context(), cred)
	if err != nil {
		t.Fatalf("resolve live policy: %v", err)
	}
	api.policyResp = fleetclient.PrivacyPolicyResponse{}
	api.policyErr = &fleetclient.NetworkError{Method: "GET", Path: "/api/v1/fleet/privacy-policy", Err: errors.New("offline")}
	cached, err := r.resolvePrivacyPolicy(t.Context(), cred)
	if err != nil {
		t.Fatalf("resolve cached policy after network failure: %v", err)
	}
	if !privacy.SameAssignment(first, cached) || !first.CreatedAt.Equal(cached.CreatedAt) {
		t.Fatalf("cached assignment = %#v, want %#v", cached, first)
	}

	api.policyErr = &fleetclient.HTTPError{Method: "GET", Path: "/api/v1/fleet/privacy-policy", StatusCode: http.StatusServiceUnavailable}
	if _, err := r.resolvePrivacyPolicy(t.Context(), cred); err != nil {
		t.Fatalf("resolve cached policy after 5xx: %v", err)
	}
}

func TestResolvePrivacyPolicyFailsClosedForAuthoritativeClientErrors(t *testing.T) {
	response := privacyPolicyResponse(t)
	api := &fakeAPI{policyResp: response}
	r := newRunner(t, api, nil, nil)
	r.cfg.baseURL = "https://control.example"
	cred := fleetclient.Credential{AgentID: "agent-1", Token: "token"}
	if _, err := r.resolvePrivacyPolicy(t.Context(), cred); err != nil {
		t.Fatalf("prime privacy policy cache: %v", err)
	}

	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			api.policyResp = fleetclient.PrivacyPolicyResponse{}
			api.policyErr = &fleetclient.HTTPError{
				Method: "GET", Path: "/api/v1/fleet/privacy-policy", StatusCode: status,
			}
			if _, err := r.resolvePrivacyPolicy(t.Context(), cred); err == nil {
				t.Fatalf("resolvePrivacyPolicy() accepted cached policy after HTTP %d", status)
			}
		})
	}
}

func TestResolvePrivacyPolicyRejectsCacheForDifferentAgentOrControlPlane(t *testing.T) {
	response := privacyPolicyResponse(t)
	api := &fakeAPI{policyResp: response}
	r := newRunner(t, api, nil, nil)
	r.cfg.baseURL = "https://control.example"
	cred := fleetclient.Credential{AgentID: "agent-1", Token: "token"}
	if _, err := r.resolvePrivacyPolicy(t.Context(), cred); err != nil {
		t.Fatalf("prime privacy policy cache: %v", err)
	}
	api.policyResp = fleetclient.PrivacyPolicyResponse{}
	api.policyErr = &fleetclient.NetworkError{Method: "GET", Path: "/api/v1/fleet/privacy-policy", Err: errors.New("offline")}

	if _, err := r.resolvePrivacyPolicy(t.Context(), fleetclient.Credential{AgentID: "agent-2", Token: "token"}); err == nil {
		t.Fatal("resolvePrivacyPolicy() accepted cache bound to another agent")
	}
	r.cfg.baseURL = "https://other.example"
	if _, err := r.resolvePrivacyPolicy(t.Context(), cred); err == nil {
		t.Fatal("resolvePrivacyPolicy() accepted cache bound to another control plane")
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
	if api.activated != 1 {
		t.Fatalf("first run must activate the enrolled transport identity, got %d activations", api.activated)
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
	if api.activated != 1 {
		t.Fatalf("a stored credential must reactivate the transport identity, got %d activations", api.activated)
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

func TestInventoryDoesNotRunAfterLeaseProgressFailure(t *testing.T) {
	api := &fakeAPI{progressErr: errors.New("stale lease")}
	collections := 0
	r := newRunner(t, api, nil, func(context.Context, string) (hostinventory.HostInventory, error) {
		collections++
		return hostinventory.HostInventory{}, nil
	})
	r.handle(context.Background(), fleetclient.Credential{Token: "token"}, fleetclient.Order{
		ID: "order-1", Capability: hostInventoryCapability, LeaseID: "lease-1", LeaseUntil: time.Now().Add(time.Minute),
	})
	if collections != 0 || len(api.results) != 0 {
		t.Fatalf("failed progress crossed work boundary: collections=%d results=%+v", collections, api.results)
	}
}

func TestHandleResponseUsesExistingClaimLoopAndRequiresProgress(t *testing.T) {
	api := &fakeAPI{}
	executor := &fakeResponseExecutor{}
	r := newRunner(t, api, nil, nil)
	r.response = executor
	command := &fleetagent.ResponseCommand{CommandID: "response-order-1", AttemptKey: "attempt-1", AgentID: "agent-1", AssetID: "asset-1"}
	order := fleetclient.Order{ID: "response-order-1", Capability: responseProcessCapability, AssetID: "asset-1", IdempotencyKey: "attempt-1", LeaseID: "lease-1", LeaseUntil: time.Now().Add(time.Minute), ResponseCommand: command}
	cred := fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1", Token: "token"}

	r.handle(context.Background(), cred, order)
	if executor.calls != 1 || len(api.progressed) != 1 || len(api.results) != 1 || api.results[0].status != "succeeded" {
		t.Fatalf("response dispatch calls=%d progressed=%v results=%+v", executor.calls, api.progressed, api.results)
	}

	api.progressErr = errors.New("control plane unavailable")
	command2 := *command
	command2.CommandID = "response-order-2"
	r.handle(context.Background(), cred, fleetclient.Order{ID: "response-order-2", Capability: responseProcessCapability, AssetID: "asset-1", IdempotencyKey: "attempt-1", LeaseID: "lease-2", LeaseUntil: time.Now().Add(time.Minute), ResponseCommand: &command2})
	if executor.calls != 1 {
		t.Fatalf("response side effect crossed boundary after progress failure; calls=%d", executor.calls)
	}
}

func TestResponseCapabilityWaitsForCanonicalAssetBinding(t *testing.T) {
	r := newRunner(t, &fakeAPI{}, nil, nil)
	executor := &fakeResponseExecutor{}
	calls := 0
	r.responseFactory = func(agentID, assetID shared.ID) (responseCommandExecutor, error) {
		calls++
		if agentID != "agent-1" || assetID != "asset-1" {
			t.Fatalf("response identity=%s/%s", agentID, assetID)
		}
		return executor, nil
	}
	if err := r.configureResponse(fleetclient.Credential{AgentID: "agent-1"}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || len(r.capabilities()) != 1 {
		t.Fatal("response capability advertised before canonical asset binding")
	}
	if err := r.configureResponse(fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || r.response != executor || len(r.capabilities()) != 3 || r.capabilities()[1] != responseProcessCapability || r.capabilities()[2] != responseHaltCapability {
		t.Fatalf("response runtime was not bound once: calls=%d capabilities=%v", calls, r.capabilities())
	}
}

func TestHeartbeatRefreshesReadyCapabilities(t *testing.T) {
	api := &fakeAPI{}
	r := newRunner(t, api, nil, nil)
	r.response = &fakeResponseExecutor{}
	if err := r.cycle(context.Background(), fleetclient.Credential{Token: "token"}); err != nil {
		t.Fatal(err)
	}
	if len(api.heartbeatRequests) != 1 || len(api.heartbeatRequests[0].Capabilities) != 3 ||
		api.heartbeatRequests[0].Capabilities[1] != responseProcessCapability || api.heartbeatRequests[0].Capabilities[2] != responseHaltCapability {
		t.Fatalf("heartbeat capabilities=%+v", api.heartbeatRequests)
	}
}

func TestHeartbeatAppliesResponseHaltBeforeClaim(t *testing.T) {
	api := &fakeAPI{hbResp: fleetclient.HeartbeatResponse{ResponseHalted: true, ResponseHaltGeneration: 4}}
	executor := &fakeResponseExecutor{}
	r := newRunner(t, api, nil, nil)
	r.response = executor
	if err := r.cycle(context.Background(), fleetclient.Credential{Token: "token"}); err != nil {
		t.Fatal(err)
	}
	if len(executor.halts) != 1 || executor.halts[0] != 4 || api.claims != 1 {
		t.Fatalf("halt generations=%v claims=%d", executor.halts, api.claims)
	}
}

func TestHandleResponseHaltPersistsFenceAndReportsSuccess(t *testing.T) {
	api := &fakeAPI{}
	executor := &fakeResponseExecutor{}
	r := newRunner(t, api, nil, nil)
	r.response = executor
	command := &fleetagent.ResponseHaltCommand{
		CommandID: "halt-order-1", AgentID: "agent-1", AssetID: "asset-1", AttemptKey: "halt-attempt-1", Generation: 2,
	}
	r.handle(context.Background(), fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1", Token: "token"}, fleetclient.Order{
		ID: "halt-order-1", Capability: responseHaltCapability, AssetID: "asset-1", IdempotencyKey: "halt-attempt-1",
		LeaseID: "lease-1", LeaseUntil: time.Now().Add(time.Minute), ResponseHalt: command,
	})
	if executor.haltCommands != 1 || len(api.progressed) != 1 || len(api.results) != 1 || api.results[0].status != "succeeded" {
		t.Fatalf("halt commands=%d progressed=%v results=%+v", executor.haltCommands, api.progressed, api.results)
	}
}

func TestHandleResponseRejectsCrossAssetBeforeProgress(t *testing.T) {
	api := &fakeAPI{}
	executor := &fakeResponseExecutor{}
	r := newRunner(t, api, nil, nil)
	r.response = executor
	r.handle(context.Background(), fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1", Token: "token"}, fleetclient.Order{
		ID: "response-order-1", Capability: responseProcessCapability, AssetID: "asset-2", IdempotencyKey: "attempt-1", LeaseID: "lease-1", LeaseUntil: time.Now().Add(time.Minute),
		ResponseCommand: &fleetagent.ResponseCommand{CommandID: "response-order-1", AttemptKey: "attempt-1", AgentID: "agent-1", AssetID: "asset-2"},
	})
	if executor.calls != 0 || len(api.progressed) != 0 || len(api.results) != 1 || api.results[0].status != "failed" {
		t.Fatalf("cross-asset response reached execution: calls=%d progressed=%v results=%+v", executor.calls, api.progressed, api.results)
	}
}

func TestFlushResponseResultsRetriesDurableOutboxBeforeClaim(t *testing.T) {
	digest := strings.Repeat("d", 64)
	terminal := fleetagent.ResponseExecutionResult{
		AttemptKey: "attempt-1", CommandDigest: digest, LeaseID: "lease-1", State: fleetagent.ResponseExecutionApplied,
		ObservedRadius: "state_changing", AffectedCount: 1, CompletedAt: time.Now().UTC(),
	}
	executor := &fakeResponseExecutor{pending: []fleetagent.ResponseExecutionJournalEntry{{
		Command:       fleetagent.ResponseCommand{CommandID: "order-1", AttemptKey: terminal.AttemptKey},
		CommandDigest: digest, LeaseID: terminal.LeaseID, LeaseUntil: time.Now().Add(time.Minute), State: terminal.State, Result: &terminal,
	}}}
	api := &fakeAPI{responseResultErr: errors.New("control plane unavailable")}
	r := newRunner(t, api, nil, nil)
	r.response = executor
	cred := fleetclient.Credential{Token: "token"}
	if err := r.flushResponseResults(context.Background(), cred); err == nil || executor.acked != 0 || len(executor.pending) != 1 {
		t.Fatalf("failed delivery err=%v acked=%d pending=%d", err, executor.acked, len(executor.pending))
	}
	api.responseResultErr = nil
	if err := r.flushResponseResults(context.Background(), cred); err != nil || executor.acked != 1 || len(executor.pending) != 0 {
		t.Fatalf("retry err=%v acked=%d pending=%d", err, executor.acked, len(executor.pending))
	}
	if len(api.responseResults) != 1 || api.responseResults[0].AttemptKey != terminal.AttemptKey || api.responseResults[0].CommandDigest != digest ||
		api.responseResults[0].ObservedRadius != terminal.ObservedRadius || api.responseResults[0].AffectedCount != terminal.AffectedCount ||
		!api.responseResults[0].CompletedAt.Equal(terminal.CompletedAt) {
		t.Fatalf("submitted response results=%+v", api.responseResults)
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

func TestProducerControllerKeepsSamePolicyProducer(t *testing.T) {
	assignment := func() privacy.Assignment {
		assignment, err := privacyPolicyResponse(t).AssignmentDomain()
		if err != nil {
			t.Fatalf("AssignmentDomain() error = %v", err)
		}
		return assignment
	}()
	cancelled := false
	controller := producerController{
		digest: assignment.Digest,
		cancel: func() { cancelled = true },
		done:   make(chan struct{}),
	}
	if !controller.reconcile(t.Context(), nil, nil, assignment) {
		t.Fatal("reconcile rejected the running producer for the same policy digest")
	}
	if cancelled {
		t.Fatal("same policy digest restarted the running producer")
	}
}

func TestProducerControllerDoesNotActivateFailedPolicy(t *testing.T) {
	assignment := func() privacy.Assignment {
		assignment, err := privacyPolicyResponse(t).AssignmentDomain()
		if err != nil {
			t.Fatalf("AssignmentDomain() error = %v", err)
		}
		return assignment
	}()
	controller := producerController{}
	if controller.reconcile(t.Context(), &runner{}, nil, assignment) {
		t.Fatal("reconcile activated a policy whose producer failed to start")
	}
	if controller.digest != "" || controller.cancel != nil || controller.done != nil {
		t.Fatalf("failed producer left active controller state: digest=%q cancel=%v done=%v", controller.digest, controller.cancel != nil, controller.done != nil)
	}
}

func TestProducerControllerJoinsOldProducerBeforeFailedReplacement(t *testing.T) {
	assignment := func() privacy.Assignment {
		assignment, err := privacyPolicyResponse(t).AssignmentDomain()
		if err != nil {
			t.Fatalf("AssignmentDomain() error = %v", err)
		}
		return assignment
	}()
	oldDone := make(chan struct{})
	cancelled := false
	controller := producerController{
		digest: "old-policy-digest",
		cancel: func() {
			cancelled = true
			close(oldDone)
		},
		done: oldDone,
	}
	if controller.reconcile(t.Context(), &runner{}, nil, assignment) {
		t.Fatal("reconcile activated a replacement whose producer failed to start")
	}
	if !cancelled {
		t.Fatal("replacement did not cancel and join the old producer")
	}
	if controller.digest != "" || controller.cancel != nil || controller.done != nil {
		t.Fatalf("failed replacement retained stale controller state: digest=%q cancel=%v done=%v", controller.digest, controller.cancel != nil, controller.done != nil)
	}
}

func TestProducerControllerStopDisablesFutureReconciliation(t *testing.T) {
	assignment := func() privacy.Assignment {
		assignment, err := privacyPolicyResponse(t).AssignmentDomain()
		if err != nil {
			t.Fatalf("AssignmentDomain() error = %v", err)
		}
		return assignment
	}()
	done := make(chan struct{})
	controller := producerController{
		digest: assignment.Digest,
		cancel: func() { close(done) },
		done:   done,
	}
	controller.stop()
	if !controller.disabled || controller.cancel != nil || controller.done != nil {
		t.Fatalf("stopped controller state: disabled=%v cancel=%v done=%v", controller.disabled, controller.cancel != nil, controller.done != nil)
	}
	if controller.reconcile(t.Context(), nil, nil, assignment) {
		t.Fatal("stopped controller restarted source observation")
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

// resolvedFakeAPI is fakeAPI plus the resolved host-inventory response the production client returns.
type resolvedFakeAPI struct {
	*fakeAPI
	assetID  string
	resolved int
}

func (f *resolvedFakeAPI) SendHostInventoryResolved(_ context.Context, _ string, _ any) (fleetclient.HostInventoryResponse, error) {
	f.resolved++
	return fleetclient.HostInventoryResponse{AssetID: f.assetID}, nil
}

// TestSweepPersistsTheCanonicalAssetBinding pins the binding the whole detection pipeline waits on.
//
// The run loop starts the telemetry transport only once the credential carries the canonical asset id
// the control plane assigned. That id was persisted only from the work-order branch, and nothing in the
// product can issue a work order, so on a stock agent the field stayed empty for the life of the
// process and no detection was ever shipped. The inventory sweep already makes the server-side binding
// on every pass; it simply threw the answer away.
func TestSweepPersistsTheCanonicalAssetBinding(t *testing.T) {
	dir := t.TempDir()
	base := &fakeAPI{}
	api := &resolvedFakeAPI{fakeAPI: base, assetID: "asset-canonical-1"}
	r := &runner{
		api: api,
		collect: func(context.Context, string) (hostinventory.HostInventory, error) {
			return hostinventory.HostInventory{}, nil
		},
		cfg:   config{stateDir: dir, root: dir, name: "host1", enrolToken: "enrol"},
		store: fleetclient.NewCredentialStore(dir),
	}
	cred := fleetclient.Credential{Token: "tok", AgentID: "agent-1"}
	if err := r.store.Persist(cred, []byte("-----BEGIN PRIVATE KEY-----\nseed\n-----END PRIVATE KEY-----\n")); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	r.sweepOnce(t.Context(), cred)

	if api.resolved != 1 {
		t.Fatalf("sweep used the resolved inventory call %d times, want 1", api.resolved)
	}
	stored, ok := r.store.Load()
	if !ok {
		t.Fatal("credential disappeared")
	}
	if stored.AssetID != "asset-canonical-1" {
		t.Fatalf("stored asset id = %q, want the canonical id the control plane returned; without it the telemetry transport never starts", stored.AssetID)
	}
}
