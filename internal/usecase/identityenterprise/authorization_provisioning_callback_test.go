package identityenterprise

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type callbackFailureFactory struct {
	fail  bool
	calls int
}

func (f *callbackFailureFactory) ProviderForConnection(context.Context, ports.IdentityConnection) (ports.OIDCProvider, error) {
	f.calls++
	if f.fail {
		return nil, errors.New("provider factory unavailable")
	}
	return authProvider{}, nil
}

type provisioningCallbackFixture struct {
	clock        authClock
	store        *provisioningMemory
	provisioning *Provisioning
	connections  *testRecordingConnections
	transactions *authTransactions
	protocol     *Service
	capability   string
	state        string
}

func newProvisioningCallbackFixture(t *testing.T, factory ports.IdentityOIDCProviderFactory) provisioningCallbackFixture {
	t.Helper()
	clock := authClock{time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)}
	store := &provisioningMemory{}
	provisioning := provisioningService(t, store, clock, "current")
	operation, capability, err := provisioning.Begin(t.Context(), provisioningActor(), "destination", "admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	store.state.State = "draft"
	connections, transactions := &testRecordingConnections{}, &authTransactions{}
	protocol := bindingTestService(t, "current", connections, transactions, clock, factory)
	if err = protocol.SetProvisioning(provisioning); err != nil {
		t.Fatal(err)
	}
	started, err := protocol.Begin(t.Context(), BeginInput{TenantID: operation.TenantID, ConnectionID: operation.ConnectionID, Revision: 1, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "browser", ProvisioningToken: capability})
	if err != nil {
		t.Fatal(err)
	}
	return provisioningCallbackFixture{
		clock: clock, store: store, provisioning: provisioning, connections: connections, transactions: transactions,
		protocol: protocol, capability: capability, state: strings.TrimPrefix(started.AuthorizationURL, "https://issuer.example/auth?state="),
	}
}

func provisioningCallbackInput(state, caller, code string) CallbackInput {
	return CallbackInput{TenantID: "destination", State: state, CallerNonce: caller, Code: code}
}

func TestProvisioningTestBeginRejectsIneligibleOperationStateBeforeProviderOrTransaction(t *testing.T) {
	for _, operationState := range []string{"open", "closed", "active", "invited"} {
		t.Run(operationState, func(t *testing.T) {
			clock := authClock{time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)}
			store := &provisioningMemory{}
			provisioning := provisioningService(t, store, clock, "current")
			operation, capability, err := provisioning.Begin(t.Context(), provisioningActor(), "destination", "admin@example.test")
			if err != nil {
				t.Fatal(err)
			}
			store.state.State = operationState
			factory := &callbackFailureFactory{}
			transactions := &authTransactions{}
			protocol := bindingTestService(t, "current", &testRecordingConnections{}, transactions, clock, factory)
			if err = protocol.SetProvisioning(provisioning); err != nil {
				t.Fatal(err)
			}

			_, err = protocol.Begin(t.Context(), BeginInput{TenantID: operation.TenantID, ConnectionID: operation.ConnectionID, Revision: 1, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "browser", ProvisioningToken: capability})
			if !errors.Is(err, shared.ErrForbidden) || factory.calls != 0 || !transactions.v.ID.IsZero() {
				t.Fatalf("ineligible operation started provider or transaction: err=%v calls=%d transaction=%+v", err, factory.calls, transactions.v)
			}
		})
	}
}

func TestProvisioningTestCallbackAfterClosureBurnsStateBeforeProviderOrRecord(t *testing.T) {
	factory := &callbackFailureFactory{}
	f := newProvisioningCallbackFixture(t, factory)
	providerCalls := factory.calls
	f.store.state.State = "closed"

	_, err := f.protocol.Callback(t.Context(), provisioningCallbackInput(f.state, "browser", "code"))
	var setup *ProvisioningCallbackError
	if !errors.Is(err, shared.ErrForbidden) || errors.As(err, &setup) || !f.transactions.consumed || f.store.tests != 0 || factory.calls != providerCalls {
		t.Fatalf("closed operation callback reached provider, record, or setup return: err=%v setup=%+v consumed=%v tests=%d calls=%d want=%d", err, setup, f.transactions.consumed, f.store.tests, factory.calls, providerCalls)
	}
}

func TestProvisioningCallbackCancellationReturnsTrustedSetupErrorForTestedOperation(t *testing.T) {
	f := newProvisioningCallbackFixture(t, authFactory{})
	f.store.state.State = "tested"

	_, err := f.protocol.Callback(t.Context(), provisioningCallbackInput(f.state, "browser", ""))
	var setup *ProvisioningCallbackError
	if !errors.As(err, &setup) || setup.TenantID != "destination" || f.store.tests != 0 || !f.transactions.consumed {
		t.Fatalf("tested operation cancellation did not return setup error safely: err=%v setup=%+v tests=%d consumed=%v", err, setup, f.store.tests, f.transactions.consumed)
	}
}

func TestProvisioningCallbackCancellationReturnsTrustedSetupErrorAndSameOperationCanRetry(t *testing.T) {
	f := newProvisioningCallbackFixture(t, authFactory{})
	_, err := f.protocol.Callback(t.Context(), provisioningCallbackInput(f.state, "browser", ""))
	var setup *ProvisioningCallbackError
	if !errors.As(err, &setup) || setup.TenantID != "destination" || f.store.tests != 0 || !f.transactions.consumed {
		t.Fatalf("cancellation did not consume trusted provisioning callback safely: err=%v setup=%+v tests=%d consumed=%v", err, setup, f.store.tests, f.transactions.consumed)
	}

	// Provider cancellation burns its one-use transaction, but it does not consume the scoped
	// provisioning capability. A subsequent Test starts a new transaction for the same operation.
	retryTransactions := &authTransactions{}
	retry := bindingTestService(t, "current", f.connections, retryTransactions, f.clock, authFactory{})
	if err = retry.SetProvisioning(f.provisioning); err != nil {
		t.Fatal(err)
	}
	started, err := retry.Begin(t.Context(), BeginInput{TenantID: "destination", ConnectionID: f.store.state.ConnectionID, Revision: 1, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "retry", ProvisioningToken: f.capability})
	if err != nil {
		t.Fatalf("same operation could not start a retry: %v", err)
	}
	state := strings.TrimPrefix(started.AuthorizationURL, "https://issuer.example/auth?state=")
	result, err := retry.Callback(t.Context(), provisioningCallbackInput(state, "retry", "code"))
	if err != nil || result.ProvisioningTenantID != "destination" || f.store.tests != 1 {
		t.Fatalf("same operation retry did not record its real Test: result=%+v err=%v tests=%d", result, err, f.store.tests)
	}
}

func TestProvisioningCallbackCancellationRejectsUntrustedContext(t *testing.T) {
	for _, tc := range []struct {
		name         string
		wantConsumed bool
		mutate       func(*provisioningCallbackFixture) CallbackInput
	}{
		{name: "bad state", mutate: func(f *provisioningCallbackFixture) CallbackInput {
			return provisioningCallbackInput("wrong-state", "browser", "")
		}},
		{name: "wrong caller nonce", mutate: func(f *provisioningCallbackFixture) CallbackInput {
			return provisioningCallbackInput(f.state, "wrong-caller", "")
		}},
		{name: "forged context", wantConsumed: true, mutate: func(f *provisioningCallbackFixture) CallbackInput {
			f.transactions.v.ContextSealed = `{"nonce":"forged","initial_provisioning":"forged"}`
			return provisioningCallbackInput(f.state, "browser", "")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProvisioningCallbackFixture(t, authFactory{})
			_, err := f.protocol.Callback(t.Context(), tc.mutate(&f))
			var setup *ProvisioningCallbackError
			if err == nil || errors.As(err, &setup) || f.store.tests != 0 || f.transactions.consumed != tc.wantConsumed {
				t.Fatalf("untrusted cancellation produced setup return or wrong state consumption: err=%v setup=%+v tests=%d consumed=%v", err, setup, f.store.tests, f.transactions.consumed)
			}
		})
	}
}

func TestProvisioningCallbackCancellationRejectsRotatedBootstrapCapability(t *testing.T) {
	f := newProvisioningCallbackFixture(t, authFactory{})
	rotated := provisioningService(t, f.store, f.clock, "replacement")
	protocol := bindingTestService(t, "replacement", f.connections, f.transactions, f.clock, authFactory{})
	if err := protocol.SetProvisioning(rotated); err != nil {
		t.Fatal(err)
	}
	_, err := protocol.Callback(t.Context(), provisioningCallbackInput(f.state, "browser", ""))
	var setup *ProvisioningCallbackError
	if !errors.Is(err, shared.ErrForbidden) || errors.As(err, &setup) || f.store.tests != 0 || !f.transactions.consumed {
		t.Fatalf("rotated bootstrap capability produced setup return or mutation: err=%v setup=%+v tests=%d consumed=%v", err, setup, f.store.tests, f.transactions.consumed)
	}
}

func TestProvisioningCallbackProviderFactoryFailureReturnsTrustedSetupError(t *testing.T) {
	factory := &callbackFailureFactory{}
	f := newProvisioningCallbackFixture(t, factory)
	factory.fail = true
	_, err := f.protocol.Callback(t.Context(), provisioningCallbackInput(f.state, "browser", "code"))
	var setup *ProvisioningCallbackError
	if !errors.As(err, &setup) || setup.TenantID != "destination" || f.store.tests != 0 || !f.transactions.consumed {
		t.Fatalf("trusted provider factory failure did not return setup error safely: err=%v setup=%+v tests=%d consumed=%v", err, setup, f.store.tests, f.transactions.consumed)
	}
}
