package cloudsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type runnerStub struct {
	spec      ports.ToolSpec
	result    ports.ToolResult
	err       error
	operation ports.CloudOperation
	// passthroughStdout returns result.Stdout verbatim instead of the canned inventory, so a test can
	// drive the executor's own stdout scrub over chosen helper output.
	passthroughStdout bool
}

func (r *runnerStub) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	r.spec = spec
	if len(spec.ExtraFiles) == 3 {
		operation := r.operation
		if operation.Provider == "" {
			operation = ports.CloudOperation{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-test", Name: "ListAccounts"}
		}
		_ = json.NewEncoder(spec.ExtraFiles[1]).Encode(operation)
		_ = spec.ExtraFiles[1].Close()
		var decision struct {
			Allowed bool `json:"allowed"`
		}
		if err := json.NewDecoder(spec.ExtraFiles[2]).Decode(&decision); err != nil || !decision.Allowed {
			return ports.ToolResult{}, fmt.Errorf("authorization denied: %v", err)
		}
	}
	out, _ := json.Marshal(struct {
		Inventory cloudposture.Inventory       `json:"inventory"`
		Coverage  []cloudposture.CoverageIssue `json:"coverage"`
	}{Inventory: cloudposture.Inventory{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-test", Complete: true}})
	if r.err != nil {
		return ports.ToolResult{}, r.err
	}
	if r.result.ExitCode != 0 || r.result.TimedOut || r.result.Truncated {
		return r.result, nil
	}
	if r.passthroughStdout {
		return r.result, nil
	}
	return ports.ToolResult{Stdout: out}, nil
}

func TestExecutorUsesSecretPlaceholderAndDefaultDenyEgress(t *testing.T) {
	runner := &runnerStub{}
	executor, err := New(runner, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", EgressExecutionKind: "cspm", EgressExecutionID: "run-1", Authorize: func(_ context.Context, operation ports.CloudOperation) error {
		if operation.Provider != cloudposture.ProviderAWS || operation.ScopeKey != "aws:organizations/o-test" || operation.Name != "ListAccounts" {
			t.Fatalf("operation = %#v", operation)
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if runner.spec.EgressPolicy == nil || len(runner.spec.EgressPolicy.AllowDomainRules) != 1 || runner.spec.HostNetwork {
		t.Fatalf("egress policy = %#v", runner.spec.EgressPolicy)
	}
	if runner.spec.EgressExecutionKind != "cspm" || runner.spec.EgressExecutionID != "run-1" {
		t.Fatalf("execution identity = %q/%q", runner.spec.EgressExecutionKind, runner.spec.EgressExecutionID)
	}
	if len(runner.spec.Env) != 3 || runner.spec.Env[0] != "SYNAPSE_CSPM_CREDENTIAL_FD=4" || runner.spec.Env[1] != "SYNAPSE_CSPM_AUTH_REQUEST_FD=5" || runner.spec.Env[2] != "SYNAPSE_CSPM_AUTH_DECISION_FD=6" || len(runner.spec.ExtraFiles) != 3 {
		t.Fatalf("env=%#v files=%d", runner.spec.Env, len(runner.spec.ExtraFiles))
	}
}

func TestExecutorRejectsMissingExecutionIdentityBeforeSecretResolution(t *testing.T) {
	runner := &runnerStub{}
	resolved := false
	executor, err := New(runner, secretVault{
		secret:  []byte("must-not-resolve"),
		resolve: func() { resolved = true },
	}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{
		EngagementID: "eng", Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-test",
		CredentialRef: "aws-prod", Authorize: func(context.Context, ports.CloudOperation) error { return nil },
	})
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "authoritative signed execution grants") {
		t.Fatalf("EnumerateCloud() error = %v, want signed-grant validation", err)
	}
	if resolved {
		t.Fatal("credential vault was resolved before execution identity validation")
	}
	if runner.spec.Name != "" {
		t.Fatalf("runner reached with spec %#v", runner.spec)
	}
}

func TestExecutorPreservesRunnerFailure(t *testing.T) {
	runErr := errors.New("sandbox unavailable")
	executor, err := New(&runnerStub{err: runErr}, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", EgressExecutionKind: "cspm", EgressExecutionID: "run-1", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if !errors.Is(err, runErr) {
		t.Fatalf("error = %v", err)
	}
}

func TestExecutorReportsHelperExitState(t *testing.T) {
	executor, err := New(&runnerStub{result: ports.ToolResult{ExitCode: 3, TimedOut: true}}, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", EgressExecutionKind: "cspm", EgressExecutionID: "run-1", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "exit_code=3 timed_out=true truncated=false") {
		t.Fatalf("error = %v", err)
	}
}

func TestExecutorPreservesAuthorizationDenial(t *testing.T) {
	executor, err := New(&runnerStub{}, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", EgressExecutionKind: "cspm", EgressExecutionID: "run-1", Authorize: func(context.Context, ports.CloudOperation) error { return shared.ErrForbidden }})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("error = %v", err)
	}
}

func TestExecutorClassifiesAuthorizationScopeMismatchAsForbidden(t *testing.T) {
	runner := &runnerStub{}
	runner.operation = ports.CloudOperation{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-other", Name: "ListAccounts"}
	executor, err := New(runner, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", EgressExecutionKind: "cspm", EgressExecutionID: "run-1", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("error = %v", err)
	}
}

type nilVault struct{}

func (nilVault) Resolve(context.Context, shared.ID, string) ([]byte, error)      { return nil, nil }
func (nilVault) Put(context.Context, shared.ID, string, []byte) error            { return nil }
func (nilVault) List(context.Context, shared.ID) ([]ports.CredentialMeta, error) { return nil, nil }
func (nilVault) Delete(context.Context, shared.ID, string) error                 { return nil }

// secretVault hands out real credential material so the redaction path is exercised for real
// rather than against nilVault's empty secret.
type secretVault struct {
	secret  []byte
	resolve func()
}

func (v secretVault) Resolve(context.Context, shared.ID, string) ([]byte, error) {
	if v.resolve != nil {
		v.resolve()
	}
	return append([]byte(nil), v.secret...), nil
}
func (secretVault) Put(context.Context, shared.ID, string, []byte) error            { return nil }
func (secretVault) List(context.Context, shared.ID) ([]ports.CredentialMeta, error) { return nil, nil }
func (secretVault) Delete(context.Context, shared.ID, string) error                 { return nil }

// TestExecutorSurfacesHelperStderr pins the helper's failure REASON onto the error. The executor
// used to report only "exit_code=1", so an operator-fixable misconfiguration (unassumable role,
// denied API, blocked egress) was indistinguishable from a crash: the durable run dead-lettered
// after three attempts with no recorded cause anywhere in the worker log or the run row.
func TestExecutorSurfacesHelperStderr(t *testing.T) {
	runner := &runnerStub{result: ports.ToolResult{ExitCode: 1, Stderr: []byte("enumerate accounts: AccessDenied\n")}}
	executor, err := New(runner, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", EgressExecutionKind: "cspm", EgressExecutionID: "run-1", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if err == nil {
		t.Fatal("expected a helper failure")
	}
	if !strings.Contains(err.Error(), "exit_code=1") {
		t.Errorf("error = %v, want the exit code preserved", err)
	}
	if !strings.Contains(err.Error(), "reason=enumerate accounts: AccessDenied") {
		t.Errorf("error = %v, want the helper's stderr reason", err)
	}
}

// TestExecutorNeverLeaksCredentialsThroughStderr is the other half of the contract: stderr is
// attacker-influenced, untrusted output on a credentialed path, so a helper that echoes its own
// credential must not turn an error message into a secret sink.
func TestExecutorNeverLeaksCredentialsThroughStderr(t *testing.T) {
	const secret = "AKIAEXAMPLECANARY"
	runner := &runnerStub{result: ports.ToolResult{ExitCode: 1, Stderr: []byte("failed for key " + secret)}}
	executor, err := New(runner, secretVault{secret: []byte(secret)}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", EgressExecutionKind: "cspm", EgressExecutionID: "run-1", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if err == nil {
		t.Fatal("expected a helper failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("credential material leaked into the error message")
	}
	if !strings.Contains(err.Error(), "reason=<redacted>") {
		t.Errorf("error = %v, want the reason dropped once a placeholder survives", err)
	}
}

// TestDiagnosticBoundsAndNormalizesReason keeps the suffix log-safe: empty stderr adds nothing, and
// a malfunctioning helper cannot emit an unbounded multi-line blob into a structured log field.
func TestDiagnosticBoundsAndNormalizesReason(t *testing.T) {
	if got := diagnostic(nil, nil); got != "" {
		t.Errorf("diagnostic(nil) = %q, want empty", got)
	}
	if got := diagnostic([]byte("  \n\t "), nil); got != "" {
		t.Errorf("diagnostic(whitespace) = %q, want empty", got)
	}
	if got := diagnostic([]byte("first line\nsecond line"), nil); got != " reason=first line second line" {
		t.Errorf("diagnostic(multiline) = %q, want a single line", got)
	}
	long := diagnostic([]byte(strings.Repeat("x", diagnosticCap*3)), nil)
	if len(long) > diagnosticCap+len(" reason=")+len("…") {
		t.Errorf("diagnostic(long) length = %d, want bounded by diagnosticCap", len(long))
	}
}

// TestExecutorRedactsIndividualCredentialFields is the review finding this file previously missed.
// A provider credential is a JSON document with several secret-bearing fields, and provider SDK
// errors echo exactly ONE of them in isolation ("The AWS Access Key Id you provided does not exist
// in our records: AKIA..."). Scrubbing only the whole document never matches that substring, so the
// field survived redaction, passed the placeholder check, and reached the returned error - which by
// diagnostic's own contract lands in structured logs and JSON API error bodies.
func TestExecutorRedactsIndividualCredentialFields(t *testing.T) {
	const (
		accessKeyID = "AKIAIOSFODNN7EXAMPLE"
		secretKey   = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY123"
		sessionTok  = "FwoGZXIvYXdzEBYaDEXAMPLESESSIONTOKENVALUE"
	)
	document := `{"access_key_id":"` + accessKeyID + `","secret_access_key":"` + secretKey +
		`","session_token":"` + sessionTok + `","role_arn_template":"arn:aws:iam::{account_id}:role/Reader"}`

	for _, tc := range []struct {
		name   string
		stderr string
		leaked string
	}{
		{"access key id alone", "The AWS Access Key Id you provided does not exist in our records: " + accessKeyID, accessKeyID},
		{"secret access key alone", "signature mismatch for key " + secretKey, secretKey},
		{"session token alone", "expired session token " + sessionTok, sessionTok},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &runnerStub{result: ports.ToolResult{ExitCode: 1, Stderr: []byte(tc.stderr)}}
			executor, err := New(runner, secretVault{secret: []byte(document)}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", EgressExecutionKind: "cspm", EgressExecutionID: "run-1", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
			if err == nil {
				t.Fatal("expected a helper failure")
			}
			if strings.Contains(err.Error(), tc.leaked) {
				t.Fatalf("credential field leaked into the error message: %v", err)
			}
			if !strings.Contains(err.Error(), "reason=<redacted>") {
				t.Errorf("error = %v, want the reason dropped once a credential field is detected", err)
			}
		})
	}
}

// has reports whether the scrub set contains an exact value.
func hasSecret(secrets [][]byte, want string) bool {
	for _, secret := range secrets {
		if string(secret) == want {
			return true
		}
	}
	return false
}

// gcpCredential mirrors a real GCP service-account key: PUBLIC identifiers (client_email, project_id)
// sitting next to actual secret material (private_key).
const gcpCredential = `{"type":"service_account","project_id":"synapse-e2e-project","private_key":"-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg-----END PRIVATE KEY-----","client_email":"synapse-cspm@synapse-e2e-project.iam.gserviceaccount.com","client_id":"114857320991827364550"}`

// TestDiagnosticSecretsCoversEveryFieldAtAnyLength pins the DIAGNOSTIC set as maximal. A provider SDK
// error echoes one field in isolation, which never matches the whole document, and the only cost of a
// false match here is that the reason text is dropped. Length must not gate membership: an Azure
// client_secret is validated non-empty only, so a SHORT secret has to be covered too.
func TestDiagnosticSecretsCoversEveryFieldAtAnyLength(t *testing.T) {
	document := []byte(`{"tenant_id":"t","client_id":"c","client_secret":"sh0rt","subscription_id":"sub-1234"}`)
	got := diagnosticSecrets(document)
	if !hasSecret(got, string(document)) {
		t.Error("the whole credential document must stay in the scrub set")
	}
	for _, value := range []string{"sh0rt", "sub-1234", "t", "c"} {
		if !hasSecret(got, value) {
			t.Errorf("field value %q is not scrubbed in a diagnostic; a short secret must not slip a length threshold", value)
		}
	}
	// Nested and array-wrapped values are reached too.
	nested := diagnosticSecrets([]byte(`{"outer":{"session_token":"nested-token"},"list":["listed-token"]}`))
	if !hasSecret(nested, "nested-token") || !hasSecret(nested, "listed-token") {
		t.Errorf("nested/array credential values were not decomposed: %q", nested)
	}
	if opaque := diagnosticSecrets([]byte("not-json-credential-material")); len(opaque) != 1 {
		t.Errorf("opaque credential produced %d secrets, want just the blob", len(opaque))
	}
}

// TestOutputSecretsExcludesPublicIdentifiers pins the STDOUT set as narrow, and is the regression
// guard for the review finding that a maximal set breaks every GCP run. Stdout is the enumeration
// result, not a diagnostic: a placeholder hit REJECTS the run. A GCP client_email appears verbatim in
// enumerated IAM bindings and project_id in every resource ID, so scrubbing them would fail a
// successful enumeration with "output contained credential material".
func TestOutputSecretsExcludesPublicIdentifiers(t *testing.T) {
	got := outputSecrets([]byte(gcpCredential))
	if !hasSecret(got, string(gcpCredential)) {
		t.Error("the whole credential document must stay in the scrub set")
	}
	if !hasSecret(got, "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg-----END PRIVATE KEY-----") {
		t.Error("private_key is real secret material and must be scrubbed from stdout")
	}
	for _, public := range []string{
		"synapse-cspm@synapse-e2e-project.iam.gserviceaccount.com", // appears in enumerated IAM bindings
		"synapse-e2e-project", // appears in every resource ID
		"service_account",
	} {
		if hasSecret(got, public) {
			t.Errorf("public identifier %q is scrubbed from stdout; that rejects a successful enumeration", public)
		}
	}
}

// TestOutputScrubKeepsLegitimateInventory drives the full executor: a helper that emits its own
// client_email and project_id in normal inventory - exactly what the GCP connector does - must still
// have its output accepted.
func TestOutputScrubKeepsLegitimateInventory(t *testing.T) {
	inventory, err := json.Marshal(struct {
		Inventory cloudposture.Inventory       `json:"inventory"`
		Coverage  []cloudposture.CoverageIssue `json:"coverage"`
	}{Inventory: cloudposture.Inventory{
		Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-test", Complete: true,
		Resources: []cloudposture.Resource{{
			Provider: cloudposture.ProviderAWS,
			ID:       "projects/synapse-e2e-project/iam/roles~owner/serviceAccount:synapse-cspm@synapse-e2e-project.iam.gserviceaccount.com",
			Name:     "synapse-cspm@synapse-e2e-project.iam.gserviceaccount.com",
			Kind:     asset.KindIdentity,
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &runnerStub{result: ports.ToolResult{Stdout: inventory}, passthroughStdout: true}
	executor, err := New(runner, secretVault{secret: []byte(gcpCredential)}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "gcp-prod", EgressExecutionKind: "cspm", EgressExecutionID: "run-1", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if err != nil {
		t.Fatalf("legitimate inventory was rejected: %v", err)
	}
	if len(got.Resources) != 1 || got.Resources[0].Name == "" {
		t.Fatalf("inventory = %#v, want the enumerated identity preserved", got.Resources)
	}
}

// TestDiagnosticTruncatesOnARuneBoundary keeps the suffix valid UTF-8. A byte-offset cut can split a
// multi-byte rune and emit invalid UTF-8 into a structured log and a JSON error body, and the
// strings.Fields pass afterwards does not repair it.
func TestDiagnosticTruncatesOnARuneBoundary(t *testing.T) {
	// "é" is two bytes, so a diagnosticCap-byte cut lands mid-rune for some repetition counts.
	for _, filler := range []string{"é", "字", "🔒"} {
		reason := strings.Repeat(filler, diagnosticCap)
		got := diagnostic([]byte(reason), nil)
		if !utf8.ValidString(got) {
			t.Errorf("diagnostic(%q...) produced invalid UTF-8", filler)
		}
		if len(got) > diagnosticCap+len(" reason=")+len("…") {
			t.Errorf("diagnostic(%q...) length = %d, want bounded", filler, len(got))
		}
	}
}
