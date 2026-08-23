// Package cloudsandbox executes credentialed cloud SDK helpers inside the hardened sandbox.
package cloudsandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const credentialFD = 4

type Executor struct {
	runner     ports.ToolRunner
	vault      ports.CredentialVault
	binary     string
	rate       int
	maxOutput  int
	timeout    time.Duration
	egressHost map[cloudposture.Provider][]string
}

var _ ports.CloudSandboxExecutor = (*Executor)(nil)

func New(runner ports.ToolRunner, vault ports.CredentialVault, binary string, rate int, timeout time.Duration, maxOutput int, egressHosts map[cloudposture.Provider][]string) (*Executor, error) {
	if runner == nil || vault == nil || strings.TrimSpace(binary) == "" || timeout <= 0 || maxOutput < 1 {
		return nil, fmt.Errorf("%w: invalid cloud sandbox executor", shared.ErrValidation)
	}
	return &Executor{runner: runner, vault: vault, binary: binary, rate: rate, timeout: timeout, maxOutput: maxOutput, egressHost: egressHosts}, nil
}

// diagnosticCap bounds how much helper stderr reaches an error message. The helper writes one
// short reason line; anything longer is a malfunction and must not become an unbounded log write.
const diagnosticCap = 512

// secretFieldMarkers name a credential field whose VALUE is secret material rather than a public
// identifier. Matching is on the field name, not the value: a credential document mixes secrets
// (private_key, client_secret, session_token) with identifiers that legitimately appear in enumerated
// inventory (a GCP client_email and project_id, an Azure subscription_id, an AWS account id). Value
// length cannot separate the two - a GCP client_email is long and public, an Azure client_secret may
// be short and secret - so any length threshold both over- and under-matches.
//
// This is a name heuristic and it errs toward scrubbing: "key" also matches AWS access_key_id, which
// is a semi-public identifier. That is deliberate - the current AWS connector enumerates IAM users,
// not access keys, so nothing legitimately emits one. If a future connector enumerates access keys it
// must rename the credential field or narrow this list, or a successful run will be rejected the way
// an unfiltered GCP client_email once was. A provider that names a secret generically (a bare
// "values" array) would likewise not be matched here; add a marker when one appears.
var secretFieldMarkers = []string{"secret", "password", "passwd", "passphrase", "token", "private", "credential", "key"}

// isSecretFieldName reports whether a JSON field name marks its value as secret material.
func isSecretFieldName(name string) bool {
	lowered := strings.ToLower(name)
	for _, marker := range secretFieldMarkers {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}

// walkCredential calls visit for every string value in a credential document, with the field name it
// was reached through (empty at the root). A non-JSON credential is opaque and yields no callbacks;
// callers always seed their set with the whole blob, so an unparseable credential echoed wholesale is
// still covered. The document is treated as opaque provider-shaped JSON on purpose: this executor is
// the shared sandbox path for every provider and must not import a concrete connector's credential
// type.
func walkCredential(secret []byte, visit func(name, value string)) {
	var document any
	if err := json.Unmarshal(secret, &document); err != nil {
		return
	}
	var walk func(name string, node any)
	walk = func(name string, node any) {
		switch typed := node.(type) {
		case map[string]any:
			for field, value := range typed {
				walk(field, value)
			}
		case []any:
			for _, value := range typed {
				walk(name, value) // elements inherit the field the array hangs off
			}
		case string:
			visit(name, typed)
		}
	}
	walk("", document)
}

// diagnosticSecrets is the scrub set for the DIAGNOSTIC sink: the whole document plus every string
// value in it, whatever its name or length. Provider SDK errors echo exactly one field in isolation
// ("The AWS Access Key Id you provided does not exist in our records: AKIA..."), which never matches
// the whole document, so the field would otherwise survive redaction and reach a structured log or a
// JSON API error body.
//
// This set is deliberately maximal. The only cost of a false match here is that diagnostic() drops
// the reason text; the cost of a miss is credential disclosure. Every field is therefore in scope
// regardless of length - an Azure client_secret is only validated non-empty, so a short secret must
// not slip through a length threshold.
func diagnosticSecrets(secret []byte) [][]byte {
	secrets := [][]byte{secret}
	walkCredential(secret, func(_, value string) {
		if value != "" {
			secrets = append(secrets, []byte(value))
		}
	})
	return secrets
}

// outputSecrets is the scrub set for the helper's STDOUT: the whole document plus only the values
// whose field name marks them as secret material.
//
// Stdout is load-bearing data, not a diagnostic - a placeholder hit REJECTS the whole enumeration -
// so this set must not contain public identifiers the helper legitimately emits. A GCP credential's
// client_email appears verbatim in enumerated IAM bindings and its project_id in every resource ID,
// so scrubbing every field here would fail every GCP run with "output contained credential material"
// after the helper had already succeeded. Real secret fields are still scrubbed at any length, and
// the whole-document match still catches a wholesale echo of an unparseable credential.
func outputSecrets(secret []byte) [][]byte {
	secrets := [][]byte{secret}
	walkCredential(secret, func(name, value string) {
		if value != "" && isSecretFieldName(name) {
			secrets = append(secrets, []byte(value))
		}
	})
	return secrets
}

// diagnostic renders the helper's stderr as a bounded, credential-free error suffix. Without it a
// failing helper surfaces only "exit_code=1", which says nothing about WHY posture enumeration
// failed and makes an operator-fixable misconfiguration (bad role ARN, denied API, blocked egress)
// indistinguishable from a crash. Every credential value is redacted first and, if any placeholder
// survives, the text is dropped entirely rather than risking secret material in a log or API error.
func diagnostic(stderr []byte, secrets [][]byte) string {
	redacted := redact.Bytes(stderr, secrets)
	if strings.Contains(string(redacted), redact.Placeholder) {
		return " reason=<redacted>"
	}
	reason := strings.TrimSpace(string(redacted))
	if reason == "" {
		return ""
	}
	// Coerce to valid UTF-8 unconditionally, not only when truncating: a helper can emit a latin-1
	// provider message or a partial write that is invalid UTF-8 well under the cap, and this string
	// lands in a structured log and a JSON error body. ToValidUTF8 also makes the truncation below
	// safe to do on a byte offset walked back to a rune boundary.
	reason = strings.ToValidUTF8(reason, "�")
	if len(reason) > diagnosticCap {
		cut := diagnosticCap
		for cut > 0 && !utf8.ValidString(reason[:cut]) {
			cut--
		}
		reason = reason[:cut] + "…"
	}
	// Collapse to a single line: these reasons land in structured logs and JSON error bodies.
	reason = strings.Join(strings.Fields(reason), " ")
	return " reason=" + reason
}

func (e *Executor) EnumerateCloud(ctx context.Context, scope ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	if scope.Authorize == nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("%w: cloud operation authorizer is required", shared.ErrForbidden)
	}
	input, err := json.Marshal(struct {
		Scope ports.CloudScope `json:"scope"`
		Rate  int              `json:"rate"`
	}{scope, e.rate})
	if err != nil {
		return cloudposture.Inventory{}, nil, err
	}
	hosts := e.egressHost[scope.Provider]
	if len(hosts) == 0 {
		return cloudposture.Inventory{}, nil, fmt.Errorf("%w: no CSPM egress hosts configured for %s", shared.ErrValidation, scope.Provider)
	}
	if strings.TrimSpace(scope.EgressExecutionKind) == "" || strings.TrimSpace(scope.EgressExecutionID) == "" {
		return cloudposture.Inventory{}, nil, fmt.Errorf("%w: CSPM execution requires authoritative signed execution grants", shared.ErrValidation)
	}
	policy := &ports.EgressPolicy{}
	for _, host := range hosts {
		policy.AllowDomainRules = append(policy.AllowDomainRules, ports.DomainRule{Host: host, Ports: []uint16{443}})
	}
	secret, err := e.vault.Resolve(ctx, scope.EngagementID, scope.CredentialRef)
	if err != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("resolve CSPM credential: %w", err)
	}
	defer clear(secret)
	credentialR, credentialW, err := os.Pipe()
	if err != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("create CSPM credential pipe: %w", err)
	}
	defer func() { _ = credentialR.Close() }()
	go func() {
		_, _ = credentialW.Write(secret)
		_ = credentialW.Close()
	}()
	requestR, requestW, err := os.Pipe()
	if err != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("create CSPM authorization request pipe: %w", err)
	}
	defer func() { _ = requestR.Close() }()
	decisionR, decisionW, err := os.Pipe()
	if err != nil {
		_ = requestW.Close()
		return cloudposture.Inventory{}, nil, fmt.Errorf("create CSPM authorization decision pipe: %w", err)
	}
	defer func() { _ = decisionR.Close() }()
	var authErr error
	var authOnce sync.Once
	authDone := make(chan struct{})
	go func() {
		defer close(authDone)
		decoder := json.NewDecoder(bufio.NewReader(requestR))
		encoder := json.NewEncoder(decisionW)
		for {
			var operation ports.CloudOperation
			if err := decoder.Decode(&operation); err != nil {
				if err != io.EOF {
					authOnce.Do(func() { authErr = fmt.Errorf("read CSPM authorization request: %w", err) })
				}
				return
			}
			if operation.Provider != scope.Provider || operation.ScopeKey != scope.ScopeKey {
				authOnce.Do(func() { authErr = fmt.Errorf("%w: CSPM authorization scope mismatch", shared.ErrForbidden) })
				_ = encoder.Encode(struct {
					Allowed bool `json:"allowed"`
				}{})
				return
			}
			authorizationErr := scope.Authorize(ctx, operation)
			allowed := authorizationErr == nil
			if authorizationErr != nil {
				authOnce.Do(func() { authErr = fmt.Errorf("authorize CSPM operation: %w", authorizationErr) })
			}
			if err := encoder.Encode(struct {
				Allowed bool `json:"allowed"`
			}{allowed}); err != nil {
				authOnce.Do(func() { authErr = fmt.Errorf("write CSPM authorization decision: %w", err) })
				return
			}
			if !allowed {
				return
			}
		}
	}()
	result, runErr := e.runner.Run(ctx, ports.ToolSpec{
		Name: e.binary, Stdin: input, Timeout: e.timeout, MaxOutputBytes: e.maxOutput,
		EngagementID: scope.EngagementID, EgressPolicy: policy,
		EgressExecutionKind: scope.EgressExecutionKind, EgressExecutionID: scope.EgressExecutionID,
		ExtraFiles: []*os.File{credentialR, requestW, decisionR},
		Env: []string{
			fmt.Sprintf("SYNAPSE_CSPM_CREDENTIAL_FD=%d", credentialFD),
			"SYNAPSE_CSPM_AUTH_REQUEST_FD=5",
			"SYNAPSE_CSPM_AUTH_DECISION_FD=6",
		},
	})
	_ = requestW.Close()
	_ = decisionR.Close()
	<-authDone
	_ = decisionW.Close()
	if authErr != nil {
		return cloudposture.Inventory{}, nil, authErr
	}
	if runErr != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("sandboxed CSPM helper failed: %w", runErr)
	}
	// The two sinks get DIFFERENT scrub sets because they tolerate a false match differently: a
	// diagnostic can be dropped, but stdout is the enumeration result and a placeholder hit rejects
	// the whole run. See diagnosticSecrets and outputSecrets.
	if result.ExitCode != 0 || result.TimedOut || result.Truncated {
		return cloudposture.Inventory{}, nil, fmt.Errorf("sandboxed CSPM helper failed: exit_code=%d timed_out=%t truncated=%t%s", result.ExitCode, result.TimedOut, result.Truncated, diagnostic(result.Stderr, diagnosticSecrets(secret)))
	}
	result.Stdout = redact.Bytes(result.Stdout, outputSecrets(secret))
	if strings.Contains(string(result.Stdout), redact.Placeholder) {
		return cloudposture.Inventory{}, nil, errors.New("sandboxed CSPM output contained credential material")
	}
	var output struct {
		Inventory cloudposture.Inventory       `json:"inventory"`
		Coverage  []cloudposture.CoverageIssue `json:"coverage"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(result.Stdout)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("decode sandboxed CSPM output: %w", err)
	}
	return output.Inventory, output.Coverage, nil
}
