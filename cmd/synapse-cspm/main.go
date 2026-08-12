// Command synapse-cspm is the sandboxed CSPM SDK helper. It reads one bounded scope from stdin,
// resolves one credential supplied by the parent sandbox environment, and emits normalized JSON.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	cloudaws "github.com/KKloudTarus/synapse-ce/internal/infrastructure/cloud/aws"
	cloudazure "github.com/KKloudTarus/synapse-ce/internal/infrastructure/cloud/azure"
	cloudgcp "github.com/KKloudTarus/synapse-ce/internal/infrastructure/cloud/gcp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const inputCap = 64 << 10

type helperInput struct {
	Scope ports.CloudScope `json:"scope"`
	Rate  int              `json:"rate"`
}

type helperOutput struct {
	Inventory cloudposture.Inventory       `json:"inventory"`
	Coverage  []cloudposture.CoverageIssue `json:"coverage"`
}

type envVault struct{ secret []byte }

func (v envVault) Resolve(context.Context, shared.ID, string) ([]byte, error) {
	return append([]byte(nil), v.secret...), nil
}
func (envVault) Put(context.Context, shared.ID, string, []byte) error {
	return fmt.Errorf("read-only helper vault")
}
func (envVault) List(context.Context, shared.ID) ([]ports.CredentialMeta, error) { return nil, nil }
func (envVault) Delete(context.Context, shared.ID, string) error {
	return fmt.Errorf("read-only helper vault")
}

func main() {
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, inputCap))
	decoder.DisallowUnknownFields()
	var input helperInput
	if err := decoder.Decode(&input); err != nil {
		fail("decode input")
	}
	fd, err := strconv.Atoi(os.Getenv("SYNAPSE_CSPM_CREDENTIAL_FD"))
	if err != nil || fd < 3 {
		fail("credential descriptor unavailable")
	}
	credentialFile := os.NewFile(uintptr(fd), "cspm-credential")
	if credentialFile == nil {
		fail("credential descriptor unavailable")
	}
	defer credentialFile.Close()
	secret, err := io.ReadAll(io.LimitReader(credentialFile, 1<<20))
	if err != nil || len(secret) == 0 {
		fail("credential unavailable")
	}
	defer clear(secret)
	_ = os.Unsetenv("SYNAPSE_CSPM_CREDENTIAL_FD")
	authorize, err := helperAuthorizer()
	if err != nil {
		fail("authorization channel unavailable")
	}
	input.Scope.Authorize = authorize
	vault := envVault{secret: secret}
	var connector ports.CloudConnector
	switch input.Scope.Provider {
	case cloudposture.ProviderAWS:
		connector, err = cloudaws.New(vault, cloudaws.Options{RequestsPerSecond: input.Rate})
	case cloudposture.ProviderAzure:
		cfg := cloudazure.Config{}
		if input.Rate > 0 {
			cfg.MinRequestWait = time.Second / time.Duration(input.Rate)
		}
		connector, err = cloudazure.New(vault, cfg)
	case cloudposture.ProviderGCP:
		opts := cloudgcp.Options{}
		if input.Rate > 0 {
			opts.MinRequestWait = time.Second / time.Duration(input.Rate)
		}
		connector, err = cloudgcp.New(vault, opts)
	default:
		fail("unsupported provider")
	}
	if err != nil {
		fail("initialize connector")
	}
	inventory, coverage, err := connector.Enumerate(context.Background(), input.Scope)
	if err != nil {
		fail("enumerate cloud posture")
	}
	if err := json.NewEncoder(os.Stdout).Encode(helperOutput{Inventory: inventory, Coverage: coverage}); err != nil {
		fail("encode output")
	}
}

func helperAuthorizer() (ports.CloudOperationAuthorizer, error) {
	requestFD, err := strconv.Atoi(os.Getenv("SYNAPSE_CSPM_AUTH_REQUEST_FD"))
	if err != nil || requestFD < 3 {
		return nil, errors.New("CSPM authorization channel unavailable")
	}
	decisionFD, err := strconv.Atoi(os.Getenv("SYNAPSE_CSPM_AUTH_DECISION_FD"))
	if err != nil || decisionFD < 3 {
		return nil, errors.New("CSPM authorization channel unavailable")
	}
	requests := json.NewEncoder(os.NewFile(uintptr(requestFD), "cspm-auth-request"))
	decisions := json.NewDecoder(bufio.NewReader(os.NewFile(uintptr(decisionFD), "cspm-auth-decision")))
	var mu sync.Mutex
	return func(_ context.Context, operation ports.CloudOperation) error {
		mu.Lock()
		defer mu.Unlock()
		if err := requests.Encode(operation); err != nil {
			return errors.New("CSPM operation authorization denied")
		}
		var decision struct {
			Allowed bool `json:"allowed"`
		}
		if err := decisions.Decode(&decision); err != nil || !decision.Allowed {
			return errors.New("CSPM operation authorization denied")
		}
		return nil
	}, nil
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(message))
	os.Exit(1)
}
