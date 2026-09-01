// Package integration models tenant-scoped external CI/CD connections and
// provider-neutral build provenance.
package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	MaxConfigBytes       = 32 << 10
	MaxCredentialBytes   = 16 << 10
	MaxPipelines         = 1000
	MaxRunsPerPoll       = 200
	MaxOperationErrors   = 20
	MaxOperationErrorLen = 256
	DefaultPollInterval  = 5 * time.Minute
)

var (
	providerPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
	fieldPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

type Provider string

func (provider Provider) Valid() bool {
	value := string(provider)
	return len(value) <= 64 && providerPattern.MatchString(value)
}

func NormalizeProvider(raw string) (Provider, error) {
	provider := Provider(strings.ToLower(strings.TrimSpace(raw)))
	if !provider.Valid() {
		return "", fmt.Errorf("%w: integration provider must be a lowercase slug", shared.ErrValidation)
	}
	return provider, nil
}

type Capability string

const (
	CapabilityTestConnection Capability = "test_connection"
	CapabilityDiscover       Capability = "discover_pipelines"
	CapabilityReadRuns       Capability = "read_runs"
)

type FieldKind string

const (
	FieldText     FieldKind = "text"
	FieldPassword FieldKind = "password"
	FieldBoolean  FieldKind = "boolean"
)

type FieldDescriptor struct {
	Name        string    `json:"name"`
	Label       string    `json:"label"`
	Kind        FieldKind `json:"kind"`
	Required    bool      `json:"required"`
	Description string    `json:"description,omitempty"`
}

type ProviderDescriptor struct {
	Provider     Provider          `json:"provider"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Capabilities []Capability      `json:"capabilities"`
	ConfigFields []FieldDescriptor `json:"config_fields"`
	SecretFields []FieldDescriptor `json:"secret_fields"`
}

func (descriptor ProviderDescriptor) Validate() error {
	if !descriptor.Provider.Valid() || strings.TrimSpace(descriptor.Name) == "" {
		return fmt.Errorf("%w: provider descriptor identity is invalid", shared.ErrValidation)
	}
	seenCapabilities := map[Capability]struct{}{}
	for _, capability := range descriptor.Capabilities {
		switch capability {
		case CapabilityTestConnection, CapabilityDiscover, CapabilityReadRuns:
		default:
			return fmt.Errorf("%w: provider capability %q is invalid", shared.ErrValidation, capability)
		}
		if _, exists := seenCapabilities[capability]; exists {
			return fmt.Errorf("%w: provider capability %q is duplicated", shared.ErrValidation, capability)
		}
		seenCapabilities[capability] = struct{}{}
	}
	seenFields := map[string]struct{}{}
	for _, fields := range [][]FieldDescriptor{descriptor.ConfigFields, descriptor.SecretFields} {
		for _, field := range fields {
			if !fieldPattern.MatchString(field.Name) || strings.TrimSpace(field.Label) == "" {
				return fmt.Errorf("%w: provider field descriptor is invalid", shared.ErrValidation)
			}
			switch field.Kind {
			case FieldText, FieldPassword, FieldBoolean:
			default:
				return fmt.Errorf("%w: provider field %q has invalid kind", shared.ErrValidation, field.Name)
			}
			if _, exists := seenFields[field.Name]; exists {
				return fmt.Errorf("%w: provider field %q is duplicated", shared.ErrValidation, field.Name)
			}
			seenFields[field.Name] = struct{}{}
		}
	}
	return nil
}

func (descriptor ProviderDescriptor) Supports(capability Capability) bool {
	for _, supported := range descriptor.Capabilities {
		if supported == capability {
			return true
		}
	}
	return false
}

func (descriptor ProviderDescriptor) ValidateConfig(config map[string]any) error {
	return validateFields(config, descriptor.ConfigFields, "configuration")
}

func (descriptor ProviderDescriptor) ValidateSecrets(secrets map[string]string) error {
	values := make(map[string]any, len(secrets))
	for key, value := range secrets {
		values[key] = value
	}
	return validateFields(values, descriptor.SecretFields, "credential")
}

func validateFields(values map[string]any, fields []FieldDescriptor, kind string) error {
	allowed := make(map[string]FieldDescriptor, len(fields))
	for _, field := range fields {
		allowed[field.Name] = field
	}
	for key := range values {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%w: unsupported provider %s field %q", shared.ErrValidation, kind, key)
		}
	}
	for _, field := range fields {
		value, exists := values[field.Name]
		if !exists {
			if field.Required {
				return fmt.Errorf("%w: provider %s field %q is required", shared.ErrValidation, kind, field.Name)
			}
			continue
		}
		switch field.Kind {
		case FieldText, FieldPassword:
			text, ok := value.(string)
			if !ok || (field.Required && strings.TrimSpace(text) == "") || len(text) > MaxCredentialBytes {
				return fmt.Errorf("%w: provider %s field %q is invalid", shared.ErrValidation, kind, field.Name)
			}
		case FieldBoolean:
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%w: provider %s field %q must be boolean", shared.ErrValidation, kind, field.Name)
			}
		}
	}
	return nil
}

type Integration struct {
	ID                   shared.ID       `json:"id"`
	TenantID             shared.ID       `json:"tenant_id"`
	Provider             Provider        `json:"provider"`
	Name                 string          `json:"name"`
	Endpoint             string          `json:"endpoint"`
	Config               json.RawMessage `json:"config"`
	AllowPrivateNetwork  bool            `json:"allow_private_network"`
	PollInterval         time.Duration   `json:"-"`
	Enabled              bool            `json:"enabled"`
	Archived             bool            `json:"archived"`
	Version              int             `json:"version"`
	CredentialConfigured bool            `json:"credential_configured"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

func (item *Integration) Normalize() error {
	item.TenantID = shared.TenantOrDefault(item.TenantID)
	item.Name = strings.TrimSpace(item.Name)
	if item.ID.IsZero() || item.TenantID.IsZero() || !item.Provider.Valid() || item.Name == "" || len(item.Name) > 120 {
		return fmt.Errorf("%w: integration identity is invalid", shared.ErrValidation)
	}
	endpoint, err := CanonicalEndpoint(item.Endpoint)
	if err != nil {
		return err
	}
	item.Endpoint = endpoint
	config, err := DecodeConfig(item.Config)
	if err != nil {
		return err
	}
	item.Config, err = json.Marshal(config)
	if err != nil {
		return fmt.Errorf("%w: integration configuration is invalid", shared.ErrValidation)
	}
	if item.PollInterval == 0 {
		item.PollInterval = DefaultPollInterval
	}
	if item.PollInterval < 30*time.Second || item.PollInterval > 24*time.Hour {
		return fmt.Errorf("%w: integration poll interval must be between 30 seconds and 24 hours", shared.ErrValidation)
	}
	if item.Version < 1 {
		return fmt.Errorf("%w: integration version must be positive", shared.ErrValidation)
	}
	return nil
}

func (item Integration) Clone() Integration {
	item.Config = append(json.RawMessage(nil), item.Config...)
	return item
}

func DecodeConfig(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if len(raw) > MaxConfigBytes {
		return nil, fmt.Errorf("%w: integration configuration is too large", shared.ErrValidation)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, fmt.Errorf("%w: integration configuration must be a JSON object", shared.ErrValidation)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: integration configuration must contain one JSON object", shared.ErrValidation)
	}
	if jsonDepth(value, 0) > 8 {
		return nil, fmt.Errorf("%w: integration configuration is too deeply nested", shared.ErrValidation)
	}
	return value, nil
}

func jsonDepth(value any, depth int) int {
	if depth > 8 {
		return depth
	}
	maxDepth := depth
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			maxDepth = max(maxDepth, jsonDepth(child, depth+1))
		}
	case []any:
		for _, child := range typed {
			maxDepth = max(maxDepth, jsonDepth(child, depth+1))
		}
	}
	return maxDepth
}

func CanonicalEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: integration endpoint must be an https origin/path without userinfo, query, or fragment", shared.ErrValidation)
	}
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port == "" || port == "443" {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else {
		host = net.JoinHostPort(host, port)
	}
	parsed.Scheme = "https"
	parsed.Host = host
	parsed.RawPath = ""
	parsed.Path = path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	if parsed.Path == "/" {
		parsed.Path = ""
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

type Pipeline struct {
	ExternalKey string `json:"external_key"`
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Kind        string `json:"kind"`
	URL         string `json:"url,omitempty"`
}

func (pipeline *Pipeline) Normalize() error {
	key, err := CanonicalExternalKey(pipeline.ExternalKey)
	if err != nil {
		return err
	}
	pipeline.ExternalKey = key
	pipeline.Name = strings.TrimSpace(pipeline.Name)
	pipeline.FullName = strings.TrimSpace(pipeline.FullName)
	pipeline.Kind = strings.TrimSpace(pipeline.Kind)
	if pipeline.Name == "" || len(pipeline.Name) > 255 || len(pipeline.FullName) > 1024 || len(pipeline.Kind) > 64 || len(pipeline.URL) > 2048 {
		return fmt.Errorf("%w: external pipeline is invalid", shared.ErrValidation)
	}
	return nil
}

func CanonicalExternalKey(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: external pipeline key must be a relative job path", shared.ErrValidation)
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	if cleaned == "/" || !strings.HasPrefix(cleaned, "/job/") || strings.Contains(cleaned, "..") || len(cleaned) > 1024 {
		return "", fmt.Errorf("%w: external pipeline key is invalid", shared.ErrValidation)
	}
	return strings.TrimSuffix(cleaned, "/"), nil
}

type Binding struct {
	ID            shared.ID `json:"id"`
	TenantID      shared.ID `json:"tenant_id"`
	IntegrationID shared.ID `json:"integration_id"`
	ProjectID     shared.ID `json:"project_id"`
	ExternalKey   string    `json:"external_key"`
	ExternalName  string    `json:"external_name"`
	Version       int       `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (binding *Binding) Normalize() error {
	binding.TenantID = shared.TenantOrDefault(binding.TenantID)
	key, err := CanonicalExternalKey(binding.ExternalKey)
	if err != nil {
		return err
	}
	binding.ExternalKey = key
	binding.ExternalName = strings.TrimSpace(binding.ExternalName)
	if binding.ID.IsZero() || binding.TenantID.IsZero() || binding.IntegrationID.IsZero() || binding.ProjectID.IsZero() || binding.ExternalName == "" || len(binding.ExternalName) > 1024 || binding.Version < 1 {
		return fmt.Errorf("%w: integration binding is invalid", shared.ErrValidation)
	}
	return nil
}

type OperationType string

const (
	OperationTest     OperationType = "test"
	OperationDiscover OperationType = "discover"
	OperationPoll     OperationType = "poll"
)

func (operation OperationType) Valid() bool {
	return operation == OperationTest || operation == OperationDiscover || operation == OperationPoll
}

type OperationState string

const (
	OperationQueued    OperationState = "queued"
	OperationRunning   OperationState = "running"
	OperationSucceeded OperationState = "succeeded"
	OperationPartial   OperationState = "partial"
	OperationFailed    OperationState = "failed"
	OperationCancelled OperationState = "cancelled"
)

func (state OperationState) Terminal() bool {
	return state == OperationSucceeded || state == OperationPartial || state == OperationFailed || state == OperationCancelled
}

type OperationCounts struct {
	Pipelines int `json:"pipelines"`
	Runs      int `json:"runs"`
	Linked    int `json:"linked"`
	Unlinked  int `json:"unlinked"`
	Errors    int `json:"errors"`
}

type Operation struct {
	ID            shared.ID       `json:"id"`
	TenantID      shared.ID       `json:"tenant_id"`
	IntegrationID shared.ID       `json:"integration_id"`
	Type          OperationType   `json:"type"`
	State         OperationState  `json:"state"`
	Checkpoint    string          `json:"checkpoint,omitempty"`
	Counts        OperationCounts `json:"counts"`
	Errors        []string        `json:"errors"`
	Pipelines     []Pipeline      `json:"pipelines,omitempty"`
	JobID         string          `json:"job_id"`
	Actor         string          `json:"actor"`
	StartedAt     *time.Time      `json:"started_at,omitempty"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

func (operation Operation) Clone() Operation {
	operation.Errors = append([]string(nil), operation.Errors...)
	operation.Pipelines = append([]Pipeline(nil), operation.Pipelines...)
	return operation
}

func BoundedErrors(errorsIn []string) []string {
	if len(errorsIn) > MaxOperationErrors {
		errorsIn = errorsIn[:MaxOperationErrors]
	}
	out := make([]string, 0, len(errorsIn))
	for _, value := range errorsIn {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) > MaxOperationErrorLen {
			value = value[:MaxOperationErrorLen]
		}
		out = append(out, value)
	}
	return out
}

type RunLifecycle string

const (
	RunQueued    RunLifecycle = "queued"
	RunRunning   RunLifecycle = "running"
	RunCompleted RunLifecycle = "completed"
)

type RunResult string

const (
	ResultSuccess  RunResult = "success"
	ResultFailure  RunResult = "failure"
	ResultUnstable RunResult = "unstable"
	ResultAborted  RunResult = "aborted"
	ResultNotBuilt RunResult = "not_built"
	ResultUnknown  RunResult = "unknown"
)

type CorrelationState string

const (
	CorrelationLinked    CorrelationState = "linked"
	CorrelationMissing   CorrelationState = "missing"
	CorrelationAmbiguous CorrelationState = "ambiguous"
)

type ExternalRun struct {
	ID                shared.ID        `json:"id"`
	TenantID          shared.ID        `json:"tenant_id"`
	IntegrationID     shared.ID        `json:"integration_id"`
	BindingID         shared.ID        `json:"binding_id,omitempty"`
	ProviderKey       string           `json:"provider_key"`
	PipelineKey       string           `json:"pipeline_key"`
	Number            string           `json:"number,omitempty"`
	URL               string           `json:"url,omitempty"`
	Lifecycle         RunLifecycle     `json:"lifecycle"`
	Result            RunResult        `json:"result"`
	Revision          string           `json:"revision,omitempty"`
	Branch            string           `json:"branch,omitempty"`
	AnalysisID        shared.ID        `json:"analysis_id,omitempty"`
	Correlation       CorrelationState `json:"correlation"`
	QueuedAt          *time.Time       `json:"queued_at,omitempty"`
	StartedAt         *time.Time       `json:"started_at,omitempty"`
	FinishedAt        *time.Time       `json:"finished_at,omitempty"`
	ProviderUpdatedAt time.Time        `json:"provider_updated_at"`
	CreatedAt         time.Time        `json:"created_at"`
	UpdatedAt         time.Time        `json:"updated_at"`
}

func (run *ExternalRun) Normalize() error {
	run.TenantID = shared.TenantOrDefault(run.TenantID)
	key, err := CanonicalExternalKey(run.PipelineKey)
	if err != nil {
		return err
	}
	run.PipelineKey = key
	run.ProviderKey = strings.TrimSpace(run.ProviderKey)
	run.Revision = strings.TrimSpace(run.Revision)
	run.Branch = strings.TrimSpace(run.Branch)
	if run.ID.IsZero() || run.TenantID.IsZero() || run.IntegrationID.IsZero() || run.ProviderKey == "" || len(run.ProviderKey) > 1024 || len(run.Number) > 128 || len(run.URL) > 2048 || len(run.Revision) > 128 || len(run.Branch) > 512 {
		return fmt.Errorf("%w: external run identity is invalid", shared.ErrValidation)
	}
	switch run.Lifecycle {
	case RunQueued, RunRunning, RunCompleted:
	default:
		return fmt.Errorf("%w: external run lifecycle is invalid", shared.ErrValidation)
	}
	switch run.Result {
	case ResultSuccess, ResultFailure, ResultUnstable, ResultAborted, ResultNotBuilt, ResultUnknown:
	default:
		return fmt.Errorf("%w: external run result is invalid", shared.ErrValidation)
	}
	switch run.Correlation {
	case CorrelationLinked, CorrelationMissing, CorrelationAmbiguous:
	default:
		return fmt.Errorf("%w: external run correlation is invalid", shared.ErrValidation)
	}
	return nil
}

func SortDescriptors(descriptors []ProviderDescriptor) {
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Provider < descriptors[j].Provider })
}
