// Package azurepipelines provides read-only, tenant-scoped Azure DevOps build observations.
package azurepipelines

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

const (
	Provider              integration.Provider = "azure-pipelines"
	maxResponseBytes                           = 4 << 20
	pageSize                                   = 100
	maxPages                                   = 20
	maxContinuationLength                      = 2048
)

var (
	orgName       = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
	definitionKey = regexp.MustCompile("^/definitions/([1-9][0-9]*)$")
	descriptor    = integration.ProviderDescriptor{
		Provider: Provider, Name: "Azure Pipelines",
		Description:  "Read-only Azure DevOps Services build definitions and runs for one project.",
		Capabilities: []integration.Capability{integration.CapabilityTestConnection, integration.CapabilityDiscover, integration.CapabilityReadRuns},
		SecretFields: []integration.FieldDescriptor{{Name: "pat", Label: "Read-only personal access token", Kind: integration.FieldPassword, Required: true, Description: "Azure DevOps Build (Read) permission only; never grant build-write access."}},
	}
)

type Adapter struct {
	base   *url.URL
	client *http.Client
	pat    string
}

func Register(registry *integration.Registry) error { return registry.Register(descriptor, New) }

// New builds the adapter. Azure DevOps Services is SaaS: the host is pinned to dev.azure.com below,
// so the operator's self-hosted endpoint rules do not apply.
func New(item integration.Integration, credentials integration.CredentialBundle, _ selfhosted.Rules) (integration.Adapter, error) {
	// Check the raw path before generic endpoint normalization cleans dot segments.
	raw, rawErr := url.Parse(item.Endpoint)
	if rawErr != nil || raw.ForceQuery || raw.RawQuery != "" || raw.User != nil || raw.Fragment != "" {
		return nil, fmt.Errorf("%w: invalid Azure Pipelines endpoint", shared.ErrValidation)
	}
	for _, segment := range strings.Split(raw.EscapedPath(), "/") {
		decoded, decodeErr := url.PathUnescape(segment)
		if decodeErr != nil || decoded == "." || decoded == ".." || strings.ContainsAny(decoded, "%\\") || strings.Contains(decoded, "/") {
			return nil, fmt.Errorf("%w: invalid Azure Pipelines endpoint path", shared.ErrValidation)
		}
	}
	if err := item.Normalize(); err != nil {
		return nil, err
	}
	if item.Provider != Provider {
		return nil, fmt.Errorf("%w: wrong Azure Pipelines provider", shared.ErrValidation)
	}
	if err := descriptor.ValidateSecrets(map[string]string(credentials)); err != nil {
		return nil, err
	}
	base, err := url.Parse(item.Endpoint)
	if err != nil || !strings.EqualFold(base.Hostname(), "dev.azure.com") || (base.Port() != "" && base.Port() != "443") || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return nil, fmt.Errorf("%w: azure Pipelines requires an HTTPS dev.azure.com organization/project URL", shared.ErrValidation)
	}
	segments := strings.Split(strings.Trim(base.Path, "/"), "/")
	if len(segments) != 2 || !orgName.MatchString(segments[0]) || strings.TrimSpace(segments[1]) != segments[1] || segments[1] == "" || len(segments[1]) > 128 {
		return nil, fmt.Errorf("%w: azure Pipelines endpoint must identify one organization and project", shared.ErrValidation)
	}
	for _, s := range segments {
		if s == "." || s == ".." || strings.ContainsAny(s, "%\\") {
			return nil, fmt.Errorf("%w: azure Pipelines endpoint has an unsafe path", shared.ErrValidation)
		}
		for _, r := range s {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return nil, fmt.Errorf("%w: azure Pipelines endpoint has an unsafe path", shared.ErrValidation)
			}
		}
	}
	if strings.Contains(item.Endpoint, credentials["pat"]) {
		return nil, fmt.Errorf("%w: azure Pipelines endpoint contains credential material", shared.ErrValidation)
	}
	base.Scheme = "https"
	base.Host = "dev.azure.com"
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return &Adapter{base: base, client: safehttp.New(20*time.Second, false), pat: credentials["pat"]}, nil
}

func (a *Adapter) Descriptor() integration.ProviderDescriptor { return descriptor }
func (a *Adapter) Close()                                     { a.client.CloseIdleConnections() }

func (a *Adapter) TestConnection(ctx context.Context) error {
	var page struct {
		Count int
		Value []json.RawMessage
	}
	_, err := a.get(ctx, "_apis/build/definitions", url.Values{"$top": {"1"}}, &page)
	return err
}

type definition struct {
	ID   int64
	Name string
	Path string
}
type definitionPage struct {
	Count int
	Value []definition
}

func (a *Adapter) DiscoverPipelines(ctx context.Context, _ string) ([]integration.Pipeline, string, error) {
	out := make([]integration.Pipeline, 0)
	seenIDs := map[int64]struct{}{}
	seenTokens := map[string]struct{}{}
	continuation := ""
	for pages := 0; pages < maxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		query := url.Values{"$top": {strconv.Itoa(pageSize)}}
		if continuation != "" {
			query.Set("continuationToken", continuation)
		}
		var page definitionPage
		next, err := a.get(ctx, "_apis/build/definitions", query, &page)
		if err != nil {
			return nil, "", err
		}
		if page.Count < 0 || page.Count > pageSize || len(page.Value) > pageSize {
			return nil, "", integration.PermanentError(errors.New("azure Pipelines returned an invalid definition page"))
		}
		for _, def := range page.Value {
			if def.ID <= 0 || strings.TrimSpace(def.Name) == "" || len(def.Name) > 255 || len(def.Path) > 1024 {
				return nil, "", integration.PermanentError(errors.New("azure Pipelines returned an invalid definition"))
			}
			if _, found := seenIDs[def.ID]; found {
				return nil, "", integration.PermanentError(errors.New("azure Pipelines repeated a definition"))
			}
			if err := a.noSecrets(def.Name, def.Path); err != nil {
				return nil, "", integration.PermanentError(err)
			}
			if !safeProviderText(def.Name) || !safeProviderText(def.Path) {
				return nil, "", integration.PermanentError(errors.New("azure Pipelines returned unsafe definition metadata"))
			}
			seenIDs[def.ID] = struct{}{}
			fullName := strings.Trim(strings.ReplaceAll(def.Path, "\\", "/"), "/")
			if fullName != "" {
				fullName += "/"
			}
			fullName += strings.TrimSpace(def.Name)
			p := integration.Pipeline{ExternalKey: definitionExternalKey(def.ID), Name: strings.TrimSpace(def.Name), FullName: fullName, Kind: "pipeline", URL: a.webURL("definitionId", def.ID)}
			if err := p.Normalize(); err != nil {
				return nil, "", integration.PermanentError(errors.New("azure Pipelines returned an invalid definition"))
			}
			out = append(out, p)
			if len(out) > integration.MaxPipelines {
				return nil, "", integration.PermanentError(errors.New("azure Pipelines discovery exceeds pipeline limit"))
			}
		}
		if next == "" {
			sort.Slice(out, func(i, j int) bool { return out[i].ExternalKey < out[j].ExternalKey })
			h := sha256.New()
			for _, p := range out {
				_, _ = io.WriteString(h, p.ExternalKey+"\x00"+p.FullName+"\n")
			}
			return out, hex.EncodeToString(h.Sum(nil)), nil
		}
		if len(page.Value) == 0 {
			return nil, "", integration.PermanentError(errors.New("azure Pipelines returned an empty continuation page"))
		}
		if _, found := seenTokens[next]; found {
			return nil, "", integration.PermanentError(errors.New("azure Pipelines repeated a continuation token"))
		}
		seenTokens[next] = struct{}{}
		continuation = next
	}
	return nil, "", integration.PermanentError(errors.New("azure Pipelines discovery exceeds page limit"))
}

type build struct {
	ID            int64
	BuildNumber   string
	Status        string
	Result        string
	SourceVersion string
	SourceBranch  string
	QueueTime     *time.Time
	StartTime     *time.Time
	FinishTime    *time.Time
	Definition    struct{ ID int64 }
}
type buildPage struct {
	Count int
	Value []build
}

func (a *Adapter) ReadRuns(ctx context.Context, binding integration.Binding, checkpoint string) ([]integration.ExternalRun, string, error) {
	match := definitionKey.FindStringSubmatch(binding.ExternalKey)
	if len(match) != 2 {
		return nil, checkpoint, integration.PermanentError(errors.New("azure Pipelines binding has an invalid definition key"))
	}
	defID, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || defID <= 0 {
		return nil, checkpoint, integration.PermanentError(errors.New("azure Pipelines binding has an invalid definition ID"))
	}
	maxID := int64(0)
	if checkpoint != "" {
		maxID, err = strconv.ParseInt(checkpoint, 10, 64)
		if err != nil || maxID < 0 {
			return nil, checkpoint, integration.PermanentError(errors.New("azure Pipelines checkpoint is invalid"))
		}
	}
	runs := make([]integration.ExternalRun, 0)
	seenIDs := map[int64]struct{}{}
	seenTokens := map[string]struct{}{}
	continuation := ""
	for pages := 0; pages < maxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return nil, checkpoint, err
		}
		query := url.Values{"definitions": {strconv.FormatInt(defID, 10)}, "$top": {strconv.Itoa(pageSize)}, "queryOrder": {"queueTimeDescending"}}
		if continuation != "" {
			query.Set("continuationToken", continuation)
		}
		var page buildPage
		next, err := a.get(ctx, "_apis/build/builds", query, &page)
		if err != nil {
			return nil, checkpoint, err
		}
		if page.Count < 0 || page.Count > pageSize || len(page.Value) > pageSize {
			return nil, checkpoint, integration.PermanentError(errors.New("azure Pipelines returned an invalid build page"))
		}
		for _, b := range page.Value {
			if b.ID <= 0 || b.Definition.ID != defID {
				return nil, checkpoint, integration.PermanentError(errors.New("azure Pipelines returned a build outside the bound definition"))
			}
			if _, found := seenIDs[b.ID]; found {
				return nil, checkpoint, integration.PermanentError(errors.New("azure Pipelines repeated a build"))
			}
			seenIDs[b.ID] = struct{}{}
			run, err := a.normalizeBuild(defID, b)
			if err != nil {
				return nil, checkpoint, integration.PermanentError(err)
			}
			runs = append(runs, run)
			if len(runs) > integration.MaxRunsPerPoll {
				return nil, checkpoint, integration.PermanentError(errors.New("azure Pipelines run page exceeds poll limit"))
			}
			if b.ID > maxID {
				maxID = b.ID
			}
		}
		if next == "" {
			return runs, strconv.FormatInt(maxID, 10), nil
		}
		if len(page.Value) == 0 {
			return nil, checkpoint, integration.PermanentError(errors.New("azure Pipelines returned an empty continuation page"))
		}
		// Polling is a bounded recent-window projection, like the Jenkins adapter. A definition may
		// have years of history; reaching the global run budget is not a provider defect. Persist the
		// newest bounded window and its high-water mark instead of failing forever on older history.
		// Re-reading recent runs is intentional so queued/running rows can transition to completed.
		if len(runs) >= integration.MaxRunsPerPoll {
			return runs, strconv.FormatInt(maxID, 10), nil
		}
		if _, found := seenTokens[next]; found {
			return nil, checkpoint, integration.PermanentError(errors.New("azure Pipelines repeated a continuation token"))
		}
		seenTokens[next] = struct{}{}
		continuation = next
	}
	return nil, checkpoint, integration.PermanentError(errors.New("azure Pipelines read exceeds page limit"))
}

func (a *Adapter) normalizeBuild(defID int64, b build) (integration.ExternalRun, error) {
	if err := a.noSecrets(b.BuildNumber, b.Status, b.Result, b.SourceVersion, b.SourceBranch); err != nil {
		return integration.ExternalRun{}, err
	}
	for _, value := range []string{b.BuildNumber, b.Status, b.Result, b.SourceVersion, b.SourceBranch} {
		if !safeProviderText(value) {
			return integration.ExternalRun{}, errors.New("azure Pipelines returned unsafe build metadata")
		}
	}
	if len(b.BuildNumber) > 128 || len(b.SourceVersion) > 128 || len(b.SourceBranch) > 512 {
		return integration.ExternalRun{}, errors.New("azure Pipelines returned oversized build metadata")
	}
	lifecycle, result := normalizeStatus(b.Status, b.Result)
	updated := time.Now().UTC()
	if b.QueueTime != nil {
		updated = b.QueueTime.UTC()
	}
	if b.StartTime != nil {
		updated = b.StartTime.UTC()
	}
	if b.FinishTime != nil {
		updated = b.FinishTime.UTC()
	}
	if lifecycle == integration.RunRunning {
		updated = time.Now().UTC()
	}
	run := integration.ExternalRun{
		ProviderKey: strconv.FormatInt(b.ID, 10), PipelineKey: definitionExternalKey(defID),
		Number: b.BuildNumber, URL: a.webURL("buildId", b.ID),
		Lifecycle: lifecycle, Result: result, Revision: strings.TrimSpace(b.SourceVersion),
		Branch: strings.TrimSpace(b.SourceBranch), QueuedAt: b.QueueTime, StartedAt: b.StartTime,
		FinishedAt: b.FinishTime, ProviderUpdatedAt: updated,
	}
	if lifecycle != integration.RunCompleted {
		run.FinishedAt = nil
	}
	return run, nil
}

func normalizeStatus(status, result string) (integration.RunLifecycle, integration.RunResult) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "notstarted", "postponed", "none", "":
		return integration.RunQueued, integration.ResultUnknown
	case "inprogress", "cancelling":
		return integration.RunRunning, integration.ResultUnknown
	case "completed":
		switch strings.ToLower(strings.TrimSpace(result)) {
		case "succeeded":
			return integration.RunCompleted, integration.ResultSuccess
		case "partiallysucceeded":
			return integration.RunCompleted, integration.ResultUnstable
		case "failed":
			return integration.RunCompleted, integration.ResultFailure
		case "canceled":
			return integration.RunCompleted, integration.ResultAborted
		default:
			return integration.RunCompleted, integration.ResultUnknown
		}
	default:
		return integration.RunRunning, integration.ResultUnknown
	}
}

func definitionExternalKey(id int64) string { return "/definitions/" + strconv.FormatInt(id, 10) }

func (a *Adapter) webURL(key string, id int64) string {
	u := *a.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/_build/results"
	if key == "definitionId" {
		u.Path = strings.TrimSuffix(a.base.Path, "/") + "/_build"
	}
	u.RawPath = ""
	u.RawQuery = url.Values{key: {strconv.FormatInt(id, 10)}}.Encode()
	return u.String()
}

func (a *Adapter) get(ctx context.Context, resource string, query url.Values, out any) (string, error) {
	if err := integration.ConsumeOperationRequest(ctx); err != nil {
		return "", integration.PermanentError(err)
	}
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + "/" + resource
	u.RawPath = ""
	query.Set("api-version", "7.1")
	u.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", integration.PermanentError(errors.New("invalid Azure Pipelines request"))
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+a.pat)))
	response, err := a.client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		return "", integration.RetryableError(errors.New("azure Pipelines request failed"))
	}
	defer func() { _ = response.Body.Close() }()
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return "", integration.PermanentError(errors.New("azure Pipelines authentication failed"))
	case response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500:
		return "", integration.RetryableError(errors.New("azure Pipelines is temporarily unavailable"))
	case response.StatusCode != http.StatusOK:
		return "", integration.PermanentError(fmt.Errorf("azure Pipelines returned HTTP %d", response.StatusCode))
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return "", integration.RetryableError(errors.New("azure Pipelines response read failed"))
	}
	if len(data) > maxResponseBytes {
		return "", integration.PermanentError(errors.New("azure Pipelines response exceeds size limit"))
	}
	if err := integration.ConsumeOperationBytes(ctx, int64(len(data))); err != nil {
		return "", integration.PermanentError(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return "", integration.PermanentError(errors.New("azure Pipelines returned invalid JSON"))
	}
	token := response.Header.Get("x-ms-continuationtoken")
	if len(token) > maxContinuationLength || strings.ContainsAny(token, "\r\n") || a.containsCredential(token) {
		return "", integration.PermanentError(errors.New("azure Pipelines returned an invalid continuation token"))
	}
	return token, nil
}

func (a *Adapter) containsCredential(s string) bool {
	if a.pat == "" {
		return false
	}
	basic := base64.StdEncoding.EncodeToString([]byte(":" + a.pat))
	for tries := 0; tries < 4; tries++ {
		if strings.Contains(s, a.pat) || strings.Contains(s, basic) {
			return true
		}
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	return false
}
func (a *Adapter) noSecrets(values ...string) error {
	for _, v := range values {
		if a.containsCredential(v) {
			return errors.New("azure Pipelines response contains credential material")
		}
	}
	return nil
}

func safeProviderText(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
