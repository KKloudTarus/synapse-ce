package jenkins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

const (
	Provider             integration.Provider = "jenkins"
	maxResponseBytes                          = 4 << 20
	maxFolderDepth                            = 16
	maxBuildsPerPipeline                      = 50
)

var descriptor = integration.ProviderDescriptor{
	Provider:    Provider,
	Name:        "Jenkins",
	Description: "Read-only polling for Jenkins folders, jobs, pipelines, multibranch projects, and builds.",
	Capabilities: []integration.Capability{
		integration.CapabilityTestConnection,
		integration.CapabilityDiscover,
		integration.CapabilityReadRuns,
	},
	SecretFields: []integration.FieldDescriptor{
		{Name: "username", Label: "Username", Kind: integration.FieldText, Required: true, Description: "Jenkins user associated with the API token."},
		{Name: "api_token", Label: "API token", Kind: integration.FieldPassword, Required: true, Description: "Use a Jenkins API token rather than a password."},
	},
}

type Adapter struct {
	descriptor integration.ProviderDescriptor
	base       *url.URL
	client     *http.Client
	username   string
	token      string
}

func Register(registry *integration.Registry) error {
	return registry.Register(descriptor, New)
}

func New(item integration.Integration, credentials integration.CredentialBundle) (integration.Adapter, error) {
	if err := item.Normalize(); err != nil {
		return nil, err
	}
	if item.Provider != Provider {
		return nil, fmt.Errorf("%w: Jenkins adapter received provider %q", shared.ErrValidation, item.Provider)
	}
	if err := descriptor.ValidateSecrets(map[string]string(credentials)); err != nil {
		return nil, err
	}
	base, err := url.Parse(item.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: Jenkins endpoint is invalid", shared.ErrValidation)
	}
	return &Adapter{
		descriptor: descriptor,
		base:       base,
		client:     safehttp.New(20*time.Second, item.AllowPrivateNetwork),
		username:   credentials["username"],
		token:      credentials["api_token"],
	}, nil
}

func (adapter *Adapter) Descriptor() integration.ProviderDescriptor { return adapter.descriptor }

func (adapter *Adapter) TestConnection(ctx context.Context) error {
	var response struct {
		Mode     string `json:"mode"`
		NodeName string `json:"nodeName"`
	}
	return adapter.get(ctx, "/api/json", url.Values{"tree": {"mode,nodeName"}}, &response)
}

func (adapter *Adapter) DiscoverPipelines(ctx context.Context, _ string) ([]integration.Pipeline, string, error) {
	type pendingFolder struct {
		externalKey string
		fullName    string
		depth       int
	}
	queue := []pendingFolder{{}}
	visited := map[string]struct{}{"": {}}
	pipelines := make([]integration.Pipeline, 0)
	for len(queue) > 0 {
		folder := queue[0]
		queue = queue[1:]
		var response struct {
			Jobs []jenkinsJob `json:"jobs"`
		}
		resource := folder.externalKey + "/api/json"
		if folder.externalKey == "" {
			resource = "/api/json"
		}
		if err := adapter.get(ctx, resource, url.Values{"tree": {"jobs[name,url,_class]"}}, &response); err != nil {
			return nil, "", err
		}
		for _, job := range response.Jobs {
			if len(pipelines) >= integration.MaxPipelines {
				return nil, "", integration.PermanentError(fmt.Errorf("Jenkins returned more than %d pipelines", integration.MaxPipelines))
			}
			externalKey, err := adapter.externalKey(job.URL)
			if err != nil {
				return nil, "", integration.PermanentError(err)
			}
			name := strings.TrimSpace(job.Name)
			if name == "" {
				return nil, "", integration.PermanentError(fmt.Errorf("Jenkins returned a job without a name"))
			}
			fullName := name
			if folder.fullName != "" {
				fullName = folder.fullName + "/" + name
			}
			kind, recurse, include := classify(job.Class)
			if include {
				pipeline := integration.Pipeline{ExternalKey: externalKey, Name: name, FullName: fullName, Kind: kind, URL: adapter.absolute(externalKey)}
				if err := pipeline.Normalize(); err != nil {
					return nil, "", integration.PermanentError(err)
				}
				pipelines = append(pipelines, pipeline)
			}
			if recurse {
				if folder.depth >= maxFolderDepth {
					return nil, "", integration.PermanentError(fmt.Errorf("Jenkins folder nesting exceeds %d levels", maxFolderDepth))
				}
				if _, exists := visited[externalKey]; !exists {
					visited[externalKey] = struct{}{}
					queue = append(queue, pendingFolder{externalKey: externalKey, fullName: fullName, depth: folder.depth + 1})
				}
			}
		}
	}
	sort.Slice(pipelines, func(i, j int) bool { return pipelines[i].FullName < pipelines[j].FullName })
	hash := sha256.New()
	for _, pipeline := range pipelines {
		_, _ = io.WriteString(hash, pipeline.ExternalKey+"\x00"+pipeline.Kind+"\n")
	}
	return pipelines, hex.EncodeToString(hash.Sum(nil)), nil
}

func (adapter *Adapter) ReadRuns(ctx context.Context, binding integration.Binding, checkpoint string) ([]integration.ExternalRun, string, error) {
	externalKey, err := integration.CanonicalExternalKey(binding.ExternalKey)
	if err != nil {
		return nil, checkpoint, integration.PermanentError(err)
	}
	queued, err := adapter.queuedRuns(ctx, externalKey)
	if err != nil {
		return nil, checkpoint, err
	}
	var response struct {
		Builds []jenkinsBuild `json:"builds"`
	}
	tree := "builds[number,url,building,result,timestamp,duration,queueId,actions[lastBuiltRevision[SHA1,branch[SHA1,name]],remoteUrls],changeSet[items[commitId]]]{0," + strconv.Itoa(maxBuildsPerPipeline) + "}"
	if err := adapter.get(ctx, externalKey+"/api/json", url.Values{"tree": {tree}}, &response); err != nil {
		return nil, checkpoint, err
	}
	runs := make([]integration.ExternalRun, 0, len(queued)+len(response.Builds))
	runs = append(runs, queued...)
	runIndexes := make(map[string]int, len(runs))
	for index := range runs {
		runIndexes[runs[index].ProviderKey] = index
	}
	maxNumber, _ := strconv.ParseInt(checkpoint, 10, 64)
	for _, build := range response.Builds {
		run, err := adapter.normalizeBuild(externalKey, build)
		if err != nil {
			return nil, checkpoint, integration.PermanentError(err)
		}
		if index, exists := runIndexes[run.ProviderKey]; exists {
			runs[index] = run
		} else {
			runIndexes[run.ProviderKey] = len(runs)
			runs = append(runs, run)
		}
		if build.Number > maxNumber {
			maxNumber = build.Number
		}
	}
	return runs, strconv.FormatInt(maxNumber, 10), nil
}

type jenkinsJob struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Class string `json:"_class"`
}

type jenkinsBuild struct {
	Number    int64  `json:"number"`
	URL       string `json:"url"`
	Building  bool   `json:"building"`
	Result    string `json:"result"`
	Timestamp int64  `json:"timestamp"`
	Duration  int64  `json:"duration"`
	QueueID   int64  `json:"queueId"`
	Actions   []struct {
		LastBuiltRevision *struct {
			SHA1   string `json:"SHA1"`
			Branch []struct {
				SHA1 string `json:"SHA1"`
				Name string `json:"name"`
			} `json:"branch"`
		} `json:"lastBuiltRevision"`
	} `json:"actions"`
	ChangeSet struct {
		Items []struct {
			CommitID string `json:"commitId"`
		} `json:"items"`
	} `json:"changeSet"`
}

func (adapter *Adapter) normalizeBuild(externalKey string, build jenkinsBuild) (integration.ExternalRun, error) {
	if build.Number < 0 {
		return integration.ExternalRun{}, fmt.Errorf("Jenkins returned an invalid build number")
	}
	providerKey := runProviderKey(externalKey, "build", build.Number)
	if build.QueueID > 0 {
		providerKey = runProviderKey(externalKey, "queue", build.QueueID)
	}
	startedAt := time.UnixMilli(build.Timestamp).UTC()
	providerUpdatedAt := startedAt
	var finishedAt *time.Time
	lifecycle := integration.RunCompleted
	result := normalizeResult(build.Result)
	if build.Building {
		lifecycle, result = integration.RunRunning, integration.ResultUnknown
		providerUpdatedAt = time.Now().UTC()
	} else if build.Duration > 0 {
		finished := startedAt.Add(time.Duration(build.Duration) * time.Millisecond)
		finishedAt = &finished
		providerUpdatedAt = finished
	}
	revision, branch := buildRevision(build)
	return integration.ExternalRun{
		ProviderKey: providerKey, PipelineKey: externalKey, Number: strconv.FormatInt(build.Number, 10), URL: adapter.safeRunURL(build.URL, externalKey),
		Lifecycle: lifecycle, Result: result, Revision: revision, Branch: branch, StartedAt: &startedAt, FinishedAt: finishedAt, ProviderUpdatedAt: providerUpdatedAt,
	}, nil
}

func (adapter *Adapter) queuedRuns(ctx context.Context, externalKey string) ([]integration.ExternalRun, error) {
	var response struct {
		Items []struct {
			ID           int64  `json:"id"`
			URL          string `json:"url"`
			InQueueSince int64  `json:"inQueueSince"`
			Task         struct {
				URL string `json:"url"`
			} `json:"task"`
			Executable *struct {
				Number int64  `json:"number"`
				URL    string `json:"url"`
			} `json:"executable"`
		} `json:"items"`
	}
	if err := adapter.get(ctx, "/queue/api/json", url.Values{"tree": {"items[id,url,inQueueSince,task[url],executable[number,url]]"}}, &response); err != nil {
		return nil, err
	}
	runs := make([]integration.ExternalRun, 0)
	for _, item := range response.Items {
		taskKey, err := adapter.externalKey(item.Task.URL)
		if err != nil || taskKey != externalKey || item.ID <= 0 {
			continue
		}
		queuedAt := time.UnixMilli(item.InQueueSince).UTC()
		run := integration.ExternalRun{
			ProviderKey: runProviderKey(externalKey, "queue", item.ID), PipelineKey: externalKey, URL: adapter.safeRunURL(item.URL, externalKey),
			Lifecycle: integration.RunQueued, Result: integration.ResultUnknown, QueuedAt: &queuedAt, ProviderUpdatedAt: queuedAt,
		}
		if item.Executable != nil {
			run.Number = strconv.FormatInt(item.Executable.Number, 10)
			run.URL = adapter.safeRunURL(item.Executable.URL, externalKey)
			run.Lifecycle = integration.RunRunning
			run.StartedAt = &queuedAt
			run.ProviderUpdatedAt = time.Now().UTC()
		}
		runs = append(runs, run)
	}
	return runs, nil
}

func runProviderKey(externalKey, kind string, id int64) string {
	digest := sha256.Sum256([]byte(externalKey))
	return hex.EncodeToString(digest[:]) + ":" + kind + ":" + strconv.FormatInt(id, 10)
}

func buildRevision(build jenkinsBuild) (string, string) {
	for _, action := range build.Actions {
		if action.LastBuiltRevision == nil {
			continue
		}
		revision := strings.TrimSpace(action.LastBuiltRevision.SHA1)
		branch := ""
		for _, candidate := range action.LastBuiltRevision.Branch {
			if branch == "" {
				branch = strings.TrimSpace(candidate.Name)
			}
			if revision == "" {
				revision = strings.TrimSpace(candidate.SHA1)
			}
		}
		if revision != "" {
			return revision, branch
		}
	}
	commits := map[string]struct{}{}
	for _, item := range build.ChangeSet.Items {
		if commit := strings.TrimSpace(item.CommitID); commit != "" {
			commits[commit] = struct{}{}
		}
	}
	if len(commits) == 1 {
		for commit := range commits {
			return commit, ""
		}
	}
	return "", ""
}

func normalizeResult(raw string) integration.RunResult {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "SUCCESS":
		return integration.ResultSuccess
	case "FAILURE":
		return integration.ResultFailure
	case "UNSTABLE":
		return integration.ResultUnstable
	case "ABORTED":
		return integration.ResultAborted
	case "NOT_BUILT":
		return integration.ResultNotBuilt
	default:
		return integration.ResultUnknown
	}
}

func classify(class string) (kind string, recurse, include bool) {
	class = strings.ToLower(class)
	switch {
	case strings.Contains(class, "workflowmultibranchproject"):
		return "multibranch", true, true
	case strings.Contains(class, "organizationfolder"):
		return "organization", true, false
	case strings.Contains(class, "folder"):
		return "folder", true, false
	case strings.Contains(class, "workflowjob"):
		return "pipeline", false, true
	default:
		return "job", false, true
	}
}

func (adapter *Adapter) get(ctx context.Context, resource string, query url.Values, output any) error {
	requestURL, err := adapter.resourceURL(resource, query)
	if err != nil {
		return integration.PermanentError(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return integration.PermanentError(fmt.Errorf("build Jenkins request: %w", err))
	}
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(adapter.username, adapter.token)
	response, err := adapter.client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		return integration.RetryableError(fmt.Errorf("Jenkins request failed"))
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return integration.PermanentError(fmt.Errorf("Jenkins authentication failed"))
	case response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500:
		return integration.RetryableError(fmt.Errorf("Jenkins temporarily unavailable"))
	case response.StatusCode < 200 || response.StatusCode >= 300:
		return integration.PermanentError(fmt.Errorf("Jenkins returned HTTP %d", response.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return integration.RetryableError(fmt.Errorf("read Jenkins response: %w", err))
	}
	if len(body) > maxResponseBytes {
		return integration.PermanentError(fmt.Errorf("Jenkins response exceeds %d bytes", maxResponseBytes))
	}
	if err := json.Unmarshal(body, output); err != nil {
		return integration.PermanentError(fmt.Errorf("Jenkins returned invalid JSON"))
	}
	return nil
}

func (adapter *Adapter) resourceURL(resource string, query url.Values) (*url.URL, error) {
	unescaped, err := url.PathUnescape(strings.TrimPrefix(resource, "/"))
	if err != nil {
		return nil, fmt.Errorf("Jenkins resource path is invalid")
	}
	for _, segment := range strings.Split(unescaped, "/") {
		if segment == "." || segment == ".." {
			return nil, fmt.Errorf("Jenkins resource path is invalid")
		}
	}
	resourceURL := *adapter.base
	resourcePath := path.Clean("/" + strings.TrimPrefix(resource, "/"))
	resourceURL.Path = strings.TrimSuffix(adapter.base.Path, "/") + resourcePath
	resourceURL.RawPath = ""
	resourceURL.RawQuery = query.Encode()
	resourceURL.Fragment = ""
	if resourceURL.Scheme != adapter.base.Scheme || resourceURL.Host != adapter.base.Host {
		return nil, fmt.Errorf("Jenkins resource left the configured origin")
	}
	return &resourceURL, nil
}

func (adapter *Adapter) externalKey(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("Jenkins returned an invalid job URL")
	}
	if !parsed.IsAbs() {
		parsed = adapter.base.ResolveReference(parsed)
	}
	if !strings.EqualFold(parsed.Scheme, adapter.base.Scheme) || !strings.EqualFold(parsed.Host, adapter.base.Host) {
		return "", fmt.Errorf("Jenkins returned a cross-origin job URL")
	}
	basePath := strings.TrimSuffix(adapter.base.Path, "/")
	if basePath != "" && !strings.HasPrefix(parsed.Path, basePath+"/") {
		return "", fmt.Errorf("Jenkins returned a job URL outside the configured base path")
	}
	return integration.CanonicalExternalKey(strings.TrimPrefix(parsed.Path, basePath))
}

func (adapter *Adapter) absolute(externalKey string) string {
	value, err := adapter.resourceURL(externalKey, nil)
	if err != nil {
		return ""
	}
	return value.String()
}

func (adapter *Adapter) safeRunURL(raw, fallbackKey string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err == nil {
		if !parsed.IsAbs() {
			parsed = adapter.base.ResolveReference(parsed)
		}
		if strings.EqualFold(parsed.Scheme, adapter.base.Scheme) && strings.EqualFold(parsed.Host, adapter.base.Host) {
			return parsed.String()
		}
	}
	return adapter.absolute(fallbackKey)
}
