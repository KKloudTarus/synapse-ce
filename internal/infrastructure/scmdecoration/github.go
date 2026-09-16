package scmdecoration

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	githubAPIBase          = "https://api.github.com"
	githubCredentialHost   = "github.com"
	githubAPIVersion       = "2022-11-28"
	githubCheckName        = "Synapse quality gate"
	githubStatusContext    = "synapse/code-quality"
	githubCommentMarker    = "<!-- synapse:code-quality-decoration:v1 -->"
	githubAnnotationBatch  = 50
	githubSummaryLimit     = 60_000
	githubAnnotationLimit  = 60_000
	githubAnnotationTitle  = 255
	githubStatusPageLimit  = 20
	githubCheckPageLimit   = 20
	githubCommentPageLimit = 20
)

// GitHubDecorator publishes the provider-neutral PR decoration through GitHub's statuses, checks, and
// issue-comment APIs. The connector token is resolved at call time from tenant context and is never
// stored in the decoration payload or included in returned errors.
type GitHubDecorator struct {
	api            *jsonHTTPClient
	credentials    ports.GitCredentialResolver
	credentialHost string
	locks          [32]sync.Mutex
}

var _ ports.PRDecorator = (*GitHubDecorator)(nil)

// NewGitHubDecorator constructs the production github.com adapter. Provider composition is intentionally
// left to #1125; creating this adapter alone causes no outward traffic.
func NewGitHubDecorator(credentials ports.GitCredentialResolver) (*GitHubDecorator, error) {
	if credentials == nil {
		return nil, fmt.Errorf("%w: github decoration needs a credential resolver", shared.ErrValidation)
	}
	return newGitHubDecorator(safehttp.New(30*time.Second, false), githubAPIBase, githubCredentialHost, credentials)
}

func newGitHubDecorator(client *http.Client, apiBase, credentialHost string, credentials ports.GitCredentialResolver) (*GitHubDecorator, error) {
	if client == nil || credentials == nil {
		return nil, fmt.Errorf("%w: github decoration dependencies are required", shared.ErrValidation)
	}
	parsed, err := url.Parse(strings.TrimSpace(apiBase))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: github API base is invalid", shared.ErrValidation)
	}
	if strings.TrimSpace(credentialHost) == "" {
		return nil, fmt.Errorf("%w: github credential host is required", shared.ErrValidation)
	}
	return &GitHubDecorator{api: newJSONHTTPClient(client, parsed.String()), credentials: credentials, credentialHost: credentialHost}, nil
}

// Decorate updates the three GitHub surfaces independently. One provider failure (for example Checks
// permission denied on a PAT) does not prevent the status or summary comment from being attempted; the
// caller already treats the joined error as fail-soft. Calls are serialized in-process so two completion
// hooks cannot race each other into duplicate check/comment creation.
func (d *GitHubDecorator) Decorate(ctx context.Context, decoration ports.PRDecoration) error {
	if d == nil || d.api == nil || d.credentials == nil {
		return fmt.Errorf("%w: github decorator is not configured", shared.ErrValidation)
	}
	if !decoration.Target.Complete() {
		return fmt.Errorf("%w: github decoration target is incomplete", shared.ErrValidation)
	}
	repoPath, err := githubRepoPath(decoration.Target.Repository)
	if err != nil {
		return err
	}
	prNumber, err := strconv.ParseInt(strings.TrimSpace(decoration.Target.PullRequest), 10, 64)
	if err != nil || prNumber < 1 {
		return fmt.Errorf("%w: github pull request number is invalid", shared.ErrValidation)
	}

	credential, ok, err := d.credentials.ResolveGitCredential(ctx, d.credentialHost)
	if err != nil {
		return fmt.Errorf("resolve github decoration credential: %w", err)
	}
	if !ok || len(credential.Token) == 0 {
		return fmt.Errorf("%w: no github credential is configured for decoration", shared.ErrValidation)
	}
	defer func() {
		for i := range credential.Token {
			credential.Token[i] = 0
		}
	}()
	headers := githubHeaders(credential.Token)

	lock := d.targetLock(decoration.Target.Repository, decoration.Target.PullRequest)
	lock.Lock()
	defer lock.Unlock()

	var errs []error
	if err := d.publishStatus(ctx, repoPath, decoration, headers); err != nil {
		errs = append(errs, fmt.Errorf("github commit status: %w", err))
	}
	if err := d.publishCheck(ctx, repoPath, decoration, headers); err != nil {
		errs = append(errs, fmt.Errorf("github check run: %w", err))
	}
	if err := d.publishComment(ctx, repoPath, prNumber, decoration, headers); err != nil {
		errs = append(errs, fmt.Errorf("github pull request comment: %w", err))
	}
	return errors.Join(errs...)
}

func (d *GitHubDecorator) targetLock(repository, pullRequest string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(repository))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(pullRequest))
	return &d.locks[int(h.Sum32()%uint32(len(d.locks)))]
}

func githubHeaders(token []byte) http.Header {
	headers := http.Header{}
	headers.Set("Accept", "application/vnd.github+json")
	headers.Set("X-GitHub-Api-Version", githubAPIVersion)
	headers.Set("Authorization", "Bearer "+string(token))
	return headers
}

func githubRepoPath(slug string) (string, error) {
	parts := strings.Split(strings.TrimSpace(slug), "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("%w: github repository must be owner/repo", shared.ErrValidation)
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "." || part == ".." || strings.ContainsAny(part, "\r\n\x00") {
			return "", fmt.Errorf("%w: github repository contains an unsafe path segment", shared.ErrValidation)
		}
	}
	return url.PathEscape(strings.TrimSpace(parts[0])) + "/" + url.PathEscape(strings.TrimSpace(parts[1])), nil
}

type githubCommitStatus struct {
	State       string `json:"state"`
	Description string `json:"description"`
	Context     string `json:"context"`
}

func (d *GitHubDecorator) publishStatus(ctx context.Context, repo string, decoration ports.PRDecoration, headers http.Header) error {
	sha := url.PathEscape(strings.TrimSpace(decoration.Target.CommitSHA))
	state, description := githubGateState(decoration.Gate.Passed)
	for page := 1; page <= githubStatusPageLimit; page++ {
		query := url.Values{}
		query.Set("per_page", "100")
		query.Set("page", strconv.Itoa(page))
		path := fmt.Sprintf("/repos/%s/commits/%s/statuses?%s", repo, sha, query.Encode())
		var statuses []githubCommitStatus
		if err := d.api.doJSON(ctx, http.MethodGet, path, headers, nil, &statuses, true); err != nil {
			return err
		}
		for _, status := range statuses {
			if strings.EqualFold(status.Context, githubStatusContext) {
				if status.State == state && status.Description == description {
					return nil
				}
				// GitHub returns statuses newest first, including across pages. The first owned
				// status is therefore authoritative; an older page must never suppress an update.
				return d.postStatus(ctx, repo, sha, state, description, headers)
			}
		}
		if len(statuses) < 100 {
			break
		}
	}
	return d.postStatus(ctx, repo, sha, state, description, headers)
}

func (d *GitHubDecorator) postStatus(ctx context.Context, repo, sha, state, description string, headers http.Header) error {
	body := struct {
		State       string `json:"state"`
		Description string `json:"description"`
		Context     string `json:"context"`
	}{State: state, Description: description, Context: githubStatusContext}
	return d.api.doJSON(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/statuses/%s", repo, sha), headers, body, nil, false)
}

func githubGateState(passed bool) (string, string) {
	if passed {
		return "success", "Synapse quality gate passed"
	}
	return "failure", "Synapse quality gate failed"
}

type githubCheckRun struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	ExternalID string `json:"external_id"`
}

type githubCheckRuns struct {
	CheckRuns []githubCheckRun `json:"check_runs"`
}

type githubCheckAnnotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"`
	Message         string `json:"message"`
	Title           string `json:"title,omitempty"`
}

type githubCheckOutput struct {
	Title       string                  `json:"title"`
	Summary     string                  `json:"summary"`
	Annotations []githubCheckAnnotation `json:"annotations,omitempty"`
}

type githubCheckPayload struct {
	Name       string            `json:"name,omitempty"`
	HeadSHA    string            `json:"head_sha,omitempty"`
	ExternalID string            `json:"external_id,omitempty"`
	Status     string            `json:"status"`
	Conclusion string            `json:"conclusion"`
	Output     githubCheckOutput `json:"output"`
}

func (d *GitHubDecorator) publishCheck(ctx context.Context, repo string, decoration ports.PRDecoration, headers http.Header) error {
	sha := strings.TrimSpace(decoration.Target.CommitSHA)
	annotations := githubAnnotations(decoration.Annotations, decoration.FileChanges)
	externalID := githubExternalID(decoration.Target)
	existing, err := d.findCheckRun(ctx, repo, sha, externalID, headers)
	if err != nil {
		return err
	}
	core := githubCheckPayload{
		Name: githubCheckName, Status: "completed", Conclusion: githubConclusion(decoration.Gate.Passed),
		Output: githubCheckOutput{Title: githubCheckTitle(decoration.Gate.Passed), Summary: githubRenderedSummary(decoration)},
	}
	if existing.ID != 0 {
		// GitHub appends annotations on PATCH and offers no replace/clear operation. Keep one stable,
		// owned run for the logical PR target and update its conclusion/summary without re-appending
		// annotations. This preserves rerun idempotency instead of creating duplicate check runs.
		return d.api.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/check-runs/%d", repo, existing.ID), headers, core, nil, true)
	}

	first := annotations
	if len(first) > githubAnnotationBatch {
		first = first[:githubAnnotationBatch]
	}
	create := core
	create.HeadSHA = sha
	create.ExternalID = externalID
	create.Output.Annotations = first
	var created githubCheckRun
	createErr := d.api.doJSON(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/check-runs", repo), headers, create, &created, false)
	if createErr != nil {
		// A POST can time out after GitHub accepted it. Reconcile by the stable owned external ID before
		// giving up; never blindly repeat a create and risk duplicating the check run.
		reconciled, reconcileErr := d.findCheckRun(ctx, repo, sha, externalID, headers)
		if reconcileErr != nil || reconciled.ID == 0 {
			return createErr
		}
		created = reconciled
	}
	if created.ID == 0 {
		return fmt.Errorf("github create check run returned no id")
	}
	for start := len(first); start < len(annotations); start += githubAnnotationBatch {
		end := start + githubAnnotationBatch
		if end > len(annotations) {
			end = len(annotations)
		}
		batch := core
		batch.Output.Annotations = annotations[start:end]
		// Annotation updates append, so a timeout-after-success is uncertain: rate-limit retries are safe,
		// but network/5xx retries are intentionally disabled to avoid duplicate annotations.
		if err := d.api.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/check-runs/%d", repo, created.ID), headers, batch, nil, false); err != nil {
			return err
		}
	}
	return nil
}

func (d *GitHubDecorator) findCheckRun(ctx context.Context, repo, sha, externalID string, headers http.Header) (githubCheckRun, error) {
	for page := 1; page <= githubCheckPageLimit; page++ {
		query := url.Values{}
		query.Set("check_name", githubCheckName)
		query.Set("filter", "all")
		query.Set("per_page", "100")
		query.Set("page", strconv.Itoa(page))
		path := fmt.Sprintf("/repos/%s/commits/%s/check-runs?%s", repo, url.PathEscape(sha), query.Encode())
		var response githubCheckRuns
		if err := d.api.doJSON(ctx, http.MethodGet, path, headers, nil, &response, true); err != nil {
			return githubCheckRun{}, err
		}
		for _, run := range response.CheckRuns {
			if run.Name == githubCheckName && run.HeadSHA == sha && run.ExternalID == externalID {
				return run, nil
			}
		}
		if len(response.CheckRuns) < 100 {
			break
		}
	}
	return githubCheckRun{}, nil
}

func githubConclusion(passed bool) string {
	if passed {
		return "success"
	}
	return "failure"
}

func githubCheckTitle(passed bool) string {
	if passed {
		return "Synapse quality gate passed"
	}
	return "Synapse quality gate failed"
}

func githubExternalID(target ports.PRDecorationTarget) string {
	h := sha256.New()
	for _, value := range []string{target.Repository, target.CommitSHA, target.PullRequest, target.TargetBranch} {
		_, _ = h.Write([]byte(strings.TrimSpace(value)))
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("synapse-code-quality:%x", h.Sum(nil))
}

func githubAnnotations(items []projectanalysis.Annotation, changes []projectanalysis.FileChange) []githubCheckAnnotation {
	hunksByPath := make(map[string][]projectanalysis.DiffHunk, len(changes))
	for _, change := range changes {
		if change.Binary || strings.TrimSpace(change.NewPath) == "" || len(change.Hunks) == 0 {
			continue
		}
		hunksByPath[change.NewPath] = append(hunksByPath[change.NewPath], change.Hunks...)
	}

	out := make([]githubCheckAnnotation, 0, len(items))
	for _, item := range items {
		if item.Location.Validate() != nil {
			continue
		}
		startLine, endLine, ok := githubDiffRange(item.Location.StartLine, item.Location.EndLine, hunksByPath[item.Location.File])
		if !ok {
			continue
		}
		message := strings.TrimSpace(item.Message)
		if message == "" {
			message = strings.TrimSpace(item.RuleName)
		}
		if message == "" {
			message = strings.TrimSpace(item.RuleKey)
		}
		if message == "" {
			message = strings.TrimSpace(item.FindingKey)
		}
		if message == "" {
			continue
		}
		// Synapse SourceLocation columns are UTF-8 byte offsets. GitHub's check-run column contract
		// does not carry that unit, and this adapter has no source bytes to convert losslessly, so publish
		// the persisted diff-mapped path plus inclusive line range only rather than inventing a column.
		out = append(out, githubCheckAnnotation{
			Path: item.Location.File, StartLine: startLine, EndLine: endLine,
			AnnotationLevel: githubAnnotationLevel(item.Severity), Message: truncateUTF8(message, githubAnnotationLimit),
			Title: truncateUTF8(firstNonEmpty(item.RuleName, item.RuleKey), githubAnnotationTitle),
		})
	}
	return out
}

// githubDiffRange anchors a head-side source range to one persisted Git hunk. A finding outside the
// retained PR diff is intentionally omitted from inline annotations; it remains represented in the
// summary instead of being attached to a line GitHub cannot prove belongs to this change.
func githubDiffRange(startLine, endLine int, hunks []projectanalysis.DiffHunk) (int, int, bool) {
	for _, hunk := range hunks {
		first, last := 0, 0
		for _, row := range hunk.Rows {
			if row.NewLine < 1 {
				continue
			}
			if first == 0 || row.NewLine < first {
				first = row.NewLine
			}
			if row.NewLine > last {
				last = row.NewLine
			}
		}
		if first == 0 || endLine < first || startLine > last {
			continue
		}
		mappedStart, mappedEnd := startLine, endLine
		if mappedStart < first {
			mappedStart = first
		}
		if mappedEnd > last {
			mappedEnd = last
		}
		if mappedStart <= mappedEnd {
			return mappedStart, mappedEnd, true
		}
	}
	return 0, 0, false
}

func githubAnnotationLevel(severity shared.Severity) string {
	switch severity {
	case shared.SeverityCritical, shared.SeverityHigh:
		return "failure"
	case shared.SeverityMedium:
		return "warning"
	default:
		return "notice"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

type githubIssueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

func (d *GitHubDecorator) publishComment(ctx context.Context, repo string, prNumber int64, decoration ports.PRDecoration, headers http.Header) error {
	body := githubCommentBody(decoration)
	existing, err := d.findComment(ctx, repo, prNumber, headers)
	if err != nil {
		return err
	}
	payload := struct {
		Body string `json:"body"`
	}{Body: body}
	if existing.ID != 0 {
		if existing.Body == body {
			return nil
		}
		return d.api.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/comments/%d", repo, existing.ID), headers, payload, nil, true)
	}
	createErr := d.api.doJSON(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", repo, prNumber), headers, payload, nil, false)
	if createErr == nil {
		return nil
	}
	// As with check creation, reconcile an uncertain POST before reporting failure instead of blindly
	// repeating it and creating a second summary thread.
	reconciled, reconcileErr := d.findComment(ctx, repo, prNumber, headers)
	if reconcileErr == nil && reconciled.ID != 0 {
		return nil
	}
	return createErr
}

func (d *GitHubDecorator) findComment(ctx context.Context, repo string, prNumber int64, headers http.Header) (githubIssueComment, error) {
	for page := 1; page <= githubCommentPageLimit; page++ {
		path := fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100&page=%d", repo, prNumber, page)
		var comments []githubIssueComment
		if err := d.api.doJSON(ctx, http.MethodGet, path, headers, nil, &comments, true); err != nil {
			return githubIssueComment{}, err
		}
		for _, comment := range comments {
			if strings.HasPrefix(strings.TrimSpace(comment.Body), githubCommentMarker) {
				return comment, nil
			}
		}
		if len(comments) < 100 {
			break
		}
	}
	return githubIssueComment{}, nil
}

func githubCommentBody(decoration ports.PRDecoration) string {
	summary := githubRenderedSummary(decoration)
	available := githubSummaryLimit - utf8.RuneCountInString(githubCommentMarker) - 2
	if available < 0 {
		available = 0
	}
	return githubCommentMarker + "\n\n" + truncateUTF8(summary, available)
}

func githubRenderedSummary(decoration ports.PRDecoration) string {
	base := strings.TrimSpace(decoration.Summary)
	newIssues := "unavailable"
	if decoration.NewIssues != nil {
		newIssues = strconv.Itoa(*decoration.NewIssues)
	}
	newCoverage := "unavailable"
	if decoration.NewCoverage != nil {
		newCoverage = fmt.Sprintf("%.1f%%", *decoration.NewCoverage)
	} else if reason := strings.TrimSpace(decoration.NewCoverageReason); reason != "" {
		newCoverage = "unavailable (" + reason + ")"
	}
	delta := fmt.Sprintf("### New code\n\n- New issues: %s\n- New coverage: %s", newIssues, newCoverage)
	if base == "" {
		return truncateUTF8(delta, githubSummaryLimit)
	}
	return truncateUTF8(base+"\n\n"+delta, githubSummaryLimit)
}

func truncateUTF8(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	if maxRunes == 1 {
		return string(runes[:1])
	}
	return string(runes[:maxRunes-1]) + "…"
}
