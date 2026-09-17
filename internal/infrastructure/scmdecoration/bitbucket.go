package scmdecoration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	bitbucketAPIBase          = "https://api.bitbucket.org/2.0"
	bitbucketCredentialHost   = "bitbucket.org"
	bitbucketStatusKey        = "synapse-code-quality"
	bitbucketReportID         = "synapse-code-quality"
	bitbucketReportTitle      = "Synapse quality gate"
	bitbucketReporter         = "Synapse"
	bitbucketCommentMarker    = "<!-- synapse:code-quality-decoration:v1 -->"
	bitbucketDefaultUser      = "x-token-auth"
	bitbucketAnnotationBatch  = 100
	bitbucketAnnotationCap    = 1000
	bitbucketSummaryLimit     = 32_000
	bitbucketReportDetail     = 2_000
	bitbucketAnnotationTitle  = 255
	bitbucketAnnotationDetail = 2_000
	bitbucketCommentPageLimit = 20
)

// BitbucketDecorator publishes the provider-neutral PR decoration through Bitbucket Cloud's build-status,
// Code Insights, and pull-request comment APIs. The connector token is resolved at call time from tenant
// context, presented via HTTP Basic auth, and is never stored in the decoration payload or included in
// returned errors.
type BitbucketDecorator struct {
	api            *jsonHTTPClient
	credentials    ports.GitCredentialResolver
	credentialHost string
	locks          [32]sync.Mutex
}

var _ ports.PRDecorator = (*BitbucketDecorator)(nil)

// NewBitbucketDecorator constructs the production bitbucket.org adapter. Provider composition is
// intentionally left to #1125; creating this adapter alone causes no outward traffic.
func NewBitbucketDecorator(credentials ports.GitCredentialResolver) (*BitbucketDecorator, error) {
	if credentials == nil {
		return nil, fmt.Errorf("%w: bitbucket decoration needs a credential resolver", shared.ErrValidation)
	}
	return newBitbucketDecorator(safehttp.New(30*time.Second, false), bitbucketAPIBase, bitbucketCredentialHost, credentials)
}

func newBitbucketDecorator(client *http.Client, apiBase, credentialHost string, credentials ports.GitCredentialResolver) (*BitbucketDecorator, error) {
	if client == nil || credentials == nil {
		return nil, fmt.Errorf("%w: bitbucket decoration dependencies are required", shared.ErrValidation)
	}
	parsed, err := url.Parse(strings.TrimSpace(apiBase))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: bitbucket API base is invalid", shared.ErrValidation)
	}
	if strings.TrimSpace(credentialHost) == "" {
		return nil, fmt.Errorf("%w: bitbucket credential host is required", shared.ErrValidation)
	}
	return &BitbucketDecorator{api: newJSONHTTPClient(client, parsed.String()), credentials: credentials, credentialHost: credentialHost}, nil
}

// Decorate updates the three Bitbucket surfaces independently. One surface failing (for example the
// token lacking pullrequest:write for the comment) does not prevent the others from being attempted;
// the caller already treats the joined error as fail-soft. Calls are serialized in-process per target
// so two completion hooks cannot race each other into a duplicate comment.
func (d *BitbucketDecorator) Decorate(ctx context.Context, decoration ports.PRDecoration) error {
	if d == nil || d.api == nil || d.credentials == nil {
		return fmt.Errorf("%w: bitbucket decorator is not configured", shared.ErrValidation)
	}
	if !decoration.Target.Complete() {
		return fmt.Errorf("%w: bitbucket decoration target is incomplete", shared.ErrValidation)
	}
	repoPath, err := bitbucketRepoPath(decoration.Target.Repository)
	if err != nil {
		return err
	}
	prID, err := strconv.ParseInt(strings.TrimSpace(decoration.Target.PullRequest), 10, 64)
	if err != nil || prID < 1 {
		return fmt.Errorf("%w: bitbucket pull request id is invalid", shared.ErrValidation)
	}
	sha := strings.TrimSpace(decoration.Target.CommitSHA)
	if sha == "" || strings.ContainsAny(sha, "/?#\r\n\x00") {
		return fmt.Errorf("%w: bitbucket commit sha is invalid", shared.ErrValidation)
	}

	credential, ok, err := d.credentials.ResolveGitCredential(ctx, d.credentialHost)
	if err != nil {
		return fmt.Errorf("resolve bitbucket decoration credential: %w", err)
	}
	if !ok || len(credential.Token) == 0 {
		return fmt.Errorf("%w: no bitbucket credential is configured for decoration", shared.ErrValidation)
	}
	defer func() {
		for i := range credential.Token {
			credential.Token[i] = 0
		}
	}()
	headers := bitbucketHeaders(credential.Username, credential.Token)

	lock := d.targetLock(decoration.Target.Repository, decoration.Target.PullRequest)
	lock.Lock()
	defer lock.Unlock()

	var errs []error
	if err := d.publishBuildStatus(ctx, repoPath, sha, decoration, headers); err != nil {
		errs = append(errs, fmt.Errorf("bitbucket build status: %w", err))
	}
	if err := d.publishReport(ctx, repoPath, sha, decoration, headers); err != nil {
		errs = append(errs, fmt.Errorf("bitbucket code insights report: %w", err))
	}
	if err := d.publishComment(ctx, repoPath, prID, decoration, headers); err != nil {
		errs = append(errs, fmt.Errorf("bitbucket pull request comment: %w", err))
	}
	return errors.Join(errs...)
}

func (d *BitbucketDecorator) targetLock(repository, pullRequest string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(repository))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(pullRequest))
	return &d.locks[int(h.Sum32()%uint32(len(d.locks)))]
}

func bitbucketHeaders(username string, token []byte) http.Header {
	user := strings.TrimSpace(username)
	if user == "" {
		// Bitbucket access tokens (workspace/repo/project) authenticate over Basic with a fixed username.
		user = bitbucketDefaultUser
	}
	credential := base64.StdEncoding.EncodeToString([]byte(user + ":" + string(token)))
	headers := http.Header{}
	headers.Set("Accept", "application/json")
	headers.Set("Authorization", "Basic "+credential)
	return headers
}

func bitbucketRepoPath(slug string) (string, error) {
	parts := strings.Split(strings.TrimSpace(slug), "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("%w: bitbucket repository must be workspace/repo", shared.ErrValidation)
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "." || part == ".." || strings.ContainsAny(part, "\r\n\x00") {
			return "", fmt.Errorf("%w: bitbucket repository contains an unsafe path segment", shared.ErrValidation)
		}
	}
	return url.PathEscape(strings.TrimSpace(parts[0])) + "/" + url.PathEscape(strings.TrimSpace(parts[1])), nil
}

type bitbucketBuildStatus struct {
	Key         string `json:"key"`
	State       string `json:"state"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (d *BitbucketDecorator) publishBuildStatus(ctx context.Context, repo, sha string, decoration ports.PRDecoration, headers http.Header) error {
	state := bitbucketBuildState(decoration.Gate.Passed)
	description := bitbucketGateDescription(decoration.Gate.Passed)
	// The build status is keyed; a GET by key lets us skip a redundant write, and a POST upserts by key
	// so a rerun updates the one owned status in place rather than duplicating it.
	var existing bitbucketBuildStatus
	err := d.api.doJSON(ctx, http.MethodGet, fmt.Sprintf("/repositories/%s/commit/%s/statuses/build/%s", repo, url.PathEscape(sha), bitbucketStatusKey), headers, nil, &existing, true)
	if err == nil && existing.Key == bitbucketStatusKey && existing.State == state && existing.Description == description {
		return nil
	}
	body := bitbucketBuildStatus{Key: bitbucketStatusKey, State: state, Name: bitbucketReportTitle, Description: description}
	return d.api.doJSON(ctx, http.MethodPost, fmt.Sprintf("/repositories/%s/commit/%s/statuses/build", repo, url.PathEscape(sha)), headers, body, nil, true)
}

func bitbucketBuildState(passed bool) string {
	if passed {
		return "SUCCESSFUL"
	}
	return "FAILED"
}

func bitbucketGateDescription(passed bool) string {
	if passed {
		return "Synapse quality gate passed"
	}
	return "Synapse quality gate failed"
}

type bitbucketReport struct {
	Title      string `json:"title"`
	Details    string `json:"details"`
	ReportType string `json:"report_type"`
	Reporter   string `json:"reporter"`
	Result     string `json:"result"`
}

type bitbucketAnnotation struct {
	ExternalID     string `json:"external_id"`
	Title          string `json:"title,omitempty"`
	AnnotationType string `json:"annotation_type"`
	Summary        string `json:"summary"`
	Severity       string `json:"severity"`
	Path           string `json:"path"`
	Line           int    `json:"line"`
}

func (d *BitbucketDecorator) publishReport(ctx context.Context, repo, sha string, decoration ports.PRDecoration, headers http.Header) error {
	report := bitbucketReport{
		Title: bitbucketReportTitle,
		// Bitbucket's Code Insights report `details` field caps at 2000 characters, much smaller than the
		// PR comment; truncate to the report-specific limit so a large summary does not make the PUT 400.
		Details:    truncateUTF8(bitbucketRenderedSummary(decoration), bitbucketReportDetail),
		ReportType: "BUG",
		Reporter:   bitbucketReporter,
		Result:     bitbucketReportResult(decoration.Gate.Passed),
	}
	// PUT upserts by the owned report id, so a rerun replaces the one report rather than duplicating it.
	if err := d.api.doJSON(ctx, http.MethodPut, fmt.Sprintf("/repositories/%s/commit/%s/reports/%s", repo, url.PathEscape(sha), bitbucketReportID), headers, report, nil, true); err != nil {
		return err
	}
	annotations := bitbucketAnnotations(decoration.Annotations, decoration.FileChanges)
	for start := 0; start < len(annotations); start += bitbucketAnnotationBatch {
		end := start + bitbucketAnnotationBatch
		if end > len(annotations) {
			end = len(annotations)
		}
		// Bulk create/update upserts by external_id, so re-publishing the same findings is idempotent.
		if err := d.api.doJSON(ctx, http.MethodPost, fmt.Sprintf("/repositories/%s/commit/%s/reports/%s/annotations", repo, url.PathEscape(sha), bitbucketReportID), headers, annotations[start:end], nil, true); err != nil {
			return err
		}
	}
	return nil
}

func bitbucketReportResult(passed bool) string {
	if passed {
		return "PASSED"
	}
	return "FAILED"
}

func bitbucketAnnotations(items []projectanalysis.Annotation, changes []projectanalysis.FileChange) []bitbucketAnnotation {
	hunksByPath := make(map[string][]projectanalysis.DiffHunk, len(changes))
	for _, change := range changes {
		if change.Binary || strings.TrimSpace(change.NewPath) == "" || len(change.Hunks) == 0 {
			continue
		}
		hunksByPath[change.NewPath] = append(hunksByPath[change.NewPath], change.Hunks...)
	}

	out := make([]bitbucketAnnotation, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if len(out) >= bitbucketAnnotationCap {
			break
		}
		if item.Location.Validate() != nil {
			continue
		}
		startLine, _, ok := githubDiffRange(item.Location.StartLine, item.Location.EndLine, hunksByPath[item.Location.File])
		if !ok {
			continue
		}
		message := firstNonEmpty(item.Message, item.RuleName, item.RuleKey, item.FindingKey)
		if message == "" {
			continue
		}
		externalID := bitbucketAnnotationID(item)
		if _, dup := seen[externalID]; dup {
			continue
		}
		seen[externalID] = struct{}{}
		out = append(out, bitbucketAnnotation{
			ExternalID:     externalID,
			Title:          truncateUTF8(firstNonEmpty(item.RuleName, item.RuleKey), bitbucketAnnotationTitle),
			AnnotationType: bitbucketAnnotationType(item.RuleType),
			Summary:        truncateUTF8(message, bitbucketAnnotationDetail),
			Severity:       bitbucketAnnotationSeverity(item.Severity),
			Path:           item.Location.File,
			Line:           startLine,
		})
	}
	return out
}

func bitbucketAnnotationID(item projectanalysis.Annotation) string {
	h := sha256.New()
	for _, value := range []string{
		item.FindingKey, item.RuleKey, item.Location.File,
		strconv.Itoa(item.Location.StartLine), strconv.Itoa(item.Location.EndLine), item.Message,
	} {
		_, _ = h.Write([]byte(strings.TrimSpace(value)))
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("synapse-%x", h.Sum(nil))
}

// bitbucketAnnotationType maps the code-quality rule taxonomy onto Bitbucket's Code Insights annotation
// vocabulary (BUG/VULNERABILITY/CODE_SMELL). A security hotspot is reported as a vulnerability so it is
// not lost in the neutral code-smell bucket.
func bitbucketAnnotationType(ruleType rule.Type) string {
	switch ruleType {
	case rule.TypeVulnerability, rule.TypeSecurityHotspot:
		return "VULNERABILITY"
	case rule.TypeBug:
		return "BUG"
	default:
		return "CODE_SMELL"
	}
}

func bitbucketAnnotationSeverity(severity shared.Severity) string {
	switch severity {
	case shared.SeverityCritical:
		return "CRITICAL"
	case shared.SeverityHigh:
		return "HIGH"
	case shared.SeverityMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

type bitbucketComment struct {
	ID      int64 `json:"id"`
	Content struct {
		Raw string `json:"raw"`
	} `json:"content"`
	Deleted bool `json:"deleted"`
}

type bitbucketCommentPage struct {
	Values []bitbucketComment `json:"values"`
	Next   string             `json:"next"`
}

func (d *BitbucketDecorator) publishComment(ctx context.Context, repo string, prID int64, decoration ports.PRDecoration, headers http.Header) error {
	body := bitbucketCommentBody(decoration)
	existing, err := d.findComment(ctx, repo, prID, headers)
	if err != nil {
		return err
	}
	payload := bitbucketCommentPayload(body)
	if existing.ID != 0 {
		if strings.TrimSpace(existing.Content.Raw) == strings.TrimSpace(body) {
			return nil
		}
		return d.api.doJSON(ctx, http.MethodPut, fmt.Sprintf("/repositories/%s/pullrequests/%d/comments/%d", repo, prID, existing.ID), headers, payload, nil, true)
	}
	createErr := d.api.doJSON(ctx, http.MethodPost, fmt.Sprintf("/repositories/%s/pullrequests/%d/comments", repo, prID), headers, payload, nil, false)
	if createErr == nil {
		return nil
	}
	// Reconcile an uncertain POST by the owned marker before reporting failure, so a timeout after the
	// comment was created does not add a second summary thread on retry.
	reconciled, reconcileErr := d.findComment(ctx, repo, prID, headers)
	if reconcileErr == nil && reconciled.ID != 0 {
		return nil
	}
	return createErr
}

func (d *BitbucketDecorator) findComment(ctx context.Context, repo string, prID int64, headers http.Header) (bitbucketComment, error) {
	path := fmt.Sprintf("/repositories/%s/pullrequests/%d/comments?pagelen=100", repo, prID)
	for page := 0; page < bitbucketCommentPageLimit && path != ""; page++ {
		var response bitbucketCommentPage
		if err := d.api.doJSON(ctx, http.MethodGet, path, headers, nil, &response, true); err != nil {
			return bitbucketComment{}, err
		}
		for _, comment := range response.Values {
			if comment.Deleted {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(comment.Content.Raw), bitbucketCommentMarker) {
				return comment, nil
			}
		}
		next, ok := bitbucketRelativeNext(response.Next)
		if !ok {
			break
		}
		path = next
	}
	return bitbucketComment{}, nil
}

// bitbucketRelativeNext converts the absolute pagination cursor Bitbucket returns into a path the shared
// client can send, and refuses any cursor that would leave the pinned API host.
func bitbucketRelativeNext(next string) (string, bool) {
	next = strings.TrimSpace(next)
	if next == "" {
		return "", false
	}
	parsed, err := url.Parse(next)
	if err != nil {
		return "", false
	}
	if parsed.Host != "" && parsed.Host != "api.bitbucket.org" {
		return "", false
	}
	path := parsed.EscapedPath()
	if !strings.HasPrefix(path, "/2.0/") {
		return "", false
	}
	relative := strings.TrimPrefix(path, "/2.0")
	if parsed.RawQuery != "" {
		relative += "?" + parsed.RawQuery
	}
	return relative, true
}

func bitbucketCommentPayload(body string) map[string]any {
	return map[string]any{"content": map[string]any{"raw": body}}
}

func bitbucketCommentBody(decoration ports.PRDecoration) string {
	summary := bitbucketRenderedSummary(decoration)
	available := bitbucketSummaryLimit - utf8.RuneCountInString(bitbucketCommentMarker) - 2
	if available < 0 {
		available = 0
	}
	return bitbucketCommentMarker + "\n\n" + truncateUTF8(summary, available)
}

func bitbucketRenderedSummary(decoration ports.PRDecoration) string {
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
		return truncateUTF8(delta, bitbucketSummaryLimit)
	}
	return truncateUTF8(base+"\n\n"+delta, bitbucketSummaryLimit)
}
