package scmdecoration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"sort"
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
	gitlabAPIBase          = "https://gitlab.com/api/v4"
	gitlabCredentialHost   = "gitlab.com"
	gitlabStatusName       = "synapse/code-quality"
	gitlabNoteMarker       = "<!-- synapse:code-quality-decoration:v1 -->"
	gitlabSummaryLimit     = 900_000
	gitlabStatusPageLimit  = 20
	gitlabNotePageLimit    = 20
	gitlabReportEntryLimit = 100_000
)

// GitLabDecorator publishes the provider-neutral PR decoration through GitLab's commit-status and
// merge-request note APIs. The connector token is resolved at call time from tenant context, presented
// as the PRIVATE-TOKEN header, and is never stored in the decoration payload or included in returned
// errors. The native Code Quality report artifact (CodeClimate schema) is rendered by
// GitLabCodeQualityReport for the CI wiring in #1125; the adapter itself performs no artifact upload.
type GitLabDecorator struct {
	api            *jsonHTTPClient
	credentials    ports.GitCredentialResolver
	credentialHost string
	locks          [32]sync.Mutex
}

var _ ports.PRDecorator = (*GitLabDecorator)(nil)

// NewGitLabDecorator constructs the production gitlab.com adapter. Provider composition is intentionally
// left to #1125; creating this adapter alone causes no outward traffic.
func NewGitLabDecorator(credentials ports.GitCredentialResolver) (*GitLabDecorator, error) {
	if credentials == nil {
		return nil, fmt.Errorf("%w: gitlab decoration needs a credential resolver", shared.ErrValidation)
	}
	return newGitLabDecorator(safehttp.New(30*time.Second, false), gitlabAPIBase, gitlabCredentialHost, credentials)
}

func newGitLabDecorator(client *http.Client, apiBase, credentialHost string, credentials ports.GitCredentialResolver) (*GitLabDecorator, error) {
	if client == nil || credentials == nil {
		return nil, fmt.Errorf("%w: gitlab decoration dependencies are required", shared.ErrValidation)
	}
	parsed, err := url.Parse(strings.TrimSpace(apiBase))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: gitlab API base is invalid", shared.ErrValidation)
	}
	if strings.TrimSpace(credentialHost) == "" {
		return nil, fmt.Errorf("%w: gitlab credential host is required", shared.ErrValidation)
	}
	return &GitLabDecorator{api: newJSONHTTPClient(client, parsed.String()), credentials: credentials, credentialHost: credentialHost}, nil
}

// Decorate updates the two GitLab surfaces independently. One surface failing (for example the token
// lacking api scope for notes) does not prevent the other from being attempted; the caller already
// treats the joined error as fail-soft. Calls are serialized in-process per target so two completion
// hooks cannot race each other into a duplicate MR note.
func (d *GitLabDecorator) Decorate(ctx context.Context, decoration ports.PRDecoration) error {
	if d == nil || d.api == nil || d.credentials == nil {
		return fmt.Errorf("%w: gitlab decorator is not configured", shared.ErrValidation)
	}
	if !decoration.Target.Complete() {
		return fmt.Errorf("%w: gitlab decoration target is incomplete", shared.ErrValidation)
	}
	projectID, err := gitlabProjectID(decoration.Target.Repository)
	if err != nil {
		return err
	}
	mrIID, err := strconv.ParseInt(strings.TrimSpace(decoration.Target.PullRequest), 10, 64)
	if err != nil || mrIID < 1 {
		return fmt.Errorf("%w: gitlab merge request iid is invalid", shared.ErrValidation)
	}
	sha := strings.TrimSpace(decoration.Target.CommitSHA)
	if sha == "" || strings.ContainsAny(sha, "/?#\r\n\x00") {
		return fmt.Errorf("%w: gitlab commit sha is invalid", shared.ErrValidation)
	}

	credential, ok, err := d.credentials.ResolveGitCredential(ctx, d.credentialHost)
	if err != nil {
		return fmt.Errorf("resolve gitlab decoration credential: %w", err)
	}
	if !ok || len(credential.Token) == 0 {
		return fmt.Errorf("%w: no gitlab credential is configured for decoration", shared.ErrValidation)
	}
	defer func() {
		for i := range credential.Token {
			credential.Token[i] = 0
		}
	}()
	headers := gitlabHeaders(credential.Token)

	lock := d.targetLock(decoration.Target.Repository, decoration.Target.PullRequest)
	lock.Lock()
	defer lock.Unlock()

	var errs []error
	if err := d.publishStatus(ctx, projectID, sha, decoration, headers); err != nil {
		errs = append(errs, fmt.Errorf("gitlab commit status: %w", err))
	}
	if err := d.publishNote(ctx, projectID, mrIID, decoration, headers); err != nil {
		errs = append(errs, fmt.Errorf("gitlab merge request note: %w", err))
	}
	return errors.Join(errs...)
}

func (d *GitLabDecorator) targetLock(repository, pullRequest string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(repository))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(pullRequest))
	return &d.locks[int(h.Sum32()%uint32(len(d.locks)))]
}

func gitlabHeaders(token []byte) http.Header {
	headers := http.Header{}
	headers.Set("Accept", "application/json")
	headers.Set("PRIVATE-TOKEN", string(token))
	return headers
}

// gitlabProjectID renders the owner/project slug as the URL-encoded path identifier GitLab accepts in
// place of a numeric id. Nested groups (group/subgroup/project) are supported; every slash becomes %2F.
func gitlabProjectID(slug string) (string, error) {
	slug = strings.TrimSpace(slug)
	parts := strings.Split(slug, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("%w: gitlab repository must be group/project", shared.ErrValidation)
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\r\n\x00") {
			return "", fmt.Errorf("%w: gitlab repository contains an unsafe path segment", shared.ErrValidation)
		}
	}
	return url.PathEscape(slug), nil
}

type gitlabCommitStatus struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

func (d *GitLabDecorator) publishStatus(ctx context.Context, projectID, sha string, decoration ports.PRDecoration, headers http.Header) error {
	state, description := gitlabGateState(decoration.Gate.Passed)
	// Skip only when the exact owned target already exists; otherwise POST. This is order-independent
	// so it does not depend on GitLab's undocumented status ordering, and a GitLab status POST with the
	// same (name, ref) updates the owned entry in place, so re-posting the current verdict is idempotent.
	for page := 1; page <= gitlabStatusPageLimit; page++ {
		query := url.Values{}
		query.Set("per_page", "100")
		query.Set("page", strconv.Itoa(page))
		path := fmt.Sprintf("/projects/%s/repository/commits/%s/statuses?%s", projectID, url.PathEscape(sha), query.Encode())
		var statuses []gitlabCommitStatus
		if err := d.api.doJSON(ctx, http.MethodGet, path, headers, nil, &statuses, true); err != nil {
			return err
		}
		for _, status := range statuses {
			if strings.EqualFold(status.Name, gitlabStatusName) && status.Status == state && status.Description == description {
				return nil
			}
		}
		if len(statuses) < 100 {
			break
		}
	}
	return d.postStatus(ctx, projectID, sha, state, description, headers)
}

func (d *GitLabDecorator) postStatus(ctx context.Context, projectID, sha, state, description string, headers http.Header) error {
	body := struct {
		State       string `json:"state"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}{State: state, Name: gitlabStatusName, Description: description}
	return d.api.doJSON(ctx, http.MethodPost, fmt.Sprintf("/projects/%s/statuses/%s", projectID, url.PathEscape(sha)), headers, body, nil, false)
}

// gitlabGateState maps the gate verdict onto GitLab's commit-status state vocabulary
// (success/failed/pending/running/canceled).
func gitlabGateState(passed bool) (string, string) {
	if passed {
		return "success", "Synapse quality gate passed"
	}
	return "failed", "Synapse quality gate failed"
}

type gitlabNote struct {
	ID     int64  `json:"id"`
	Body   string `json:"body"`
	System bool   `json:"system"`
}

func (d *GitLabDecorator) publishNote(ctx context.Context, projectID string, mrIID int64, decoration ports.PRDecoration, headers http.Header) error {
	body := gitlabNoteBody(decoration)
	existing, err := d.findNote(ctx, projectID, mrIID, headers)
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
		return d.api.doJSON(ctx, http.MethodPut, fmt.Sprintf("/projects/%s/merge_requests/%d/notes/%d", projectID, mrIID, existing.ID), headers, payload, nil, true)
	}
	createErr := d.api.doJSON(ctx, http.MethodPost, fmt.Sprintf("/projects/%s/merge_requests/%d/notes", projectID, mrIID), headers, payload, nil, false)
	if createErr == nil {
		return nil
	}
	// A POST can time out after GitLab accepted it. Reconcile by the owned marker before giving up
	// instead of blindly repeating the create and posting a second summary note.
	reconciled, reconcileErr := d.findNote(ctx, projectID, mrIID, headers)
	if reconcileErr == nil && reconciled.ID != 0 {
		return nil
	}
	return createErr
}

func (d *GitLabDecorator) findNote(ctx context.Context, projectID string, mrIID int64, headers http.Header) (gitlabNote, error) {
	for page := 1; page <= gitlabNotePageLimit; page++ {
		path := fmt.Sprintf("/projects/%s/merge_requests/%d/notes?per_page=100&page=%d", projectID, mrIID, page)
		var notes []gitlabNote
		if err := d.api.doJSON(ctx, http.MethodGet, path, headers, nil, &notes, true); err != nil {
			return gitlabNote{}, err
		}
		for _, note := range notes {
			if note.System {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(note.Body), gitlabNoteMarker) {
				return note, nil
			}
		}
		if len(notes) < 100 {
			break
		}
	}
	return gitlabNote{}, nil
}

func gitlabNoteBody(decoration ports.PRDecoration) string {
	summary := gitlabRenderedSummary(decoration)
	available := gitlabSummaryLimit - utf8.RuneCountInString(gitlabNoteMarker) - 2
	if available < 0 {
		available = 0
	}
	return gitlabNoteMarker + "\n\n" + truncateUTF8(summary, available)
}

func gitlabRenderedSummary(decoration ports.PRDecoration) string {
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
		return truncateUTF8(delta, gitlabSummaryLimit)
	}
	return truncateUTF8(base+"\n\n"+delta, gitlabSummaryLimit)
}

// codeClimateIssue is one entry of the GitLab Code Quality report (CodeClimate schema). GitLab renders
// inline quality diffs by matching entry fingerprints between the target-branch and head reports, so the
// fingerprint must be stable across runs for the same finding and unique within a report.
type codeClimateIssue struct {
	Description string              `json:"description"`
	CheckName   string              `json:"check_name"`
	Fingerprint string              `json:"fingerprint"`
	Severity    string              `json:"severity"`
	Location    codeClimateLocation `json:"location"`
}

type codeClimateLocation struct {
	Path  string           `json:"path"`
	Lines codeClimateLines `json:"lines"`
}

type codeClimateLines struct {
	Begin int `json:"begin"`
}

// GitLabCodeQualityReport renders the decoration annotations as a deterministic gl-code-quality-report.json
// document (CodeClimate schema). The CI wiring (#1125) writes this to the job workspace so GitLab renders
// inline quality diffs on the merge request. Output is stable: entries are sorted by (path, line,
// fingerprint) and every fingerprint is a content hash, so an unchanged analysis yields byte-identical
// bytes and GitLab reports no spurious degradation.
func GitLabCodeQualityReport(decoration ports.PRDecoration) ([]byte, error) {
	issues := make([]codeClimateIssue, 0, len(decoration.Annotations))
	seen := make(map[string]struct{}, len(decoration.Annotations))
	for _, item := range decoration.Annotations {
		if item.Location.Validate() != nil || item.Location.StartLine < 1 {
			continue
		}
		message := firstNonEmpty(item.Message, item.RuleName, item.RuleKey, item.FindingKey)
		if message == "" {
			continue
		}
		fingerprint := codeClimateFingerprint(item)
		if _, dup := seen[fingerprint]; dup {
			continue
		}
		seen[fingerprint] = struct{}{}
		issues = append(issues, codeClimateIssue{
			Description: truncateUTF8(message, gitlabReportEntryLimit),
			CheckName:   firstNonEmpty(item.RuleKey, item.RuleName, "synapse:code-quality"),
			Fingerprint: fingerprint,
			Severity:    gitlabCodeClimateSeverity(item.Severity),
			Location:    codeClimateLocation{Path: item.Location.File, Lines: codeClimateLines{Begin: item.Location.StartLine}},
		})
	}
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Location.Path != issues[j].Location.Path {
			return issues[i].Location.Path < issues[j].Location.Path
		}
		if issues[i].Location.Lines.Begin != issues[j].Location.Lines.Begin {
			return issues[i].Location.Lines.Begin < issues[j].Location.Lines.Begin
		}
		return issues[i].Fingerprint < issues[j].Fingerprint
	})
	return json.MarshalIndent(issues, "", "  ")
}

// codeClimateFingerprint is a stable per-finding content hash: identical across runs for the same
// finding (so GitLab matches base/head reports without spurious degradation) and distinct between
// findings. Message is included so two findings sharing a file and line but differing in rule text do
// not collapse into one entry when their keys are empty.
func codeClimateFingerprint(item projectanalysis.Annotation) string {
	h := sha256.New()
	for _, value := range []string{
		item.FindingKey, item.RuleKey, item.Location.File,
		strconv.Itoa(item.Location.StartLine), strconv.Itoa(item.Location.EndLine),
		item.Message,
	} {
		_, _ = h.Write([]byte(strings.TrimSpace(value)))
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// gitlabCodeClimateSeverity maps the owned severity onto the CodeClimate severity vocabulary GitLab
// accepts (info/minor/major/critical/blocker).
func gitlabCodeClimateSeverity(severity shared.Severity) string {
	switch severity {
	case shared.SeverityCritical:
		return "blocker"
	case shared.SeverityHigh:
		return "critical"
	case shared.SeverityMedium:
		return "major"
	case shared.SeverityLow:
		return "minor"
	default:
		return "info"
	}
}
