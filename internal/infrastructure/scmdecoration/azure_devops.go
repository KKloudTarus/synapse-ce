package scmdecoration

import (
	"context"
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

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	azureAPIBase       = "https://dev.azure.com"
	azureSCMHost       = "dev.azure.com"
	azureStatusName    = "synapse/code-quality"
	azureStatusGenre   = "synapse"
	azureCommentMarker = "<!-- synapse:azure-devops:code-quality:v1 -->"
	azureCommentLimit  = 30000
)

// AzureDevOpsDecorator publishes quality-gate statuses and one owned PR summary thread.
// Credentials are resolved from the current tenant's scmconnector at call time and are
// sent only to the pinned Azure DevOps SaaS origin. A status failure cannot suppress
// the comment attempt (or vice versa), and the caller treats joined errors as fail-soft.
type AzureDevOpsDecorator struct {
	api            *jsonHTTPClient
	credentials    ports.GitCredentialResolver
	credentialHost string
	locks          [32]sync.Mutex
}

var _ ports.PRDecorator = (*AzureDevOpsDecorator)(nil)

func NewAzureDevOpsDecorator(credentials ports.GitCredentialResolver) (*AzureDevOpsDecorator, error) {
	if credentials == nil {
		return nil, fmt.Errorf("%w: Azure DevOps decoration requires a credential resolver", shared.ErrValidation)
	}
	return newAzureDevOpsDecorator(safehttp.New(30*time.Second, false), azureAPIBase, azureSCMHost, credentials)
}

// The injected client and API origin are used only by fake-server contract tests.
func newAzureDevOpsDecorator(client *http.Client, apiBase, credentialHost string, credentials ports.GitCredentialResolver) (*AzureDevOpsDecorator, error) {
	if client == nil || credentials == nil {
		return nil, fmt.Errorf("%w: Azure DevOps decoration dependencies are required", shared.ErrValidation)
	}
	u, err := url.Parse(strings.TrimSpace(apiBase))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, fmt.Errorf("%w: invalid Azure DevOps API origin", shared.ErrValidation)
	}
	if credentialHost != azureSCMHost {
		return nil, fmt.Errorf("%w: Azure DevOps credential host must be dev.azure.com", shared.ErrValidation)
	}
	return &AzureDevOpsDecorator{api: newJSONHTTPClient(client, u.String()), credentials: credentials, credentialHost: credentialHost}, nil
}

func (d *AzureDevOpsDecorator) Decorate(ctx context.Context, decoration ports.PRDecoration) error {
	if d == nil || d.api == nil || d.credentials == nil {
		return fmt.Errorf("%w: Azure DevOps decorator is not configured", shared.ErrValidation)
	}
	if !decoration.Target.Complete() {
		return fmt.Errorf("%w: Azure DevOps PR target is incomplete", shared.ErrValidation)
	}
	repoPath, err := azureRepoPath(decoration.Target.Repository)
	if err != nil {
		return err
	}
	prID, err := strconv.ParseInt(strings.TrimSpace(decoration.Target.PullRequest), 10, 32)
	if err != nil || prID < 1 {
		return fmt.Errorf("%w: Azure DevOps PR number is invalid", shared.ErrValidation)
	}
	sha := strings.TrimSpace(decoration.Target.CommitSHA)
	if len(sha) > 128 || sha == "" || strings.IndexFunc(sha, func(c rune) bool {
		return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')
	}) >= 0 {
		return fmt.Errorf("%w: Azure DevOps commit is invalid", shared.ErrValidation)
	}
	credential, ok, err := d.credentials.ResolveGitCredential(ctx, d.credentialHost)
	if err != nil {
		return fmt.Errorf("resolve Azure DevOps decoration credential: %w", err)
	}
	if !ok || len(credential.Token) == 0 {
		return fmt.Errorf("%w: no Azure DevOps credential configured for decoration", shared.ErrValidation)
	}
	defer func() {
		for i := range credential.Token {
			credential.Token[i] = 0
		}
	}()
	headers := azureHeaders(credential.Token)

	// A stable, per-target lock prevents duplicate thread creation from concurrent hooks.
	h := fnv.New32a()
	_, _ = h.Write([]byte(decoration.Target.Repository + "\x00" + decoration.Target.PullRequest))
	lock := &d.locks[int(h.Sum32()%uint32(len(d.locks)))]
	lock.Lock()
	defer lock.Unlock()

	parts := strings.Split(repoPath, "/")
	base := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s/pullRequests/%d", parts[0], parts[1], parts[2], prID)
	var errs []error
	if err := d.publishStatus(ctx, base, sha, decoration.Gate.Passed, headers); err != nil {
		errs = append(errs, fmt.Errorf("azure DevOps PR status: %w", err))
	}
	if err := d.publishComment(ctx, base, sha, decoration, headers); err != nil {
		errs = append(errs, fmt.Errorf("azure DevOps PR comment: %w", err))
	}
	return errors.Join(errs...)
}

// azureRepoPath accepts organization/project/repository and percent-encodes each component.
// Never accept URL, query, encoded slash, dot segment or a missing project: the token is
// resolved for dev.azure.com only after this validation.
func azureRepoPath(slug string) (string, error) {
	parts := strings.Split(slug, "/")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: Azure Repos repository must be organization/project/repository", shared.ErrValidation)
	}
	for i, part := range parts {
		if part == "" || part != strings.TrimSpace(part) || part == "." || part == ".." || strings.ContainsAny(part, "\\?#%\r\n\x00") {
			return "", fmt.Errorf("%w: Azure Repos repository contains an unsafe segment", shared.ErrValidation)
		}
		parts[i] = url.PathEscape(part)
	}
	return parts[0] + "/" + parts[1] + "/" + parts[2], nil
}

func azureHeaders(token []byte) http.Header {
	// Azure DevOps PATs use Basic auth with an empty username.
	h := make(http.Header)
	h.Set("Accept", "application/json")
	h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(append([]byte(":"), token...)))
	return h
}

type azureStatus struct {
	ID          int64  `json:"id"`
	State       string `json:"state"`
	Description string `json:"description"`
	Context     struct {
		Name  string `json:"name"`
		Genre string `json:"genre"`
	} `json:"context"`
}
type azureStatusPage struct {
	Value []azureStatus `json:"value"`
}
type azureStatusBody struct {
	State       string `json:"state"`
	Description string `json:"description"`
	Context     struct {
		Name  string `json:"name"`
		Genre string `json:"genre"`
	} `json:"context"`
}

func azureGateState(passed bool) string {
	if passed {
		return "succeeded"
	}
	return "failed"
}

func azureGateDescription(passed bool, sha string) string {
	verdict := "failed"
	if passed {
		verdict = "passed"
	}
	return "Synapse quality gate " + verdict + " (head " + sha + ")"
}

func (d *AzureDevOpsDecorator) listStatuses(ctx context.Context, path string, headers http.Header) ([]azureStatus, error) {
	var page azureStatusPage
	if err := d.api.doJSON(ctx, http.MethodGet, path+"/statuses?api-version=7.1", headers, nil, &page, true); err != nil {
		return nil, err
	}
	return page.Value, nil
}

func azureStatusFound(items []azureStatus, state, description string) bool {
	// Azure returns all historical statuses for the pull request without documenting their order.
	// Only the highest server-assigned ID for our own context is authoritative: an older verdict
	// must neither mask a newer one nor cause a duplicate POST on a rerun.
	var latest *azureStatus
	for i := range items {
		status := &items[i]
		if status.Context.Name == azureStatusName && status.Context.Genre == azureStatusGenre &&
			(latest == nil || status.ID > latest.ID) {
			latest = status
		}
	}
	return latest != nil && latest.State == state && latest.Description == description
}

func (d *AzureDevOpsDecorator) publishStatus(ctx context.Context, path, sha string, passed bool, headers http.Header) error {
	state, description := azureGateState(passed), azureGateDescription(passed, sha)
	existing, err := d.listStatuses(ctx, path, headers)
	if err != nil {
		return err
	}
	if azureStatusFound(existing, state, description) {
		return nil
	}
	body := azureStatusBody{State: state, Description: description}
	body.Context.Name, body.Context.Genre = azureStatusName, azureStatusGenre
	err = d.api.doJSON(ctx, http.MethodPost, path+"/statuses?api-version=7.1", headers, body, nil, false)
	if err == nil {
		return nil
	}
	// An accepted POST with a lost response is uncertain. Reconcile by owned context,
	// never blindly retry a non-idempotent status POST.
	reconciled, getErr := d.listStatuses(ctx, path, headers)
	if getErr == nil && azureStatusFound(reconciled, state, description) {
		return nil
	}
	return err
}

type azureThreadComment struct {
	ID              int64  `json:"id"`
	Content         string `json:"content"`
	CommentType     string `json:"commentType"`
	ParentCommentID int64  `json:"parentCommentId"`
	IsDeleted       bool   `json:"isDeleted"`
}
type azureThread struct {
	ID            int64                `json:"id"`
	IsDeleted     bool                 `json:"isDeleted"`
	Comments      []azureThreadComment `json:"comments"`
	ThreadContext any                  `json:"threadContext"`
}
type azureThreadPage struct {
	Value []azureThread `json:"value"`
}

func (d *AzureDevOpsDecorator) findComment(ctx context.Context, path string, headers http.Header) (int64, azureThreadComment, error) {
	var page azureThreadPage
	if err := d.api.doJSON(ctx, http.MethodGet, path+"/threads?api-version=7.1", headers, nil, &page, true); err != nil {
		return 0, azureThreadComment{}, err
	}
	for _, thread := range page.Value {
		if thread.IsDeleted || thread.ID <= 0 || thread.ThreadContext != nil {
			continue
		}
		for _, comment := range thread.Comments {
			if comment.ID > 0 && comment.ParentCommentID == 0 && !comment.IsDeleted &&
				comment.CommentType == "text" && strings.HasPrefix(strings.TrimSpace(comment.Content), azureCommentMarker) {
				return thread.ID, comment, nil
			}
		}
	}
	return 0, azureThreadComment{}, nil
}

func azureRenderedSummary(decoration ports.PRDecoration) string {
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
		return truncateUTF8(delta, azureCommentLimit)
	}
	return truncateUTF8(base+"\n\n"+delta, azureCommentLimit)
}

func azureCommentBody(sha string, decoration ports.PRDecoration) string {
	// Include the head in the owned text: a new source revision must update the
	// comment even when the quality-gate verdict and numbers are unchanged.
	verdict := "FAILED"
	if decoration.Gate.Passed {
		verdict = "PASSED"
	}
	prefix := azureCommentMarker + "\n\nHead: " + sha + "\nGate: " + verdict + "\n\n"
	return prefix + truncateUTF8(azureRenderedSummary(decoration), azureCommentLimit-len(prefix))
}

func (d *AzureDevOpsDecorator) publishComment(ctx context.Context, path, sha string, decoration ports.PRDecoration, headers http.Header) error {
	body := azureCommentBody(sha, decoration)
	threadID, existing, err := d.findComment(ctx, path, headers)
	if err != nil {
		return err
	}
	if threadID != 0 {
		if existing.Content == body {
			return nil
		}
		// PATCH the exact marker-owned root comment in place, not the entire thread.
		return d.api.doJSON(ctx, http.MethodPatch, fmt.Sprintf("%s/threads/%d/comments/%d?api-version=7.1", path, threadID, existing.ID),
			headers, struct {
				Content string `json:"content"`
			}{Content: body}, nil, true)
	}
	// Azure's Create Thread request uses numeric enum values (1 = text comment, 1 = active
	// thread); its response serializes the same enums as strings. Do not reuse the response DTO.
	create := struct {
		Comments []struct {
			ParentCommentID int    `json:"parentCommentId"`
			Content         string `json:"content"`
			CommentType     int    `json:"commentType"`
		} `json:"comments"`
		Status int `json:"status"`
	}{Status: 1}
	create.Comments = append(create.Comments, struct {
		ParentCommentID int    `json:"parentCommentId"`
		Content         string `json:"content"`
		CommentType     int    `json:"commentType"`
	}{Content: body, CommentType: 1})
	err = d.api.doJSON(ctx, http.MethodPost, path+"/threads?api-version=7.1", headers, create, nil, false)
	if err == nil {
		return nil
	}
	// Reconcile a timeout-after-success before attempting another create.
	_, recovered, getErr := d.findComment(ctx, path, headers)
	if getErr == nil && recovered.ID != 0 && recovered.Content == body {
		return nil
	}
	return err
}
