package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

// pushTarget is where a pipeline scan sends its result. Zero value means "do not push", which keeps
// `synapse-cli scan` the self-contained gate it has always been; the push is opt-in through --server.
type pushTarget struct {
	server  string
	project string
	token   string
	ci      projectanalysis.CIContext
	// insecureHTTP allows a plain-http server that is not loopback. The bearer token travels in the
	// clear then; a pipeline has to say so explicitly.
	insecureHTTP bool
}

// projectKeyPattern mirrors the server's project key rule (internal/domain/project): lowercase
// alphanumerics joined by single hyphens. A key that fails it would either be refused by the server or,
// with a slash, change the route.
var projectKeyPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func (p pushTarget) enabled() bool { return strings.TrimSpace(p.server) != "" }

// validate checks the target before the scan runs, so a pipeline learns about a missing token in
// seconds rather than after a full scan.
func (p pushTarget) validate() error {
	if !p.enabled() {
		return nil
	}
	if strings.TrimSpace(p.project) == "" {
		return fmt.Errorf("--server requires --project KEY (the server-owned project this result belongs to)")
	}
	if !projectKeyPattern.MatchString(strings.TrimSpace(p.project)) {
		return fmt.Errorf("--project %q is not a project key (lowercase letters, digits and single hyphens)", p.project)
	}
	if strings.TrimSpace(p.token) == "" {
		return fmt.Errorf("--server requires SYNAPSE_API_TOKEN in the environment")
	}
	u, err := pushBaseURL(p.server)
	if err != nil {
		return err
	}
	if u.Scheme == "http" && !p.insecureHTTP && !loopbackHost(u.Hostname()) {
		return fmt.Errorf("--server %s sends the API token over plain http; use https, or pass --insecure-http to accept that on a trusted network", u.Host)
	}
	if _, err := p.ci.Normalize(); err != nil {
		return err
	}
	return nil
}

func pushBaseURL(server string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(server))
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("--server must be an absolute http(s) URL, got %q", server)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""
	return u, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// pushedAnalysis is the part of the server's answer the pipeline log needs.
type pushedAnalysis struct {
	ID        string `json:"id"`
	Origin    string `json:"origin"`
	CreatedAt string `json:"created_at"`
	Gate      struct {
		Passed bool `json:"passed"`
	} `json:"gate"`
	GateInfo struct {
		Name string `json:"name"`
	} `json:"gate_info"`
	Issues struct {
		Total int `json:"total"`
	} `json:"issues"`
	NewCode struct {
		Counts struct {
			Total int `json:"total"`
		} `json:"counts"`
	} `json:"new_code"`
}

// pushAnalysis records the scan result as the project's next analysis on the server and returns what
// the server made of it. The gate in the result is deliberately not sent as policy: the server's
// managed gate decides, and this function reports that verdict rather than the local --fail-on one.
func pushAnalysis(ctx context.Context, client *http.Client, target pushTarget, result *scauc.ScanResult) (pushedAnalysis, string, error) {
	base, err := pushBaseURL(target.server)
	if err != nil {
		return pushedAnalysis{}, "", err
	}
	ci, err := target.ci.Normalize()
	if err != nil {
		return pushedAnalysis{}, "", err
	}
	body, err := json.Marshal(struct {
		CI     projectanalysis.CIContext `json:"ci"`
		Result *scauc.ScanResult         `json:"result"`
	}{CI: ci, Result: result})
	if err != nil {
		return pushedAnalysis{}, "", fmt.Errorf("encode scan result: %w", err)
	}

	// url.URL.Path holds the UNESCAPED path; String() escapes it. Pre-escaping here would send
	// "my%2520app" for a key with a space, which the server decodes to a project that does not exist.
	endpoint := *base
	endpoint.Path = base.Path + "/api/v1/projects/" + target.project + "/analyses/import"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return pushedAnalysis{}, "", fmt.Errorf("build import request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+target.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return pushedAnalysis{}, "", fmt.Errorf("push analysis to %s: %w", endpoint.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return pushedAnalysis{}, "", fmt.Errorf("read import response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		msg := strings.TrimSpace(string(payload))
		var serverErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(payload, &serverErr) == nil && serverErr.Error != "" {
			msg = serverErr.Error
		}
		return pushedAnalysis{}, "", fmt.Errorf("server refused the analysis (HTTP %d): %s", resp.StatusCode, msg)
	}
	var analysis pushedAnalysis
	if err := json.Unmarshal(payload, &analysis); err != nil {
		return pushedAnalysis{}, "", fmt.Errorf("decode import response: %w", err)
	}
	// The console page for this project's history: the dashboard is served from the same origin as
	// the API in every documented deployment.
	console := *base
	console.Path = base.Path + "/code-quality/projects/" + target.project + "/activity"
	return analysis, console.String(), nil
}

// ciContextFromEnv fills what the pipeline did not say on the command line from the well-known
// variables of the providers the action and the CI guides cover. An explicit flag always wins.
func ciContextFromEnv(explicit projectanalysis.CIContext, lookup func(string) string) projectanalysis.CIContext {
	return ciContextFromEnvWithReader(explicit, lookup, os.ReadFile)
}

// ciContextFromEnvWithReader keeps GitHub event parsing testable without touching the network. GitHub's
// GITHUB_SHA is a synthetic merge commit for pull_request events, so the event payload is the canonical
// place to obtain pull_request.head.sha; silently substituting GITHUB_SHA could decorate the wrong commit.
func ciContextFromEnvWithReader(explicit projectanalysis.CIContext, lookup func(string) string, readFile func(string) ([]byte, error)) projectanalysis.CIContext {
	out := explicit
	pick := func(dst *string, keys ...string) {
		if strings.TrimSpace(*dst) != "" {
			return
		}
		for _, k := range keys {
			if v := strings.TrimSpace(lookup(k)); v != "" {
				*dst = v
				return
			}
		}
	}
	switch {
	case lookup("GITHUB_ACTIONS") == "true":
		pick(&out.Provider, "SYNAPSE_CI_PROVIDER")
		if out.Provider == "" {
			out.Provider = "github-actions"
		}
		pick(&out.Branch, "GITHUB_HEAD_REF", "GITHUB_REF_NAME")
		pick(&out.RunID, "GITHUB_RUN_ID")
		pick(&out.Actor, "GITHUB_ACTOR")
		pick(&out.TargetBranch, "GITHUB_BASE_REF")
		pick(&out.RepoSlug, "GITHUB_REPOSITORY")
		pick(&out.HeadSHA, "SYNAPSE_PR_HEAD_SHA", "GITHUB_HEAD_SHA")
		pick(&out.PullRequest, "SYNAPSE_PR_NUMBER")
		if out.PullRequest == "" {
			out.PullRequest = githubPullRequestNumber(lookup("GITHUB_REF"))
		}
		if eventPath := strings.TrimSpace(lookup("GITHUB_EVENT_PATH")); eventPath != "" && readFile != nil {
			if data, err := readFile(eventPath); err == nil {
				var event struct {
					Number      int `json:"number"`
					PullRequest struct {
						Number int `json:"number"`
						Base   struct {
							Ref string `json:"ref"`
						} `json:"base"`
						Head struct {
							Ref string `json:"ref"`
							SHA string `json:"sha"`
						} `json:"head"`
					} `json:"pull_request"`
					Repository struct {
						FullName string `json:"full_name"`
					} `json:"repository"`
				}
				if json.Unmarshal(data, &event) == nil {
					if out.PullRequest == "" {
						n := event.PullRequest.Number
						if n == 0 {
							n = event.Number
						}
						if n > 0 {
							out.PullRequest = fmt.Sprintf("%d", n)
						}
					}
					if out.TargetBranch == "" {
						out.TargetBranch = strings.TrimSpace(event.PullRequest.Base.Ref)
					}
					if out.Branch == "" {
						out.Branch = strings.TrimSpace(event.PullRequest.Head.Ref)
					}
					if out.HeadSHA == "" {
						out.HeadSHA = strings.TrimSpace(event.PullRequest.Head.SHA)
					}
					if out.RepoSlug == "" {
						out.RepoSlug = strings.TrimSpace(event.Repository.FullName)
					}
				}
			}
		}
		if out.RunURL == "" {
			server, repo, run := lookup("GITHUB_SERVER_URL"), lookup("GITHUB_REPOSITORY"), lookup("GITHUB_RUN_ID")
			if server != "" && repo != "" && run != "" {
				out.RunURL = strings.TrimRight(server, "/") + "/" + repo + "/actions/runs/" + run
			}
		}
	case lookup("GITLAB_CI") == "true":
		if out.Provider == "" {
			out.Provider = "gitlab-ci"
		}
		pick(&out.Branch, "CI_COMMIT_REF_NAME")
		pick(&out.RunID, "CI_PIPELINE_ID")
		pick(&out.RunURL, "CI_PIPELINE_URL")
		pick(&out.Actor, "GITLAB_USER_LOGIN")
		pick(&out.PullRequest, "CI_MERGE_REQUEST_IID")
		pick(&out.TargetBranch, "CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
		pick(&out.RepoSlug, "CI_PROJECT_PATH")
		pick(&out.HeadSHA, "CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", "CI_COMMIT_SHA")
	case lookup("BITBUCKET_BUILD_NUMBER") != "":
		if out.Provider == "" {
			out.Provider = "bitbucket-pipelines"
		}
		pick(&out.Branch, "BITBUCKET_BRANCH")
		pick(&out.RunID, "BITBUCKET_BUILD_NUMBER")
		pick(&out.Actor, "BITBUCKET_STEP_TRIGGERER_UUID")
		pick(&out.PullRequest, "BITBUCKET_PR_ID")
		pick(&out.TargetBranch, "BITBUCKET_PR_DESTINATION_BRANCH")
		pick(&out.RepoSlug, "BITBUCKET_REPO_FULL_NAME")
		pick(&out.HeadSHA, "BITBUCKET_COMMIT")
	case lookup("JENKINS_URL") != "":
		if out.Provider == "" {
			out.Provider = "jenkins"
		}
		pick(&out.Branch, "BRANCH_NAME", "GIT_BRANCH")
		pick(&out.RunID, "BUILD_NUMBER")
		pick(&out.RunURL, "BUILD_URL")
		pick(&out.PullRequest, "CHANGE_ID")
		pick(&out.TargetBranch, "CHANGE_TARGET")
		pick(&out.RepoSlug, "SYNAPSE_REPO_SLUG")
		pick(&out.HeadSHA, "GIT_COMMIT")
	}
	pick(&out.Provider, "SYNAPSE_CI_PROVIDER")
	pick(&out.PullRequest, "SYNAPSE_PR_NUMBER")
	pick(&out.TargetBranch, "SYNAPSE_PR_TARGET_BRANCH")
	pick(&out.RepoSlug, "SYNAPSE_REPO_SLUG")
	pick(&out.HeadSHA, "SYNAPSE_PR_HEAD_SHA")
	return out
}

func githubPullRequestNumber(ref string) string {
	parts := strings.Split(strings.TrimSpace(ref), "/")
	if len(parts) >= 4 && parts[0] == "refs" && parts[1] == "pull" && strings.TrimSpace(parts[2]) != "" {
		return strings.TrimSpace(parts[2])
	}
	return ""
}

// reportPush prints the server's verdict for the pipeline log. It is written to stderr so the
// --json/--sarif/--sbom stdout contracts stay intact.
func reportPush(analysis pushedAnalysis, console string) {
	verdict := "PASSED"
	if !analysis.Gate.Passed {
		verdict = "FAILED"
	}
	fmt.Fprintf(os.Stderr, "synapse-cli: recorded analysis %s on the server (origin %s); managed gate %q %s; issues %d, new %d\n",
		analysis.ID, analysis.Origin, analysis.GateInfo.Name, verdict, analysis.Issues.Total, analysis.NewCode.Counts.Total)
	fmt.Fprintf(os.Stderr, "synapse-cli: console: %s\n", console)
}

func pushHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		// A redirect would re-send the bearer token to wherever the server pointed; refuse to follow.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
