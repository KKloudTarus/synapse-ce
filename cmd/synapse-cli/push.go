package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
}

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
	if strings.TrimSpace(p.token) == "" {
		return fmt.Errorf("--server requires SYNAPSE_API_TOKEN in the environment")
	}
	if _, err := pushBaseURL(p.server); err != nil {
		return err
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
	case lookup("JENKINS_URL") != "":
		if out.Provider == "" {
			out.Provider = "jenkins"
		}
		pick(&out.Branch, "BRANCH_NAME", "GIT_BRANCH")
		pick(&out.RunID, "BUILD_NUMBER")
		pick(&out.RunURL, "BUILD_URL")
	}
	pick(&out.Provider, "SYNAPSE_CI_PROVIDER")
	return out
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
