package main

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
)

func TestCIContextFromEnvGitHubUsesPullRequestHeadSHA(t *testing.T) {
	env := map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_EVENT_PATH": "/event.json",
		"GITHUB_REF":        "refs/pull/42/merge",
		"GITHUB_SHA":        "synthetic-merge-sha",
		"GITHUB_REPOSITORY": "acme/widget",
		"GITHUB_RUN_ID":     "99",
		"GITHUB_SERVER_URL": "https://github.com",
	}
	lookup := func(k string) string { return env[k] }
	read := func(path string) ([]byte, error) {
		if path != "/event.json" {
			return nil, errors.New("unexpected path")
		}
		return []byte(`{"number":42,"pull_request":{"number":42,"base":{"ref":"main"},"head":{"ref":"feature/pr","sha":"real-head-sha"}},"repository":{"full_name":"acme/widget"}}`), nil
	}

	got := ciContextFromEnvWithReader(projectanalysis.CIContext{}, lookup, read)
	if got.PullRequest != "42" || got.TargetBranch != "main" || got.RepoSlug != "acme/widget" || got.HeadSHA != "real-head-sha" || got.Branch != "feature/pr" {
		t.Fatalf("CI identity = %+v", got)
	}
	if got.HeadSHA == env["GITHUB_SHA"] {
		t.Fatalf("HeadSHA used synthetic merge SHA %q", got.HeadSHA)
	}
}

func TestCIContextFromEnvGitLabBitbucketAndJenkins(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want projectanalysis.CIContext
	}{
		{
			name: "gitlab",
			env: map[string]string{
				"GITLAB_CI": "true", "CI_COMMIT_REF_NAME": "feature", "CI_MERGE_REQUEST_IID": "17",
				"CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main", "CI_PROJECT_PATH": "acme/widget",
				"CI_MERGE_REQUEST_SOURCE_BRANCH_SHA": "gitlab-head",
			},
			want: projectanalysis.CIContext{Provider: "gitlab-ci", Branch: "feature", PullRequest: "17", TargetBranch: "main", RepoSlug: "acme/widget", HeadSHA: "gitlab-head"},
		},
		{
			name: "bitbucket",
			env: map[string]string{
				"BITBUCKET_BUILD_NUMBER": "12", "BITBUCKET_BRANCH": "feature", "BITBUCKET_PR_ID": "5",
				"BITBUCKET_PR_DESTINATION_BRANCH": "main", "BITBUCKET_REPO_FULL_NAME": "acme/widget", "BITBUCKET_COMMIT": "bb-head",
			},
			want: projectanalysis.CIContext{Provider: "bitbucket-pipelines", Branch: "feature", RunID: "12", PullRequest: "5", TargetBranch: "main", RepoSlug: "acme/widget", HeadSHA: "bb-head"},
		},
		{
			name: "jenkins",
			env: map[string]string{
				"JENKINS_URL": "https://jenkins.example/", "BRANCH_NAME": "feature", "BUILD_NUMBER": "77",
				"BUILD_URL": "https://jenkins.example/job/widget/77/", "CHANGE_ID": "23", "CHANGE_TARGET": "main",
				"SYNAPSE_REPO_SLUG": "acme/widget", "GIT_COMMIT": "jenkins-head",
			},
			want: projectanalysis.CIContext{Provider: "jenkins", Branch: "feature", RunID: "77", RunURL: "https://jenkins.example/job/widget/77/", PullRequest: "23", TargetBranch: "main", RepoSlug: "acme/widget", HeadSHA: "jenkins-head"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ciContextFromEnvWithReader(projectanalysis.CIContext{}, func(k string) string { return tt.env[k] }, nil)
			if got.Provider != tt.want.Provider || got.Branch != tt.want.Branch || got.RunID != tt.want.RunID || got.RunURL != tt.want.RunURL || got.PullRequest != tt.want.PullRequest || got.TargetBranch != tt.want.TargetBranch || got.RepoSlug != tt.want.RepoSlug || got.HeadSHA != tt.want.HeadSHA {
				t.Fatalf("CI identity = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCIContextExplicitPullRequestIdentityWins(t *testing.T) {
	explicit := projectanalysis.CIContext{PullRequest: "7", TargetBranch: "release", RepoSlug: "explicit/repo", HeadSHA: "explicit-head"}
	env := map[string]string{
		"GITLAB_CI": "true", "CI_MERGE_REQUEST_IID": "8", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
		"CI_PROJECT_PATH": "env/repo", "CI_MERGE_REQUEST_SOURCE_BRANCH_SHA": "env-head",
	}
	got := ciContextFromEnvWithReader(explicit, func(k string) string { return env[k] }, nil)
	if got.PullRequest != "7" || got.TargetBranch != "release" || got.RepoSlug != "explicit/repo" || got.HeadSHA != "explicit-head" {
		t.Fatalf("explicit identity overwritten: %+v", got)
	}
}
