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

func TestCIContextFromAzurePipelines(t *testing.T) {
	env := map[string]string{
		"TF_BUILD": "True", "BUILD_BUILDID": "123",
		"BUILD_SOURCEBRANCH": "refs/pull/31/merge", "BUILD_SOURCEVERSION": "synthetic-merge",
		"SYSTEM_PULLREQUEST_PULLREQUESTID":  "31",
		"SYSTEM_PULLREQUEST_SOURCEBRANCH":   "refs/heads/feature/azure",
		"SYSTEM_PULLREQUEST_TARGETBRANCH":   "refs/heads/main",
		"SYSTEM_PULLREQUEST_SOURCECOMMITID": "actual-pr-head",
		"BUILD_REQUESTEDFOR":                "ci-bot", "SYSTEM_COLLECTIONURI": "https://dev.azure.com/example/",
		"SYSTEM_TEAMPROJECT": "My Project", "BUILD_REPOSITORY_NAME": "widgets", "BUILD_REPOSITORY_PROVIDER": "TfsGit",
	}
	get := func(k string) string { return env[k] }
	got := ciContextFromEnvWithReader(projectanalysis.CIContext{}, get, nil)
	if got.Provider != "azure-pipelines" || got.Branch != "feature/azure" || got.RunID != "123" ||
		got.RunURL != "https://dev.azure.com/example/My%20Project/_build/results?buildId=123" ||
		got.Actor != "ci-bot" || got.PullRequest != "31" || got.TargetBranch != "main" ||
		got.RepoSlug != "example/My Project/widgets" || got.HeadSHA != "actual-pr-head" {
		t.Fatalf("Azure CI context = %+v", got)
	}
	if got.HeadSHA == env["BUILD_SOURCEVERSION"] {
		t.Fatal("Azure PR identity used synthetic merge SHA")
	}
	// GitHub builds expose a forge-visible PR number that can differ from Azure's PR ID. Do not
	// fabricate an Azure Repos slug for an external forge merely because Azure Pipelines runs it.
	env["BUILD_REPOSITORY_PROVIDER"] = "GitHub"
	env["BUILD_REPOSITORY_NAME"] = "acme/widgets"
	env["SYSTEM_PULLREQUEST_PULLREQUESTID"] = "9001"
	env["SYSTEM_PULLREQUEST_PULLREQUESTNUMBER"] = "77"
	got = ciContextFromEnvWithReader(projectanalysis.CIContext{}, get, nil)
	if got.PullRequest != "77" || got.RepoSlug != "" {
		t.Fatalf("GitHub-backed Azure PR identity = %+v", got)
	}
	env["SYNAPSE_REPO_SLUG"] = "acme/widgets"
	env["SYNAPSE_CI_PROVIDER"] = "github"
	got = ciContextFromEnvWithReader(projectanalysis.CIContext{}, get, nil)
	if got.Provider != "github" || got.RepoSlug != "acme/widgets" || got.PullRequest != "77" {
		t.Fatalf("explicit external-forge overrides ignored: %+v", got)
	}
	delete(env, "SYNAPSE_REPO_SLUG")
	delete(env, "SYNAPSE_CI_PROVIDER")
	env["BUILD_REPOSITORY_PROVIDER"] = "TfsGit"
	env["BUILD_REPOSITORY_NAME"] = "widgets"
	env["SYSTEM_PULLREQUEST_PULLREQUESTID"] = "31"
	delete(env, "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER")
	env["SYNAPSE_PR_HEAD_SHA"] = "operator-head"
	if got := ciContextFromEnvWithReader(projectanalysis.CIContext{}, get, nil); got.HeadSHA != "operator-head" {
		t.Fatalf("SYNAPSE_PR_HEAD_SHA override ignored: %+v", got)
	}
	delete(env, "SYNAPSE_PR_HEAD_SHA")
	delete(env, "SYSTEM_PULLREQUEST_SOURCECOMMITID")
	got = ciContextFromEnvWithReader(projectanalysis.CIContext{}, get, nil)
	if got.HeadSHA != "" {
		t.Fatalf("missing Azure PR head was silently replaced: %+v", got)
	}
	explicit := projectanalysis.CIContext{
		Provider: "manual", Branch: "refs/heads/release", RunID: "999", RunURL: "https://safe.example/run",
		PullRequest: "44", TargetBranch: "stable", RepoSlug: "explicit/repo", HeadSHA: "explicit-head",
	}
	got = ciContextFromEnvWithReader(explicit, get, nil)
	explicit.Actor = "ci-bot"
	if got != explicit {
		t.Fatalf("explicit Azure fields overwritten: %+v vs %+v", got, explicit)
	}
	delete(env, "SYSTEM_PULLREQUEST_PULLREQUESTID")
	delete(env, "SYSTEM_PULLREQUEST_SOURCEBRANCH")
	delete(env, "SYSTEM_PULLREQUEST_TARGETBRANCH")
	env["BUILD_SOURCEBRANCH"] = "refs/heads/main"
	got = ciContextFromEnvWithReader(projectanalysis.CIContext{}, get, nil)
	if got.HeadSHA != "synthetic-merge" || got.PullRequest != "" || got.Branch != "main" {
		t.Fatalf("non-PR Azure build not detected: %+v", got)
	}
}

func TestAzurePipelinesRunURLRejectsUntrustedOrigins(t *testing.T) {
	env := map[string]string{
		"TF_BUILD": "True", "SYSTEM_COLLECTIONURI": "https://dev.azure.com/organization/",
		"SYSTEM_TEAMPROJECT": "My Project", "BUILD_BUILDID": "123",
	}
	get := func(k string) string { return env[k] }
	for _, raw := range []string{
		"http://dev.azure.com/organization/", "https://evil.example/organization/",
		"https://dev.azure.com/organization/?token=secret",
		"https://user:password@dev.azure.com/organization/",
		"https://dev.azure.com/organization/another/",
	} {
		env["SYSTEM_COLLECTIONURI"] = raw
		if got := azurePipelinesRunURL(get); got != "" {
			t.Errorf("untrusted URL accepted: %q => %q", raw, got)
		}
	}
	env["SYSTEM_COLLECTIONURI"] = "https://dev.azure.com/organization/"
	for _, id := range []string{"", "1&token=secret", "abc"} {
		env["BUILD_BUILDID"] = id
		if got := azurePipelinesRunURL(get); got != "" {
			t.Errorf("untrusted build ID accepted: %q => %q", id, got)
		}
	}
	env["BUILD_BUILDID"] = "123"
	env["TF_BUILD"] = ""
	if got := ciContextFromEnvWithReader(projectanalysis.CIContext{}, get, nil); !got.Empty() {
		t.Fatalf("Azure variables without TF_BUILD triggered detection: %+v", got)
	}
}
