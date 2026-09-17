package main

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type cliRecordingDecorator struct {
	calls int
	got   ports.PRDecoration
	err   error
}

func (f *cliRecordingDecorator) Decorate(_ context.Context, d ports.PRDecoration) error {
	f.calls++
	f.got = d
	return f.err
}

func clearPRDecorationCIEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"SYNAPSE_CI_PROVIDER", "SYNAPSE_PR_NUMBER", "SYNAPSE_PR_TARGET_BRANCH", "SYNAPSE_REPO_SLUG", "SYNAPSE_PR_HEAD_SHA",
		"GITHUB_ACTIONS", "GITHUB_HEAD_REF", "GITHUB_REF_NAME", "GITHUB_RUN_ID", "GITHUB_ACTOR", "GITHUB_BASE_REF", "GITHUB_REPOSITORY", "GITHUB_HEAD_SHA", "GITHUB_REF", "GITHUB_EVENT_PATH", "GITHUB_SERVER_URL",
		"GITLAB_CI", "CI_COMMIT_REF_NAME", "CI_PIPELINE_ID", "CI_PIPELINE_URL", "GITLAB_USER_LOGIN", "CI_MERGE_REQUEST_IID", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "CI_PROJECT_PATH", "CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", "CI_COMMIT_SHA",
		"BITBUCKET_BUILD_NUMBER", "BITBUCKET_BRANCH", "BITBUCKET_STEP_TRIGGERER_UUID", "BITBUCKET_PR_ID", "BITBUCKET_PR_DESTINATION_BRANCH", "BITBUCKET_REPO_FULL_NAME", "BITBUCKET_COMMIT",
		"JENKINS_URL", "BRANCH_NAME", "GIT_BRANCH", "BUILD_NUMBER", "BUILD_URL", "CHANGE_ID", "CHANGE_TARGET", "GIT_COMMIT",
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}
}

func TestTriggerGateDecorationFromEnv(t *testing.T) {
	clearPRDecorationCIEnv(t)
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_MERGE_REQUEST_IID", "17")
	t.Setenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main")
	t.Setenv("CI_PROJECT_PATH", "acme/widget")
	t.Setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", "head-sha")
	fake := &cliRecordingDecorator{}
	loc := &finding.SourceLocation{File: "src/app.go", StartLine: 12, EndLine: 12}
	findings := []finding.Finding{{
		DedupKey: "cq:test:src/app.go:12", RuleKey: "test-rule", Title: "test finding", Description: "details",
		Kind: finding.KindQuality, Severity: shared.SeverityHigh, SourceLocation: loc,
	}}
	result := qualitygate.Result{Passed: false}

	triggerGateDecorationFromEnv(context.Background(), fake, result, "summary", findings)
	if fake.calls != 1 {
		t.Fatalf("decorator calls = %d, want 1", fake.calls)
	}
	if fake.got.Target.Repository != "acme/widget" || fake.got.Target.PullRequest != "17" || fake.got.Target.TargetBranch != "main" || fake.got.Target.CommitSHA != "head-sha" {
		t.Fatalf("target = %+v", fake.got.Target)
	}
	if len(fake.got.Annotations) != 1 || fake.got.Annotations[0].Location.File != "src/app.go" || fake.got.Annotations[0].Location.StartLine != 12 {
		t.Fatalf("annotations = %+v", fake.got.Annotations)
	}
}

func TestTriggerGateDecorationIsFailSoft(t *testing.T) {
	clearPRDecorationCIEnv(t)
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_MERGE_REQUEST_IID", "17")
	t.Setenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main")
	t.Setenv("CI_PROJECT_PATH", "acme/widget")
	t.Setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", "head-sha")
	fake := &cliRecordingDecorator{err: errors.New("forge unavailable")}
	triggerGateDecorationFromEnv(context.Background(), fake, qualitygate.Result{Passed: true}, "summary", nil)
	if fake.calls != 1 {
		t.Fatalf("decorator calls = %d, want 1", fake.calls)
	}
}

func TestTriggerGateDecorationSkipsPartialIdentity(t *testing.T) {
	clearPRDecorationCIEnv(t)
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_MERGE_REQUEST_IID", "17")
	t.Setenv("CI_PROJECT_PATH", "acme/widget")

	fake := &cliRecordingDecorator{}
	triggerGateDecorationFromEnv(context.Background(), fake, qualitygate.Result{Passed: true}, "summary", nil)
	if fake.calls != 0 {
		t.Fatalf("partial target should be skipped; decorator calls = %d", fake.calls)
	}
}

func TestPRBaseRef(t *testing.T) {
	pr := projectanalysis.CIContext{PullRequest: "42", TargetBranch: "develop"}
	cases := []struct {
		name    string
		baseRef string
		image   bool
		ci      projectanalysis.CIContext
		want    string
	}{
		{"explicit base wins", "origin/custom", false, pr, "origin/custom"},
		{"pr defaults to target", "", false, pr, "origin/develop"},
		{"pr target trimmed", "", false, projectanalysis.CIContext{PullRequest: "1", TargetBranch: "  release/2 "}, "origin/release/2"},
		{"whitespace base is not explicit", "   ", false, pr, "origin/develop"},
		{"image scan keeps empty", "", true, pr, ""},
		{"non-pr keeps empty", "", false, projectanalysis.CIContext{Branch: "main"}, ""},
		{"pr without target keeps empty", "", false, projectanalysis.CIContext{PullRequest: "42"}, ""},
	}
	for _, c := range cases {
		if got := prBaseRef(c.baseRef, c.image, c.ci); got != c.want {
			t.Errorf("%s: prBaseRef(%q,%v,%+v) = %q, want %q", c.name, c.baseRef, c.image, c.ci, got, c.want)
		}
	}
}
