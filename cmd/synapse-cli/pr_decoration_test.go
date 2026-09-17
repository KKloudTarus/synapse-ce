package main

import (
	"context"
	"errors"
	"testing"

	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
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

func TestBuildGateDecoratorDisabledByDefault(t *testing.T) {
	clearPRDecorationCIEnv(t)
	got, err := buildGateDecorator(func(string) string { return "" }, false, false)
	if err != nil || got != nil {
		t.Fatalf("no flags = %v,%v want nil decorator, no error", got, err)
	}
}

func TestBuildGateDecoratorDryRunNeedsNoToken(t *testing.T) {
	env := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/widget", "SYNAPSE_PR_NUMBER": "7", "GITHUB_BASE_REF": "main", "SYNAPSE_PR_HEAD_SHA": "deadbeef"}
	got, err := buildGateDecorator(func(k string) string { return env[k] }, true, true)
	if err != nil {
		t.Fatalf("dry-run build error = %v", err)
	}
	if _, ok := got.(*dryRunDecorator); !ok {
		t.Fatalf("dry-run decorator = %T, want *dryRunDecorator", got)
	}
}

func TestBuildGateDecoratorRequiresTokenWhenDecorating(t *testing.T) {
	env := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/widget", "SYNAPSE_PR_NUMBER": "7", "GITHUB_BASE_REF": "main", "SYNAPSE_PR_HEAD_SHA": "deadbeef"}
	if _, err := buildGateDecorator(func(k string) string { return env[k] }, true, false); err == nil {
		t.Fatal("decorate without SYNAPSE_DECORATION_TOKEN must error")
	}
}

func TestBuildGateDecoratorBuildsProviderAdapterWithToken(t *testing.T) {
	env := map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/widget", "SYNAPSE_PR_NUMBER": "7",
		"GITHUB_BASE_REF": "main", "SYNAPSE_PR_HEAD_SHA": "deadbeef", "SYNAPSE_DECORATION_TOKEN": "ghp-token",
	}
	got, err := buildGateDecorator(func(k string) string { return env[k] }, true, false)
	if err != nil || got == nil {
		t.Fatalf("decorate with token = %v,%v", got, err)
	}
	if _, ok := got.(*dryRunDecorator); ok {
		t.Fatal("a real decorate must not return the dry-run decorator")
	}
}

func TestBuildGateDecoratorRejectsUnknownProvider(t *testing.T) {
	env := map[string]string{"SYNAPSE_CI_PROVIDER": "jenkins", "SYNAPSE_REPO_SLUG": "acme/widget", "SYNAPSE_PR_NUMBER": "7", "SYNAPSE_PR_TARGET_BRANCH": "main", "SYNAPSE_PR_HEAD_SHA": "deadbeef", "SYNAPSE_DECORATION_TOKEN": "t"}
	if _, err := buildGateDecorator(func(k string) string { return env[k] }, true, false); err == nil {
		t.Fatal("unsupported provider must error")
	}
}

func TestDryRunDecoratorPrintsAndPostsNothing(t *testing.T) {
	var buf strings.Builder
	d := &dryRunDecorator{out: &buf, provider: "github-actions"}
	err := d.Decorate(context.Background(), ports.PRDecoration{
		Target: ports.PRDecorationTarget{Repository: "acme/widget", PullRequest: "7", CommitSHA: "abc", TargetBranch: "main"},
		Gate:   qualitygate.Result{Passed: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run") || !strings.Contains(out, "acme/widget") || !strings.Contains(out, "gate=FAILED") {
		t.Fatalf("dry-run output = %q", out)
	}
}
