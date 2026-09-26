package misconfig

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// An include without a ref resolves to the template project's default branch every time the pipeline runs, so
// whoever can push there runs commands with this project's deploy credentials. A pinned ref is the fix and is
// not reported, and each entry is judged on its own.
func TestGitLabCIIncludeNeedsAPinnedRef(t *testing.T) {
	pipeline := `include:
  - project: "devops/pipeline-templates"
    file: "/docker.gitlab-ci.yml"
  - project: "devops/pipeline-templates"
    ref: "v1.4.0"
    file: "/deploy.gitlab-ci.yml"
  - project: "devops/pipeline-templates"
    file: "/trigger.gitlab-ci.yml"
  - local: "/ci/local.gitlab-ci.yml"
  - template: "Security/SAST.gitlab-ci.yml"

build:
  image: node@sha256:aaaa
  script:
    - npm ci
`
	var got []ports.MisconfigRawFinding
	for _, f := range scan(t, map[string]string{".gitlab-ci.yml": pipeline}) {
		if f.RuleID == "gitlab-ci-include-project-unpinned" {
			got = append(got, f)
		}
	}
	if len(got) != 2 {
		t.Fatalf("exactly the two unpinned project includes must be reported, got %d: %v", len(got), got)
	}
	if got[0].Line != 2 || got[1].Line != 7 {
		t.Errorf("each finding must land on its own include entry, got lines %d and %d", got[0].Line, got[1].Line)
	}
	if _, ok := ruleIDs(scan(t, map[string]string{".gitlab-ci.yml": pipeline}))["gitlab-ci-include-remote"]; ok {
		t.Error("a local or template include is not a remote include")
	}
}

// A remote include runs whatever the URL serves at pipeline time, with no checksum and no record.
func TestGitLabCIRemoteInclude(t *testing.T) {
	pipeline := `include:
  - remote: "https://example.com/ci/shared.gitlab-ci.yml"

build:
  image: node@sha256:aaaa
  script:
    - npm ci
`
	got := ruleIDs(scan(t, map[string]string{".gitlab-ci.yml": pipeline}))
	if _, ok := got["gitlab-ci-include-remote"]; !ok {
		t.Errorf("a remote include must be reported, got %v", keys(got))
	}
	if _, ok := got["gitlab-ci-include-project-unpinned"]; ok {
		t.Error("a remote include is reported once, as a remote include")
	}
}

// GitLab passes an untrusted value as an environment variable, and shell parameter expansion does not re-parse
// it as code. Only a second parse makes it executable, so a quoted use and a command substitution that turns a
// branch name into a tag are both left alone: reporting them is the false positive this rule exists to avoid.
func TestGitLabCIScriptInjectionNeedsASecondEvaluation(t *testing.T) {
	safe := `build:
  image: node@sha256:aaaa
  script:
    - printf '%s' "$CI_COMMIT_MESSAGE" > message.txt
    - TAG=$(echo "$CI_COMMIT_REF_NAME" | tr '/' '-')
    - docker build -t "registry.example.com/app:$TAG" .
`
	if _, ok := ruleIDs(scan(t, map[string]string{".gitlab-ci.yml": safe}))["gitlab-ci-script-injection"]; ok {
		t.Error("an environment-variable expansion is data and must not be reported as injection")
	}

	for _, injected := range []string{
		"build:\n  script:\n    - eval \"echo $CI_COMMIT_MESSAGE\"\n",
		"build:\n  script:\n    - sh -c \"release $CI_MERGE_REQUEST_TITLE\"\n",
		"build:\n  before_script:\n    - bash -lc \"git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME\"\n",
	} {
		got := ruleIDs(scan(t, map[string]string{".gitlab-ci.yml": injected}))
		if _, ok := got["gitlab-ci-script-injection"]; !ok {
			t.Errorf("a second evaluation of an untrusted variable must be reported: %q gave %v", injected, keys(got))
		}
	}

	// A sanitised variable carries nothing executable, and an eval of a project-controlled variable is the
	// project's own decision about its own value.
	for _, benign := range []string{
		"build:\n  script:\n    - eval \"echo $CI_COMMIT_REF_SLUG\"\n",
		"build:\n  script:\n    - eval \"$DEPLOY_COMMAND\"\n",
	} {
		if _, ok := ruleIDs(scan(t, map[string]string{".gitlab-ci.yml": benign}))["gitlab-ci-script-injection"]; ok {
			t.Errorf("%q must not be reported as injection", benign)
		}
	}
}

// Debug tracing writes every variable's value into the job log, masked variables included.
func TestGitLabCIDebugTrace(t *testing.T) {
	on := "variables:\n  CI_DEBUG_TRACE: \"true\"\n\nbuild:\n  script:\n    - npm ci\n"
	got := ruleIDs(scan(t, map[string]string{".gitlab-ci.yml": on}))
	f, ok := got["gitlab-ci-debug-trace-enabled"]
	if !ok {
		t.Fatalf("debug tracing must be reported, got %v", keys(got))
	}
	if !contains(f.Description, "rotate") {
		t.Errorf("the finding must say the logged credential needs rotating, got %q", f.Description)
	}
	off := "variables:\n  CI_DEBUG_TRACE: \"false\"\n\nbuild:\n  script:\n    - npm ci\n"
	if _, ok := ruleIDs(scan(t, map[string]string{".gitlab-ci.yml": off}))["gitlab-ci-debug-trace-enabled"]; ok {
		t.Error("tracing switched off must not be reported")
	}
}

// A password argument is readable in the runner's process table; --password-stdin is the same login done right
// and must not be mistaken for it.
func TestGitLabCIRegistryPassword(t *testing.T) {
	bad := "build:\n  script:\n    - docker login -u \"$CI_REGISTRY_USER\" -p \"$CI_REGISTRY_PASSWORD\" \"$CI_REGISTRY\"\n"
	if _, ok := ruleIDs(scan(t, map[string]string{".gitlab-ci.yml": bad}))["gitlab-ci-registry-password-on-command-line"]; !ok {
		t.Error("a password argument must be reported")
	}
	good := "build:\n  script:\n    - echo \"$CI_REGISTRY_PASSWORD\" | docker login --password-stdin -u \"$CI_REGISTRY_USER\" \"$CI_REGISTRY\"\n"
	if _, ok := ruleIDs(scan(t, map[string]string{".gitlab-ci.yml": good}))["gitlab-ci-registry-password-on-command-line"]; ok {
		t.Error("--password-stdin is the fix and must not be reported")
	}
}

// A tag is a moving pointer, so the runner executes whatever it resolves to at pipeline time. A digest is
// fixed, and a reference built from a variable says nothing about what will run.
func TestGitLabCIImageDigest(t *testing.T) {
	pipeline := `build:
  image: node:20
  services:
    - postgres:13
    - name: redis:7
  script:
    - npm ci

test:
  image:
    name: python@sha256:bbbb
    entrypoint: [""]
  script:
    - pytest

deploy:
  image: $CI_REGISTRY_IMAGE/deployer:$CI_COMMIT_SHORT_SHA
  script:
    - ./deploy.sh
`
	var got []ports.MisconfigRawFinding
	for _, f := range scan(t, map[string]string{".gitlab-ci.yml": pipeline}) {
		if f.RuleID == "gitlab-ci-image-no-digest" {
			got = append(got, f)
		}
	}
	var refs []string
	for _, f := range got {
		refs = append(refs, f.Resource)
	}
	for _, want := range []string{"node:20", "postgres:13", "redis:7"} {
		found := false
		for _, r := range refs {
			if r == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s to be reported, got %v", want, refs)
		}
	}
	for _, unwanted := range []string{"python@sha256:bbbb"} {
		for _, r := range refs {
			if r == unwanted {
				t.Errorf("%s is digest-pinned and must not be reported", unwanted)
			}
		}
	}
	for _, r := range refs {
		if strings.Contains(r, "$") {
			t.Errorf("a reference built from a variable must not be judged, got %q", r)
		}
	}
	if len(got) != 3 {
		t.Errorf("expected exactly the three unpinned references, got %d: %v", len(got), refs)
	}
}

// A template repository keeps its pipelines as <name>.gitlab-ci.yml and those are included verbatim into other
// projects' pipelines, so they are the same surface as the root file. An ordinary YAML file is not.
func TestGitLabCIFileRecognition(t *testing.T) {
	for _, name := range []string{".gitlab-ci.yml", ".gitlab-ci.yaml", "Docker.gitlab-ci.yml", "ci/deploy.gitlab-ci.yaml"} {
		if !isGitLabCIName(filepathBase(name)) {
			t.Errorf("%s must be recognised as pipeline configuration", name)
		}
	}
	for _, name := range []string{"values.yaml", "gitlab.yml", "docker-compose.yml", "ci.yml"} {
		if isGitLabCIName(name) {
			t.Errorf("%s must not be read as pipeline configuration", name)
		}
	}
	// A template file in a nested directory is scanned like the root file.
	pipeline := "build:\n  image: node:20\n  script:\n    - npm ci\n"
	got := ruleIDs(scan(t, map[string]string{"templates/Docker.gitlab-ci.yml": pipeline}))
	if _, ok := got["gitlab-ci-image-no-digest"]; !ok {
		t.Errorf("a template pipeline must be scanned, got %v", keys(got))
	}
}

func filepathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
