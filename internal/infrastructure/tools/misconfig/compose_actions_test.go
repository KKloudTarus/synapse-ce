package misconfig

import "testing"

func TestComposeInsecure(t *testing.T) {
	compose := `services:
  web:
    image: nginx:latest
    privileged: true
    network_mode: host
    pid: host
    ipc: host
    cap_add:
      - SYS_ADMIN
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DB_PASSWORD=supersecret123
`
	got := ruleIDs(scan(t, map[string]string{"docker-compose.yml": compose}))
	for _, want := range []string{
		"compose-privileged", "compose-host-network", "compose-host-pid", "compose-host-ipc",
		"compose-dangerous-capability", "compose-docker-socket-mount", "compose-image-unpinned",
		"compose-secret-in-env",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("compose: expected %s; got %v", want, keys(got))
		}
	}
	// The docker-socket finding must name the right line (the volume line, not the service header).
	if f := got["compose-docker-socket-mount"]; f.Line == 0 {
		t.Errorf("docker-socket finding has no line")
	}
}

func TestComposeClean(t *testing.T) {
	// A hardened service: pinned image, no privileged/host modes, interpolated (not literal) secret.
	compose := `services:
  web:
    image: nginx:1.27.3@sha256:abc
    read_only: true
    environment:
      - DB_PASSWORD=${DB_PASSWORD}
      - LOG_LEVEL=info
`
	got := ruleIDs(scan(t, map[string]string{"compose.yaml": compose}))
	for bad := range got {
		t.Errorf("clean compose should not be flagged, got %s", bad)
	}
}

func TestGitHubActionsInsecure(t *testing.T) {
	wf := `name: ci
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: greet
        run: echo "hello ${{ github.event.issue.title }}"
      - name: multi
        run: |
          echo "${{ github.head_ref }}"
`
	got := ruleIDs(scan(t, map[string]string{".github/workflows/ci.yml": wf}))
	for _, want := range []string{
		"gha-pull-request-target", "gha-permissions-write-all", "gha-unpinned-action", "gha-script-injection",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("gha: expected %s; got %v", want, keys(got))
		}
	}
}

func TestGitHubActionsClean(t *testing.T) {
	// SHA-pinned action, safe trigger, untrusted input passed via env (not interpolated into the shell).
	wf := `name: ci
on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: greet
        env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "hello $TITLE"
`
	got := ruleIDs(scan(t, map[string]string{".github/workflows/ci.yaml": wf}))
	for bad := range got {
		t.Errorf("clean workflow should not be flagged, got %s", bad)
	}
}

func TestGitHubActionsEnvRoutingNotFlagged(t *testing.T) {
	// The recommended mitigation: pass untrusted input through env: (even AFTER run:) and reference it as
	// a shell variable. This must NOT be flagged as injection (regression guard for the run-block tracker).
	wf := `jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$TITLE"
        env:
          TITLE: ${{ github.event.pull_request.title }}
`
	got := ruleIDs(scan(t, map[string]string{".github/workflows/ci.yml": wf}))
	if _, ok := got["gha-script-injection"]; ok {
		t.Errorf("env-routed untrusted input (the mitigation) must not be flagged; got %v", keys(got))
	}
}

func TestGitHubActionsNoFalsePositiveInsideRunScript(t *testing.T) {
	// YAML-looking text echoed inside a run: script must not trigger the trigger/permissions/uses rules.
	wf := `jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "permissions: write-all"
          echo "uses: foo/bar@v1"
`
	got := ruleIDs(scan(t, map[string]string{".github/workflows/ci.yml": wf}))
	for _, r := range []string{"gha-permissions-write-all", "gha-unpinned-action"} {
		if _, ok := got[r]; ok {
			t.Errorf("%s must not fire on run-script content; got %v", r, keys(got))
		}
	}
}

func TestGitHubActionsCommentedTriggerNotFlagged(t *testing.T) {
	wf := `on: [push]  # not pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
`
	got := ruleIDs(scan(t, map[string]string{".github/workflows/ci.yaml": wf}))
	if _, ok := got["gha-pull-request-target"]; ok {
		t.Errorf("a commented mention of pull_request_target must not be flagged; got %v", keys(got))
	}
}

func TestComposeQuotedInlineCapAndSecurityOpt(t *testing.T) {
	compose := `services:
  app:
    image: alpine:3.20
    cap_add: ["SYS_ADMIN"]
    userns_mode: host
    security_opt:
      - seccomp:unconfined
`
	got := ruleIDs(scan(t, map[string]string{"docker-compose.yml": compose}))
	for _, want := range []string{"compose-dangerous-capability", "compose-userns-host", "compose-unconfined-security-opt"} {
		if _, ok := got[want]; !ok {
			t.Errorf("compose: expected %s; got %v", want, keys(got))
		}
	}
}

func TestComposeEnvKeyNotMisclassified(t *testing.T) {
	// An env var whose key happens to look like a directive must be treated as an env var, not the directive.
	compose := `services:
  app:
    image: alpine:3.20
    environment:
      PRIVILEGED: "true"
      NETWORK_MODE: host
`
	got := ruleIDs(scan(t, map[string]string{"compose.yaml": compose}))
	for _, bad := range []string{"compose-privileged", "compose-host-network"} {
		if _, ok := got[bad]; ok {
			t.Errorf("%s must not fire on an environment variable key; got %v", bad, keys(got))
		}
	}
}

func TestGitHubActionsRulesGatedToWorkflowPath(t *testing.T) {
	// The same `uses:`/`run:` content OUTSIDE .github/workflows/ must not trigger the workflow rules
	// (path gating), and must not be misread as a Compose file either.
	yaml := `steps:
  - uses: actions/checkout@v4
    run: echo "${{ github.event.issue.title }}"
`
	got := ruleIDs(scan(t, map[string]string{"docs/example.yaml": yaml}))
	for _, r := range []string{"gha-unpinned-action", "gha-script-injection"} {
		if _, ok := got[r]; ok {
			t.Errorf("%s must not fire outside .github/workflows/; got %v", r, keys(got))
		}
	}
}
