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
