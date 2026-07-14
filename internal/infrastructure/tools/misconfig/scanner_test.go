package misconfig

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// scan writes files into a temp root and runs the scanner over it.
func scan(t *testing.T, files map[string]string) []ports.MisconfigRawFinding {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := New().ScanConfigs(context.Background(), root)
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	return got
}

func ruleIDs(fs []ports.MisconfigRawFinding) map[string]ports.MisconfigRawFinding {
	m := make(map[string]ports.MisconfigRawFinding, len(fs))
	for _, f := range fs {
		m[f.RuleID] = f
	}
	return m
}

func TestDockerfileInsecure(t *testing.T) {
	df := `FROM ubuntu:latest
ADD https://example.com/app.tar.gz /app/
RUN curl -sSL https://get.example.com/install.sh | sh
EXPOSE 8080
`
	got := ruleIDs(scan(t, map[string]string{"Dockerfile": df}))
	for _, want := range []string{"dockerfile-image-no-tag", "dockerfile-add-remote-url", "dockerfile-run-pipe-shell", "dockerfile-run-as-root"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected rule %q on insecure Dockerfile, got rules %v", want, keys(got))
		}
	}
	if got["dockerfile-image-no-tag"].Line != 1 {
		t.Errorf("image-no-tag should be on FROM line 1, got %d", got["dockerfile-image-no-tag"].Line)
	}
	if got["dockerfile-run-pipe-shell"].Line != 3 {
		t.Errorf("pipe-to-shell should be on RUN line 3, got %d", got["dockerfile-run-pipe-shell"].Line)
	}
}

func TestDockerfileSecureNoFindings(t *testing.T) {
	// Pinned digest, explicit non-root USER, COPY instead of ADD, no pipe-to-shell.
	df := `FROM debian:12@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN useradd -r app
COPY ./bin/app /usr/local/bin/app
USER app
HEALTHCHECK CMD ["app", "healthz"]
ENTRYPOINT ["app"]
`
	if got := scan(t, map[string]string{"Dockerfile": df}); len(got) != 0 {
		t.Errorf("secure Dockerfile should yield no findings, got %+v", got)
	}
}

func TestDockerfileMultiStageJudgesFinalStage(t *testing.T) {
	// The builder stage runs as root (fine); the final stage pins a tag AND sets a non-root user, so
	// there should be no run-as-root finding and no no-tag finding.
	df := `FROM golang:1.26 AS builder
WORKDIR /src
RUN go build -o app .

FROM gcr.io/distroless/base:nonroot
COPY --from=builder /src/app /app
USER 65532
ENTRYPOINT ["/app"]
`
	got := ruleIDs(scan(t, map[string]string{"Dockerfile": df}))
	if _, bad := got["dockerfile-run-as-root"]; bad {
		t.Error("multi-stage final stage sets a non-root USER; run-as-root must not fire")
	}
	// golang:1.26 and distroless:nonroot are both tagged → no no-tag finding.
	if _, bad := got["dockerfile-image-no-tag"]; bad {
		t.Errorf("both stages are tagged; image-no-tag must not fire, got %+v", got)
	}
}

func TestDockerfileNoUserIsRoot(t *testing.T) {
	df := "FROM alpine:3.20\nRUN echo hi\n"
	got := ruleIDs(scan(t, map[string]string{"Dockerfile": df}))
	if _, ok := got["dockerfile-run-as-root"]; !ok {
		t.Error("Dockerfile with no USER must flag run-as-root")
	}
}

func TestKubernetesInsecure(t *testing.T) {
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
        - name: hostroot
          hostPath:
            path: /
      containers:
        - name: app
          image: myapp:1.0
          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
            capabilities:
              add: ["SYS_ADMIN"]
`
	got := ruleIDs(scan(t, map[string]string{"deploy.yaml": manifest}))
	for _, want := range []string{
		"kubernetes-host-network", "kubernetes-host-path", "kubernetes-privileged",
		"kubernetes-run-as-root", "kubernetes-allow-priv-escalation", "kubernetes-dangerous-capability",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected rule %q on insecure Deployment, got %v", want, keys(got))
		}
	}
	if got["kubernetes-privileged"].Severity != shared.SeverityHigh {
		t.Errorf("privileged should be High, got %s", got["kubernetes-privileged"].Severity)
	}
	if r := got["kubernetes-privileged"].Resource; r == "" || r[:10] != "Deployment" {
		t.Errorf("resource should name the Deployment + container, got %q", r)
	}
}

func TestKubernetesHardenedNoFindings(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: safe
  namespace: prod
spec:
  automountServiceAccountToken: false
  serviceAccountName: safe
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
      securityContext:
        privileged: false
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 3000
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: prod
spec:
  podSelector: {}
`
	if got := scan(t, map[string]string{"pod.yaml": manifest}); len(got) != 0 {
		t.Errorf("fully hardened Pod should yield no findings, got %+v", got)
	}
}

func TestKubernetesDeprecatedServiceAccountAlias(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  serviceAccount: app
  containers:
  - name: app
    image: app:1
`
	if _, bad := ruleIDs(scan(t, map[string]string{"pod.yaml": manifest}))["kubernetes-default-service-account"]; bad {
		t.Error("dedicated deprecated serviceAccount alias must not trigger the default-service-account rule")
	}
}

func TestKubernetesCronJobPodSpec(t *testing.T) {
	manifest := `apiVersion: batch/v1
kind: CronJob
metadata:
  name: app
  namespace: prod
spec:
  jobTemplate:
    spec:
      template:
        spec:
          automountServiceAccountToken: false
          serviceAccountName: app
          containers:
          - name: app
            image: app:1
            env:
            - name: API_TOKEN
              value: literal
`
	got := ruleIDs(scan(t, map[string]string{"cronjob.yaml": manifest}))
	if _, ok := got["kubernetes-secret-in-env"]; !ok {
		t.Errorf("CronJob literal secret env must be flagged, got %v", keys(got))
	}
	for _, rule := range []string{"kubernetes-default-service-account", "kubernetes-automount-sa-token"} {
		if _, bad := got[rule]; bad {
			t.Errorf("CronJob with secure pod spec must not trigger %q", rule)
		}
	}
}

func TestKubernetesUnhardenedFlagged(t *testing.T) {
	// A container with no securityContext now yields the missing-hardening findings (the comprehensive
	// KSV/CIS posture that matches Trivy/kube-bench); the earlier low-FP "stay quiet" policy was
	// intentionally replaced so Synapse is not weaker than comprehensive scanners on IaC coverage.
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: plain
spec:
  containers:
    - name: app
      image: myapp:1.0
`
	got := ruleIDs(scan(t, map[string]string{"pod.yaml": manifest}))
	for _, want := range []string{
		"kubernetes-no-run-as-non-root", "kubernetes-no-priv-escalation-disabled",
		"kubernetes-no-read-only-root-fs", "kubernetes-caps-not-dropped",
		"kubernetes-no-seccomp", "kubernetes-no-cpu-limit", "kubernetes-no-memory-limit",
		"kubernetes-no-run-as-user",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("unhardened container must flag %q, got %v", want, keys(got))
		}
	}
}

func TestKubernetesRulePackAdditions(t *testing.T) {
	files := map[string]string{
		"rbac.yaml": `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: unsafe
rules:
- apiGroups: ["*"]
  resources: ["pods"]
  verbs: ["bind"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin
roleRef:
  kind: ClusterRole
  name: cluster-admin
`,
		"secrets.yaml": `apiVersion: v1
kind: Secret
metadata:
  name: api
stringData:
  token: literal
---
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: prod
spec:
  serviceAccountName: default
  containers:
  - name: app
    image: app:1
    env:
    - name: API_TOKEN
      value: literal
`,
		"ingress.yaml": `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
spec:
  tls:
  - hosts: [app.example.test]
`,
	}
	got := ruleIDs(scan(t, files))
	for _, want := range []string{
		"kubernetes-rbac-wildcard-permissions", "kubernetes-rbac-escalation-verbs",
		"kubernetes-rbac-cluster-admin-binding", "kubernetes-default-service-account",
		"kubernetes-secret-in-env", "kubernetes-secret-in-manifest", "kubernetes-ingress-tls-no-secret",
		"kubernetes-namespace-no-network-policy",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected rule %q, got %v", want, keys(got))
		}
	}
	if _, bad := got["kubernetes-ingress-no-tls"]; bad {
		t.Error("Ingress with a TLS entry must not trigger no-tls")
	}
}

func TestKubernetesNetworkPolicyNamespaceCoverage(t *testing.T) {
	files := map[string]string{
		"workloads.yaml": `apiVersion: v1
kind: Pod
metadata:
  name: one
  namespace: protected
spec:
  serviceAccountName: app
  containers:
  - name: app
    image: app:1
---
apiVersion: v1
kind: Pod
metadata:
  name: two
  namespace: unprotected
spec:
  serviceAccountName: app
  containers:
  - name: app
    image: app:1
`,
		"policy.yaml": `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: protected
spec:
  podSelector: {}
`,
	}
	var count int
	for _, finding := range scan(t, files) {
		if finding.RuleID == "kubernetes-namespace-no-network-policy" {
			count++
			if finding.Resource != "Pod/two" {
				t.Errorf("policy finding must identify unprotected workload, got %q", finding.Resource)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected one unprotected-namespace finding, got %d", count)
	}
}

func TestKubernetesSecretReferenceAndIngressTLSAreCompliant(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: prod
spec:
  serviceAccountName: app
  containers:
  - name: app
    image: app:1
    env:
    - name: API_TOKEN
      valueFrom:
        secretKeyRef:
          name: api
          key: token
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
spec:
  tls:
  - secretName: app-tls
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: prod
spec:
  podSelector: {}
`
	got := ruleIDs(scan(t, map[string]string{"manifest.yaml": manifest}))
	for _, rule := range []string{"kubernetes-secret-in-env", "kubernetes-ingress-no-tls", "kubernetes-ingress-tls-no-secret", "kubernetes-namespace-no-network-policy"} {
		if _, bad := got[rule]; bad {
			t.Errorf("compliant manifest must not trigger %q", rule)
		}
	}
}

func TestNonKubernetesYAMLSkipped(t *testing.T) {
	// A CI/compose YAML with no apiVersion+kind must not be parsed as a manifest.
	ci := "jobs:\n  build:\n    steps:\n      - run: make\n"
	if got := scan(t, map[string]string{".github/workflows/ci.yml": ci}); len(got) != 0 {
		t.Errorf("non-Kubernetes YAML must be skipped, got %+v", got)
	}
}

func TestMultiDocYAML(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: a
spec:
  containers:
    - name: c
      image: x:1
      securityContext:
        privileged: true
---
apiVersion: v1
kind: Pod
metadata:
  name: b
spec:
  hostPID: true
  containers:
    - name: c
      image: x:1
`
	got := scan(t, map[string]string{"multi.yaml": manifest})
	rules := ruleIDs(got)
	if _, ok := rules["kubernetes-privileged"]; !ok {
		t.Error("first doc's privileged container must be flagged")
	}
	if _, ok := rules["kubernetes-host-pid"]; !ok {
		t.Error("second doc's hostPID must be flagged")
	}
}

func TestSkipsVendorDir(t *testing.T) {
	df := "FROM ubuntu\nRUN echo hi\n"
	got := scan(t, map[string]string{"vendor/some/Dockerfile": df, "node_modules/x/Dockerfile": df})
	if len(got) != 0 {
		t.Errorf("Dockerfiles under vendored dirs must be skipped, got %+v", got)
	}
}

func TestScanIgnoresSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	root := t.TempDir()
	// An insecure Dockerfile OUTSIDE the scanned root.
	outside := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(outside, []byte("FROM ubuntu:latest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the root pointing at it must not be followed.
	if err := os.Symlink(outside, filepath.Join(root, "Dockerfile")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	got, err := New().ScanConfigs(context.Background(), root)
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a symlink out of the workspace must not be scanned, got %+v", got)
	}
}

func TestContextCancelled(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM ubuntu\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().ScanConfigs(ctx, root); err == nil {
		t.Error("a cancelled context must surface an error, not a silent empty result")
	}
}

func TestDeeplyNestedYAMLIsSkippedNotCrash(t *testing.T) {
	// A crafted manifest that passes the looksKubernetes pre-filter and is small on disk but nests flow
	// collections far deeper than any real manifest. It must be skipped (returns cleanly), never overflow
	// the yaml.v3 parser stack (an unrecoverable fatal).
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Pod\nx: ")
	for i := 0; i < 100000; i++ {
		b.WriteByte('[')
	}
	got := scan(t, map[string]string{"bomb.yaml": b.String()})
	if len(got) != 0 {
		t.Errorf("a pathologically deep document must be skipped, got %+v", got)
	}
}

func TestNormalNestingStillScans(t *testing.T) {
	// Sanity: the depth guard must not reject a manifest with ordinary flow style.
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: flowy
spec:
  containers:
    - {name: app, image: "x:1", securityContext: {privileged: true}}
`
	if got := ruleIDs(scan(t, map[string]string{"pod.yaml": manifest})); got["kubernetes-privileged"].RuleID == "" {
		t.Error("ordinary flow-style manifest must still be scanned and flagged")
	}
}

func TestUntrustedValuesAreClipped(t *testing.T) {
	long := strings.Repeat("A", 5000)
	manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + long +
		"\nspec:\n  volumes:\n    - name: v\n      hostPath:\n        path: /" + long + "\n"
	got := scan(t, map[string]string{"pod.yaml": manifest})
	for _, f := range got {
		if len(f.Resource) > maxValueLen*3 { // Kind + '/' + clipped name, all bounded
			t.Errorf("Resource not clipped: %d bytes", len(f.Resource))
		}
		if len(f.Description) > maxValueLen*6 {
			t.Errorf("Description embeds an unclipped value: %d bytes", len(f.Description))
		}
	}
}

func keys(m map[string]ports.MisconfigRawFinding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
