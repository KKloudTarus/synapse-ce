package misconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// dangerousCaps are Linux capabilities that grant broad host control; adding any of them (or ALL)
// effectively removes the container boundary.
var dangerousCaps = set("ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE",
	"SYS_MODULE", "SYS_BOOT", "DAC_READ_SEARCH", "SYS_RAWIO")

// maxNestDepth bounds YAML flow-collection nesting before we decode. yaml.v3 has no recursion-depth
// limit, so a deeply-nested untrusted document (e.g. millions of '[') can overflow the parser's stack –
// a FATAL error that recover() cannot catch. Real manifests nest < ~30 deep; 200 is generous headroom.
const maxNestDepth = 200

// maxLocatorDepth bounds the best-effort line locator's recursion (defense-in-depth; the pre-decode
// depth guard already keeps trees shallow).
const maxLocatorDepth = 1000

// k8sDoc is the slice of a Kubernetes object we inspect. A workload (Deployment, StatefulSet, ...) nests
// the pod under spec.template.spec; a bare Pod uses spec directly – podSpec() resolves both.
type k8sDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec                         k8sSpec           `yaml:"spec"`
	AutomountServiceAccountToken *bool             `yaml:"automountServiceAccountToken"`
	Rules                        []k8sRBACRule     `yaml:"rules"`
	RoleRef                      k8sRoleRef        `yaml:"roleRef"`
	Data                         map[string]string `yaml:"data"`
	StringData                   map[string]string `yaml:"stringData"`
}

type k8sSpec struct {
	HostNetwork                  bool           `yaml:"hostNetwork"`
	HostPID                      bool           `yaml:"hostPID"`
	HostIPC                      bool           `yaml:"hostIPC"`
	AutomountServiceAccountToken *bool          `yaml:"automountServiceAccountToken"`
	ServiceAccountName           string         `yaml:"serviceAccountName"`
	ServiceAccount               string         `yaml:"serviceAccount"` // deprecated Kubernetes alias
	Containers                   []k8sContainer `yaml:"containers"`
	InitContainers               []k8sContainer `yaml:"initContainers"`
	Volumes                      []k8sVolume    `yaml:"volumes"`
	SecurityContext              *podSecCtx     `yaml:"securityContext"` // pod-level (inherited by containers)
	Template                     *struct {
		Spec k8sSpec `yaml:"spec"`
	} `yaml:"template"`
	JobTemplate *struct {
		Spec k8sSpec `yaml:"spec"`
	} `yaml:"jobTemplate"`
	TLS []k8sIngressTLS `yaml:"tls"`
}

type k8sRBACRule struct {
	APIGroups       []string `yaml:"apiGroups"`
	Resources       []string `yaml:"resources"`
	Verbs           []string `yaml:"verbs"`
	NonResourceURLs []string `yaml:"nonResourceURLs"`
}

type k8sRoleRef struct {
	Kind string `yaml:"kind"`
	Name string `yaml:"name"`
}

type k8sIngressTLS struct {
	SecretName string `yaml:"secretName"`
}

// podSecCtx is the pod-level securityContext; runAsNonRoot / runAsUser / seccompProfile set here are
// inherited by every container that does not override them.
type podSecCtx struct {
	RunAsNonRoot   *bool `yaml:"runAsNonRoot"`
	RunAsUser      *int  `yaml:"runAsUser"`
	RunAsGroup     *int  `yaml:"runAsGroup"`
	SeccompProfile *struct {
		Type string `yaml:"type"`
	} `yaml:"seccompProfile"`
}

type k8sVolume struct {
	Name     string `yaml:"name"`
	HostPath *struct {
		Path string `yaml:"path"`
	} `yaml:"hostPath"`
}

type k8sContainer struct {
	Name            string     `yaml:"name"`
	Image           string     `yaml:"image"`
	SecurityContext *ctnSecCtx `yaml:"securityContext"`
	Resources       *struct {
		Limits map[string]any `yaml:"limits"`
	} `yaml:"resources"`
	Ports []struct {
		HostPort int `yaml:"hostPort"`
	} `yaml:"ports"`
	Env []k8sEnvVar `yaml:"env"`
}

type k8sEnvVar struct {
	Name      string `yaml:"name"`
	Value     string `yaml:"value"`
	ValueFrom any    `yaml:"valueFrom"`
}

type ctnSecCtx struct {
	Privileged               *bool `yaml:"privileged"`
	RunAsNonRoot             *bool `yaml:"runAsNonRoot"`
	RunAsUser                *int  `yaml:"runAsUser"`
	RunAsGroup               *int  `yaml:"runAsGroup"`
	AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   *bool `yaml:"readOnlyRootFilesystem"`
	Capabilities             *struct {
		Add  []string `yaml:"add"`
		Drop []string `yaml:"drop"`
	} `yaml:"capabilities"`
	SeccompProfile *struct {
		Type string `yaml:"type"`
	} `yaml:"seccompProfile"`
}

// podSpec resolves the effective pod spec: CronJobs nest it under jobTemplate.spec.template.spec,
// other workloads use template.spec, and a bare Pod uses spec directly.
func (s k8sSpec) podSpec() k8sSpec {
	if s.JobTemplate != nil {
		return s.JobTemplate.Spec.podSpec()
	}
	if s.Template != nil {
		return s.Template.Spec
	}
	return s
}

type k8sWorkloadFact struct {
	namespace string
	file      string
	line      int
	resource  string
}

type k8sScanResult struct {
	findings         []ports.MisconfigRawFinding
	workloads        []k8sWorkloadFact
	policyNamespaces map[string]struct{}
}

// scanKubernetes decodes every YAML document in data and returns findings plus namespace facts. Best-effort:
// a document that decodes but does not fit our shape (or has no kind) is skipped and later documents are
// still scanned; a YAML *stream* syntax error halts parsing of the rest of THIS file (prior results are
// kept), because yaml.v3 cannot reliably resume mid-stream. Either way the overall scan never fails.
func scanKubernetes(rel string, data []byte) k8sScanResult {
	out := k8sScanResult{policyNamespaces: make(map[string]struct{})}
	// Refuse pathologically deep documents BEFORE decoding: yaml.v3 recurses per nesting level with no
	// depth cap, so a crafted deep document would overflow the goroutine stack (an unrecoverable fatal),
	// not merely return an error. This keeps a malformed file a per-file skip, per the port contract.
	if tooDeepYAML(data) {
		return out
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return out // stream syntax error: stop this file, keep prior findings
		}
		var doc k8sDoc
		if err := node.Decode(&doc); err != nil || doc.Kind == "" {
			continue // not a manifest we recognise; try the next document
		}
		out.findings = append(out.findings, checkK8sDoc(rel, doc, &node)...)
		namespace := k8sNamespace(doc.Metadata.Namespace)
		if isWorkloadKind(doc.Kind) {
			resource := clip(doc.Kind)
			if doc.Metadata.Name != "" {
				resource += "/" + clip(doc.Metadata.Name)
			}
			out.workloads = append(out.workloads, k8sWorkloadFact{namespace: namespace, file: rel, line: firstKeyLine(&node, "kind"), resource: resource})
		}
		if doc.Kind == "NetworkPolicy" {
			out.policyNamespaces[namespace] = struct{}{}
		}
	}
	return out
}

func k8sNamespace(namespace string) string {
	if strings.TrimSpace(namespace) == "" {
		return "default"
	}
	return namespace
}

func mergeK8sScanResult(dst *k8sScanResult, src k8sScanResult) {
	dst.findings = append(dst.findings, src.findings...)
	dst.workloads = append(dst.workloads, src.workloads...)
	if dst.policyNamespaces == nil {
		dst.policyNamespaces = make(map[string]struct{})
	}
	for namespace := range src.policyNamespaces {
		dst.policyNamespaces[namespace] = struct{}{}
	}
}

func networkPolicyFindings(result k8sScanResult) []ports.MisconfigRawFinding {
	seen := make(map[string]struct{})
	var out []ports.MisconfigRawFinding
	for _, workload := range result.workloads {
		if _, ok := result.policyNamespaces[workload.namespace]; ok {
			continue
		}
		if _, ok := seen[workload.namespace]; ok {
			continue
		}
		seen[workload.namespace] = struct{}{}
		out = append(out, ports.MisconfigRawFinding{
			File: workload.file, Line: workload.line, RuleID: "kubernetes-namespace-no-network-policy",
			Title: "Namespace has no NetworkPolicy", Severity: shared.SeverityLow, Resource: workload.resource,
			Description: "No NetworkPolicy manifest declares coverage for namespace " + clip(workload.namespace) + ". Add a default-deny policy and explicit traffic rules for this workload namespace.",
		})
	}
	return out
}

func checkK8sDoc(rel string, doc k8sDoc, node *yaml.Node) []ports.MisconfigRawFinding {
	spec := doc.Spec.podSpec()
	res := clip(doc.Kind)
	if doc.Metadata.Name != "" {
		res += "/" + clip(doc.Metadata.Name)
	}
	docLine := firstKeyLine(node, "kind")
	var out []ports.MisconfigRawFinding
	add := func(rule, title, desc string, sev shared.Severity, key string) {
		line := firstKeyLine(node, key)
		if line == 0 {
			line = docLine
		}
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: rule, Title: title, Severity: sev, Resource: res, Description: desc,
		})
	}

	if isWorkloadKind(doc.Kind) && (doc.Metadata.Namespace == "" || doc.Metadata.Namespace == "default") {
		add("kubernetes-default-namespace", "Workload in the default namespace",
			"The workload has no namespace or uses \"default\", so it shares a namespace with unrelated workloads and weakens RBAC/network-policy scoping. Deploy it to a dedicated namespace.",
			shared.SeverityLow, "metadata")
	}
	if isWorkloadKind(doc.Kind) && usesDefaultServiceAccount(spec) {
		add("kubernetes-default-service-account", "Workload uses the default ServiceAccount",
			"serviceAccountName is omitted or set to default, so the workload shares the namespace default identity. Create and assign a dedicated ServiceAccount with only the permissions it needs.",
			shared.SeverityLow, "serviceAccountName")
	}
	if (isWorkloadKind(doc.Kind) && (spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken)) ||
		(doc.Kind == "ServiceAccount" && (doc.AutomountServiceAccountToken == nil || *doc.AutomountServiceAccountToken)) {
		add("kubernetes-automount-sa-token", "Service-account token auto-mounted",
			"automountServiceAccountToken is not set to false, so a pod receives the API token even if it never calls the API server, widening the blast radius of a compromise. Set it to false unless API access is needed.",
			shared.SeverityLow, "automountServiceAccountToken")
	}
	if isRBACRoleKind(doc.Kind) {
		if rbacHasWildcard(doc.Rules) {
			add("kubernetes-rbac-wildcard-permissions", "RBAC rule grants wildcard permissions",
				"The RBAC rule uses a wildcard in its API groups, resources, verbs, or non-resource URLs. Replace it with the smallest explicit permission set required.", shared.SeverityHigh, "rules")
		}
		if rbacHasEscalationVerb(doc.Rules) {
			add("kubernetes-rbac-escalation-verbs", "RBAC rule grants escalation permissions",
				"The RBAC rule grants bind, escalate, or impersonate, which can be used to obtain broader privileges. Remove these verbs unless an administrator explicitly requires them.", shared.SeverityHigh, "verbs")
		}
	}
	if isRBACBindingKind(doc.Kind) && doc.RoleRef.Kind == "ClusterRole" && doc.RoleRef.Name == "cluster-admin" {
		add("kubernetes-rbac-cluster-admin-binding", "Binding grants cluster-admin",
			"The binding assigns the built-in cluster-admin ClusterRole, which grants unrestricted control-plane access. Bind a narrowly scoped Role or ClusterRole instead.", shared.SeverityHigh, "roleRef")
	}
	if doc.Kind == "Secret" && (len(doc.Data) != 0 || len(doc.StringData) != 0) {
		add("kubernetes-secret-in-manifest", "Secret value stored in manifest",
			"The Secret embeds data directly in a manifest, which can expose credentials through source control, reviews, and build artifacts. Reference a managed secret source or inject the value at deployment time.", shared.SeverityMedium, "data")
	}
	if doc.Kind == "Ingress" {
		if len(doc.Spec.TLS) == 0 {
			add("kubernetes-ingress-no-tls", "Ingress has no TLS configuration",
				"The Ingress declares routes without a TLS entry, so clients may connect without transport encryption. Configure TLS for every hostname that serves sensitive traffic.", shared.SeverityLow, "spec")
		} else {
			for _, tls := range doc.Spec.TLS {
				if strings.TrimSpace(tls.SecretName) == "" {
					add("kubernetes-ingress-tls-no-secret", "Ingress TLS entry has no secret",
						"The Ingress TLS entry omits secretName, so the controller has no named certificate secret to use. Set secretName to the TLS certificate Secret.", shared.SeverityLow, "tls")
					break
				}
			}
		}
	}
	if spec.HostNetwork {
		add("kubernetes-host-network", "Pod shares the host network namespace",
			"hostNetwork: true lets the pod see and bind host interfaces, bypassing network policy and exposing host services. Remove hostNetwork unless the workload is a node-level agent that genuinely needs it.",
			shared.SeverityHigh, "hostNetwork")
	}
	if spec.HostPID {
		add("kubernetes-host-pid", "Pod shares the host PID namespace",
			"hostPID: true lets the pod see and signal all host processes. Remove it unless strictly required.",
			shared.SeverityHigh, "hostPID")
	}
	if spec.HostIPC {
		add("kubernetes-host-ipc", "Pod shares the host IPC namespace",
			"hostIPC: true shares host inter-process-communication with the pod, a container-escape aid. Remove it unless strictly required.",
			shared.SeverityHigh, "hostIPC")
	}
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			add("kubernetes-host-path", "Volume mounts a host path",
				fmt.Sprintf("Volume %q mounts hostPath %q from the node filesystem; a compromised container can read or tamper with host files. Use a PersistentVolumeClaim or emptyDir instead.", clip(v.Name), clip(v.HostPath.Path)),
				shared.SeverityMedium, "hostPath")
		}
	}

	all := append(append([]k8sContainer{}, spec.Containers...), spec.InitContainers...)
	for _, c := range all {
		cres := res + " container=" + clip(c.Name)
		sc := c.SecurityContext
		// KSV/CIS hardening: fire when a recommended secure setting is MISSING (the comprehensive
		// posture that matches Trivy/kube-bench), regardless of whether a securityContext block exists.
		out = append(out, k8sHardening(rel, node, cres, docLine, sc, c, spec.SecurityContext)...)
		if hasLiteralSecretEnv(c.Env) {
			out = append(out, k8sContainerFinding(rel, node, cres, "kubernetes-secret-in-env",
				"Literal secret in environment variable", shared.SeverityMedium, "env",
				"A secret-named environment variable is assigned a literal value, which can leak through manifests, process inspection, logs, and debugging output. Load it from a Secret reference or a managed secret provider instead.", docLine))
		}
		if sc == nil {
			continue // the explicit-insecure checks below need a securityContext to inspect
		}
		if sc.Privileged != nil && *sc.Privileged {
			out = append(out, k8sContainerFinding(rel, node, cres, "kubernetes-privileged",
				"Privileged container", shared.SeverityHigh, "privileged",
				"securityContext.privileged: true gives the container near-root access to the host (all devices, all capabilities). Drop privileged and grant only the specific capabilities the workload needs.", docLine))
		}
		if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
			out = append(out, k8sContainerFinding(rel, node, cres, "kubernetes-allow-priv-escalation",
				"Privilege escalation allowed", shared.SeverityMedium, "allowPrivilegeEscalation",
				"securityContext.allowPrivilegeEscalation: true lets a process gain more privileges than its parent (e.g. via setuid). Set it to false.", docLine))
		}
		if runsAsRoot(sc) {
			out = append(out, k8sContainerFinding(rel, node, cres, "kubernetes-run-as-root",
				"Container runs as root", shared.SeverityMedium, "runAsUser",
				"The container is configured to run as root (runAsUser: 0 or runAsNonRoot: false). Set runAsNonRoot: true and a non-zero runAsUser.", docLine))
		}
		if sc.Capabilities != nil {
			for _, capName := range sc.Capabilities.Add {
				if dangerousCaps[strings.ToUpper(strings.TrimSpace(capName))] {
					out = append(out, k8sContainerFinding(rel, node, cres, "kubernetes-dangerous-capability",
						"Dangerous Linux capability added", shared.SeverityHigh, "capabilities",
						fmt.Sprintf("securityContext.capabilities.add includes %q, which grants broad host control and can enable container escape. Drop it and add only least-privilege capabilities.", clip(capName)), docLine))
					break
				}
			}
		}
	}
	return out
}

// k8sHardening emits the missing-hardening findings (KSV / CIS / Pod Security baseline) for one
// container: a recommended secure setting that is absent is flagged, matching the comprehensive posture
// of scanners like Trivy and kube-bench. Pod-level runAsNonRoot / seccompProfile are inherited when the
// container does not set its own. Severities are low/medium so they never bury the explicit-insecure highs.
func k8sHardening(rel string, node *yaml.Node, cres string, docLine int, sc *ctnSecCtx, c k8sContainer, pod *podSecCtx) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	h := func(rule, title, desc, key string, sev shared.Severity) {
		out = append(out, k8sContainerFinding(rel, node, cres, rule, title, sev, key, desc, docLine))
	}
	if !runAsNonRootEnforced(sc, pod) {
		h("kubernetes-no-run-as-non-root", "Container may run as root",
			"Nothing enforces a non-root user (runAsNonRoot: true or a non-zero runAsUser) on the container or the pod, so it can run as UID 0. Set securityContext.runAsNonRoot: true.",
			"runAsNonRoot", shared.SeverityMedium)
	}
	if !(sc != nil && sc.AllowPrivilegeEscalation != nil && !*sc.AllowPrivilegeEscalation) {
		h("kubernetes-no-priv-escalation-disabled", "Privilege escalation not disabled",
			"allowPrivilegeEscalation is not set to false, so a process can gain more privileges than its parent (e.g. via a setuid binary). Set securityContext.allowPrivilegeEscalation: false.",
			"allowPrivilegeEscalation", shared.SeverityLow)
	}
	if !(sc != nil && sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem) {
		h("kubernetes-no-read-only-root-fs", "Writable container root filesystem",
			"readOnlyRootFilesystem is not true, so the container can write to its own filesystem (tampering, dropped tooling persists). Set securityContext.readOnlyRootFilesystem: true and mount writable paths explicitly.",
			"readOnlyRootFilesystem", shared.SeverityLow)
	}
	if !dropsAllCaps(sc) {
		h("kubernetes-caps-not-dropped", "Default Linux capabilities not dropped",
			"The container does not drop ALL capabilities (securityContext.capabilities.drop: [ALL]), so it keeps the default capability set. Drop ALL and add back only the few that are required.",
			"capabilities", shared.SeverityLow)
	}
	if !seccompEnforced(sc, pod) {
		h("kubernetes-no-seccomp", "No seccomp profile",
			"No seccompProfile is set (RuntimeDefault or Localhost) on the container or the pod, so syscalls are unrestricted. Set seccompProfile.type: RuntimeDefault.",
			"seccompProfile", shared.SeverityLow)
	}
	cpu, mem := false, false
	if c.Resources != nil {
		_, cpu = c.Resources.Limits["cpu"]
		_, mem = c.Resources.Limits["memory"]
	}
	if !cpu {
		h("kubernetes-no-cpu-limit", "No CPU limit",
			"The container sets no resources.limits.cpu, so a runaway workload can starve other pods on the node. Set a CPU limit.",
			"resources", shared.SeverityLow)
	}
	if !mem {
		h("kubernetes-no-memory-limit", "No memory limit",
			"The container sets no resources.limits.memory, so a memory leak or hostile workload can OOM the node (noisy-neighbor / DoS). Set a memory limit.",
			"resources", shared.SeverityLow)
	}
	if !runAsUserSet(sc, pod) {
		h("kubernetes-no-run-as-user", "No explicit runAsUser",
			"Neither the container nor the pod sets an explicit securityContext.runAsUser, so the UID is left to the image. Pin a non-zero runAsUser for a predictable, non-root identity.",
			"runAsUser", shared.SeverityLow)
	}
	if (sc == nil || sc.RunAsGroup == nil) && (pod == nil || pod.RunAsGroup == nil) {
		h("kubernetes-no-run-as-group", "No explicit runAsGroup",
			"Neither the container nor the pod sets securityContext.runAsGroup, so the primary GID defaults to the image (often 0/root group). Pin a non-zero runAsGroup.",
			"runAsGroup", shared.SeverityLow)
	}
	if t := imageTag(c.Image); c.Image != "" && (t == "" || t == "latest") {
		h("kubernetes-image-no-tag", "Container image not version-pinned",
			"The container image uses no tag or :latest, so the deployed version is not reproducible and can silently change. Pin an explicit tag, ideally by digest.",
			"image", shared.SeverityLow)
	}
	for _, p := range c.Ports {
		if p.HostPort != 0 {
			h("kubernetes-host-port", "Container binds a host port",
				"A container port sets hostPort, binding directly to the node's network and bypassing Service abstraction and network policy. Expose the workload through a Service instead.",
				"hostPort", shared.SeverityMedium)
			break
		}
	}
	return out
}

func usesDefaultServiceAccount(spec k8sSpec) bool {
	name := spec.ServiceAccountName
	if name == "" {
		name = spec.ServiceAccount
	}
	return name == "" || name == "default"
}

func isRBACRoleKind(kind string) bool { return kind == "Role" || kind == "ClusterRole" }

func isRBACBindingKind(kind string) bool {
	return kind == "RoleBinding" || kind == "ClusterRoleBinding"
}

func rbacHasWildcard(rules []k8sRBACRule) bool {
	for _, rule := range rules {
		for _, values := range [][]string{rule.APIGroups, rule.Resources, rule.Verbs, rule.NonResourceURLs} {
			for _, value := range values {
				if strings.TrimSpace(value) == "*" {
					return true
				}
			}
		}
	}
	return false
}

func rbacHasEscalationVerb(rules []k8sRBACRule) bool {
	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			switch strings.ToLower(strings.TrimSpace(verb)) {
			case "bind", "escalate", "impersonate":
				return true
			}
		}
	}
	return false
}

func hasLiteralSecretEnv(env []k8sEnvVar) bool {
	for _, entry := range env {
		if secretKeyRe.MatchString(entry.Name) && strings.TrimSpace(entry.Value) != "" && entry.ValueFrom == nil {
			return true
		}
	}
	return false
}

// isWorkloadKind reports whether a Kubernetes kind carries a pod template / runs workloads (so pod-level
// namespace and service-account checks apply); cluster-scoped objects like Namespace or ClusterRole do not.
func isWorkloadKind(kind string) bool {
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "ReplicationController":
		return true
	}
	return false
}

// runAsUserSet reports whether an explicit runAsUser is set on the container or, by inheritance, the pod.
func runAsUserSet(sc *ctnSecCtx, pod *podSecCtx) bool {
	if sc != nil && sc.RunAsUser != nil {
		return true
	}
	return pod != nil && pod.RunAsUser != nil
}

// runAsNonRootEnforced reports whether a non-root user is enforced by the container or, by inheritance,
// the pod. An EXPLICIT root setting also counts as "enforced/handled" here so the missing-hardening rule
// does not double-report with runsAsRoot (which flags the explicit case at a higher severity).
func runAsNonRootEnforced(sc *ctnSecCtx, pod *podSecCtx) bool {
	if sc != nil {
		if sc.RunAsNonRoot != nil {
			return true // explicitly true (secure) or false (handled by runsAsRoot)
		}
		if sc.RunAsUser != nil {
			return true // any explicit UID: >0 secure, 0 handled by runsAsRoot
		}
	}
	if pod != nil {
		if pod.RunAsNonRoot != nil && *pod.RunAsNonRoot {
			return true
		}
		if pod.RunAsUser != nil && *pod.RunAsUser > 0 {
			return true
		}
	}
	return false
}

// seccompEnforced reports whether a seccomp profile is set on the container or, by inheritance, the pod.
func seccompEnforced(sc *ctnSecCtx, pod *podSecCtx) bool {
	if sc != nil && sc.SeccompProfile != nil && strings.TrimSpace(sc.SeccompProfile.Type) != "" {
		return true
	}
	return pod != nil && pod.SeccompProfile != nil && strings.TrimSpace(pod.SeccompProfile.Type) != ""
}

// dropsAllCaps reports whether the container drops ALL Linux capabilities.
func dropsAllCaps(sc *ctnSecCtx) bool {
	if sc == nil || sc.Capabilities == nil {
		return false
	}
	for _, d := range sc.Capabilities.Drop {
		if strings.EqualFold(strings.TrimSpace(d), "ALL") {
			return true
		}
	}
	return false
}

// runsAsRoot reports an EXPLICIT root configuration only (runAsUser 0, or runAsNonRoot false) – an unset
// securityContext is left alone to keep false positives low.
func runsAsRoot(sc *ctnSecCtx) bool {
	if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
		return true
	}
	if sc.RunAsNonRoot != nil && !*sc.RunAsNonRoot {
		return true
	}
	return false
}

func k8sContainerFinding(rel string, node *yaml.Node, resource, rule, title string, sev shared.Severity, key, desc string, fallback int) ports.MisconfigRawFinding {
	line := firstKeyLine(node, key)
	if line == 0 {
		line = fallback
	}
	return ports.MisconfigRawFinding{
		File: rel, Line: line, RuleID: rule, Title: title, Severity: sev, Resource: resource, Description: desc,
	}
}

// firstKeyLine returns the 1-indexed line of the first mapping key whose name equals key, searched
// depth-first. It is a best-effort locator for the finding, not a precise scope resolver; 0 = not found.
func firstKeyLine(node *yaml.Node, key string) int {
	return firstKeyLineDepth(node, key, 0)
}

func firstKeyLineDepth(node *yaml.Node, key string, depth int) int {
	if node == nil || depth > maxLocatorDepth {
		return 0
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, c := range node.Content {
			if l := firstKeyLineDepth(c, key, depth+1); l != 0 {
				return l
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			k, v := node.Content[i], node.Content[i+1]
			if k.Value == key {
				return k.Line
			}
			if l := firstKeyLineDepth(v, key, depth+1); l != 0 {
				return l
			}
		}
	case yaml.SequenceNode:
		for _, c := range node.Content {
			if l := firstKeyLineDepth(c, key, depth+1); l != 0 {
				return l
			}
		}
	}
	return 0
}

// tooDeepYAML reports whether data nests deeper than maxNestDepth in a way that could overflow yaml.v3's
// recursive parser. It covers both linear-cost forms: flow collections ('['/'{') and compact block chains
// ("- - - x"). Indented block nesting is not checked because it costs ~O(depth^2) bytes, so the file-size
// cap already bounds it well below a stack-overflowing depth.
func tooDeepYAML(data []byte) bool {
	return maxFlowDepth(data) > maxNestDepth || maxBlockChainDepth(data) > maxNestDepth
}

// maxFlowDepth returns the deepest nesting of YAML flow collections ('[' and '{') in data, ignoring
// brackets inside quoted scalars and comments. It is a cheap linear pre-scan so a deep untrusted document
// is rejected before it reaches the recursive yaml.v3 parser.
func maxFlowDepth(data []byte) int {
	var depth, maxd int
	var inSingle, inDouble bool
	var prev byte
	for i := 0; i < len(data); i++ {
		b := data[i]
		switch {
		case inDouble:
			if b == '\\' { // skip an escaped char inside a double-quoted scalar
				i++
				prev = 0
				continue
			}
			if b == '"' {
				inDouble = false
			}
		case inSingle:
			if b == '\'' {
				inSingle = false
			}
		default:
			switch b {
			case '"':
				inDouble = true
			case '\'':
				inSingle = true
			case '#': // a comment runs to end of line only when '#' begins a token
				if prev == 0 || prev == ' ' || prev == '\t' || prev == '\n' || prev == '\r' {
					for i < len(data) && data[i] != '\n' {
						i++
					}
					prev = '\n'
					continue
				}
			case '[', '{':
				depth++
				if depth > maxd {
					maxd = depth
					if maxd > maxNestDepth {
						return maxd // early out: already past the cap
					}
				}
			case ']', '}':
				if depth > 0 {
					depth--
				}
			}
		}
		prev = b
	}
	return maxd
}

// maxBlockChainDepth returns the longest run of compact block-collection indicators ("- " or "? ") at the
// start of a line, after leading whitespace. Compact block nesting like "- - - - x" is a single line whose
// nesting depth equals that run and costs only ~2 bytes per level, so unlike indented block nesting it is
// NOT bounded by the file-size cap. Only leading indicator runs are counted, so a dash inside a scalar
// value does not inflate the result. yaml.v3 recurses per level, so this is capped alongside maxFlowDepth.
func maxBlockChainDepth(data []byte) int {
	maxd, i, n := 0, 0, len(data)
	for i < n {
		for i < n && (data[i] == ' ' || data[i] == '\t') { // leading indentation
			i++
		}
		chain := 0
		for i+1 < n && (data[i] == '-' || data[i] == '?') && (data[i+1] == ' ' || data[i+1] == '\t') {
			chain++
			i += 2
			for i < n && (data[i] == ' ' || data[i] == '\t') {
				i++
			}
		}
		if chain > maxd {
			maxd = chain
			if maxd > maxNestDepth {
				return maxd // early out: already past the cap
			}
		}
		for i < n && data[i] != '\n' { // advance to the next line
			i++
		}
		if i < n {
			i++
		}
	}
	return maxd
}
