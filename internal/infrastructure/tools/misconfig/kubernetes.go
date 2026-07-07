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
// limit, so a deeply-nested untrusted document (e.g. millions of '[') can overflow the parser's stack —
// a FATAL error that recover() cannot catch. Real manifests nest < ~30 deep; 200 is generous headroom.
const maxNestDepth = 200

// maxLocatorDepth bounds the best-effort line locator's recursion (defense-in-depth; the pre-decode
// depth guard already keeps trees shallow).
const maxLocatorDepth = 1000

// k8sDoc is the slice of a Kubernetes object we inspect. A workload (Deployment, StatefulSet, ...) nests
// the pod under spec.template.spec; a bare Pod uses spec directly — podSpec() resolves both.
type k8sDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec k8sSpec `yaml:"spec"`
}

type k8sSpec struct {
	HostNetwork    bool           `yaml:"hostNetwork"`
	HostPID        bool           `yaml:"hostPID"`
	HostIPC        bool           `yaml:"hostIPC"`
	Containers     []k8sContainer `yaml:"containers"`
	InitContainers []k8sContainer `yaml:"initContainers"`
	Volumes        []k8sVolume    `yaml:"volumes"`
	Template       *struct {
		Spec k8sSpec `yaml:"spec"`
	} `yaml:"template"`
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
}

type ctnSecCtx struct {
	Privileged               *bool `yaml:"privileged"`
	RunAsNonRoot             *bool `yaml:"runAsNonRoot"`
	RunAsUser                *int  `yaml:"runAsUser"`
	AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
	Capabilities             *struct {
		Add []string `yaml:"add"`
	} `yaml:"capabilities"`
}

// podSpec resolves the effective pod spec: a workload's spec.template.spec, or the object's own spec.
func (s k8sSpec) podSpec() k8sSpec {
	if s.Template != nil {
		return s.Template.Spec
	}
	return s
}

// scanKubernetes decodes every YAML document in data and returns located misconfig findings. Best-effort:
// a document that decodes but does not fit our shape (or has no kind) is skipped and later documents are
// still scanned; a YAML *stream* syntax error halts parsing of the rest of THIS file (prior findings are
// kept), because yaml.v3 cannot reliably resume mid-stream. Either way the overall scan never fails.
func scanKubernetes(rel string, data []byte) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	// Refuse pathologically deep documents BEFORE decoding: yaml.v3 recurses per nesting level with no
	// depth cap, so a crafted deep document would overflow the goroutine stack (an unrecoverable fatal),
	// not merely return an error. This keeps a malformed file a per-file skip, per the port contract.
	if maxFlowDepth(data) > maxNestDepth {
		return nil
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
		out = append(out, checkK8sDoc(rel, doc, &node)...)
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
		sc := c.SecurityContext
		if sc == nil {
			continue
		}
		cres := res + " container=" + clip(c.Name)
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

// runsAsRoot reports an EXPLICIT root configuration only (runAsUser 0, or runAsNonRoot false) — an unset
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

// maxFlowDepth returns the deepest nesting of YAML flow collections ('[' and '{') in data, ignoring
// brackets inside quoted scalars and comments. It is a cheap linear pre-scan so a deep untrusted document
// is rejected before it reaches the recursive yaml.v3 parser. (Block-style nesting is naturally bounded
// by the file-size cap, since each level costs a line of indentation.)
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
