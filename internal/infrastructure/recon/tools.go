// Package recon provides ports.ReconTool adapters: each knows one recon binary's
// argv and output format. Arguments are built ONLY from a validated, in-scope
// target – never from free-form strings – and every
// target value is checked so it cannot be smuggled in as a flag. Output is parsed
// from the tools' JSON-lines format into domain recon.Results.
//
// Tools are registered with the recon use case; capability-sensitive ones
// (naabu/nuclei – raw sockets) are flagged so the use case keeps them behind the
// lab-only / sandbox gate.
package recon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Compile-time assertions that each adapter satisfies the port (value receivers).
var (
	_ ports.ReconTool = Subfinder{}
	_ ports.ReconTool = HTTPX{}
	_ ports.ReconTool = Naabu{}
)

// Registry returns the built-in recon tools, keyed by name.
func Registry() map[string]ports.ReconTool {
	tools := []ports.ReconTool{Subfinder{}, HTTPX{}, Naabu{}}
	out := make(map[string]ports.ReconTool, len(tools))
	for _, t := range tools {
		out[t.Name()] = t
	}
	return out
}

// ---- subfinder: passive subdomain enumeration (pure-Go, no special caps) ----

type Subfinder struct{}

func (Subfinder) Name() string                         { return "subfinder" }
func (Subfinder) Binary() string                       { return "subfinder" }
func (Subfinder) Action() string                       { return "recon.subfinder" }
func (Subfinder) CapabilitySensitive() bool            { return false }
func (Subfinder) Accepts(k engagement.TargetKind) bool { return k == engagement.TargetDomain }

func (Subfinder) BuildArgs(t engagement.Target) (ports.ToolSpec, error) {
	host, err := safeHost(t)
	if err != nil {
		return ports.ToolSpec{}, err
	}
	return ports.ToolSpec{Name: "subfinder", Args: []string{"-silent", "-json", "-d", host}}, nil
}

func (Subfinder) Parse(stdout []byte) ([]recon.Result, error) {
	type rec struct {
		Host string `json:"host"`
	}
	return parseJSONLines(stdout, func(r rec) (recon.Result, bool) {
		if r.Host == "" {
			return recon.Result{}, false
		}
		return recon.Result{Kind: recon.ResultSubdomain, Value: strings.ToLower(r.Host)}, true
	})
}

// ---- httpx: HTTP(S) probe (pure-Go, no special caps) ----

type HTTPX struct{}

func (HTTPX) Name() string              { return "httpx" }
func (HTTPX) Binary() string            { return "httpx" }
func (HTTPX) Action() string            { return "recon.httpx" }
func (HTTPX) CapabilitySensitive() bool { return false }
func (HTTPX) Accepts(k engagement.TargetKind) bool {
	switch k {
	case engagement.TargetDomain, engagement.TargetURL, engagement.TargetIP:
		return true
	default:
		return false
	}
}

func (HTTPX) BuildArgs(t engagement.Target) (ports.ToolSpec, error) {
	host, err := safeHost(t)
	if err != nil {
		return ports.ToolSpec{}, err
	}
	return ports.ToolSpec{Name: "httpx", Args: []string{"-silent", "-json", "-u", host}}, nil
}

func (HTTPX) Parse(stdout []byte) ([]recon.Result, error) {
	type rec struct {
		URL    string `json:"url"`
		Status int    `json:"status_code"`
		Title  string `json:"title"`
	}
	return parseJSONLines(stdout, func(r rec) (recon.Result, bool) {
		if r.URL == "" {
			return recon.Result{}, false
		}
		detail := strconv.Itoa(r.Status)
		if r.Title != "" {
			detail += " · " + r.Title
		}
		return recon.Result{Kind: recon.ResultURL, Value: r.URL, Detail: detail}, true
	})
}

// ---- naabu: port scan (capability-sensitive – wants CAP_NET_RAW; lab-only) ----

type Naabu struct{}

func (Naabu) Name() string              { return "naabu" }
func (Naabu) Binary() string            { return "naabu" }
func (Naabu) Action() string            { return "recon.naabu" }
func (Naabu) CapabilitySensitive() bool { return true }
func (Naabu) Accepts(k engagement.TargetKind) bool {
	switch k {
	case engagement.TargetDomain, engagement.TargetIP, engagement.TargetCIDR:
		return true
	default:
		return false
	}
}

func (Naabu) BuildArgs(t engagement.Target) (ports.ToolSpec, error) {
	host, err := safeHost(t)
	if err != nil {
		return ports.ToolSpec{}, err
	}
	// CONNECT scan (`-s c`), NOT a SYN scan (F6, audit fix). A SYN scan needs CAP_NET_RAW,
	// which also authorizes AF_PACKET link-layer sockets whose frames bypass the netns
	// iptables egress filter AND the connect() eBPF log – a scope-bypass + a forensic
	// blind spot for a *compromised* tool binary. So Synapse grants NO capability: a connect
	// scan uses ordinary TCP sockets, which the egress filter constrains and the connect4/6
	// hook logs. Scope integrity > scan stealth for an authorized-pentest platform. (The
	// runner's allowlist still permits ONLY CAP_NET_RAW should a future contained raw-socket
	// design need it; today nothing requests it.)
	return ports.ToolSpec{Name: "naabu", Args: []string{"-silent", "-json", "-s", "c", "-host", host}}, nil
}

func (Naabu) Parse(stdout []byte) ([]recon.Result, error) {
	type rec struct {
		Host string `json:"host"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}
	return parseJSONLines(stdout, func(r rec) (recon.Result, bool) {
		hostpart := r.Host
		if hostpart == "" {
			hostpart = r.IP
		}
		if hostpart == "" || r.Port == 0 {
			return recon.Result{}, false
		}
		return recon.Result{Kind: recon.ResultPort, Value: hostpart + ":" + strconv.Itoa(r.Port), Detail: r.IP}, true
	})
}

// ---- shared helpers ----

// safeHost extracts a clean, single-token host/value from an in-scope target and
// guarantees it cannot be interpreted as a CLI flag. Even though everything is
// passed as an argv array (no shell), a value beginning with "-" could be parsed by
// the tool as an option – so we reject it (defense against flag injection via a
// crafted scope entry).
func safeHost(t engagement.Target) (string, error) {
	v := strings.TrimSpace(t.Value)
	// reduce a URL scope entry to its host
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
		if j := strings.IndexAny(v, "/?#"); j >= 0 {
			v = v[:j]
		}
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("%w: empty recon target", shared.ErrValidation)
	}
	if strings.HasPrefix(v, "-") {
		return "", fmt.Errorf("%w: recon target may not start with '-' (flag injection)", shared.ErrValidation)
	}
	if strings.ContainsAny(v, " \t\n\r") {
		return "", fmt.Errorf("%w: recon target may not contain whitespace", shared.ErrValidation)
	}
	return v, nil
}

// parseJSONLines decodes one JSON object per line (the projectdiscovery -json
// format), skipping blank/non-JSON noise lines, and maps each record to a Result.
func parseJSONLines[T any](stdout []byte, fn func(T) (recon.Result, bool)) ([]recon.Result, error) {
	var out []recon.Result
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var rec T
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // tolerate noise/banner lines
		}
		if r, ok := fn(rec); ok {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}
