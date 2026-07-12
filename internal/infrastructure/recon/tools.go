// Package recon provides ports.ReconTool adapters: each knows one recon binary's
// argv and output format. Arguments are built ONLY from a validated, in-scope
// target – never from free-form strings – and every target value is checked so
// it cannot be smuggled in as a flag. Output is parsed from the tools' JSON-lines
// format into canonical domain recon.Results.
package recon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

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
		host, err := engagement.NormalizeDomain(r.Host)
		if err != nil {
			return recon.Result{}, false
		}
		return recon.Result{Kind: recon.ResultSubdomain, Value: host}, true
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
	value, err := safeHTTPXTarget(t)
	if err != nil {
		return ports.ToolSpec{}, err
	}
	return ports.ToolSpec{Name: "httpx", Args: []string{"-silent", "-json", "-u", value}}, nil
}

func (HTTPX) Parse(stdout []byte) ([]recon.Result, error) {
	type rec struct {
		URL    string `json:"url"`
		Status int    `json:"status_code"`
		Title  string `json:"title"`
	}
	return parseJSONLines(stdout, func(r rec) (recon.Result, bool) {
		identity, err := engagement.NormalizeURL(r.URL)
		if err != nil {
			return recon.Result{}, false
		}
		detail := strconv.Itoa(r.Status)
		if r.Title != "" {
			detail += " · " + r.Title
		}
		return recon.Result{Kind: recon.ResultURL, Value: identity.URL, Detail: detail}, true
	})
}

// ---- naabu: port scan (capability-sensitive – no raw sockets) ----

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
	// hook logs. Scope integrity > scan stealth for an authorized-pentest platform.
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
		if hostpart == "" || r.Port <= 0 || r.Port > 65535 {
			return recon.Result{}, false
		}
		_, _, endpoint, err := engagement.NormalizeEndpoint(net.JoinHostPort(hostpart, strconv.Itoa(r.Port)))
		if err != nil {
			return recon.Result{}, false
		}
		ip, err := engagement.NormalizeHost(r.IP)
		if err != nil {
			ip = ""
		}
		return recon.Result{Kind: recon.ResultPort, Value: endpoint, Detail: ip}, true
	})
}

// ---- shared helpers ----

// safeHost canonicalizes a non-URL target into a single argv token and keeps the
// adapter-level defense-in-depth guard against option injection.
func safeHost(t engagement.Target) (string, error) {
	if err := engagement.ValidateTargetValue(t.Value); err != nil {
		return "", err
	}
	if t.Kind == engagement.TargetURL {
		return "", fmt.Errorf("%w: URL target requires HTTPX URL handling", shared.ErrValidation)
	}
	normalized, err := engagement.NormalizeTarget(t, false)
	if err != nil {
		return "", err
	}
	return normalized.Value, nil
}

// safeHTTPXTarget preserves the canonical URL, including its path, scheme, and
// port, when an operator selected a URL scope. Bare domain/IP targets remain
// host-based HTTPX inputs.
func safeHTTPXTarget(t engagement.Target) (string, error) {
	if err := engagement.ValidateTargetValue(t.Value); err != nil {
		return "", err
	}
	normalized, err := engagement.NormalizeTarget(t, false)
	if err != nil {
		return "", err
	}
	return normalized.Value, nil
}

// parseJSONLines decodes one JSON object per line (the ProjectDiscovery -json
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
			continue // diagnostics/schema drift are TODO item 5
		}
		if r, ok := fn(rec); ok {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}
