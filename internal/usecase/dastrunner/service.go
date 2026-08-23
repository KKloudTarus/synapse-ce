// Package dastrunner executes narrowly-scoped, approved runtime verification probes.
//
// This is not an autonomous exploit engine. The service only accepts a safety.AdmittedAction,
// which can be produced by safety.Gate after scope/window/RoE and HITL approval. It then runs a
// bounded, argv-only, safe HTTP probe, seals a compact result summary, and hands the typed proof
// class to dastverifier.Service / analysis.Verify for custody and score movement.
package dastrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastverifier"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

const (
	ToolRunDASTVerifier = "run_dast_verifier"
	ActionSafeHTTPProbe = "dast.safe_http_probe"
	evidenceKindResult  = "dast_verifier_result"
)

type resultApplier interface {
	Apply(ctx context.Context, engagementID shared.ID, r dastverifier.Result) (judgment.Judgment, error)
}

type Service struct {
	runner   ports.ToolRunner
	evidence *evidence.Service
	applier  resultApplier
	curlBin  string
	timeout  time.Duration
	maxOut   int
	resolve  func(context.Context, string) ([]netip.Addr, error)
}

func NewService(runner ports.ToolRunner, ev *evidence.Service, applier resultApplier, curlBin string, timeout time.Duration, maxOut int) (*Service, error) {
	if runner == nil || ev == nil || applier == nil {
		return nil, fmt.Errorf("%w: dast runner requires runner, evidence, and verifier applier", shared.ErrValidation)
	}
	if strings.TrimSpace(curlBin) == "" {
		curlBin = "curl"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if maxOut <= 0 {
		maxOut = 128 << 10
	}
	return &Service{
		runner: runner, evidence: ev, applier: applier, curlBin: curlBin, timeout: timeout, maxOut: maxOut,
		resolve: defaultResolve,
	}, nil
}

type Probe struct {
	JudgmentID           shared.ID
	URL                  string
	Method               string
	ExpectedStatus       int
	ExpectedBodyContains string
	ScoreIfConfirmed     int
	ScoreIfRefuted       int
	ExpectedVersion      int
	Rationale            string
}

type Result struct {
	Judgment judgment.Judgment
	Proof    dastverifier.ProofClass
	Status   int
	Evidence shared.ID
}

type sealedResult struct {
	JudgmentID        string `json:"judgment_id"`
	URLHost           string `json:"url_host"`
	URLPath           string `json:"url_path"`
	Method            string `json:"method"`
	ExpectedStatus    int    `json:"expected_status,omitempty"`
	Status            int    `json:"status,omitempty"`
	BodySHA256        string `json:"body_sha256,omitempty"`
	BodyTruncated     bool   `json:"body_truncated,omitempty"`
	BodyExcerpt       string `json:"body_excerpt,omitempty"`
	BodyMarkerMatched bool   `json:"body_marker_matched"`
	ProofClass        string `json:"proof_class"`
	RunnerExitCode    int    `json:"runner_exit_code"`
	RunnerTimedOut    bool   `json:"runner_timed_out"`
	RunnerTruncated   bool   `json:"runner_truncated"`
	ConnectAttempts   int    `json:"connect_attempts,omitempty"`
}

func (s *Service) Execute(ctx context.Context, admitted safety.AdmittedAction, probe Probe) (Result, error) {
	action := admitted.Action()
	if action.Tool != ToolRunDASTVerifier || action.Action != ActionSafeHTTPProbe {
		return Result{}, fmt.Errorf("%w: admitted action is not a safe DAST verifier probe", shared.ErrValidation)
	}
	if action.Target.Kind != engagement.TargetURL {
		return Result{}, fmt.Errorf("%w: DAST verifier target must be a URL", shared.ErrValidation)
	}
	if admitted.DecidedBy() == "" || admitted.DecidedBy() == "auto" {
		return Result{}, fmt.Errorf("%w: runtime exploitability verification requires explicit human approval", shared.ErrForbidden)
	}
	method := strings.ToUpper(strings.TrimSpace(probe.Method))
	if method == "" {
		method = "GET"
	}
	if method != "GET" && method != "HEAD" {
		return Result{}, fmt.Errorf("%w: safe HTTP probe supports only GET or HEAD", shared.ErrValidation)
	}
	if probe.JudgmentID == "" {
		return Result{}, fmt.Errorf("%w: judgment id is required", shared.ErrValidation)
	}
	u, err := parseProbeURL(probe.URL)
	if err != nil {
		return Result{}, err
	}
	pinnedIP, err := s.resolvePublicHost(ctx, u.Hostname())
	if err != nil {
		return Result{}, err
	}
	if probe.URL != action.Target.Value {
		return Result{}, fmt.Errorf("%w: probe URL must match the admitted action target", shared.ErrValidation)
	}

	spec := ports.ToolSpec{
		Name:                s.curlBin,
		Args:                curlArgs(method, probe.URL, u, pinnedIP, s.timeout),
		Timeout:             s.timeout,
		MaxOutputBytes:      s.maxOut,
		EngagementID:        action.EngagementID,
		EgressPolicy:        egressPolicyForPinnedIP(pinnedIP, u),
		EgressExecutionKind: "dast-verifier",
		EgressExecutionID:   probe.JudgmentID.String(),
	}
	res, runErr := s.runner.Run(ctx, spec)
	status, body := splitCurlStatus(res.Stdout)
	markerMatched := probe.ExpectedBodyContains == "" || bytes.Contains(body, []byte(probe.ExpectedBodyContains))
	proof := classify(runErr, status, markerMatched, probe.ExpectedStatus)
	if res.Truncated {
		proof = dastverifier.ProofClassNeedsMoreProof
	}
	bodyHash := sha256.Sum256(body)
	sealed, err := json.Marshal(sealedResult{
		JudgmentID:        probe.JudgmentID.String(),
		URLHost:           u.Host,
		URLPath:           redact.String(u.EscapedPath(), nil),
		Method:            method,
		ExpectedStatus:    probe.ExpectedStatus,
		Status:            status,
		BodySHA256:        hex.EncodeToString(bodyHash[:]),
		BodyTruncated:     res.Truncated,
		BodyExcerpt:       redactProbeExcerpt(body),
		BodyMarkerMatched: markerMatched,
		ProofClass:        string(proof),
		RunnerExitCode:    res.ExitCode,
		RunnerTimedOut:    res.TimedOut,
		RunnerTruncated:   res.Truncated,
		ConnectAttempts:   len(res.ConnectLog),
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal DAST verifier evidence: %w", err)
	}
	ev, err := s.evidence.Seal(ctx, action.EngagementID, evidenceKindResult, sealed, admitted.DecidedBy())
	if err != nil {
		return Result{}, fmt.Errorf("seal DAST verifier evidence: %w", err)
	}
	if runErr != nil {
		return Result{Proof: proof, Status: status, Evidence: ev.ID}, fmt.Errorf("safe HTTP probe failed: %w", runErr)
	}
	score := probe.ScoreIfRefuted
	if proof == dastverifier.ProofClassRuntimeConfirmed {
		score = probe.ScoreIfConfirmed
	}
	rationale := strings.TrimSpace(probe.Rationale)
	if rationale == "" {
		rationale = "safe HTTP verifier probe completed"
	}
	rationale = fmt.Sprintf("%s; evidence_id=%s; status=%d", rationale, ev.ID, status)
	j, err := s.applier.Apply(ctx, action.EngagementID, dastverifier.Result{
		JudgmentID:      probe.JudgmentID,
		Verifier:        admitted.DecidedBy(),
		Score:           score,
		ProofClass:      proof,
		Rationale:       rationale,
		ExpectedVersion: probe.ExpectedVersion,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Judgment: j, Proof: proof, Status: status, Evidence: ev.ID}, nil
}

func parseProbeURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" {
		return nil, fmt.Errorf("%w: invalid probe URL", shared.ErrValidation)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: probe URL must be http or https", shared.ErrValidation)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: probe URL must not include credentials", shared.ErrValidation)
	}
	return u, nil
}

func (s *Service) resolvePublicHost(ctx context.Context, host string) (netip.Addr, error) {
	ips, err := s.resolve(ctx, host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: probe host could not be resolved safely", shared.ErrValidation)
	}
	var chosen netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if isForbiddenProbeIP(ip) {
			return netip.Addr{}, fmt.Errorf("%w: probe host resolves to a forbidden internal address", shared.ErrValidation)
		}
		if !chosen.IsValid() {
			chosen = ip
		}
	}
	if !chosen.IsValid() {
		return netip.Addr{}, fmt.Errorf("%w: probe host did not resolve to a usable address", shared.ErrValidation)
	}
	return chosen, nil
}

func defaultResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			out = append(out, ip)
		}
	}
	return out, nil
}

func isForbiddenProbeIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return !ip.IsValid() ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast()
}

func egressPolicyForPinnedIP(ip netip.Addr, u *url.URL) *ports.EgressPolicy {
	bits := 32
	if ip.Is6() {
		bits = 128
	}
	return &ports.EgressPolicy{Rules: []ports.EgressRule{{
		Allow: true,
		Net:   netip.PrefixFrom(ip, bits),
		Ports: []uint16{uint16(probePort(u))},
	}}}
}

func probePort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
			return n
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func curlArgs(method, target string, u *url.URL, pinnedIP netip.Addr, timeout time.Duration) []string {
	maxTime := int(timeout.Seconds())
	if maxTime <= 0 {
		maxTime = 1
	}
	ip := pinnedIP.String()
	if pinnedIP.Is6() {
		ip = "[" + ip + "]"
	}
	resolve := fmt.Sprintf("%s:%d:%s", u.Hostname(), probePort(u), ip)
	args := []string{"-sS", "--path-as-is", "--max-time", strconv.Itoa(maxTime), "--resolve", resolve, "-X", method, "-w", "\nSYNAPSE_HTTP_STATUS:%{http_code}\n"}
	if method == "HEAD" {
		args = append(args, "-I")
	}
	return append(args, target)
}

func splitCurlStatus(stdout []byte) (int, []byte) {
	marker := []byte("\nSYNAPSE_HTTP_STATUS:")
	idx := bytes.LastIndex(stdout, marker)
	if idx < 0 {
		return 0, stdout
	}
	codeLine := strings.TrimSpace(string(stdout[idx+len(marker):]))
	if nl := strings.IndexByte(codeLine, '\n'); nl >= 0 {
		codeLine = codeLine[:nl]
	}
	code, _ := strconv.Atoi(codeLine)
	return code, stdout[:idx]
}

func classify(runErr error, status int, markerMatched bool, expectedStatus int) dastverifier.ProofClass {
	if runErr != nil || status == 0 {
		return dastverifier.ProofClassNeedsMoreProof
	}
	statusOK := expectedStatus == 0 || status == expectedStatus
	if statusOK && markerMatched {
		return dastverifier.ProofClassRuntimeConfirmed
	}
	return dastverifier.ProofClassRuntimeRefuted
}

func redactProbeExcerpt(body []byte) string {
	const max = 1024
	if len(body) > max {
		body = body[:max]
	}
	text := redact.String(string(body), nil)
	for _, key := range []string{"token", "session", "api_key", "key", "secret", "password", "auth", "signature", "cookie"} {
		text = regexp.MustCompile("(?i)"+key+"[[:space:]]*[:=][[:space:]]*[^[:space:]&<,;]+").ReplaceAllString(text, key+"=[REDACTED]")
	}
	return text
}
