// Package dastsession executes approved, authenticated DAST request batches.
package dastsession

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastcrawl"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

const (
	ToolAuthenticatedDAST   = "run_authenticated_dast"
	ActionAuthenticatedDAST = "dast.authenticated_scan"
	evidenceKindSession     = "dast_authenticated_session"
)

// Service delegates all HTTP to the sandboxed helper and authorizes every request
// through the shared execution guard before the helper can issue it.
type Service struct {
	engine   ports.DASTEngine
	guard    *execution.Guard
	evidence *evidence.Service
}

func NewService(engine ports.DASTEngine, guard *execution.Guard, ev *evidence.Service) (*Service, error) {
	if engine == nil || guard == nil || ev == nil {
		return nil, fmt.Errorf("%w: DAST session service requires engine, guard, and evidence", shared.ErrValidation)
	}
	return &Service{engine: engine, guard: guard, evidence: ev}, nil
}

// Execute refuses, for the same reason Crawl does: without an approval-bound helper and configuration
// digest there is nothing tying this run to what a human approved, and dastengine.Engine rightly rejects
// such a plan. Refusing HERE names the missing binding instead of failing deep inside the engine with a
// message about a digest the caller was never asked to supply.
//
// Use ExecuteWithBinding, passing the helper and digest from the approval whose argv commits to them --
// exactly as dastworkflow/scan.go already does for CrawlWithRate.
func (s *Service) Execute(_ context.Context, _ safety.AdmittedAction, _ dastsession.Config, _ []dastsurface.Request) (ports.DASTOutcome, error) {
	return ports.DASTOutcome{}, fmt.Errorf("%w: DAST replay requires an approval-bound helper and configuration digest", shared.ErrValidation)
}

// ExecuteWithBinding replays an approved request set. It reauthorizes every actual helper request; the
// helper receives credentials only as vault placeholders in env. helperBin and configDigest come from
// the approval that authorized this exact configuration.
func (s *Service) ExecuteWithBinding(ctx context.Context, admitted safety.AdmittedAction, helperBin, configDigest string, config dastsession.Config, requests []dastsurface.Request) (ports.DASTOutcome, error) {
	return s.execute(ctx, admitted, helperBin, configDigest, config, requests, ports.DefaultDASTRatePerSec, ports.DefaultDASTConcurrency)
}

func (s *Service) execute(ctx context.Context, admitted safety.AdmittedAction, helperBin, configDigest string, config dastsession.Config, requests []dastsurface.Request, ratePerSec, concurrency int) (ports.DASTOutcome, error) {
	action := admitted.Action()
	if action.Tool != ToolAuthenticatedDAST || action.Action != ActionAuthenticatedDAST || action.Target.Kind != engagement.TargetURL {
		return ports.DASTOutcome{}, fmt.Errorf("%w: admitted action is not an authenticated DAST scan", shared.ErrValidation)
	}
	if admitted.DecidedBy() == "" || admitted.DecidedBy() == "auto" {
		return ports.DASTOutcome{}, fmt.Errorf("%w: authenticated DAST requires explicit human approval", shared.ErrForbidden)
	}
	if err := config.Validate(); err != nil {
		return ports.DASTOutcome{}, err
	}
	base, err := url.Parse(action.Target.Value)
	if err != nil || base.User != nil || base.Scheme == "" || base.Host == "" {
		return ports.DASTOutcome{}, fmt.Errorf("%w: DAST action target must be an absolute HTTP URL", shared.ErrValidation)
	}
	secretEnv := make([]string, 0, len(config.Credentials))
	for _, binding := range config.Credentials {
		secretEnv = append(secretEnv, secretEnvName(binding.Name)+"="+ports.SecretPlaceholder(binding.Reference))
	}
	egressPolicy, err := sessionEgressPolicy(ctx, base)
	if err != nil {
		return ports.DASTOutcome{}, err
	}
	outcome, runErr := s.engine.Run(ctx, ports.DASTPlan{
		HelperBin: helperBin, ConfigDigest: configDigest,
		Target: action.Target.Value, Session: config, Requests: requests,
		RatePerSec: ratePerSec, Concurrency: concurrency,
		EngagementID: action.EngagementID, EgressPolicy: egressPolicy,
		EgressExecutionKind: "dast-session", EgressExecutionID: action.SessionID.String(),
	}, secretEnv, func(ctx context.Context, request ports.DASTRequest) error {
		target, err := requestTarget(base, request.URL)
		if err != nil {
			return err
		}
		_, err = s.guard.Authorize(ctx, execution.Request{
			Actor: admitted.DecidedBy(), EngagementID: action.EngagementID, Action: ActionAuthenticatedDAST,
			Target: target, Metadata: map[string]string{"method": strings.ToUpper(request.Method), "session": action.SessionID.String()},
		})
		return err
	})
	payload, err := json.Marshal(outcome)
	if err != nil {
		return ports.DASTOutcome{}, fmt.Errorf("marshal DAST evidence: %w", err)
	}
	if _, err := s.evidence.Seal(ctx, action.EngagementID, evidenceKindSession, payload, admitted.DecidedBy()); err != nil {
		return ports.DASTOutcome{}, fmt.Errorf("seal DAST evidence: %w", err)
	}
	if runErr != nil {
		return outcome, fmt.Errorf("run authenticated DAST: %w", runErr)
	}
	return outcome, nil
}

func sessionEgressPolicy(ctx context.Context, base *url.URL) (*ports.EgressPolicy, error) {
	port := 80
	if base.Scheme == "https" {
		port = 443
	}
	if base.Port() != "" {
		parsed, err := strconv.Atoi(base.Port())
		if err != nil || parsed < 1 || parsed > 65535 {
			return nil, fmt.Errorf("%w: invalid DAST target port", shared.ErrValidation)
		}
		port = parsed
	}
	var addrs []netip.Addr
	if ip := net.ParseIP(base.Hostname()); ip != nil {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("%w: invalid DAST target address", shared.ErrValidation)
		}
		addrs = []netip.Addr{addr.Unmap()}
	} else {
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", base.Hostname())
		if err != nil || len(resolved) == 0 {
			return nil, fmt.Errorf("%w: DAST target could not be resolved safely", shared.ErrValidation)
		}
		addrs = resolved
	}
	policy := &ports.EgressPolicy{Rules: make([]ports.EgressRule, 0, len(addrs)), PinnedHosts: map[string][]netip.Addr{base.Hostname(): {}}}
	seen := map[netip.Addr]bool{}
	for _, addr := range addrs {
		addr = addr.Unmap()
		if forbiddenAddress(addr) {
			return nil, fmt.Errorf("%w: DAST target resolves to a forbidden address", shared.ErrValidation)
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		policy.Rules = append(policy.Rules, ports.EgressRule{Allow: true, Net: netip.PrefixFrom(addr, addr.BitLen()), Ports: []uint16{uint16(port)}})
		policy.PinnedHosts[base.Hostname()] = append(policy.PinnedHosts[base.Hostname()], addr)
	}
	return policy, nil
}

func forbiddenAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	return !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast()
}

func requestTarget(base *url.URL, raw string) (engagement.Target, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || !strings.EqualFold(base.Scheme, u.Scheme) || !strings.EqualFold(base.Host, u.Host) {
		return engagement.Target{}, fmt.Errorf("%w: DAST request leaves admitted target origin", shared.ErrForbidden)
	}
	return engagement.Target{Kind: engagement.TargetURL, Value: u.String()}, nil
}

func secretEnvName(name string) string {
	return "SYNAPSE_DAST_SECRET_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name))
}

// Crawl submits each discovered GET/HEAD request through Execute, retaining its
// per-request authorization and sandbox helper boundary.
func (s *Service) Crawl(ctx context.Context, admitted safety.AdmittedAction, config dastsession.Config, input dastcrawl.Input, limits dastcrawl.Limits) (dastcrawl.Result, error) {
	return dastcrawl.Result{}, fmt.Errorf("%w: DAST crawl requires an approval-bound helper and configuration digest", shared.ErrValidation)
}

func (s *Service) CrawlWithRate(ctx context.Context, admitted safety.AdmittedAction, helperBin, configDigest string, config dastsession.Config, input dastcrawl.Input, limits dastcrawl.Limits, ratePerSec, concurrency int) (dastcrawl.Result, error) {
	action := admitted.Action()
	if action.Tool != ToolAuthenticatedDAST || action.Action != ActionAuthenticatedDAST || action.Target.Kind != engagement.TargetURL {
		return dastcrawl.Result{}, fmt.Errorf("%w: admitted action is not an authenticated DAST scan", shared.ErrValidation)
	}
	if admitted.DecidedBy() == "" || admitted.DecidedBy() == "auto" {
		return dastcrawl.Result{}, fmt.Errorf("%w: authenticated DAST requires explicit human approval", shared.ErrForbidden)
	}
	if err := config.Validate(); err != nil {
		return dastcrawl.Result{}, err
	}
	base, err := url.Parse(action.Target.Value)
	if err != nil || base.User != nil || base.Scheme == "" || base.Host == "" {
		return dastcrawl.Result{}, fmt.Errorf("%w: DAST action target must be an absolute HTTP URL", shared.ErrValidation)
	}
	secretEnv := make([]string, 0, len(config.Credentials))
	for _, binding := range config.Credentials {
		secretEnv = append(secretEnv, secretEnvName(binding.Name)+"="+ports.SecretPlaceholder(binding.Reference))
	}
	egressPolicy, err := sessionEgressPolicy(ctx, base)
	if err != nil {
		return dastcrawl.Result{}, err
	}
	outcome, runErr := s.engine.Run(ctx, ports.DASTPlan{
		HelperBin: helperBin, ConfigDigest: configDigest,
		Target: action.Target.Value, Session: config,
		Crawl: &ports.DASTCrawlPlan{
			Target: input.Target, Seeds: input.Seeds, Robots: input.Robots, Sitemaps: input.Sitemaps,
			OpenAPI: input.OpenAPI, GraphQL: input.GraphQL, Depth: limits.Depth, Pages: limits.Pages,
			Requests: limits.Requests, WallClock: limits.WallClock,
		},
		RatePerSec: ratePerSec, Concurrency: concurrency,
		EngagementID: action.EngagementID, EgressPolicy: egressPolicy,
		EgressExecutionKind: "dast-session", EgressExecutionID: action.SessionID.String(),
	}, secretEnv, func(ctx context.Context, request ports.DASTRequest) error {
		target, err := requestTarget(base, request.URL)
		if err != nil {
			return err
		}
		_, err = s.guard.Authorize(ctx, execution.Request{
			Actor: admitted.DecidedBy(), EngagementID: action.EngagementID, Action: ActionAuthenticatedDAST,
			Target: target, Metadata: map[string]string{"method": strings.ToUpper(request.Method), "session": action.SessionID.String()},
		})
		return err
	})
	payload, err := json.Marshal(outcome)
	if err != nil {
		return dastcrawl.Result{}, fmt.Errorf("marshal DAST evidence: %w", err)
	}
	if _, err := s.evidence.Seal(ctx, action.EngagementID, evidenceKindSession, payload, admitted.DecidedBy()); err != nil {
		return dastcrawl.Result{}, fmt.Errorf("seal DAST evidence: %w", err)
	}
	if runErr != nil {
		return dastcrawl.Result{}, fmt.Errorf("run authenticated DAST crawl: %w", runErr)
	}
	return dastcrawl.Result{Surface: outcome.Surface, Coverage: outcome.Coverage, Observations: outcome.Observations, Incomplete: outcome.Incomplete, Reason: outcome.Reason}, nil
}
