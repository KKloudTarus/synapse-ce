package egressbroker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const protocolVersion = 2

var (
	ErrUnavailable = errors.New("egress broker unavailable")
	runIDPattern   = regexp.MustCompile(`^syn[0-9]{1,2}$`)
)

type CanonicalRule = ports.CanonicalEgressRule

type request struct {
	Version       int             `json:"version"`
	Action        string          `json:"action"`
	RunID         string          `json:"run_id"`
	Slot          int             `json:"slot,omitempty"`
	PID           int             `json:"pid,omitempty"`
	TenantID      string          `json:"tenant_id,omitempty"`
	ExecutionKind string          `json:"execution_kind,omitempty"`
	ExecutionID   string          `json:"execution_id,omitempty"`
	Grant         string          `json:"grant,omitempty"`
	Rules         []CanonicalRule `json:"rules,omitempty"`
}

type response struct {
	Version int             `json:"version"`
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	Rules   []CanonicalRule `json:"rules,omitempty"`
}

func encodeRequest(w io.Writer, req request) error {
	return json.NewEncoder(w).Encode(req)
}

func decodeRequest(r io.Reader) (request, error) {
	decoder := json.NewDecoder(io.LimitReader(r, 64<<10))
	decoder.DisallowUnknownFields()
	var req request
	if err := decoder.Decode(&req); err != nil {
		return request{}, fmt.Errorf("decode broker request: %w", err)
	}
	if err := validateRequest(req); err != nil {
		return request{}, err
	}
	return req, nil
}

func encodeResponse(w io.Writer, res response) error {
	return json.NewEncoder(w).Encode(res)
}

func decodeResponse(r io.Reader) (response, error) {
	decoder := json.NewDecoder(io.LimitReader(r, 64<<10))
	decoder.DisallowUnknownFields()
	var res response
	if err := decoder.Decode(&res); err != nil {
		return response{}, fmt.Errorf("decode broker response: %w", err)
	}
	if res.Version != protocolVersion {
		return response{}, fmt.Errorf("unexpected broker protocol version %d", res.Version)
	}
	if !res.OK {
		if strings.TrimSpace(res.Error) == "" {
			return response{}, errors.New("egress broker rejected the request")
		}
		return response{}, errors.New(res.Error)
	}
	return res, nil
}

func validateRequest(req request) error {
	if req.Version != protocolVersion {
		return fmt.Errorf("unexpected broker protocol version %d", req.Version)
	}
	if !runIDPattern.MatchString(req.RunID) {
		return fmt.Errorf("invalid run id %q", req.RunID)
	}
	switch req.Action {
	case "probe", "cleanup":
		if req.Slot != 0 || req.PID != 0 || req.TenantID != "" || req.ExecutionKind != "" || req.ExecutionID != "" || req.Grant != "" || len(req.Rules) != 0 {
			return fmt.Errorf("%s request contains setup fields", req.Action)
		}
	case "setup":
		if req.Slot < 0 || req.Slot >= 64 {
			return fmt.Errorf("invalid slot %d", req.Slot)
		}
		if req.PID <= 1 {
			return fmt.Errorf("invalid sandbox pid %d", req.PID)
		}
		if strings.TrimSpace(req.TenantID) == "" || len(req.TenantID) > 200 {
			return errors.New("setup request requires a tenant id")
		}
		if strings.TrimSpace(req.ExecutionKind) == "" || len(req.ExecutionKind) > 64 {
			return errors.New("setup request requires an execution kind")
		}
		if strings.TrimSpace(req.ExecutionID) == "" || len(req.ExecutionID) > 200 {
			return errors.New("setup request requires an execution id")
		}
		if strings.TrimSpace(req.Grant) == "" || len(req.Grant) > 16*1024 {
			return errors.New("setup request requires a bounded authorization grant")
		}
		if len(req.Rules) > 256 {
			return fmt.Errorf("too many egress rules")
		}
		for _, rule := range req.Rules {
			if _, err := parseWireRule(rule); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported broker action %q", req.Action)
	}
	return nil
}

func canonicalPolicy(policy ports.EgressPolicy) ([]CanonicalRule, error) {
	if len(policy.AllowDomains) != 0 || len(policy.DenyDomains) != 0 || len(policy.AllowDomainRules) != 0 || len(policy.DenyDomainRules) != 0 {
		return nil, errors.New("egress broker accepts only pre-resolved CIDR/port rules")
	}
	rules := make([]CanonicalRule, 0, len(policy.Rules)+len(policy.PinnedHosts))
	for _, rule := range policy.Rules {
		wire, err := canonicalRule(rule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, wire)
	}
	for _, addrs := range policy.PinnedHosts {
		for _, addr := range addrs {
			addr = addr.Unmap()
			wire, err := canonicalRule(ports.EgressRule{
				Allow: true,
				Net:   netip.PrefixFrom(addr, addr.BitLen()),
			})
			if err != nil {
				return nil, err
			}
			rules = append(rules, wire)
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Allow != rules[j].Allow {
			return !rules[i].Allow
		}
		if rules[i].CIDR != rules[j].CIDR {
			return rules[i].CIDR < rules[j].CIDR
		}
		return fmt.Sprint(rules[i].Ports) < fmt.Sprint(rules[j].Ports)
	})
	for i := 1; i < len(rules); i++ {
		if rules[i].Allow == rules[i-1].Allow && rules[i].CIDR == rules[i-1].CIDR && fmt.Sprint(rules[i].Ports) == fmt.Sprint(rules[i-1].Ports) {
			return nil, errors.New("duplicate egress rule")
		}
	}
	return rules, nil
}

func canonicalRule(rule ports.EgressRule) (CanonicalRule, error) {
	if !rule.Net.IsValid() || !rule.Net.Addr().Is4() {
		return CanonicalRule{}, errors.New("egress broker accepts only valid IPv4 prefixes")
	}
	prefix := rule.Net.Masked()
	ports := append([]uint16(nil), rule.Ports...)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	for i, port := range ports {
		if port == 0 {
			return CanonicalRule{}, errors.New("egress rule port must be between 1 and 65535")
		}
		if i > 0 && port == ports[i-1] {
			return CanonicalRule{}, errors.New("egress rule ports must be unique")
		}
	}
	return CanonicalRule{Allow: rule.Allow, CIDR: prefix.String(), Ports: ports}, nil
}

func parseWireRule(rule CanonicalRule) (ports.EgressRule, error) {
	prefix, err := netip.ParsePrefix(rule.CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
		return ports.EgressRule{}, fmt.Errorf("non-canonical IPv4 CIDR %q", rule.CIDR)
	}
	canonical, err := canonicalRule(ports.EgressRule{Allow: rule.Allow, Net: prefix, Ports: rule.Ports})
	if err != nil {
		return ports.EgressRule{}, err
	}
	if canonical.CIDR != rule.CIDR || fmt.Sprint(canonical.Ports) != fmt.Sprint(rule.Ports) {
		return ports.EgressRule{}, errors.New("egress rule is not canonical")
	}
	return ports.EgressRule{Allow: rule.Allow, Net: prefix, Ports: append([]uint16(nil), rule.Ports...)}, nil
}

func parseRules(rules []CanonicalRule) ([]ports.EgressRule, error) {
	out := make([]ports.EgressRule, 0, len(rules))
	for _, rule := range rules {
		parsed, err := parseWireRule(rule)
		if err != nil {
			return nil, err
		}
		out = append(out, parsed)
	}
	return out, nil
}

func CanonicalRulesEqual(left, right []CanonicalRule) bool {
	return ports.CanonicalEgressRulesEqual(left, right)
}
