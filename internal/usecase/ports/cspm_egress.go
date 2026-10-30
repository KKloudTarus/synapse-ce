package ports

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CSPMExecutionID uniquely identifies one scope of a durable run.
func CSPMExecutionID(runID shared.ID, index int) string {
	return "cspm/v1/" + runID.String() + "/" + strconv.Itoa(index)
}

// ParseCSPMExecutionID rejects alternative encodings and ambiguous scope identities.
func ParseCSPMExecutionID(id string) (shared.ID, int, error) {
	parts := strings.Split(id, "/")
	if len(parts) != 4 || parts[0] != "cspm" || parts[1] != "v1" || parts[2] == "" || strings.TrimSpace(parts[2]) != parts[2] {
		return "", 0, fmt.Errorf("%w: invalid CSPM execution identity", shared.ErrValidation)
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil || n < 0 || strconv.Itoa(n) != parts[3] {
		return "", 0, fmt.Errorf("%w: invalid CSPM scope index", shared.ErrValidation)
	}
	return shared.ID(parts[2]), n, nil
}

// CSPMEgressPolicy builds a provider-specific, default-deny HTTPS policy.
func CSPMEgressPolicy(provider cloudposture.Provider, hosts []string) (EgressPolicy, error) {
	if !provider.Valid() || len(hosts) == 0 {
		return EgressPolicy{}, fmt.Errorf("%w: CSPM provider hosts required", shared.ErrValidation)
	}
	p := EgressPolicy{}
	for _, host := range hosts {
		if len(host) > 253 || host == "" || host != strings.ToLower(host) || strings.TrimSpace(host) != host || strings.ContainsAny(host, "/*:@?#[]") {
			return EgressPolicy{}, fmt.Errorf("%w: invalid CSPM provider host", shared.ErrValidation)
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return EgressPolicy{}, fmt.Errorf("%w: CSPM host must be a DNS name", shared.ErrValidation)
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return EgressPolicy{}, fmt.Errorf("%w: invalid CSPM DNS label", shared.ErrValidation)
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return EgressPolicy{}, fmt.Errorf("%w: invalid CSPM DNS label", shared.ErrValidation)
				}
			}
		}
		p.AllowDomainRules = append(p.AllowDomainRules, DomainRule{Host: host, Ports: []uint16{443}})
	}
	return p, nil
}
