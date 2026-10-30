// Package dastprobe defines the immutable configuration and target policy for a DAST verifier.
package dastprobe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	ToolRunDASTVerifier = "run_dast_verifier"
	ActionSafeHTTPProbe = "dast.safe_http_probe"
)

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
	// RunID is trusted runtime context, never part of a request or queued probe.
	RunID shared.ID `json:"-"`
}

func (p Probe) NormalizedMethod() string {
	method := strings.ToUpper(strings.TrimSpace(p.Method))
	if method == "" {
		return "GET"
	}
	return method
}

// ApprovalDigest is a versioned structured encoding, so separators inside a field cannot
// make two different probe configurations share an approval.
func (p Probe) ApprovalDigest() string {
	payload, _ := json.Marshal(struct {
		Version              string    `json:"version"`
		JudgmentID           shared.ID `json:"judgment_id"`
		URL                  string    `json:"url"`
		Method               string    `json:"method"`
		ExpectedStatus       int       `json:"expected_status"`
		ExpectedBodyContains string    `json:"expected_body_contains"`
		ScoreIfConfirmed     int       `json:"score_if_confirmed"`
		ScoreIfRefuted       int       `json:"score_if_refuted"`
		ExpectedVersion      int       `json:"expected_version"`
		Rationale            string    `json:"rationale"`
	}{"dast-probe-v1", p.JudgmentID, p.URL, p.NormalizedMethod(), p.ExpectedStatus, p.ExpectedBodyContains, p.ScoreIfConfirmed, p.ScoreIfRefuted, p.ExpectedVersion, p.Rationale})
	sum := sha256.Sum256(payload)
	return "v1:" + hex.EncodeToString(sum[:])
}

func ValidateURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.User != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%w: invalid DAST target URL", shared.ErrValidation)
	}
	for key := range u.Query() {
		key = strings.ToLower(key)
		for _, sensitive := range []string{"token", "session", "api_key", "key", "secret", "password", "auth", "signature", "sig"} {
			if strings.Contains(key, sensitive) {
				return fmt.Errorf("%w: DAST target URL cannot contain credential-like query keys", shared.ErrValidation)
			}
		}
	}
	return nil
}

func ParseURL(raw string) (*url.URL, error) {
	if err := ValidateURL(raw); err != nil {
		return nil, err
	}
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

func PublicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast() && !sharedAddressSpace.Contains(ip)
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func Port(u *url.URL) uint16 {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
			return uint16(n)
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}
