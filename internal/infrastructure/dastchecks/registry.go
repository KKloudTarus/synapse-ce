// Package dastchecks evaluates deterministic, passive DAST observations.
package dastchecks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastcheck"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var checks = append([]dastcheck.Check(nil), dastcheck.Checks...)

type Evaluator struct{ checks []dastcheck.Check }

var _ ports.DASTCheckEvaluator = (*Evaluator)(nil)

func NewEvaluator() *Evaluator { return &Evaluator{checks: append([]dastcheck.Check(nil), checks...)} }

func (e *Evaluator) Evaluate(observations []ports.DASTObservation, selected []string) ([]ports.DASTFinding, error) {
	if err := dastcheck.ValidateParity(dastcheck.Catalog, e.checks); err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(e.checks))
	for _, check := range e.checks {
		allowed[check.ID] = true
	}
	if len(selected) == 0 {
		for id := range allowed {
			allowed[id] = true
		}
	} else {
		for id := range allowed {
			allowed[id] = false
		}
		for _, id := range selected {
			if !e.dastcheckID(id) {
				return nil, fmt.Errorf("%w: unknown DAST check %q", shared.ErrValidation, id)
			}
			allowed[id] = true
		}
	}
	var findings []ports.DASTFinding
	for _, observation := range observations {
		endpoint, err := normalizeEndpoint(observation.URL)
		if err != nil {
			continue
		}
		findings = append(findings, evaluate(observation, endpoint, allowed)...)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].CheckID != findings[j].CheckID {
			return findings[i].CheckID < findings[j].CheckID
		}
		return findings[i].Endpoint < findings[j].Endpoint
	})
	return findings, nil
}

func (e *Evaluator) dastcheckID(id string) bool {
	for _, check := range e.checks {
		if check.ID == id {
			return true
		}
	}
	return false
}

func evaluate(o ports.DASTObservation, endpoint string, allowed map[string]bool) []ports.DASTFinding {
	headers := normalizedHeaders(o.Headers)
	var results []ports.DASTFinding
	add := func(id, signature string, proofHeaders []string, predicateTokens ...string) {
		if allowed[id] {
			results = append(results, newFinding(id, endpoint, o, signature, proofHeaders, predicateTokens...))
		}
	}
	// A missing header is only observable when this observation captured headers at all. Without
	// that distinction an observation with no captured evidence reads as a secure response (#1638).
	if o.HeadersCaptured && !hasPrefix(headers, "strict-transport-security") {
		add("security-headers", "missing:strict-transport-security", nil)
	}
	for _, header := range headers {
		if strings.HasPrefix(header, "set-cookie:") {
			attrs := cookieAttributes(header)
			if !attrs["secure"] || !attrs["httponly"] || !attrs["samesite"] {
				add("cookie-security-flags", "missing_cookie_flag", []string{"set-cookie"})
				break
			}
		}
	}
	path := strings.ToLower(mustPath(endpoint))
	body := strings.ToLower(o.BodyExcerpt)
	// A path alone is not a published artifact. The response has to have served it, and when an
	// excerpt was captured it has to look like a source map rather than an error page (#1638).
	if strings.HasSuffix(path, ".map") && servedSuccessfully(o.Status) && (body == "" || looksSourceMap(body)) {
		add("sensitive-public-artifact", "public_artifact", nil, "source_map_path")
	} else if strings.Contains(path, "/.well-known/") && servedSuccessfully(o.Status) && strings.Contains(body, "source") {
		add("sensitive-public-artifact", "public_artifact", nil, "well_known_path", "body:source")
	} else if strings.Contains(path, "/.well-known/") && servedSuccessfully(o.Status) && strings.Contains(body, "private") {
		add("sensitive-public-artifact", "public_artifact", nil, "well_known_path", "body:private")
	}
	if strings.Contains(body, "synapse-auth-weakness") {
		add("auth-configured-weakness", "configured_auth_weakness", nil, "body:synapse-auth-weakness")
	} else if hasPrefix(headers, "x-synapse-auth-weakness:") {
		add("auth-configured-weakness", "configured_auth_weakness", nil, "header:x-synapse-auth-weakness")
	}
	return results
}

// cookieAttributes reads the attributes of one recorded Set-Cookie header.
//
// It accepts both shapes the pipeline produces: the raw header, whose first segment is the
// name=value pair, and the redacted form the helper stores, which is the attribute names alone. A
// segment counts as an attribute only when its key is one, so a cookie NAMED "secure" or whose
// VALUE contains "secure" can never stand in for the Secure attribute, which is what the previous
// whole-header substring search allowed.
func cookieAttributes(header string) map[string]bool {
	_, payload, found := strings.Cut(header, ":")
	if !found {
		return nil
	}
	attrs := map[string]bool{}
	for _, part := range strings.Split(payload, ";") {
		key, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(part)), "=")
		switch strings.TrimSpace(key) {
		case "secure", "httponly", "samesite":
			attrs[strings.TrimSpace(key)] = true
		}
	}
	return attrs
}

// servedSuccessfully reports whether the response actually delivered the resource. A 404 for a
// .map path is the server saying the artifact is absent.
func servedSuccessfully(status int) bool { return status >= 200 && status < 300 }

// looksSourceMap checks the captured excerpt for the source-map document shape, so an HTML error
// page served with 200 at a .map path is not reported as a published source map.
func looksSourceMap(body string) bool {
	return strings.Contains(body, `"mappings"`) || strings.Contains(body, `"sources"`) || strings.Contains(body, `"sourcesContent"`)
}

// proofVersion is the current closed-proof contract. Version 2 carries the corrected cookie,
// artifact-evidence and header-capture predicates and binds HeadersCaptured into the hash. Version
// 1 proofs stay verifiable against their own recorded content (#1638).
const proofVersion = 2

func newFinding(id, endpoint string, o ports.DASTObservation, signature string, headers []string, predicateTokens ...string) ports.DASTFinding {
	return newVersionedFinding(proofVersion, id, endpoint, o, signature, headers, predicateTokens...)
}

func newVersionedFinding(version int, id, endpoint string, o ports.DASTObservation, signature string, headers []string, predicateTokens ...string) ports.DASTFinding {
	proof := ports.DASTProof{CheckID: id, Version: version, NormalizedEndpoint: endpoint, Observation: ports.DASTClosedObservation{
		Method: strings.ToUpper(o.Method), Status: o.Status, BodySHA256: o.BodySHA256,
		Headers: headers, HeadersCaptured: o.HeadersCaptured, Signature: signature, PredicateTokens: predicateTokens,
	}}
	raw := proof.CheckID + "\n" + proof.NormalizedEndpoint + "\n" + proof.Observation.Method + "\n" + fmt.Sprint(proof.Observation.Status) + "\n" + proof.Observation.BodySHA256 + "\n" + strings.Join(proof.Observation.Headers, ",") + "\n" + proof.Observation.Signature + "\n" + strings.Join(proof.Observation.PredicateTokens, ",")
	if version >= 2 {
		raw += "\n" + strconv.FormatBool(proof.Observation.HeadersCaptured)
	}
	hash := sha256.Sum256([]byte(raw))
	proof.Hash = hex.EncodeToString(hash[:])
	return ports.DASTFinding{CheckID: id, CWE: checkCWE(id), Version: version, Endpoint: endpoint, Proof: proof}
}

func checkCWE(id string) string {
	for _, check := range checks {
		if check.ID == id {
			return check.CWE
		}
	}
	return ""
}

func (e *Evaluator) VerifyProof(p ports.DASTProof) error {
	if !e.dastcheckID(p.CheckID) || checkCWE(p.CheckID) == "" || p.Version < 1 || p.Version > proofVersion || p.NormalizedEndpoint == "" || p.Observation.Method == "" || p.Observation.Status < 100 || p.Observation.Status > 599 || len(p.Observation.BodySHA256) != 64 {
		return fmt.Errorf("%w: invalid closed DAST proof", shared.ErrValidation)
	}
	for _, token := range p.Observation.PredicateTokens {
		if strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") {
			return fmt.Errorf("%w: invalid DAST predicate token", shared.ErrValidation)
		}
	}
	switch p.CheckID {
	case "security-headers":
		if p.Observation.Signature != "missing:strict-transport-security" || len(p.Observation.Headers) != 0 || len(p.Observation.PredicateTokens) != 0 {
			return fmt.Errorf("%w: DAST security-header predicate did not match", shared.ErrValidation)
		}
		// A corrected proof states that headers were captured; otherwise the finding claims a
		// missing header from evidence that was never collected.
		if p.Version >= 2 && !p.Observation.HeadersCaptured {
			return fmt.Errorf("%w: DAST header proof records no captured headers", shared.ErrValidation)
		}
	case "cookie-security-flags":
		if p.Observation.Signature != "missing_cookie_flag" || len(p.Observation.Headers) != 1 || p.Observation.Headers[0] != "set-cookie" || len(p.Observation.PredicateTokens) != 0 {
			return fmt.Errorf("%w: DAST cookie predicate did not match", shared.ErrValidation)
		}
	case "sensitive-public-artifact":
		path := strings.ToLower(mustPath(p.NormalizedEndpoint))
		sourceMap := len(p.Observation.PredicateTokens) == 1 && p.Observation.PredicateTokens[0] == "source_map_path" && strings.HasSuffix(path, ".map")
		wellKnown := len(p.Observation.PredicateTokens) == 2 && p.Observation.PredicateTokens[0] == "well_known_path" && strings.Contains(path, "/.well-known/") && (p.Observation.PredicateTokens[1] == "body:source" || p.Observation.PredicateTokens[1] == "body:private")
		valid := len(p.Observation.Headers) == 0 && p.Observation.Signature == "public_artifact" && (sourceMap || wellKnown)
		if !valid {
			return fmt.Errorf("%w: DAST artifact predicate did not match", shared.ErrValidation)
		}
		// A published artifact has to have been served. The status is already recorded, so a
		// corrected proof is checked against it rather than against the path alone.
		if p.Version >= 2 && !servedSuccessfully(p.Observation.Status) {
			return fmt.Errorf("%w: DAST artifact proof records an unserved response", shared.ErrValidation)
		}
	case "auth-configured-weakness":
		if p.Observation.Signature != "configured_auth_weakness" || len(p.Observation.Headers) != 0 || len(p.Observation.PredicateTokens) != 1 || p.Observation.PredicateTokens[0] != "body:synapse-auth-weakness" && p.Observation.PredicateTokens[0] != "header:x-synapse-auth-weakness" {
			return fmt.Errorf("%w: DAST authentication predicate did not match", shared.ErrValidation)
		}
	default:
		return fmt.Errorf("%w: unsupported DAST proof check", shared.ErrValidation)
	}
	want := newVersionedFinding(p.Version, p.CheckID, p.NormalizedEndpoint, ports.DASTObservation{Method: p.Observation.Method, Status: p.Observation.Status, BodySHA256: p.Observation.BodySHA256, HeadersCaptured: p.Observation.HeadersCaptured}, p.Observation.Signature, p.Observation.Headers, p.Observation.PredicateTokens...).Proof.Hash
	if p.Hash != want {
		return fmt.Errorf("%w: closed DAST proof hash mismatch", shared.ErrValidation)
	}
	return nil
}

func normalizeEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("invalid endpoint")
	}
	u.Fragment = ""
	u.RawQuery = ""
	u.ForceQuery = false
	return u.String(), nil
}
func mustPath(raw string) string { u, _ := url.Parse(raw); return u.Path }
func normalizedHeaders(headers []string) []string {
	out := make([]string, 0, len(headers))
	for _, h := range headers {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || strings.HasPrefix(h, "authorization:") || strings.HasPrefix(h, "cookie:") {
			continue
		}
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
func hasPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}
