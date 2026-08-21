package rulepack

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	// DigestPrefix makes a RulePack digest self-describing and prevents it from being confused with an
	// unrelated SHA-256 digest at an integration boundary.
	DigestPrefix = "rulepack-sha256:"
	// SignatureAlgorithm is the only RulePack content-signing algorithm currently accepted.
	SignatureAlgorithm = "ed25519"
	signatureContext   = "synapse-rulepack:v1"
	signatureSeparator = "\x1e"
)

// ErrBadSignature is returned when a RulePack artifact does not verify under the caller-pinned key.
var ErrBadSignature = errors.New("rulepack signature invalid")

// ComputeDigest returns the canonical content digest of p. Callers that accept an artifact should use
// Validate or Verify; ComputeDigest intentionally only computes identity so Validate can compare it.
func ComputeDigest(p RulePack) (string, error) {
	b, err := canonicalBytes(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return DigestPrefix + hex.EncodeToString(sum[:]), nil
}

// Sign returns a detached Ed25519 signature over the canonical RulePack content under a domain-separated
// context. The pack must already be sealed and valid.
func Sign(priv ed25519.PrivateKey, p RulePack) (SignedArtifact, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignedArtifact{}, fmt.Errorf("%w: rulepack signing key has invalid size", shared.ErrValidation)
	}
	if err := p.Validate(); err != nil {
		return SignedArtifact{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	msg, err := signatureMessage(p)
	if err != nil {
		return SignedArtifact{}, err
	}
	return SignedArtifact{
		Pack:      clonePack(p),
		Algorithm: SignatureAlgorithm,
		KeyID:     evidence.KeyFingerprint(pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)),
	}, nil
}

// Verify checks the artifact with a caller-supplied trusted public key. Trust is external to the artifact:
// KeyID must fingerprint trustedPub and the signature must verify over the canonical content.
func Verify(a SignedArtifact, trustedPub ed25519.PublicKey) error {
	if a.Algorithm != SignatureAlgorithm || len(trustedPub) != ed25519.PublicKeySize {
		return ErrBadSignature
	}
	if a.KeyID == "" || a.KeyID != evidence.KeyFingerprint(trustedPub) {
		return fmt.Errorf("%w: key id does not match the trusted public key", ErrBadSignature)
	}
	if err := a.Pack.Validate(); err != nil {
		return fmt.Errorf("%w: invalid pack: %v", ErrBadSignature, err)
	}
	if len(a.Signature) != base64.StdEncoding.EncodedLen(ed25519.SignatureSize) {
		return fmt.Errorf("%w: malformed signature", ErrBadSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrBadSignature)
	}
	msg, err := signatureMessage(a.Pack)
	if err != nil {
		return fmt.Errorf("%w: canonicalize pack: %v", ErrBadSignature, err)
	}
	if !ed25519.Verify(trustedPub, msg, sig) {
		return ErrBadSignature
	}
	return nil
}

func signatureMessage(p RulePack) ([]byte, error) {
	b, err := canonicalBytes(p)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 0, len(signatureContext)+1+len(b))
	msg = append(msg, signatureContext...)
	msg = append(msg, signatureSeparator...)
	msg = append(msg, b...)
	return msg, nil
}

func canonicalBytes(p RulePack) ([]byte, error) {
	c := clonePack(p)
	c.Digest = ""
	sort.Slice(c.Rules, func(i, j int) bool {
		if c.Rules[i].ID != c.Rules[j].ID {
			return c.Rules[i].ID < c.Rules[j].ID
		}
		return c.Rules[i].Version < c.Rules[j].Version
	})
	for i := range c.Rules {
		sort.Slice(c.Rules[i].Matcher.All, func(a, b int) bool {
			return predicateKey(c.Rules[i].Matcher.All[a]) < predicateKey(c.Rules[i].Matcher.All[b])
		})
		for j := range c.Rules[i].Matcher.All {
			sort.Strings(c.Rules[i].Matcher.All[j].Values)
		}
	}
	sort.Ints(c.RequiredSchemaVersions)
	sort.Slice(c.RequiredSensors, func(i, j int) bool { return c.RequiredSensors[i].ID < c.RequiredSensors[j].ID })
	sort.Slice(c.RequiredFields, func(i, j int) bool { return c.RequiredFields[i] < c.RequiredFields[j] })
	sort.Slice(c.ATTACKMappings, func(i, j int) bool {
		if c.ATTACKMappings[i].RuleID != c.ATTACKMappings[j].RuleID {
			return c.ATTACKMappings[i].RuleID < c.ATTACKMappings[j].RuleID
		}
		return c.ATTACKMappings[i].TechniqueID < c.ATTACKMappings[j].TechniqueID
	})
	normalizeFixtures := func(fs []Fixture) {
		for i := range fs {
			sort.Strings(fs[i].ExpectedRuleIDs)
		}
		sort.Slice(fs, func(i, j int) bool { return fs[i].ID < fs[j].ID })
	}
	normalizeFixtures(c.PositiveFixtures)
	normalizeFixtures(c.NegativeFixtures)
	sort.Slice(c.ExpectedCost, func(i, j int) bool { return c.ExpectedCost[i].RuleID < c.ExpectedCost[j].RuleID })
	sort.Strings(c.RolloutCohort)
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("canonicalize rulepack: %w", err)
	}
	return b, nil
}

func clonePack(p RulePack) RulePack {
	c := p
	c.Rules = make([]detection.Rule, len(p.Rules))
	for i, r := range p.Rules {
		c.Rules[i] = r
		c.Rules[i].Matcher.All = make([]detection.Predicate, len(r.Matcher.All))
		for j, pred := range r.Matcher.All {
			c.Rules[i].Matcher.All[j] = pred
			c.Rules[i].Matcher.All[j].Values = append([]string(nil), pred.Values...)
		}
	}
	c.RequiredSchemaVersions = append([]int(nil), p.RequiredSchemaVersions...)
	c.RequiredSensors = append([]SensorRequirement(nil), p.RequiredSensors...)
	c.RequiredFields = append([]detection.Field(nil), p.RequiredFields...)
	c.ATTACKMappings = append([]ATTACKMapping(nil), p.ATTACKMappings...)
	cloneFixtures := func(in []Fixture) []Fixture {
		out := make([]Fixture, len(in))
		for i, f := range in {
			out[i] = f
			out[i].ExpectedRuleIDs = append([]string(nil), f.ExpectedRuleIDs...)
			out[i].Event = cloneEvent(f.Event)
		}
		return out
	}
	c.PositiveFixtures = cloneFixtures(p.PositiveFixtures)
	c.NegativeFixtures = cloneFixtures(p.NegativeFixtures)
	c.ExpectedCost = append([]RuleCostBudget(nil), p.ExpectedCost...)
	c.RolloutCohort = append([]string(nil), p.RolloutCohort...)
	return c
}

func cloneEvent(e detection.Event) detection.Event {
	c := e
	c.At = e.At.UTC()
	if e.Process != nil {
		p := *e.Process
		p.Args = append([]string(nil), e.Process.Args...)
		c.Process = &p
	}
	if e.Network != nil {
		n := *e.Network
		c.Network = &n
	}
	if e.File != nil {
		f := *e.File
		c.File = &f
	}
	if e.Privilege != nil {
		p := *e.Privilege
		c.Privilege = &p
	}
	return c
}

func predicateKey(p detection.Predicate) string {
	values := append([]string(nil), p.Values...)
	sort.Strings(values)
	b, _ := json.Marshal(struct {
		Field  detection.Field `json:"field"`
		Op     detection.Op    `json:"op"`
		Value  string          `json:"value"`
		Values []string        `json:"values"`
	}{Field: p.Field, Op: p.Op, Value: p.Value, Values: values})
	return string(b)
}
