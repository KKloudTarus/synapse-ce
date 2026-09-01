// Package scanrun defines provider-owned scan execution provenance.
package scanrun

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Provenance string

const (
	ProvenanceNative Provenance = "native"
	ProvenanceLegacy Provenance = "legacy"
)

type TerminalStatus string

const (
	StatusBuilding  TerminalStatus = "building"
	StatusSucceeded TerminalStatus = "succeeded"
	StatusPartial   TerminalStatus = "partial"
	StatusFailed    TerminalStatus = "failed"
	StatusCancelled TerminalStatus = "cancelled"
	StatusUnknown   TerminalStatus = "unknown"
)

type TargetKind string

const (
	TargetRepository TargetKind = "repository"
	TargetImage      TargetKind = "image"
	TargetHost       TargetKind = "host"
	TargetURL        TargetKind = "url"
	TargetCloud      TargetKind = "cloud"
)

type VersionKind string

const (
	VersionTool             VersionKind = "tool"
	VersionScanner          VersionKind = "scanner"
	VersionProfile          VersionKind = "profile"
	VersionRulePack         VersionKind = "rule_pack"
	VersionAdvisoryDatabase VersionKind = "advisory_database"
	VersionCorrelation      VersionKind = "correlation"
	VersionSchema           VersionKind = "schema"
)

type StageStatus string

const (
	StageSucceeded StageStatus = "succeeded"
	StageFailed    StageStatus = "failed"
	StageSkipped   StageStatus = "skipped"
)

type TargetInput struct {
	Kind              TargetKind
	Raw               string
	EvaluatedRevision string
	SchemaVersion     int
}

type TargetIdentity struct {
	Kind              TargetKind `json:"kind"`
	SchemaVersion     int        `json:"schema_version"`
	Canonical         string     `json:"canonical"`
	EvaluatedRevision string     `json:"evaluated_revision"`
}

type Version struct {
	Kind    VersionKind `json:"kind"`
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Digest  string      `json:"digest,omitempty"`
}

type Stage struct {
	Key        string      `json:"key"`
	Status     StageStatus `json:"status"`
	ReasonCode string      `json:"reason_code,omitempty"`
	StartedAt  *time.Time  `json:"started_at,omitempty"`
	FinishedAt *time.Time  `json:"finished_at,omitempty"`
}

type Lane struct {
	Key                       string         `json:"key"`
	Producer                  string         `json:"producer"`
	TerminalStatus            TerminalStatus `json:"terminal_status"`
	Target                    TargetIdentity `json:"target"`
	AuthoritativeFindingKinds []string       `json:"authoritative_finding_kinds"`
	IncludedScope             []string       `json:"included_scope"`
	ExcludedScope             []string       `json:"excluded_scope"`
	StartedAt                 time.Time      `json:"started_at"`
	FinishedAt                *time.Time     `json:"finished_at,omitempty"`
	ResultRef                 string         `json:"result_ref,omitempty"`
	EvidenceRef               string         `json:"evidence_ref,omitempty"`
	ResultSHA256              string         `json:"result_sha256,omitempty"`
	ManifestSchemaVersion     int            `json:"manifest_schema_version"`
	ManifestHash              string         `json:"manifest_hash"`
	SealedAt                  *time.Time     `json:"sealed_at,omitempty"`
	Versions                  []Version      `json:"versions"`
	Stages                    []Stage        `json:"stages"`
}

func CanonicalTarget(input TargetInput) (TargetIdentity, error) {
	if input.SchemaVersion != 1 {
		return TargetIdentity{}, fmt.Errorf("%w: unsupported target identity schema version", shared.ErrValidation)
	}
	raw := strings.TrimSpace(input.Raw)
	if raw == "" {
		return TargetIdentity{}, fmt.Errorf("%w: target identity is required", shared.ErrValidation)
	}
	var canonical string
	var err error
	switch input.Kind {
	case TargetRepository:
		canonical, err = canonicalRepository(raw)
	case TargetImage:
		canonical, input.EvaluatedRevision, err = canonicalImage(raw, input.EvaluatedRevision)
	case TargetHost:
		canonical, err = canonicalHost(raw)
	case TargetURL:
		canonical, err = canonicalURL(raw)
	case TargetCloud:
		canonical, err = canonicalCloud(raw)
	default:
		err = fmt.Errorf("%w: unsupported target kind", shared.ErrValidation)
	}
	if err != nil {
		return TargetIdentity{}, err
	}
	revision, err := canonicalRevision(input.Kind, input.EvaluatedRevision)
	if err != nil {
		return TargetIdentity{}, err
	}
	return TargetIdentity{Kind: input.Kind, SchemaVersion: 1, Canonical: canonical, EvaluatedRevision: revision}, nil
}

func SealLanes(lanes []Lane, sealedAt time.Time) ([]Lane, error) {
	sealedAt = postgresTime(sealedAt)
	out := append([]Lane(nil), lanes...)
	for index := range out {
		lane := &out[index]
		lane.Key = strings.TrimSpace(lane.Key)
		lane.Producer = strings.TrimSpace(lane.Producer)
		lane.ResultRef = strings.TrimSpace(lane.ResultRef)
		lane.EvidenceRef = strings.TrimSpace(lane.EvidenceRef)
		lane.ResultSHA256 = strings.ToLower(strings.TrimSpace(lane.ResultSHA256))
		lane.AuthoritativeFindingKinds = sortedUnique(lane.AuthoritativeFindingKinds)
		lane.IncludedScope = sortedUnique(lane.IncludedScope)
		lane.ExcludedScope = sortedUnique(lane.ExcludedScope)
		lane.StartedAt = postgresTime(lane.StartedAt)
		if lane.FinishedAt != nil {
			finishedAt := postgresTime(*lane.FinishedAt)
			lane.FinishedAt = &finishedAt
		}
		for stageIndex := range lane.Stages {
			if lane.Stages[stageIndex].StartedAt != nil {
				startedAt := postgresTime(*lane.Stages[stageIndex].StartedAt)
				lane.Stages[stageIndex].StartedAt = &startedAt
			}
			if lane.Stages[stageIndex].FinishedAt != nil {
				finishedAt := postgresTime(*lane.Stages[stageIndex].FinishedAt)
				lane.Stages[stageIndex].FinishedAt = &finishedAt
			}
		}
		sort.Slice(lane.Versions, func(i, j int) bool {
			left, right := lane.Versions[i], lane.Versions[j]
			return string(left.Kind)+"\x00"+left.Name < string(right.Kind)+"\x00"+right.Name
		})
		sort.Slice(lane.Stages, func(i, j int) bool { return lane.Stages[i].Key < lane.Stages[j].Key })
		if err := validateLane(*lane); err != nil {
			return nil, err
		}
		lane.ManifestHash = ""
		lane.SealedAt = nil
		hash, err := CanonicalHash(*lane)
		if err != nil {
			return nil, err
		}
		lane.ManifestHash = hash
		lane.SealedAt = &sealedAt
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func ValidateSealedLane(lane Lane) error {
	if lane.SealedAt == nil || !validSHA256(lane.ManifestHash) {
		return fmt.Errorf("%w: scan run lane is not sealed", shared.ErrValidation)
	}
	if err := validateLane(lane); err != nil {
		return err
	}
	want := lane.ManifestHash
	lane.ManifestHash = ""
	lane.SealedAt = nil
	lane = canonicalLaneTimes(lane)
	got, err := CanonicalHash(lane)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%w: scan run lane manifest hash mismatch", shared.ErrValidation)
	}
	return nil
}

func canonicalLaneTimes(lane Lane) Lane {
	lane.StartedAt = postgresTime(lane.StartedAt)
	if lane.FinishedAt != nil {
		finishedAt := postgresTime(*lane.FinishedAt)
		lane.FinishedAt = &finishedAt
	}
	lane.Stages = append([]Stage(nil), lane.Stages...)
	for index := range lane.Stages {
		if lane.Stages[index].StartedAt != nil {
			startedAt := postgresTime(*lane.Stages[index].StartedAt)
			lane.Stages[index].StartedAt = &startedAt
		}
		if lane.Stages[index].FinishedAt != nil {
			finishedAt := postgresTime(*lane.Stages[index].FinishedAt)
			lane.Stages[index].FinishedAt = &finishedAt
		}
	}
	return lane
}

func CanonicalHash(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode canonical provenance: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func validateLane(lane Lane) error {
	if lane.Key == "" || lane.Producer == "" || lane.StartedAt.IsZero() || lane.ManifestSchemaVersion < 1 {
		return fmt.Errorf("%w: lane identity, producer, start, and schema are required", shared.ErrValidation)
	}
	switch lane.TerminalStatus {
	case StatusSucceeded, StatusPartial, StatusFailed, StatusCancelled:
	default:
		return fmt.Errorf("%w: lane terminal status is invalid", shared.ErrValidation)
	}
	switch lane.Target.Kind {
	case TargetRepository, TargetImage, TargetHost, TargetURL, TargetCloud:
	default:
		return fmt.Errorf("%w: lane target kind is invalid", shared.ErrValidation)
	}
	if lane.Target.SchemaVersion < 1 || strings.TrimSpace(lane.Target.Canonical) == "" {
		return fmt.Errorf("%w: canonical lane target is required", shared.ErrValidation)
	}
	if lane.FinishedAt == nil || lane.FinishedAt.Before(lane.StartedAt) {
		return fmt.Errorf("%w: terminal lane requires a valid finish time", shared.ErrValidation)
	}
	if lane.TerminalStatus == StatusSucceeded {
		if len(lane.AuthoritativeFindingKinds) == 0 || len(lane.Stages) == 0 || len(lane.Versions) == 0 {
			return fmt.Errorf("%w: successful lane requires kinds, stages, and versions", shared.ErrValidation)
		}
		if lane.ResultRef == "" || lane.EvidenceRef == "" || !validSHA256(lane.ResultSHA256) {
			return fmt.Errorf("%w: successful lane requires sealed result and evidence", shared.ErrValidation)
		}
		if lane.Target.Kind == TargetRepository {
			if _, err := canonicalRevision(TargetRepository, lane.Target.EvaluatedRevision); err != nil || lane.Target.EvaluatedRevision == "" {
				return fmt.Errorf("%w: successful repository lane requires an immutable revision", shared.ErrValidation)
			}
		}
		if lane.Target.Kind == TargetImage && !validDigest(lane.Target.EvaluatedRevision) {
			return fmt.Errorf("%w: successful image lane requires an immutable digest", shared.ErrValidation)
		}
	}
	if lane.ResultSHA256 != "" && !validSHA256(lane.ResultSHA256) {
		return fmt.Errorf("%w: lane result digest is invalid", shared.ErrValidation)
	}
	for _, version := range lane.Versions {
		switch version.Kind {
		case VersionTool, VersionScanner, VersionProfile, VersionRulePack, VersionAdvisoryDatabase, VersionCorrelation, VersionSchema:
		default:
			return fmt.Errorf("%w: lane version kind is invalid", shared.ErrValidation)
		}
		if strings.TrimSpace(version.Name) == "" || strings.TrimSpace(version.Version) == "" {
			return fmt.Errorf("%w: lane version identity is invalid", shared.ErrValidation)
		}
	}
	for _, stage := range lane.Stages {
		if strings.TrimSpace(stage.Key) == "" || (stage.Status != StageSucceeded && stage.Status != StageFailed && stage.Status != StageSkipped) {
			return fmt.Errorf("%w: lane stage is invalid", shared.ErrValidation)
		}
	}
	return nil
}

func canonicalRepository(raw string) (string, error) {
	if strings.HasPrefix(raw, "git@") && strings.Contains(raw, ":") {
		parts := strings.SplitN(strings.TrimPrefix(raw, "git@"), ":", 2)
		raw = "ssh://git@" + parts[0] + "/" + parts[1]
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: repository target is invalid", shared.ErrValidation)
	}
	if parsed.Scheme == "" {
		cleaned := path.Clean(strings.ReplaceAll(raw, "\\", "/"))
		if cleaned == "." || strings.HasPrefix(cleaned, "../") {
			return "", fmt.Errorf("%w: repository path is invalid", shared.ErrValidation)
		}
		return "file:" + strings.TrimSuffix(strings.TrimSuffix(cleaned, "/"), ".git"), nil
	}
	parsed.User = nil
	parsed.Fragment = ""
	parsed.RawQuery = ""
	if err := canonicalizeURLHost(parsed); err != nil {
		return "", err
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	cleaned = strings.TrimSuffix(strings.TrimSuffix(cleaned, "/"), ".git")
	parsed.Path, parsed.RawPath = cleaned, ""
	return parsed.String(), nil
}

func canonicalImage(raw, revision string) (string, string, error) {
	reference := strings.TrimSpace(raw)
	if at := strings.LastIndex(reference, "@"); at >= 0 {
		if revision == "" {
			revision = reference[at+1:]
		}
		reference = reference[:at]
	}
	revision = strings.ToLower(strings.TrimSpace(revision))
	if revision != "" && !validDigest(revision) {
		return "", "", fmt.Errorf("%w: image target digest is invalid", shared.ErrValidation)
	}
	parts := strings.Split(reference, "/")
	if len(parts) == 1 || (!strings.ContainsAny(parts[0], ".:") && parts[0] != "localhost") {
		parts = append([]string{"docker.io"}, parts...)
		if len(parts) == 2 {
			parts = []string{"docker.io", "library", parts[1]}
		}
	}
	host, err := canonicalDNSOrIP(parts[0])
	if err != nil {
		return "", "", err
	}
	parts[0] = host
	last := parts[len(parts)-1]
	if colon := strings.LastIndex(last, ":"); colon > 0 {
		last = last[:colon]
	}
	parts[len(parts)-1] = strings.ToLower(last)
	for index := 1; index < len(parts)-1; index++ {
		parts[index] = strings.ToLower(parts[index])
	}
	canonical := strings.Join(parts, "/")
	if revision != "" {
		canonical += "@" + revision
	}
	return canonical, revision, nil
}

func canonicalHost(raw string) (string, error) {
	host, port := raw, ""
	if parsedHost, parsedPort, err := net.SplitHostPort(raw); err == nil {
		host, port = parsedHost, parsedPort
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = strings.Trim(raw, "[]")
	}
	host, err := canonicalDNSOrIP(host)
	if err != nil {
		return "", err
	}
	if port == "" {
		return host, nil
	}
	return net.JoinHostPort(host, port), nil
}

func canonicalURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%w: URL target is invalid", shared.ErrValidation)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.User = nil
	parsed.Fragment = ""
	if err := canonicalizeURLHost(parsed); err != nil {
		return "", err
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	if cleaned == "/." {
		cleaned = "/"
	}
	parsed.Path, parsed.RawPath = cleaned, ""
	query := parsed.Query()
	for key := range query {
		if sensitiveQueryKey(key) {
			query.Del(key)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func canonicalCloud(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || strings.Trim(parsed.Path, "/") == "" {
		return "", fmt.Errorf("%w: cloud target must be provider://account/resource-id", shared.ErrValidation)
	}
	provider := strings.ToLower(parsed.Scheme)
	account := strings.ToLower(strings.TrimSpace(parsed.Host))
	resource := strings.TrimSpace(strings.Trim(parsed.Path, "/"))
	if strings.ContainsAny(account+resource, "\r\n\t") {
		return "", fmt.Errorf("%w: cloud target is invalid", shared.ErrValidation)
	}
	return provider + "://" + account + "/" + resource, nil
}

func canonicalRevision(kind TargetKind, revision string) (string, error) {
	revision = strings.ToLower(strings.TrimSpace(revision))
	if revision == "" {
		return "", nil
	}
	if kind == TargetImage {
		if !validDigest(revision) {
			return "", fmt.Errorf("%w: image revision is invalid", shared.ErrValidation)
		}
		return revision, nil
	}
	if kind == TargetRepository {
		if len(revision) != 40 && len(revision) != 64 || !validHex(revision) {
			return "", fmt.Errorf("%w: repository revision must be a full commit digest", shared.ErrValidation)
		}
	}
	return revision, nil
}

func canonicalizeURLHost(parsed *url.URL) error {
	host, err := canonicalDNSOrIP(parsed.Hostname())
	if err != nil {
		return err
	}
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "ssh" && port == "22") {
		port = ""
	}
	parsed.Host = host
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	}
	return nil
}

func canonicalDNSOrIP(raw string) (string, error) {
	host := strings.TrimSuffix(strings.TrimSpace(strings.Trim(raw, "[]")), ".")
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" {
		return "", fmt.Errorf("%w: target host is invalid", shared.ErrValidation)
	}
	return strings.ToLower(ascii), nil
}

func sensitiveQueryKey(key string) bool {
	key = strings.ToLower(key)
	for _, fragment := range []string{"token", "secret", "password", "passwd", "credential", "signature", "api_key", "apikey", "auth"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func validDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == 71 && validHex(value[7:])
}

func validSHA256(value string) bool { return len(value) == 64 && validHex(value) }

func postgresTime(value time.Time) time.Time { return value.UTC().Truncate(time.Microsecond) }

func validHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
