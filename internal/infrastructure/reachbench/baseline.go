package reachbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func (runner *Runner) verifyBaselineAllowlist(ctx context.Context, bundleRoot string, asset BundleAsset, facts runtimeFacts, analyzer RevisionIdentity) (BaselineAllowlistResult, error) {
	path, err := benchcycle.BelowRoot(bundleRoot, asset.Path)
	if err != nil {
		return BaselineAllowlistResult{}, fmt.Errorf("resolve baseline allowlist: %w", err)
	}
	var allowlist BaselineAllowlist
	encoded, err := readCanonicalJSON(path, &allowlist)
	if err != nil {
		return BaselineAllowlistResult{}, fmt.Errorf("read baseline allowlist: %w", err)
	}
	if benchmark.SHA256Digest(encoded) != asset.Digest {
		return BaselineAllowlistResult{}, errors.New("baseline allowlist digest does not match controller bundle")
	}
	if err := allowlist.Validate(); err != nil {
		return BaselineAllowlistResult{}, err
	}
	status, err := runner.dependencies.Command(ctx, "git", "status", "--porcelain")
	if err != nil {
		return BaselineAllowlistResult{}, fmt.Errorf("check harness working tree with git argv: %w", err)
	}
	if strings.TrimSpace(string(status)) != "" {
		return BaselineAllowlistResult{}, errors.New("protected baseline requires a clean harness working tree")
	}
	diff, err := runner.dependencies.Command(ctx, "git", "diff", "--name-status", "--no-renames", "-z", measurement.TrustedBaselineRevision+"..."+facts.harness.Commit)
	if err != nil {
		return BaselineAllowlistResult{}, fmt.Errorf("derive harness delta with git argv: %w", err)
	}
	entries, err := normalizeChangedEntries(diff)
	if err != nil {
		return BaselineAllowlistResult{}, err
	}
	if !equalBaselineAllowlistEntries(entries, allowlist.Entries) {
		return BaselineAllowlistResult{}, errors.New("harness change status or path does not exactly match the reviewed baseline allowlist")
	}
	encodedEntries, err := benchmark.CanonicalJSON(entries)
	if err != nil {
		return BaselineAllowlistResult{}, fmt.Errorf("encode normalized baseline changes: %w", err)
	}
	result := BaselineAllowlistResult{
		SchemaVersion:      BaselineAllowlistResultVersion,
		Allowlist:          measurement.ArtifactReference{ID: allowlist.ID, Digest: benchmark.SHA256Digest(encoded)},
		Harness:            facts.harness,
		Analyzer:           analyzer,
		ChangedEntryCount:  len(entries),
		ChangedEntryDigest: benchmark.SHA256Digest(encodedEntries),
	}
	if err := result.Validate(); err != nil {
		return BaselineAllowlistResult{}, err
	}
	return result, nil
}

func normalizeChangedEntries(raw []byte) ([]BaselineAllowlistEntry, error) {
	if len(raw) == 0 || raw[len(raw)-1] != 0 {
		return nil, errors.New("protected baseline has a malformed or empty NUL-delimited harness delta")
	}
	fields := bytes.Split(raw[:len(raw)-1], []byte{0})
	if len(fields) == 0 || len(fields)%2 != 0 || len(fields)/2 > maxCells {
		return nil, errors.New("protected baseline has a malformed or oversized NUL-delimited harness delta")
	}
	entries := make([]BaselineAllowlistEntry, 0, len(fields)/2)
	seen := make(map[string]struct{}, len(fields)/2)
	for index := 0; index < len(fields); index += 2 {
		if !utf8.Valid(fields[index]) || !utf8.Valid(fields[index+1]) {
			return nil, errors.New("protected baseline contains invalid UTF-8 change records")
		}
		status, path := string(fields[index]), string(fields[index+1])
		if !validBaselineChangeStatus(status) {
			return nil, errors.New("protected baseline contains a deletion, rename, copy, or unknown change status")
		}
		if !safeHarnessPath(path) {
			return nil, errors.New("protected baseline contains a disallowed or unsafe changed path")
		}
		if _, exists := seen[path]; exists {
			return nil, errors.New("protected baseline contains a duplicate changed path")
		}
		seen[path] = struct{}{}
		entries = append(entries, BaselineAllowlistEntry{Status: status, Path: path})
	}
	sort.Slice(entries, func(left, right int) bool {
		return baselineAllowlistEntryKey(entries[left]) < baselineAllowlistEntryKey(entries[right])
	})
	return entries, nil
}

func equalBaselineAllowlistEntries(left, right []BaselineAllowlistEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasPrivatePathVariant(raw []byte, value string) bool {
	if value == "" {
		return false
	}
	variants := []string{value, strings.ReplaceAll(value, "\\", "/"), strings.ReplaceAll(value, "/", "\\")}
	for _, variant := range variants {
		if bytes.Contains(raw, []byte(variant)) || bytes.Contains(raw, []byte(strings.ReplaceAll(variant, "\\", "\\\\"))) {
			return true
		}
	}
	return false
}

func baselineAllowlistResultPath() string { return "baseline-allowlist-result.json" }
