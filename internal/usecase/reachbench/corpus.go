package reachbench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

const (
	maxCorpusBytes = 8 << 20 // a labeled corpus file is small curated data
	maxCorpusCases = 100_000
)

// LoadCorpus reads a labeled corpus JSON file (an array of Case). It validates each row: a non-empty id,
// language, and symbol, and a Want that is exactly reachable or not_reachable (a labeled corpus never
// carries unknown as ground truth). It returns an error on a malformed file or row rather than silently
// dropping cases, so the ratchet always scores the corpus the floors were calibrated against.
func LoadCorpus(path string) ([]Case, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("corpus %q: %w", path, err)
	}
	if fi.Size() > maxCorpusBytes {
		return nil, fmt.Errorf("corpus %q exceeds %d bytes", path, maxCorpusBytes)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- caller-supplied corpus path (test / CI harness input)
	if err != nil {
		return nil, fmt.Errorf("read corpus %q: %w", path, err)
	}
	var cases []Case
	if err := json.Unmarshal(data, &cases); err != nil {
		return nil, fmt.Errorf("parse corpus %q: %w", path, err)
	}
	if len(cases) > maxCorpusCases {
		return nil, fmt.Errorf("corpus %q has %d cases (max %d)", path, len(cases), maxCorpusCases)
	}
	ids := make(map[string]bool, len(cases))
	for i, c := range cases {
		if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Language) == "" || strings.TrimSpace(c.Symbol) == "" {
			return nil, fmt.Errorf("corpus %q row %d: id, language, and symbol are required", path, i)
		}
		if ids[c.ID] {
			return nil, fmt.Errorf("corpus %q row %d: duplicate case id %q", path, i, c.ID)
		}
		ids[c.ID] = true
		if c.Want != judgment.Reachable && c.Want != judgment.NotReachable {
			return nil, fmt.Errorf("corpus %q row %d (%s): want must be reachable|not_reachable, got %q", path, i, c.ID, c.Want)
		}
	}
	return cases, nil
}

// LoadVerdicts reads an engine's (or a competitor's) recorded verdicts: a JSON object mapping a case id to a
// four-state reachability verdict. A missing case is treated as unknown at scoring time, so a verdict file
// need not enumerate cases the engine could not answer.
func LoadVerdicts(path string) (map[string]judgment.ReachabilityState, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("verdicts %q: %w", path, err)
	}
	if fi.Size() > maxCorpusBytes {
		return nil, fmt.Errorf("verdicts %q exceeds %d bytes", path, maxCorpusBytes)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- caller-supplied verdicts path (test / CI harness input)
	if err != nil {
		return nil, fmt.Errorf("read verdicts %q: %w", path, err)
	}
	var raw map[string]judgment.ReachabilityState
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse verdicts %q: %w", path, err)
	}
	return raw, nil
}

// CorpusSHA256 returns the hex sha256 of a corpus/verdicts file, so a harness can PIN the exact content the
// ratchet floors were calibrated against (a silently modified corpus would otherwise produce incomparable
// numbers that pass the ratchet falsely).
func CorpusSHA256(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- caller-supplied corpus path (test / CI harness input)
	if err != nil {
		return "", fmt.Errorf("read %q: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
