package sca

import (
	"math"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const aiTriageDistributionSchemaVersion = "synapse-ai-triage-distribution-v1"

// AITriageDistributionSnapshot is a deterministic, source-free view of
// the population evaluated by AI triage. Every populated dimension sums to
// 10,000 basis points so snapshots can be compared across scan volumes.
type AITriageDistributionSnapshot struct {
	SchemaVersion string         `json:"schema_version"`
	SampleSize    int            `json:"sample_size"`
	Language      map[string]int `json:"language_basis_points"`
	CWE           map[string]int `json:"cwe_basis_points"`
	Project       map[string]int `json:"project_basis_points"`
}

func newAITriageDistributionSnapshot(sampleSize int, language, cwe, project map[string]float64) AITriageDistributionSnapshot {
	return AITriageDistributionSnapshot{
		SchemaVersion: aiTriageDistributionSchemaVersion,
		SampleSize:    sampleSize,
		Language:      normalizeDistributionWeights(language),
		CWE:           normalizeDistributionWeights(cwe),
		Project:       normalizeDistributionWeights(project),
	}
}

func addLanguageDistributionWeights(weights map[string]float64, languages []ports.DetectedLanguage, sampleSize int) {
	if sampleSize <= 0 {
		return
	}
	valid := make(map[string]float64, len(languages))
	total := 0.0
	for _, language := range languages {
		name := strings.ToLower(strings.TrimSpace(language.Name))
		if name == "" || language.Percent <= 0 || math.IsNaN(language.Percent) || math.IsInf(language.Percent, 0) {
			continue
		}
		valid[name] += language.Percent
		total += language.Percent
	}
	if total == 0 {
		weights["unknown"] += float64(sampleSize)
		return
	}
	for name, percent := range valid {
		weights[name] += float64(sampleSize) * percent / total
	}
}

func canonicalDistributionCWE(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || value == "UNCLASSIFIED" {
		return "unclassified"
	}
	return value
}

func normalizeDistributionWeights(weights map[string]float64) map[string]int {
	type share struct {
		key       string
		basis     int
		remainder float64
	}
	keys := make([]string, 0, len(weights))
	for key := range weights {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	total := 0.0
	for _, key := range keys {
		weight := weights[key]
		if weight > 0 && !math.IsNaN(weight) && !math.IsInf(weight, 0) {
			total += weight
		}
	}
	if total == 0 {
		return map[string]int{}
	}

	shares := make([]share, 0, len(weights))
	allocated := 0
	for _, key := range keys {
		weight := weights[key]
		if weight <= 0 || math.IsNaN(weight) || math.IsInf(weight, 0) {
			continue
		}
		exact := weight * 10_000 / total
		basis := int(math.Floor(exact))
		shares = append(shares, share{key: key, basis: basis, remainder: exact - float64(basis)})
		allocated += basis
	}
	sort.Slice(shares, func(i, j int) bool {
		if shares[i].remainder != shares[j].remainder {
			return shares[i].remainder > shares[j].remainder
		}
		return shares[i].key < shares[j].key
	})
	for i := 0; i < 10_000-allocated; i++ {
		shares[i%len(shares)].basis++
	}
	result := make(map[string]int, len(shares))
	for _, item := range shares {
		if item.basis > 0 {
			result[item.key] = item.basis
		}
	}
	return result
}
