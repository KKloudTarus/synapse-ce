package reachbench

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// OSVObservations converts OSV-Scanner's documented JSON call-analysis output into a complete corpus
// observation set. A missing experimentalAnalysis entry means the tool did not analyse that advisory and is
// represented as no_analysis; it is never reinterpreted as an uncalled vulnerable function.
func OSVObservations(c Corpus, r io.Reader) ([]Observation, error) {
	if err := validateCorpus(c); err != nil {
		return nil, err
	}
	type source struct {
		Path string `json:"path"`
	}
	type key struct {
		AdvisoryID string
		SourcePath string
	}
	var output struct {
		Results []struct {
			Source   source `json:"source"`
			Packages []struct {
				Groups []struct {
					IDs                  []string `json:"ids"`
					ExperimentalAnalysis map[string]struct {
						Called *bool `json:"called"`
					} `json:"experimentalAnalysis"`
					ExperimentalAnalysisSnake map[string]struct {
						Called *bool `json:"called"`
					} `json:"experimental_analysis"`
				} `json:"groups"`
			} `json:"packages"`
		} `json:"results"`
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read OSV-Scanner reachability output: %w", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode OSV-Scanner reachability output: %w", err)
	}
	if _, ok := envelope["results"]; !ok {
		return nil, fmt.Errorf("OSV-Scanner reachability output is missing results")
	}
	if err := json.Unmarshal(body, &output); err != nil {
		return nil, fmt.Errorf("decode OSV-Scanner reachability output: %w", err)
	}
	called := map[key]bool{}
	known := map[key]bool{}
	for _, result := range output.Results {
		for _, pkg := range result.Packages {
			for _, group := range pkg.Groups {
				analyses := []map[string]struct {
					Called *bool `json:"called"`
				}{
					group.ExperimentalAnalysis,
					group.ExperimentalAnalysisSnake,
				}
				for _, analysisMap := range analyses {
					for id, analysis := range analysisMap {
						if analysis.Called == nil {
							continue
						}
						itemKey := key{AdvisoryID: id, SourcePath: strings.TrimPrefix(outputPath(result.Source.Path), "./")}
						if _, exists := known[itemKey]; exists && called[itemKey] != *analysis.Called {
							return nil, fmt.Errorf("OSV-Scanner output has contradictory call analysis for %q in %q (%t and %t)", id, itemKey.SourcePath, called[itemKey], *analysis.Called)
						}
						known[itemKey] = true
						called[itemKey] = *analysis.Called
					}
				}
			}
		}
	}
	observations := make([]Observation, 0, len(c.Cases))
	for _, item := range c.Cases {
		label := NoAnalysis
		if selector := item.Baseline.OSV; selector != nil {
			seenAnalysis := false
			for _, id := range selector.AdvisoryIDs {
				for itemKey, isCalled := range called {
					if itemKey.AdvisoryID != id || !strings.HasSuffix(itemKey.SourcePath, selector.SourceSuffix) {
						continue
					}
					seenAnalysis = true
					if isCalled {
						label = Reachable
						break
					}
				}
				if label == Reachable {
					break
				}
			}
			if label != Reachable && seenAnalysis {
				label = PresentUnreached
			}
		}
		observations = append(observations, Observation{Case: item.Name, Label: label})
	}
	return observations, nil
}

func outputPath(path string) string { return strings.ReplaceAll(path, `\`, "/") }

// SemgrepCEObservations converts Semgrep CE's native JSON or SARIF result shape. Semgrep CE's baseline is
// an explicit, checked-in rule per corpus case; a matching rule result is reachable and a clean result for
// that exact rule/path pair is present_unreached. Cases without a Semgrep selector remain no_analysis.
func SemgrepCEObservations(c Corpus, r io.Reader) ([]Observation, error) {
	if err := validateCorpus(c); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read Semgrep CE reachability output: %w", err)
	}
	type result struct {
		RuleID string
		Path   string
	}
	var native struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &native); err != nil {
		return nil, fmt.Errorf("decode Semgrep CE reachability output: %w", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode Semgrep CE reachability output: %w", err)
	}
	_, hasNative := envelope["results"]
	_, hasSARIF := envelope["runs"]
	if !hasNative && !hasSARIF {
		return nil, fmt.Errorf("Semgrep CE reachability output is neither native JSON nor SARIF")
	}
	results := make([]result, 0, len(native.Results))
	for _, item := range native.Results {
		results = append(results, result{RuleID: item.CheckID, Path: item.Path})
	}
	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(body, &sarif); err != nil {
		return nil, fmt.Errorf("decode Semgrep CE SARIF reachability output: %w", err)
	}
	for _, run := range sarif.Runs {
		for _, item := range run.Results {
			path := ""
			if len(item.Locations) > 0 {
				path = item.Locations[0].PhysicalLocation.ArtifactLocation.URI
			}
			results = append(results, result{RuleID: item.RuleID, Path: path})
		}
	}
	observations := make([]Observation, 0, len(c.Cases))
	for _, item := range c.Cases {
		label := NoAnalysis
		if selector := item.Baseline.SemgrepCE; selector != nil {
			label = PresentUnreached
			for _, result := range results {
				if result.RuleID == selector.RuleID && strings.HasSuffix(strings.TrimPrefix(result.Path, "./"), selector.PathSuffix) {
					label = Reachable
					break
				}
			}
		}
		observations = append(observations, Observation{Case: item.Name, Label: label})
	}
	return observations, nil
}

// SnykSampleObservations reduces a human-reviewed Snyk sample without embedding credentials, organization
// identifiers, or a vendor-specific API contract in the repository. Each observation cites the stable
// evidence_id declared by the corpus; missing evidence is no_analysis and duplicate evidence is rejected.
func SnykSampleObservations(c Corpus, r io.Reader) ([]Observation, error) {
	if err := validateCorpus(c); err != nil {
		return nil, err
	}
	var input struct {
		Observations []struct {
			EvidenceID string `json:"evidence_id"`
			Label      Label  `json:"label"`
		} `json:"observations"`
	}
	if err := decodeStrict(r, &input, "Snyk sample reachability input"); err != nil {
		return nil, err
	}
	byEvidence := make(map[string]Label, len(input.Observations))
	for _, item := range input.Observations {
		id := strings.TrimSpace(item.EvidenceID)
		if id == "" || !item.Label.valid() {
			return nil, fmt.Errorf("Snyk sample has invalid evidence observation")
		}
		if _, duplicate := byEvidence[id]; duplicate {
			return nil, fmt.Errorf("Snyk sample duplicates evidence id %q", id)
		}
		byEvidence[id] = item.Label
	}
	observations := make([]Observation, 0, len(c.Cases))
	for _, item := range c.Cases {
		label := NoAnalysis
		if selector := item.Baseline.SnykSample; selector != nil {
			if observed, ok := byEvidence[selector.EvidenceID]; ok {
				label = observed
			}
		}
		observations = append(observations, Observation{Case: item.Name, Label: label})
	}
	return observations, nil
}
