// Command synapse-bench reduces supplied benchmark fixture observations into a deterministic report.
// It does not execute workloads, provision infrastructure, or contact external services.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/enginecompare"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func main() {
	inputPath := flag.String("input", "", "versioned benchmark input JSON")
	outputPath := flag.String("output", "", "output benchmark report JSON (default: stdout)")
	mode := flag.String("mode", "throughput", "reduction mode: throughput, accuracy, reachability, reachability-osv, reachability-semgrep-ce, reachability-snyk-sample, or compare")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "synapse-bench: positional arguments are not supported")
		os.Exit(1)
	}
	if err := run(*mode, *inputPath, *outputPath, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "synapse-bench:", err)
		os.Exit(1)
	}
}

func run(mode, inputPath, outputPath string, stdin io.Reader, stdout io.Writer) error {
	inputReader := stdin
	var inputFile *os.File
	if inputPath != "" {
		file, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("open benchmark input: %w", err)
		}
		inputFile = file
		defer func() { _ = inputFile.Close() }()
		inputReader = inputFile
	}
	// Decode and reduce BEFORE touching the output path, so a bad input or evaluation error never creates or
	// truncates the output file. Each mode captures its report in an encode closure.
	var encode func(io.Writer) error
	switch mode {
	case "throughput", "":
		input, err := benchmark.DecodeInput(inputReader)
		if err != nil {
			return err
		}
		report, err := benchmark.Evaluate(input)
		if err != nil {
			return fmt.Errorf("evaluate benchmark input: %w", err)
		}
		encode = func(w io.Writer) error { return benchmark.EncodeReport(w, report) }
	case "accuracy":
		input, err := benchmark.DecodeAccuracyInput(inputReader)
		if err != nil {
			return err
		}
		report, err := benchmark.EvaluateAccuracy(input)
		if err != nil {
			return fmt.Errorf("evaluate accuracy input: %w", err)
		}
		encode = func(w io.Writer) error { return benchmark.EncodeAccuracyReport(w, report) }
	case "reachability":
		// A fixture runner (owned engine or an OSS baseline adapter) supplies complete labelled observations
		// against a versioned corpus. This command reduces only that evidence; it never executes a scanner
		// or contacts a service, which keeps scorecards reproducible and safe to compare in CI.
		input, err := reachbench.DecodeInput(inputReader)
		if err != nil {
			return err
		}
		report, err := reachbench.EvaluateInput(input)
		if err != nil {
			return fmt.Errorf("evaluate reachability input: %w", err)
		}
		encode = func(w io.Writer) error { return reachbench.EncodeReport(w, report) }
	case "reachability-osv":
		observations, err := reachbench.OSVObservations(reachbench.DefaultCorpus(), inputReader)
		if err != nil {
			return err
		}
		report, err := reachbench.Evaluate(reachbench.DefaultCorpus(), observations)
		if err != nil {
			return fmt.Errorf("evaluate OSV-Scanner reachability baseline: %w", err)
		}
		encode = func(w io.Writer) error { return reachbench.EncodeReport(w, report) }
	case "reachability-semgrep-ce":
		observations, err := reachbench.SemgrepCEObservations(reachbench.DefaultCorpus(), inputReader)
		if err != nil {
			return err
		}
		report, err := reachbench.Evaluate(reachbench.DefaultCorpus(), observations)
		if err != nil {
			return fmt.Errorf("evaluate Semgrep CE reachability baseline: %w", err)
		}
		encode = func(w io.Writer) error { return reachbench.EncodeReport(w, report) }
	case "reachability-snyk-sample":
		observations, err := reachbench.SnykSampleObservations(reachbench.DefaultCorpus(), inputReader)
		if err != nil {
			return err
		}
		report, err := reachbench.Evaluate(reachbench.DefaultCorpus(), observations)
		if err != nil {
			return fmt.Errorf("evaluate Snyk sample reachability baseline: %w", err)
		}
		encode = func(w io.Writer) error { return reachbench.EncodeReport(w, report) }
	case "compare":
		// Reduce two engines' finding sets (owned candidate vs a competitor baseline, e.g. Grype) over the
		// same target into an honest differential: what the owned engine found that the baseline missed, and
		// vice versa. A CI job produces both finding sets from one target, then feeds them here. The input uses
		// an EXPLICIT tagged shape ({component, id, aliases}) validated CASE-SENSITIVELY (Go's json matches
		// field names case-insensitively, so a bare struct decode would let "ID" overwrite "id" and silently
		// drop a finding, understating a recall gap and overstating the owned engine), so any unexpected or
		// case-variant key is rejected rather than dropped.
		body, err := io.ReadAll(inputReader)
		if err != nil {
			return fmt.Errorf("read compare input: %w", err)
		}
		// encoding/json collapses a duplicate object key (last value wins) before a map decode can see it, so
		// {"id":"CVE-1","id":"CVE-2"} would silently drop CVE-1 and overstate recall. Reject duplicate keys up
		// front so no finding is lost to an ambiguous input.
		if err := rejectDuplicateJSONKeys(body); err != nil {
			return fmt.Errorf("compare input: %w", err)
		}
		top := map[string]json.RawMessage{}
		if err := json.Unmarshal(body, &top); err != nil {
			return fmt.Errorf("decode compare input: %w", err)
		}
		for k := range top {
			switch k {
			case "baseline_name", "candidate_name", "baseline", "candidate":
			default:
				return fmt.Errorf("compare input: unexpected field %q", k)
			}
		}
		var baselineName, candidateName string
		var baseline, candidate []compareFinding
		if err := decodeCompareField(top, "baseline_name", &baselineName); err != nil {
			return err
		}
		if err := decodeCompareField(top, "candidate_name", &candidateName); err != nil {
			return err
		}
		if err := decodeCompareField(top, "baseline", &baseline); err != nil {
			return err
		}
		if err := decodeCompareField(top, "candidate", &candidate); err != nil {
			return err
		}
		report := enginecompare.Compare(baselineName, candidateName, toRawFindings(baseline), toRawFindings(candidate))
		encode = func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}
	default:
		return fmt.Errorf("unknown mode %q (want throughput, accuracy, reachability, reachability-osv, reachability-semgrep-ce, reachability-snyk-sample or compare)", mode)
	}

	outputWriter := stdout
	var outputFile *os.File
	if outputPath != "" && outputPath != "-" {
		file, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create benchmark output: %w", err)
		}
		outputFile = file
		defer func() { _ = outputFile.Close() }()
		outputWriter = outputFile
	}
	if err := encode(outputWriter); err != nil {
		return err
	}
	if outputFile != nil {
		if err := outputFile.Sync(); err != nil {
			return fmt.Errorf("sync benchmark output: %w", err)
		}
	}
	return nil
}

// compareFinding is the explicit input shape for `-mode compare`: one detection engine's finding of a
// vulnerability in a component. Its UnmarshalJSON validates keys CASE-SENSITIVELY against exactly
// {component, id, aliases}, so a mistyped or case-variant key ("ID", "advisory_id") is rejected rather than
// silently dropped — a dropped finding would understate a recall gap and overstate the owned engine.
type compareFinding struct {
	Component string
	ID        string
	Aliases   []string
}

// UnmarshalJSON decodes a compareFinding, rejecting any key that is not exactly one of component/id/aliases
// (case-sensitive), which Go's default field matching would otherwise accept case-insensitively.
func (f *compareFinding) UnmarshalJSON(b []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for k := range raw {
		switch k {
		case "component", "id", "aliases":
		default:
			return fmt.Errorf("compare finding: unexpected field %q (want component/id/aliases)", k)
		}
	}
	if v, ok := raw["component"]; ok {
		if err := json.Unmarshal(v, &f.Component); err != nil {
			return err
		}
	}
	if v, ok := raw["id"]; ok {
		if err := json.Unmarshal(v, &f.ID); err != nil {
			return err
		}
	}
	if v, ok := raw["aliases"]; ok {
		if err := json.Unmarshal(v, &f.Aliases); err != nil {
			return err
		}
	}
	return nil
}

// decodeCompareField decodes one top-level compare-input field into dst (a no-op when the field is absent).
func decodeCompareField(m map[string]json.RawMessage, key string, dst any) error {
	v, ok := m[key]
	if !ok {
		return nil
	}
	if err := json.Unmarshal(v, dst); err != nil {
		return fmt.Errorf("compare input field %q: %w", key, err)
	}
	return nil
}

// toRawFindings maps the tagged input findings onto the internal finding type the comparison consumes.
func toRawFindings(fs []compareFinding) []vulnerability.RawFinding {
	out := make([]vulnerability.RawFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, vulnerability.RawFinding{Component: f.Component, AdvisoryID: f.ID, Aliases: f.Aliases})
	}
	return out
}

// rejectDuplicateJSONKeys streams the JSON tokens and errors on a duplicate key WITHIN ANY object, at any
// depth. encoding/json otherwise silently keeps the last value for a repeated key, which for the compare
// input would drop a finding and overstate recall. Arrays and nested objects are tracked so only true
// same-object key repeats are rejected.
func rejectDuplicateJSONKeys(data []byte) error {
	type frame struct {
		object    bool
		keys      map[string]bool
		expectKey bool // in an object, is the next string token a key (vs a value)?
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []*frame
	sawValue := func() { // a scalar/closed value was consumed; in an object the next string is a key again
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		top := (*frame)(nil)
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, &frame{object: true, keys: map[string]bool{}, expectKey: true})
			case '[':
				stack = append(stack, &frame{})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				sawValue() // the just-closed container was a value in its parent object
			}
		case string:
			if top != nil && top.object && top.expectKey {
				if top.keys[t] {
					return fmt.Errorf("duplicate key %q", t)
				}
				top.keys[t] = true
				top.expectKey = false // next token is this key's value
			} else {
				sawValue() // a string value
			}
		default: // number, bool, null
			sawValue()
		}
	}
}
