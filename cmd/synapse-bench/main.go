// Command synapse-bench reduces supplied benchmark fixture observations into deterministic reports.
// It does not execute scanners, provision infrastructure, or contact external services.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/enginecompare"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const maxCompareJSONDepth = 256

var errGateFailed = errors.New("SCA ratchet gate failed")

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	os.Exit(executeCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// baselineCorpus returns the reachability corpus a baseline is scored against: the full checked-in corpus,
// or, when -language is set, only that language's cases. Filtering here (not just in the owned test) keeps a
// baseline report on the same language subset and corpus digest as the owned report, which
// CheckBaselineParity requires; comparing a language-scoped owned report against a full-corpus baseline
// would otherwise be rejected as different corpora.
func baselineCorpus(language string) (reachbench.Corpus, error) {
	if language == "" {
		return reachbench.DefaultCorpus(), nil
	}
	return reachbench.FilterByLanguage(reachbench.DefaultCorpus(), language)
}

// executeCLI owns process exit semantics so tests can assert them without invoking go run.
// It returns 0 for success and help, 1 for invalid commands or inputs, and 2 for flag parsing or a completed failed SCA ratchet gate.
func executeCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("synapse-bench", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inputPath := flags.String("input", "", "versioned benchmark input JSON")
	outputPath := flags.String("output", "", "output report (default: stdout)")
	mode := flags.String("mode", "throughput", "reduction mode: throughput, accuracy, reachability, reachability-osv, reachability-semgrep-ce, reachability-snyk-sample, compare, sca-accuracy, sca-render, or compare-many")
	language := flags.String("language", "", "restrict a reachability baseline to one corpus language (e.g. go, python), so its report matches the owned report's language subset and corpus digest")
	catalogPath := flags.String("catalog", "", "SCA catalog JSON")
	oraclePath := flags.String("oracle", "", "SCA oracle JSON")
	ratchetPath := flags.String("ratchet", "", "SCA ratchet JSON")
	var observationPaths stringList
	flags.Var(&observationPaths, "observation", "SCA observation envelope JSON (repeatable)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "synapse-bench: positional arguments are not supported")
		return 1
	}
	inputSpecified := false
	flags.Visit(func(item *flag.Flag) {
		inputSpecified = inputSpecified || item.Name == "input"
	})

	if err := validateLanguage(*mode, *language); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-bench:", err)
		return 1
	}

	var err error
	switch *mode {
	case "throughput", "", "accuracy", "reachability", "reachability-osv", "reachability-semgrep-ce", "reachability-snyk-sample", "compare":
		err = run(*mode, *inputPath, *outputPath, *language, stdin, stdout)
	case "sca-accuracy":
		if inputSpecified {
			err = fmt.Errorf("-input is not supported for sca-accuracy")
		} else {
			err = runSCAAccuracy(*catalogPath, *oraclePath, *ratchetPath, observationPaths, *outputPath, stdout)
		}
	case "sca-render":
		err = runSCARender(*inputPath, *outputPath, stdout)
	case "compare-many":
		err = runCompareMany(*inputPath, *outputPath, stdin, stdout)
	default:
		err = fmt.Errorf("unknown mode %q (want throughput, accuracy, reachability, reachability-osv, reachability-semgrep-ce, reachability-snyk-sample, compare, sca-accuracy, sca-render or compare-many)", *mode)
	}
	if err == nil {
		return 0
	}
	if errors.Is(err, errGateFailed) {
		_, _ = fmt.Fprintln(stderr, "synapse-bench:", err)
		return 2
	}
	_, _ = fmt.Fprintln(stderr, "synapse-bench:", err)
	return 1
}

func validateLanguage(mode, language string) error {
	if language == "" {
		return nil
	}
	switch mode {
	case "reachability-osv", "reachability-semgrep-ce", "reachability-snyk-sample":
		return nil
	default:
		return fmt.Errorf("-language is only valid for the reachability baseline modes, not %q", mode)
	}
}

// run preserves the legacy empty/throughput, accuracy, and compare behavior and error contract.
func run(mode, inputPath, outputPath, language string, stdin io.Reader, stdout io.Writer) error {
	if err := validateLanguage(mode, language); err != nil {
		return err
	}
	if err := rejectOutputInputCollision(outputPath, inputPath); err != nil {
		return err
	}
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
	// Decode and reduce before touching output, so invalid input never creates or truncates its output path.
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
		encode = func(writer io.Writer) error { return benchmark.EncodeReport(writer, report) }
	case "accuracy":
		input, err := benchmark.DecodeAccuracyInput(inputReader)
		if err != nil {
			return err
		}
		report, err := benchmark.EvaluateAccuracy(input)
		if err != nil {
			return fmt.Errorf("evaluate accuracy input: %w", err)
		}
		encode = func(writer io.Writer) error { return benchmark.EncodeAccuracyReport(writer, report) }
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
		encode = func(writer io.Writer) error { return reachbench.EncodeReport(writer, report) }
	case "reachability-osv":
		corpus, err := baselineCorpus(language)
		if err != nil {
			return err
		}
		observations, err := reachbench.OSVObservations(corpus, inputReader)
		if err != nil {
			return err
		}
		report, err := reachbench.Evaluate(corpus, observations)
		if err != nil {
			return fmt.Errorf("evaluate OSV-Scanner reachability baseline: %w", err)
		}
		encode = func(writer io.Writer) error { return reachbench.EncodeReport(writer, report) }
	case "reachability-semgrep-ce":
		corpus, err := baselineCorpus(language)
		if err != nil {
			return err
		}
		observations, err := reachbench.SemgrepCEObservations(corpus, inputReader)
		if err != nil {
			return err
		}
		report, err := reachbench.Evaluate(corpus, observations)
		if err != nil {
			return fmt.Errorf("evaluate Semgrep CE reachability baseline: %w", err)
		}
		encode = func(writer io.Writer) error { return reachbench.EncodeReport(writer, report) }
	case "reachability-snyk-sample":
		corpus, err := baselineCorpus(language)
		if err != nil {
			return err
		}
		observations, err := reachbench.SnykSampleObservations(corpus, inputReader)
		if err != nil {
			return err
		}
		report, err := reachbench.Evaluate(corpus, observations)
		if err != nil {
			return fmt.Errorf("evaluate Snyk sample reachability baseline: %w", err)
		}
		encode = func(writer io.Writer) error { return reachbench.EncodeReport(writer, report) }
	case "compare":
		report, err := decodeCompare(inputReader)
		if err != nil {
			return err
		}
		encode = encodeJSON(report)
	default:
		return fmt.Errorf("unknown mode %q (want throughput, accuracy, reachability, reachability-osv, reachability-semgrep-ce, reachability-snyk-sample or compare)", mode)
	}
	if mode == "compare" {
		return writeBoundedOutput(outputPath, stdout, encode, scabench.MaxJSONBytes)
	}
	return writeOutput(outputPath, stdout, encode)
}

func runSCAAccuracy(catalogPath, oraclePath, ratchetPath string, observationPaths []string, outputPath string, stdout io.Writer) error {
	if strings.TrimSpace(catalogPath) == "" || strings.TrimSpace(oraclePath) == "" || strings.TrimSpace(ratchetPath) == "" || len(observationPaths) == 0 {
		return fmt.Errorf("sca-accuracy requires -catalog, -oracle, -ratchet, and one or more -observation")
	}
	inputs := append([]string{catalogPath, oraclePath, ratchetPath}, observationPaths...)
	if err := rejectOutputInputCollision(outputPath, inputs...); err != nil {
		return err
	}
	catalog, err := decodeCatalogFile(catalogPath)
	if err != nil {
		return err
	}
	oracle, err := decodeOracleFile(oraclePath)
	if err != nil {
		return err
	}
	ratchet, err := decodeRatchetFile(ratchetPath)
	if err != nil {
		return err
	}
	catalogDigest, err := scabench.DigestCatalog(catalog)
	if err != nil {
		return fmt.Errorf("digest catalog: %w", err)
	}
	observations := make([]scabench.Observation, 0)
	seen := make(map[string]struct{})
	for _, path := range observationPaths {
		set, err := decodeObservationFile(path)
		if err != nil {
			return err
		}
		if set.CatalogRevision != catalog.Revision || set.CatalogDigest != catalogDigest {
			return fmt.Errorf("observation %q catalog identity does not match catalog", path)
		}
		for _, observation := range set.Observations {
			key := string(observation.Engine) + "\x00" + observation.TargetID
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate observation for engine %q and target %q across observation files", observation.Engine, observation.TargetID)
			}
			seen[key] = struct{}{}
			observations = append(observations, observation)
		}
	}
	result, err := scabench.Reduce(catalog, oracle, observations)
	if err != nil {
		return fmt.Errorf("reduce SCA observations: %w", err)
	}
	result, err = scabench.ApplyRatchet(result, ratchet)
	if err != nil {
		return fmt.Errorf("apply SCA ratchet: %w", err)
	}
	if err := writeOutput(outputPath, stdout, func(writer io.Writer) error { return scabench.EncodeResult(writer, result) }); err != nil {
		return err
	}
	if !result.Gate.Passed {
		return errGateFailed
	}
	return nil
}

func runSCARender(inputPath, outputPath string, stdout io.Writer) error {
	if strings.TrimSpace(inputPath) == "" {
		return fmt.Errorf("sca-render requires -input")
	}
	if err := rejectOutputInputCollision(outputPath, inputPath); err != nil {
		return err
	}
	result, err := decodeResultFile(inputPath)
	if err != nil {
		return err
	}
	return writeOutput(outputPath, stdout, func(writer io.Writer) error { return scabench.RenderResult(writer, result) })
}

func runCompareMany(inputPath, outputPath string, stdin io.Reader, stdout io.Writer) error {
	if err := rejectOutputInputCollision(outputPath, inputPath); err != nil {
		return err
	}
	input := stdin
	var file *os.File
	if inputPath != "" {
		opened, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("open compare-many input: %w", err)
		}
		file = opened
		defer func() { _ = file.Close() }()
		input = file
	}
	report, err := decodeManyCompare(input)
	if err != nil {
		return err
	}
	return writeBoundedOutput(outputPath, stdout, encodeJSON(report), scabench.MaxJSONBytes)
}

type boundedOutputWriter struct {
	writer    io.Writer
	remaining int64
	limit     int64
}

func (writer *boundedOutputWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > writer.remaining {
		return 0, fmt.Errorf("encoded output exceeds %d byte limit", writer.limit)
	}
	written, err := writer.writer.Write(data)
	writer.remaining -= int64(written)
	return written, err
}

func writeBoundedOutput(outputPath string, stdout io.Writer, encode func(io.Writer) error, limit int64) error {
	var encoded bytes.Buffer
	bounded := boundedOutputWriter{writer: &encoded, remaining: limit, limit: limit}
	if err := encode(&bounded); err != nil {
		return err
	}
	return writeOutput(outputPath, stdout, func(writer io.Writer) error {
		_, err := writer.Write(encoded.Bytes())
		return err
	})
}

func rejectOutputInputCollision(outputPath string, inputPaths ...string) error {
	if outputPath == "" || outputPath == "-" {
		return nil
	}
	output, err := os.Stat(outputPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect benchmark output path: %w", err)
	}
	for _, inputPath := range inputPaths {
		if inputPath == "" || inputPath == "-" {
			continue
		}
		input, err := os.Stat(inputPath)
		if err != nil {
			return fmt.Errorf("inspect benchmark input path %q: %w", inputPath, err)
		}
		if os.SameFile(output, input) {
			return fmt.Errorf("benchmark output path %q identifies input path %q", outputPath, inputPath)
		}
	}
	return nil
}

func writeOutput(outputPath string, stdout io.Writer, encode func(io.Writer) error) error {
	if outputPath == "" || outputPath == "-" {
		return encode(stdout)
	}
	directory := filepath.Dir(outputPath)
	stage, err := os.CreateTemp(directory, "."+filepath.Base(outputPath)+".tmp-")
	if err != nil {
		return fmt.Errorf("create benchmark output staging file: %w", err)
	}
	stagePath := stage.Name()
	defer func() { _ = os.Remove(stagePath) }()
	if err := encode(stage); err != nil {
		_ = stage.Close()
		return err
	}
	if err := stage.Sync(); err != nil {
		_ = stage.Close()
		return fmt.Errorf("sync benchmark output staging file: %w", err)
	}
	if err := stage.Close(); err != nil {
		return fmt.Errorf("close benchmark output staging file: %w", err)
	}
	if err := os.Rename(stagePath, outputPath); err != nil {
		return fmt.Errorf("publish benchmark output: %w", err)
	}
	if err := syncOutputDirectory(directory); err != nil {
		return err
	}
	return nil
}

func syncOutputDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open benchmark output directory: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync benchmark output directory: %w", err)
	}
	return nil
}

func decodeCatalogFile(path string) (scabench.Catalog, error) {
	file, err := os.Open(path)
	if err != nil {
		return scabench.Catalog{}, fmt.Errorf("open catalog: %w", err)
	}
	defer func() { _ = file.Close() }()
	catalog, err := scabench.DecodeCatalog(file)
	if err != nil {
		return scabench.Catalog{}, err
	}
	return catalog, nil
}

func decodeOracleFile(path string) (scabench.Oracle, error) {
	file, err := os.Open(path)
	if err != nil {
		return scabench.Oracle{}, fmt.Errorf("open oracle: %w", err)
	}
	defer func() { _ = file.Close() }()
	oracle, err := scabench.DecodeOracle(file)
	if err != nil {
		return scabench.Oracle{}, err
	}
	return oracle, nil
}

func decodeRatchetFile(path string) (scabench.Ratchet, error) {
	file, err := os.Open(path)
	if err != nil {
		return scabench.Ratchet{}, fmt.Errorf("open ratchet: %w", err)
	}
	defer func() { _ = file.Close() }()
	ratchet, err := scabench.DecodeRatchet(file)
	if err != nil {
		return scabench.Ratchet{}, err
	}
	return ratchet, nil
}

func decodeObservationFile(path string) (scabench.ObservationSet, error) {
	file, err := os.Open(path)
	if err != nil {
		return scabench.ObservationSet{}, fmt.Errorf("open observation: %w", err)
	}
	defer func() { _ = file.Close() }()
	set, err := scabench.DecodeObservationSet(file)
	if err != nil {
		return scabench.ObservationSet{}, err
	}
	return set, nil
}

func decodeResultFile(path string) (scabench.Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return scabench.Result{}, fmt.Errorf("open result: %w", err)
	}
	defer func() { _ = file.Close() }()
	result, err := scabench.DecodeResult(file)
	if err != nil {
		return scabench.Result{}, err
	}
	return result, nil
}

func encodeJSON(value any) func(io.Writer) error {
	return func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	}
}

// compareFinding is the explicit input shape for compare modes. Its unmarshaler validates field names
// case-sensitively so malformed findings cannot be silently dropped by encoding/json.
type compareFinding struct {
	Component string
	ID        string
	Aliases   []string
}

func (finding *compareFinding) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for key := range raw {
		switch key {
		case "component", "id", "aliases":
		default:
			return fmt.Errorf("compare finding: unexpected field %q (want component/id/aliases)", key)
		}
	}
	if value, exists := raw["component"]; exists {
		if err := json.Unmarshal(value, &finding.Component); err != nil {
			return err
		}
	}
	if value, exists := raw["id"]; exists {
		if err := json.Unmarshal(value, &finding.ID); err != nil {
			return err
		}
	}
	if value, exists := raw["aliases"]; exists {
		if err := json.Unmarshal(value, &finding.Aliases); err != nil {
			return err
		}
	}
	return nil
}

func readCompareJSON(input io.Reader, name string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(input, scabench.MaxJSONBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s input: %w", name, err)
	}
	if int64(len(body)) > scabench.MaxJSONBytes {
		return nil, fmt.Errorf("%s input exceeds %d byte limit", name, scabench.MaxJSONBytes)
	}
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("%s input is not valid UTF-8 JSON", name)
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, fmt.Errorf("%s input: %w", name, err)
	}
	return body, nil
}

func decodeCompareFindingSet(raw json.RawMessage) (compareFindingSet, error) {
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return compareFindingSet{}, fmt.Errorf("decode finding set: %w", err)
	}
	for key := range fields {
		switch key {
		case "name", "input_identity", "findings":
		default:
			return compareFindingSet{}, fmt.Errorf("unexpected field %q", key)
		}
	}
	var set compareFindingSet
	if err := decodeCompareField(fields, "name", &set.Name); err != nil {
		return compareFindingSet{}, err
	}
	if rawIdentity, exists := fields["input_identity"]; exists {
		identity, err := decodeCompareInputIdentity(rawIdentity)
		if err != nil {
			return compareFindingSet{}, err
		}
		set.InputIdentity = identity
	}
	if err := decodeCompareField(fields, "findings", &set.Findings); err != nil {
		return compareFindingSet{}, err
	}
	return set, nil
}

func decodeCompareInputIdentity(raw json.RawMessage) (enginecompare.InputIdentity, error) {
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return enginecompare.InputIdentity{}, fmt.Errorf("decode input identity: %w", err)
	}
	for key := range fields {
		switch key {
		case "catalog_revision", "catalog_digest", "target_digest", "sbom_digest":
		default:
			return enginecompare.InputIdentity{}, fmt.Errorf("input identity: unexpected field %q", key)
		}
	}
	var identity enginecompare.InputIdentity
	if err := decodeCompareField(fields, "catalog_revision", &identity.CatalogRevision); err != nil {
		return enginecompare.InputIdentity{}, err
	}
	if err := decodeCompareField(fields, "catalog_digest", &identity.CatalogDigest); err != nil {
		return enginecompare.InputIdentity{}, err
	}
	if err := decodeCompareField(fields, "target_digest", &identity.TargetDigest); err != nil {
		return enginecompare.InputIdentity{}, err
	}
	if err := decodeCompareField(fields, "sbom_digest", &identity.SBOMDigest); err != nil {
		return enginecompare.InputIdentity{}, err
	}
	return identity, nil
}

func decodeCompare(input io.Reader) (enginecompare.Report, error) {
	body, err := readCompareJSON(input, "compare")
	if err != nil {
		return enginecompare.Report{}, err
	}
	top := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &top); err != nil {
		return enginecompare.Report{}, fmt.Errorf("decode compare input: %w", err)
	}
	for key := range top {
		switch key {
		case "baseline_name", "candidate_name", "baseline", "candidate":
		default:
			return enginecompare.Report{}, fmt.Errorf("compare input: unexpected field %q", key)
		}
	}
	var baselineName, candidateName string
	var baseline, candidate []compareFinding
	if err := decodeCompareField(top, "baseline_name", &baselineName); err != nil {
		return enginecompare.Report{}, err
	}
	if err := decodeCompareField(top, "candidate_name", &candidateName); err != nil {
		return enginecompare.Report{}, err
	}
	if err := decodeCompareField(top, "baseline", &baseline); err != nil {
		return enginecompare.Report{}, err
	}
	if err := decodeCompareField(top, "candidate", &candidate); err != nil {
		return enginecompare.Report{}, err
	}
	return enginecompare.Compare(baselineName, candidateName, toRawFindings(baseline), toRawFindings(candidate)), nil
}

type compareFindingSet struct {
	Name          string
	InputIdentity enginecompare.InputIdentity
	Findings      []compareFinding
}

func (set *compareFindingSet) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for key := range raw {
		switch key {
		case "name", "input_identity", "findings":
		default:
			return fmt.Errorf("compare finding set: unexpected field %q (want name/input_identity/findings)", key)
		}
	}
	if value, exists := raw["name"]; exists {
		if err := json.Unmarshal(value, &set.Name); err != nil {
			return err
		}
	}
	if value, exists := raw["input_identity"]; exists {
		if err := json.Unmarshal(value, &set.InputIdentity); err != nil {
			return err
		}
	}
	if value, exists := raw["findings"]; exists {
		if err := json.Unmarshal(value, &set.Findings); err != nil {
			return err
		}
	}
	return nil
}

func decodeManyCompare(input io.Reader) (enginecompare.MultiReport, error) {
	body, err := readCompareJSON(input, "compare-many")
	if err != nil {
		return enginecompare.MultiReport{}, err
	}
	top := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &top); err != nil {
		return enginecompare.MultiReport{}, fmt.Errorf("decode compare-many input: %w", err)
	}
	for key := range top {
		switch key {
		case "candidate", "baselines":
		default:
			return enginecompare.MultiReport{}, fmt.Errorf("compare-many input: unexpected field %q", key)
		}
	}
	var candidate compareFindingSet
	if raw, exists := top["candidate"]; exists {
		candidate, err = decodeCompareFindingSet(raw)
		if err != nil {
			return enginecompare.MultiReport{}, fmt.Errorf("compare-many candidate: %w", err)
		}
	}
	var rawBaselines []json.RawMessage
	if err := decodeCompareField(top, "baselines", &rawBaselines); err != nil {
		return enginecompare.MultiReport{}, err
	}
	baselines := make([]compareFindingSet, 0, len(rawBaselines))
	for i, raw := range rawBaselines {
		baseline, err := decodeCompareFindingSet(raw)
		if err != nil {
			return enginecompare.MultiReport{}, fmt.Errorf("compare-many baseline %d: %w", i, err)
		}
		baselines = append(baselines, baseline)
	}
	candidateSet := enginecompare.EngineFindingSet{Name: candidate.Name, InputIdentity: candidate.InputIdentity, Findings: toRawFindings(candidate.Findings)}
	baselineSets := make([]enginecompare.EngineFindingSet, 0, len(baselines))
	for _, baseline := range baselines {
		baselineSets = append(baselineSets, enginecompare.EngineFindingSet{Name: baseline.Name, InputIdentity: baseline.InputIdentity, Findings: toRawFindings(baseline.Findings)})
	}
	report, err := enginecompare.CompareMany(candidateSet, baselineSets)
	if err != nil {
		return enginecompare.MultiReport{}, fmt.Errorf("compare-many input: %w", err)
	}
	return report, nil
}

func decodeCompareField(values map[string]json.RawMessage, key string, destination any) error {
	value, exists := values[key]
	if !exists {
		return nil
	}
	if err := json.Unmarshal(value, destination); err != nil {
		return fmt.Errorf("compare input field %q: %w", key, err)
	}
	return nil
}

func toRawFindings(findings []compareFinding) []vulnerability.RawFinding {
	out := make([]vulnerability.RawFinding, 0, len(findings))
	for _, finding := range findings {
		out = append(out, vulnerability.RawFinding{Component: finding.Component, AdvisoryID: finding.ID, Aliases: finding.Aliases})
	}
	return out
}

// rejectDuplicateJSONKeys rejects a repeat within one JSON object at any depth.
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeCompareJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("JSON input must contain exactly one top-level value")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

// simpleCaseFoldKey canonicalizes Unicode simple-fold equivalence classes, matching the
// case-insensitive matching semantics used by encoding/json without an O(n²) key scan.
func simpleCaseFoldKey(value string) string {
	var folded strings.Builder
	folded.Grow(len(value))
	for _, runeValue := range value {
		canonical := runeValue
		for next := unicode.SimpleFold(runeValue); next != runeValue; next = unicode.SimpleFold(next) {
			if next < canonical {
				canonical = next
			}
		}
		folded.WriteRune(canonical)
	}
	return folded.String()
}

func consumeCompareJSONValue(decoder *json.Decoder, depth int) error {
	if depth >= maxCompareJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxCompareJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]string)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			folded := simpleCaseFoldKey(key)
			if prior, exists := seen[folded]; exists {
				if prior == key {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				return fmt.Errorf("case-fold duplicate JSON keys %q and %q", prior, key)
			}
			seen[folded] = key
			if err := consumeCompareJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeCompareJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delimiter)
	}
	return nil
}
