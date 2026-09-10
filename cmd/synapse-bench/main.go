// Command synapse-bench reduces supplied benchmark fixture observations into a deterministic report.
// It does not execute workloads, provision infrastructure, or contact external services.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

func main() {
	inputPath := flag.String("input", "", "versioned benchmark input JSON")
	outputPath := flag.String("output", "", "output benchmark report JSON (default: stdout)")
	mode := flag.String("mode", "throughput", "reduction mode: throughput (latency/throughput) or accuracy (detection precision/recall)")
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
	default:
		return fmt.Errorf("unknown mode %q (want throughput or accuracy)", mode)
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
