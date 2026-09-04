package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	rollout "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentrollout"
)

const maxRolloutSnapshotBytes = 1 << 20

var errRolloutGateRejected = errors.New("assessment rollout gate rejected")

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("synapse-assessment-rollout-gate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	phaseValue := flags.String("phase", "", "internal_canary, opt_in_canary, read_cutover, ui_default, or rollback_drill")
	inputPath := flags.String("input", "-", "JSON rollout snapshot path, or - for stdin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	phase := rollout.Phase(strings.TrimSpace(*phaseValue))
	if !phase.Valid() {
		return errors.New("--phase is required and must name a supported rollout phase")
	}

	reader := stdin
	var file *os.File
	if path := strings.TrimSpace(*inputPath); path != "-" {
		if path == "" {
			return errors.New("--input must be a file path or -")
		}
		var err error
		file, err = os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		reader = file
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxRolloutSnapshotBytes+1))
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > maxRolloutSnapshotBytes {
		return fmt.Errorf("rollout snapshot must contain between 1 and %d bytes", maxRolloutSnapshotBytes)
	}
	var snapshot rollout.Snapshot
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("decode rollout snapshot: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("rollout snapshot must contain exactly one JSON object")
	}
	decision, err := rollout.Evaluate(phase, snapshot)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(decision); err != nil {
		return err
	}
	if !decision.Allowed {
		return errRolloutGateRejected
	}
	return nil
}
