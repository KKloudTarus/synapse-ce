package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sarifingest"
)

// validateSARIF runs a third-party SARIF report through the SAME usecase the HTTP endpoint uses, so the
// governance rules cannot differ between the two entry points — but it writes NOTHING to a server.
//
// That distinction is the whole point of the command's honesty contract: it exists to show exactly what
// the server would accept and refuse, and it says so in its own output. A command that printed
// `{"accepted": 12}` while persisting to a store discarded at process exit would be indistinguishable
// from a real ingest, which is the same failure mode this package refuses everywhere else.
func validateSARIF(args []string) error {
	if len(args) < 2 {
		// The usage line states the honesty contract up front: this command validates, it does not
		// ingest. An operator must not be able to believe a report reached an engagement when it did not.
		fmt.Fprintln(os.Stderr,
			"usage: synapse-cli validate-sarif <engagement-id> <report.sarif>|- [--actor <id>] [--fail-on-refusal]\n"+
				"  Validates a SARIF report locally and reports what the server would accept or refuse.\n"+
				"  It does NOT write to the server; use POST /api/v1/engagements/{id}/sarif to ingest.")
		return fmt.Errorf("validate-sarif needs an engagement id and a report path")
	}
	engagementID := shared.ID(args[0])
	source := args[1]

	// The actor is a LOCAL label only: nothing is persisted, so it cannot stamp a real provenance
	// record. The server takes the ingesting actor from the authenticated principal, never from input.
	actor := shared.ID("cli:validator")
	failOnRefusal := false
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--actor":
			if i+1 >= len(args) {
				return fmt.Errorf("--actor needs a value")
			}
			actor = shared.ID(args[i+1])
			i++
		case "--fail-on-refusal":
			failOnRefusal = true
		default:
			// An unknown flag is refused rather than ignored: a mistyped --fail-on-refusals would
			// otherwise silently disable the gate a pipeline is relying on.
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}

	document, err := readSARIFDocument(source)
	if err != nil {
		return err
	}

	// Validate cannot persist: it takes no store, no tenant and no actor. The engagement id is echoed
	// back so the operator can see which engagement they were aiming at, and nothing more.
	result, err := sarifingest.Validate(context.Background(), document, sarifingest.DefaultLimits())
	if err != nil {
		return err
	}

	payload := validationPayload{
		Persisted:  false,
		Note:       "validation only - nothing was written to a server and no audit entry was recorded",
		Engagement: engagementID.String(),
		Actor:      actor.String(),
		Accepted:   result.Accepted,
		Coverage:   make([]string, 0, len(result.Coverage)),
		Refused:    make([]refusalPayload, 0, len(result.Refused)),
	}
	for _, issue := range result.Coverage {
		payload.Coverage = append(payload.Coverage, issue.Detail)
	}
	for _, refusal := range result.Refused {
		payload.Refused = append(payload.Refused, refusalPayload{
			RunIndex: refusal.RunIndex, ResultIndex: refusal.ResultIndex,
			Code: string(refusal.Code), Detail: refusal.Detail,
		})
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return fmt.Errorf("write validation result: %w", err)
	}

	// A report whose results were ALL refused is not a usable report.
	if result.Accepted == 0 && len(result.Refused) > 0 {
		return fmt.Errorf("no result could be ingested: %d refused", len(result.Refused))
	}
	// With --fail-on-refusal a partial refusal is a failure too, so a pipeline can insist that every
	// result be attributable rather than silently shipping the ones that happened to survive.
	if failOnRefusal && len(result.Refused) > 0 {
		return fmt.Errorf("%d of %d results were refused (--fail-on-refusal)", len(result.Refused), len(result.Refused)+result.Accepted)
	}
	return nil
}

// validationPayload is the CLI's own wire format.
//
// It is declared explicitly rather than embedding the use case result: embedding produced BOTH a tagged
// "coverage" and an untagged "Coverage" in the same object, and CamelCase keys that contradicted the
// HTTP contract's snake_case. A wire format is a contract and gets written down.
type validationPayload struct {
	Persisted  bool             `json:"persisted"`
	Note       string           `json:"note"`
	Engagement string           `json:"engagement_id"`
	Actor      string           `json:"actor"`
	Accepted   int              `json:"would_accept"`
	Coverage   []string         `json:"coverage"`
	Refused    []refusalPayload `json:"refused"`
}

type refusalPayload struct {
	RunIndex    int    `json:"run_index"`
	ResultIndex int    `json:"result_index"`
	Code        string `json:"code"`
	Detail      string `json:"detail"`
}

// readSARIFDocument reads the report from a file or stdin, bounded like the server path.
//
// It reads one byte past the bound so an oversized report is DETECTED, and reports the real size rather
// than the truncated read length — an error whose job is to be honest about what was refused must not
// invent the number it names.
func readSARIFDocument(source string) ([]byte, error) {
	if source == "-" {
		return boundedRead(os.Stdin, "standard input")
	}
	f, err := os.Open(source)
	if err != nil {
		return nil, fmt.Errorf("open sarif report: %w", err)
	}
	defer func() { _ = f.Close() }()
	if info, statErr := f.Stat(); statErr == nil && info.Size() > sarifingest.DefaultMaxDocumentBytes {
		return nil, fmt.Errorf("%w: sarif report is %d bytes, over the %d byte bound; nothing was validated",
			shared.ErrValidation, info.Size(), sarifingest.DefaultMaxDocumentBytes)
	}
	return boundedRead(f, source)
}

func boundedRead(r io.Reader, name string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, sarifingest.DefaultMaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read sarif report: %w", err)
	}
	if len(data) > sarifingest.DefaultMaxDocumentBytes {
		return nil, fmt.Errorf("%w: %s holds more than the %d byte bound; nothing was validated",
			shared.ErrValidation, name, sarifingest.DefaultMaxDocumentBytes)
	}
	return data, nil
}
