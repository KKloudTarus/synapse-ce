package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
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
		}
	}

	document, err := readSARIFDocument(source)
	if err != nil {
		return err
	}

	store := memory.NewImportedFindingStore()
	service, err := sarifingest.NewService(store, nil, cliAuditLog{}, cliClock{}, idgen.RandomID{})
	if err != nil {
		return err
	}
	result, err := service.Ingest(context.Background(), sarifingest.IngestRequest{
		TenantID:     shared.DefaultTenant,
		EngagementID: engagementID,
		Document:     document,
		Actor:        actor,
	})
	if err != nil {
		return err
	}

	coverage := make([]string, 0, len(result.Coverage))
	for _, issue := range result.Coverage {
		coverage = append(coverage, issue.Detail)
	}
	if result.Accepted == 0 && len(result.Refused) == 0 {
		coverage = append(coverage, "the document declared no results; nothing was validated")
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(struct {
		Persisted bool     `json:"persisted"`
		Note      string   `json:"note"`
		Coverage  []string `json:"coverage"`
		sarifingest.IngestResult
	}{
		Persisted:    false,
		Note:         "validation only - nothing was written to a server and no audit entry was recorded",
		Coverage:     coverage,
		IngestResult: result,
	}); err != nil {
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

// readSARIFDocument reads the report from a file or stdin, bounded like the server path.
func readSARIFDocument(source string) ([]byte, error) {
	if source == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, sarifingest.DefaultMaxDocumentBytes+1))
	}
	f, err := os.Open(source)
	if err != nil {
		return nil, fmt.Errorf("open sarif report: %w", err)
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, sarifingest.DefaultMaxDocumentBytes+1))
}

type cliAuditLog struct{}

func (cliAuditLog) Record(context.Context, ports.AuditEntry) error { return nil }

type cliClock struct{}

func (cliClock) Now() time.Time { return time.Now().UTC() }
