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

// importSARIF ingests a third-party SARIF report from the command line, through the SAME usecase the
// HTTP endpoint uses — so the governance rules cannot differ between the two entry points.
//
// It prints the result as JSON on stdout, including every refusal, because a silent refusal is
// indistinguishable from a clean ingest.
func importSARIF(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: synapse-cli import-sarif <engagement-id> <report.sarif>|- [--actor <id>]")
	}
	engagementID := shared.ID(args[0])
	source := args[1]

	actor := shared.ID("cli:operator")
	for i := 2; i+1 < len(args); i++ {
		if args[i] == "--actor" {
			actor = shared.ID(args[i+1])
		}
	}

	document, err := readSARIFDocument(source)
	if err != nil {
		return err
	}

	// The CLI persists in memory: it exists to validate a report and show exactly what the server would
	// accept or refuse, without needing a database.
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

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("write ingest result: %w", err)
	}
	// A report whose results were all refused is not a successful ingest.
	if result.Accepted == 0 && len(result.Refused) > 0 {
		return fmt.Errorf("no result could be ingested: %d refused", len(result.Refused))
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
