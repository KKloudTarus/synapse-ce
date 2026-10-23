package docpublish

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type failingCommandListStore struct {
	ports.DocumentCommandStore
	commands []ports.DocumentCommand
}

func (s failingCommandListStore) ListDocumentCommands(context.Context, shared.ID, int, time.Time) ([]ports.DocumentCommand, error) {
	return s.commands, nil
}

func (s failingCommandListStore) GetDocumentCommand(ctx context.Context, tenant, id shared.ID) (ports.DocumentCommand, error) {
	if id == "unavailable" {
		return ports.DocumentCommand{}, errors.New("sensitive provider failure detail")
	}
	return s.DocumentCommandStore.GetDocumentCommand(ctx, tenant, id)
}

func TestDocumentTickReportsSafeFailureAndContinuesIndependentCommands(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	broken := command
	broken.Intent.ID = "unavailable"
	f.service.store = failingCommandListStore{DocumentCommandStore: f.store, commands: []ports.DocumentCommand{broken, command}}
	for tick := 0; tick < 16; tick++ {
		err = f.service.Tick(context.Background(), "tenant", 20)
		if err == nil || strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("tick %d failure was swallowed or unsafe: %v", tick, err)
		}
	}
	done, err := f.store.GetIntent(context.Background(), "tenant", intent.ID)
	if err != nil || done.State != writeintent.Done {
		t.Fatalf("independent command did not finish: %+v, %v", done, err)
	}
}
