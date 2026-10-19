package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestProjectSourceFindingResponseOmitsHiddenEngagementID(t *testing.T) {
	view := sourceFindingResponse(finding.Finding{ID: "finding", EngagementID: "hidden-context", Title: "Finding"})
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := view["EngagementID"]; found || string(raw) == "" || containsJSONKey(raw, "engagement_id") {
		t.Fatalf("source finding leaked hidden context: %s", raw)
	}
}

func containsJSONKey(raw []byte, key string) bool {
	var value map[string]any
	return json.Unmarshal(raw, &value) == nil && value[key] != nil
}

func TestProjectSourceJobKeepsPrivateExecutionDiagnosticsInternal(t *testing.T) {
	raw, err := json.Marshal(projectSourceScanJob(ports.ScanJob{ID: "public-job", EngagementID: "private-context", Error: "engagement private-context authorization expired", DebugEvents: []ports.ScanDebugEvent{{Step: "private-context"}}}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private-context") || !strings.Contains(string(raw), "execution authorization") {
		t.Fatalf("unsafe source job response: %s", raw)
	}
}

func TestProjectSourceAdmissionErrorPreservesCategoryWithoutPrivateContext(t *testing.T) {
	for _, category := range []error{shared.ErrForbidden, shared.ErrValidation, shared.ErrNotFound, shared.ErrConflict} {
		err := projectSourcePublicError(fmt.Errorf("engagement private-context: %w", category))
		if !errors.Is(err, category) || strings.Contains(err.Error(), "private-context") {
			t.Fatalf("unsafe admission error: %v", err)
		}
	}
}

func TestProjectSourceDelegatedErrorOmitsHiddenContext(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeError(projectSourceResponseWriter{recorder}, slog.New(slog.NewTextHandler(io.Discard, nil)), fmt.Errorf("finding hostile-id in engagement private-context: %w", shared.ErrNotFound))
	if recorder.Code != 404 || strings.Contains(recorder.Body.String(), "private-context") || !strings.Contains(recorder.Body.String(), "not_found") {
		t.Fatalf("unsafe delegated response: %d %s", recorder.Code, recorder.Body.String())
	}
}
