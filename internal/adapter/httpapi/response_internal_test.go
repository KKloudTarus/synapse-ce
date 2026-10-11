package httpapi

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// This mirrors the internal-only marker used by infrastructure import errors.
// Even a nested validation sentinel must not downgrade an internal failure
// into a public 400 containing the underlying diagnostic.
type ciImportInternalHTTPTestError struct{ cause error }

func (e ciImportInternalHTTPTestError) Error() string {
	return "audit imported analysis failed: " + e.cause.Error()
}
func (e ciImportInternalHTTPTestError) Unwrap() error { return e.cause }
func (ciImportInternalHTTPTestError) InternalOnly()   {}

func TestWriteErrorMasksInternalImportFailureWithWrappedValidation(t *testing.T) {
	root := fmt.Errorf("%w: dial tcp 10.0.0.5:5432: connection refused", shared.ErrValidation)
	err := fmt.Errorf("CI import: %w", ciImportInternalHTTPTestError{cause: root})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatal("fixture should expose the nested validation sentinel")
	}
	var logs bytes.Buffer
	recorder := httptest.NewRecorder()
	writeError(recorder, slog.New(slog.NewTextHandler(&logs, nil)), err)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("HTTP status=%d, want 500", recorder.Code)
	}
	if got := recorder.Body.String(); !strings.Contains(got, "\"internal error\"") || strings.Contains(got, "dial tcp") {
		t.Fatalf("internal cause escaped into HTTP response: %s", got)
	}
	if got := logs.String(); !strings.Contains(got, "audit imported analysis failed") || !strings.Contains(got, "dial tcp") {
		t.Fatalf("diagnostic cause lost from server log: %s", got)
	}
}
