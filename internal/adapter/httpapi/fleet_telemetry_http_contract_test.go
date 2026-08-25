package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFleetTelemetryUnsupportedContentEncodingMapsTo415(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", strings.NewReader(`{}`))
	r.Header.Set("Content-Encoding", "br")
	w := httptest.NewRecorder()

	_, err := readFleetTelemetryBody(w, r)
	if !errors.Is(err, errFleetTelemetryUnsupportedEncoding) {
		t.Fatalf("read error = %v, want unsupported encoding", err)
	}

	resp := httptest.NewRecorder()
	writeFleetTelemetryBodyError(resp, err, "batch")
	if resp.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusUnsupportedMediaType)
	}
}

func TestFleetTelemetryWireLimitMapsTo413(t *testing.T) {
	body := bytes.NewReader(bytes.Repeat([]byte{'x'}, fleetTelemetryWireCap+1))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", body)
	w := httptest.NewRecorder()

	_, err := readFleetTelemetryBody(w, r)
	var maxBytes *http.MaxBytesError
	if !errors.As(err, &maxBytes) {
		t.Fatalf("read error = %v, want *http.MaxBytesError", err)
	}

	resp := httptest.NewRecorder()
	writeFleetTelemetryBodyError(resp, err, "batch")
	if resp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestFleetTelemetryMediaTypeNormalization(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", nil)
	r.Header.Set("Content-Type", " Application/JSON ; charset=utf-8 ")
	if got := requestMediaType(r); got != fleetTelemetryJSONMediaType {
		t.Fatalf("media type = %q, want %q", got, fleetTelemetryJSONMediaType)
	}
}

func TestFleetTelemetryMissingMediaTypeDefaultsToJSON(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", nil)
	if got := requestMediaType(r); got != fleetTelemetryJSONMediaType {
		t.Fatalf("media type = %q, want default %q", got, fleetTelemetryJSONMediaType)
	}
}

func TestFleetTelemetryExplicitUnsupportedMediaTypeDoesNotDefault(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", nil)
	r.Header.Set("Content-Type", "application/xml")
	if got := requestMediaType(r); got != "application/xml" {
		t.Fatalf("media type = %q, want explicit unsupported media type preserved", got)
	}
}
