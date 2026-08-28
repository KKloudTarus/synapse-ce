package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
)

const (
	fleetTelemetryWireCap       = 8 << 20
	fleetTelemetryDecodedCap    = 32 << 20
	fleetTelemetryJSONMediaType = "application/json"
	fleetTelemetryGapMediaType  = "application/vnd.synapse.telemetry-gap+json"
	fleetSensorStateMediaType   = "application/vnd.synapse.sensor-state+json"
)

var (
	errFleetTelemetryUnsupportedEncoding = errors.New("unsupported telemetry content encoding")
	errFleetTelemetryDecodedTooLarge     = errors.New("telemetry request exceeds decoded limit")
)

// fleetTelemetryIngest is the narrow agent-plane telemetry ingest surface the handler consumes.
type fleetTelemetryIngest interface {
	Ingest(ctx context.Context, authAgentID shared.ID, req telemetryingest.IngestRequest) (telemetryingest.IngestResult, error)
	IngestGap(ctx context.Context, authAgentID shared.ID, report fleetagent.TelemetryGapReport) (telemetryingest.GapIngestResult, error)
	IngestSensorState(ctx context.Context, authAgentID shared.ID, report fleetagent.SensorStateReport) (telemetryingest.SensorStateIngestResult, error)
}

// ingestTelemetry is the agent-plane endpoint (POST /api/v1/fleet/telemetry). Batch JSON and signed
// durable-loss reports share the authenticated endpoint but use distinct media types and domain-separated
// signatures. The HTTP layer accepts raw or gzip JSON, bounds both compressed and decoded sizes, and
// rejects trailing/unknown fields before the use case reaches the trust boundary.
func (f *fleetRouter) ingestTelemetry(w http.ResponseWriter, r *http.Request) {
	if requestMediaType(r) == fleetTelemetryGapMediaType {
		f.ingestTelemetryGap(w, r)
		return
	}
	if f.telemetry == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "telemetry ingest not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	if requestMediaType(r) != fleetTelemetryJSONMediaType {
		writeJSON(w, http.StatusUnsupportedMediaType, errorBody{Error: "unsupported telemetry media type"})
		return
	}
	body, err := readFleetTelemetryBody(w, r)
	if err != nil {
		writeFleetTelemetryBodyError(w, err, "batch")
		return
	}
	var req telemetryingest.IngestRequest
	if err := decodeStrictFleetTelemetry(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry batch body"})
		return
	}
	res, err := f.telemetry.Ingest(r.Context(), agent.ID, req)
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":   res.Accepted,
		"duplicate":  res.Duplicate,
		"ack":        res.ACK,
		"provenance": res.Provenance,
		"gap_open":   res.GapOpen,
	})
}

// ingestTelemetryGap handles the gap-report media type. A successful response acknowledges the exact
// stable GapID only after the signed report has passed the server-authoritative trust boundary and been
// durably persisted.
// ingestSensorState accepts signed P0 health facts. It shares the same size and
// decompression guards as telemetry but has a dedicated media type and signature.
func (f *fleetRouter) ingestSensorState(w http.ResponseWriter, r *http.Request) {
	if f.telemetry == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "sensor-state ingest not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	if requestMediaType(r) != fleetSensorStateMediaType {
		writeJSON(w, http.StatusUnsupportedMediaType, errorBody{Error: "unsupported sensor-state media type"})
		return
	}
	body, err := readFleetTelemetryBody(w, r)
	if err != nil {
		writeFleetTelemetryBodyError(w, err, "sensor-state")
		return
	}
	var report fleetagent.SensorStateReport
	if err := decodeStrictFleetTelemetry(body, &report); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid sensor-state body"})
		return
	}
	res, err := f.telemetry.IngestSensorState(r.Context(), agent.ID, report)
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true, "report_id": res.ReportID})
}

func (f *fleetRouter) ingestTelemetryGap(w http.ResponseWriter, r *http.Request) {
	if f.telemetry == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "telemetry ingest not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	body, err := readFleetTelemetryBody(w, r)
	if err != nil {
		writeFleetTelemetryBodyError(w, err, "gap")
		return
	}
	var report fleetagent.TelemetryGapReport
	if err := decodeStrictFleetTelemetry(body, &report); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry gap body"})
		return
	}
	res, err := f.telemetry.IngestGap(r.Context(), agent.ID, report)
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged": true,
		"gap_id":       res.GapID,
	})
}

func requestMediaType(r *http.Request) string {
	mediaType := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Type")))
	if mediaType == "" {
		// Backward compatibility: legacy fleet clients sent batch JSON without an explicit
		// Content-Type. Treat absence as the default batch representation while still
		// rejecting any explicitly unsupported media type with 415.
		return fleetTelemetryJSONMediaType
	}
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = strings.TrimSpace(mediaType[:i])
	}
	return mediaType
}

func writeFleetTelemetryBodyError(w http.ResponseWriter, err error, kind string) {
	var maxBytes *http.MaxBytesError
	switch {
	case errors.Is(err, errFleetTelemetryUnsupportedEncoding):
		writeJSON(w, http.StatusUnsupportedMediaType, errorBody{Error: "unsupported telemetry content encoding"})
	case errors.Is(err, errFleetTelemetryDecodedTooLarge), errors.As(err, &maxBytes):
		writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "telemetry request too large"})
	default:
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry " + kind + " body"})
	}
}

func readFleetTelemetryBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	raw := http.MaxBytesReader(w, r.Body, fleetTelemetryWireCap)
	var reader io.Reader = raw
	var closeGzip func() error
	switch enc := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Encoding"))); enc {
	case "":
	case "gzip":
		zr, err := gzip.NewReader(raw)
		if err != nil {
			return nil, err
		}
		reader = zr
		closeGzip = zr.Close
	default:
		return nil, fmt.Errorf("%w: %q", errFleetTelemetryUnsupportedEncoding, enc)
	}
	if closeGzip != nil {
		defer func() { _ = closeGzip() }()
	}
	payload, err := io.ReadAll(io.LimitReader(reader, fleetTelemetryDecodedCap+1))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, errors.New("empty telemetry request")
	}
	if len(payload) > fleetTelemetryDecodedCap {
		return nil, errFleetTelemetryDecodedTooLarge
	}
	return payload, nil
}

func decodeStrictFleetTelemetry(body []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
