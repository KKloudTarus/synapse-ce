package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

const unmatchedRoute = "unmatched"

type requestIDKey struct{}
type requestLoggerKey struct{}
type requestObservationKey struct{}

// HTTPObserver receives bounded HTTP request measurements. It deliberately has
// no Prometheus dependency so the HTTP adapter remains transport-neutral.
type HTTPObserver interface {
	ObserveHTTPRequest(method, route, statusClass string, duration time.Duration)
}

// RequestIDFrom returns the server-generated request correlation ID.
func RequestIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey{}).(string)
	return id, ok && id != ""
}

// LoggerFrom returns the request-scoped logger, which includes the request ID.
// It returns false for contexts not created by Instrument.
func LoggerFrom(ctx context.Context) (*slog.Logger, bool) {
	log, ok := ctx.Value(requestLoggerKey{}).(*slog.Logger)
	return log, ok && log != nil
}

type requestObservation struct {
	mu          sync.RWMutex
	principalID string
}

func requestObservationFrom(ctx context.Context) *requestObservation {
	state, _ := ctx.Value(requestObservationKey{}).(*requestObservation)
	return state
}

func (o *requestObservation) setPrincipal(id string) {
	if o == nil || id == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.principalID = id
}

func (o *requestObservation) principal() string {
	if o == nil {
		return ""
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.principalID
}

type responseRecorder struct {
	http.ResponseWriter
	log    *slog.Logger
	status int
}

type requestLoggerResponseWriter interface {
	requestLogger() *slog.Logger
}

func (w *responseRecorder) requestLogger() *slog.Logger { return w.log }

func (w *responseRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the original writer without a
// buffer, preserving streaming behavior through this observability wrapper.
func (w *responseRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type flushingResponseRecorder struct{ *responseRecorder }

func (w *flushingResponseRecorder) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.ResponseWriter.(http.Flusher).Flush()
}

// normalizeMethod bounds method cardinality in metrics and access logs.
func normalizeMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

// Instrument wraps the complete normalized API handler exactly once. It avoids
// recording unbounded request data and emits a single access event after every
// request when enabled.
func Instrument(next http.Handler, log *slog.Logger, accessLogEnabled bool, observer HTTPObserver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		requestID := uuid.NewString()
		requestLog := log
		if requestLog != nil {
			requestLog = requestLog.With("request_id", requestID)
		}
		state := &requestObservation{}
		ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
		if requestLog != nil {
			ctx = context.WithValue(ctx, requestLoggerKey{}, requestLog)
		}
		ctx = context.WithValue(ctx, requestObservationKey{}, state)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", requestID)
		recorder := &responseRecorder{ResponseWriter: w, log: requestLog}
		var observedWriter http.ResponseWriter = recorder
		if _, ok := w.(http.Flusher); ok {
			observedWriter = &flushingResponseRecorder{responseRecorder: recorder}
		}

		finalize := func() {
			status := recorder.status
			if status == 0 {
				status = http.StatusOK
			}
			route := r.Pattern
			if route == "" {
				route = unmatchedRoute
			}
			method := normalizeMethod(r.Method)
			duration := time.Since(started)
			statusClass := string([]byte{byte('0' + status/100), 'x', 'x'})
			if observer != nil {
				observer.ObserveHTTPRequest(method, route, statusClass, duration)
			}
			if accessLogEnabled && requestLog != nil {
				attrs := []any{
					"method", method,
					"route", route,
					"status", status,
					"duration_ms", duration.Milliseconds(),
				}
				if principalID := state.principal(); principalID != "" {
					attrs = append(attrs, "principal_id", principalID)
				}
				requestLog.Info("http access", attrs...)
			}
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				// A response may already have started, but the observation must still
				// classify the failed handler as a 500 before propagating its panic.
				if recorder.status == 0 {
					recorder.WriteHeader(http.StatusInternalServerError)
				} else {
					recorder.status = http.StatusInternalServerError
				}
				if requestLog != nil {
					requestLog.Error("http handler panic")
				}
				finalize()
				panic(recovered)
			}
			finalize()
		}()
		next.ServeHTTP(observedWriter, r)
	})
}
