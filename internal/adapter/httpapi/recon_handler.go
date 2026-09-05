package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// maxLogStreamDuration backstops an SSE connection so it can't live forever (a run
// finishes/fails well within the recon timeout; this guards orphaned/abnormal cases).
const maxLogStreamDuration = 30 * time.Minute

// listReconTools returns the registered recon-tool catalog (name, gate action,
// accepted target kinds, capability-sensitive flag) for the launcher UI.
func (rt *Router) listReconTools(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, rt.recon.Tools())
}

// startReconRun launches a recon run against an in-scope target. The use case
// authorizes through the execution guard and only runs argv derived from the
// target; an out-of-scope target / disabled live-recon / wrong kind is rejected.
func (rt *Router) startReconRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	var body struct {
		Tool   string `json:"tool"`
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	run, err := rt.recon.Start(r.Context(), PrincipalFrom(r.Context()), shared.ID(id), body.Tool, body.Target)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

// listReconRuns returns an engagement's recon runs, newest first.
func (rt *Router) listReconRuns(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	runs, err := rt.recon.List(r.Context(), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

// getReconRun returns a single run, verifying it belongs to the path engagement.
func (rt *Router) getReconRun(w http.ResponseWriter, r *http.Request) {
	run, ok := rt.lookupRun(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// streamReconLogs tails a run's logs as Server-Sent Events. Browsers' EventSource
// can't send the bearer header, so the UI consumes this with fetch + a stream
// reader; reconnect-replay is supported via the Last-Event-ID header or a
// ?lastEventId query param (the broker replays buffered events after that id).
func (rt *Router) streamReconLogs(w http.ResponseWriter, r *http.Request) {
	run, ok := rt.lookupRun(w, r)
	if !ok {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "streaming unsupported"})
		return
	}

	// An already-terminal run's stream may never have been Closed (e.g. orphaned by a
	// crash between enqueue and execute); close it defensively so the subscriber gets
	// a Done and the loop ends rather than blocking on a stream that never finishes.
	if run.Status.Terminal() {
		rt.logs.Close(run.ID.String())
	}

	after := lastEventID(r)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering so events flush
	// The stream may run for its full ceiling, which is longer than the listener write timeout.
	releaseWriteDeadline(w)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx, cancelTimeout := context.WithTimeout(r.Context(), maxLogStreamDuration)
	defer cancelTimeout()
	events, cancel := rt.logs.Subscribe(run.ID.String(), after)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case e, open := <-events:
			if !open {
				return
			}
			if e.Done {
				_, _ = fmt.Fprintf(w, "id: %d\nevent: done\ndata: {}\n\n", e.ID)
			} else {
				payload, _ := json.Marshal(e)
				_, _ = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", e.ID, payload)
			}
			flusher.Flush()
		}
	}
}

// lookupRun loads the run named by {rid} and verifies it belongs to {id}; it writes
// the error/404 response and returns ok=false on any miss (no cross-engagement read).
func (rt *Router) lookupRun(w http.ResponseWriter, r *http.Request) (recon.Run, bool) {
	id := r.PathValue("id")
	rid := r.PathValue("rid")
	got, err := rt.recon.Get(r.Context(), shared.ID(rid))
	if err != nil {
		writeError(w, rt.log, err)
		return recon.Run{}, false
	}
	if string(got.EngagementID) != id {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "recon run not found for this engagement"})
		return recon.Run{}, false
	}
	return got, true
}

func lastEventID(r *http.Request) int {
	raw := r.Header.Get("Last-Event-ID")
	if raw == "" {
		raw = r.URL.Query().Get("lastEventId")
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return n
	}
	return 0
}
