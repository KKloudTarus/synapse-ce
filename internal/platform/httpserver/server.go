// Package httpserver runs an HTTP server with graceful shutdown.
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Run starts the HTTP server and blocks until ctx is cancelled, then shuts down
// gracefully within a 10s timeout.
func Run(ctx context.Context, addr string, handler http.Handler, log *slog.Logger) error {
	return RunPair(ctx, addr, handler, "", nil, log)
}

// Timeouts bound a connection's lifetime. Zero fields take the package defaults.
//
// ReadHeaderTimeout is the slowloris guard and is always applied. WriteTimeout in Go
// covers the span from the end of the request headers to the end of the response write,
// so it also bounds reading a large request body: the default is generous enough for a
// retained source archive on a slow link while still reaping a stuck connection.
// ReadTimeout is deliberately left unset for that same reason.
type Timeouts struct {
	ReadHeader time.Duration
	Write      time.Duration
	Idle       time.Duration
}

const (
	defaultReadHeaderTimeout = 10 * time.Second
	defaultWriteTimeout      = 10 * time.Minute
	defaultIdleTimeout       = 120 * time.Second
)

func (t Timeouts) withDefaults() Timeouts {
	if t.ReadHeader <= 0 {
		t.ReadHeader = defaultReadHeaderTimeout
	}
	if t.Write <= 0 {
		t.Write = defaultWriteTimeout
	}
	if t.Idle <= 0 {
		t.Idle = defaultIdleTimeout
	}
	return t
}

// Listener describes one HTTP listener in a coordinated server group.
type Listener struct {
	Name     string
	Addr     string
	Handler  http.Handler
	Timeouts Timeouts
}

// RunPair serves the API and an optional metrics listener under one coordinated
// lifecycle: either listener's failure cancels the shared context so the other
// listener is joined via the same graceful shutdown, instead of leaking a goroutine.
// metricsHandler nil means no metrics listener is started at all.
func RunPair(ctx context.Context, apiAddr string, apiHandler http.Handler, metricsAddr string, metricsHandler http.Handler, log *slog.Logger) error {
	listeners := []Listener{{Name: "http server", Addr: apiAddr, Handler: apiHandler}}
	if metricsHandler != nil {
		listeners = append(listeners, Listener{Name: "metrics server", Addr: metricsAddr, Handler: metricsHandler})
	}
	return RunListeners(ctx, listeners, log)
}

// RunListeners serves all configured listeners under one coordinated lifecycle.
func RunListeners(ctx context.Context, listeners []Listener, log *slog.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type namedServer struct {
		name string
		srv  *http.Server
	}
	if len(listeners) == 0 {
		return errors.New("at least one HTTP listener is required")
	}
	servers := make([]namedServer, 0, len(listeners))
	for _, listener := range listeners {
		if listener.Addr == "" || listener.Handler == nil {
			return errors.New("HTTP listener requires an address and handler")
		}
		name := listener.Name
		if name == "" {
			name = "http server"
		}
		timeouts := listener.Timeouts.withDefaults()
		servers = append(servers, namedServer{name: name, srv: &http.Server{
			Addr:              listener.Addr,
			Handler:           listener.Handler,
			ReadHeaderTimeout: timeouts.ReadHeader,
			WriteTimeout:      timeouts.Write,
			IdleTimeout:       timeouts.Idle,
		}})
	}

	errCh := make(chan error, len(servers))
	for _, ns := range servers {
		ns := ns
		go func() {
			log.Info(ns.name+" listening", "addr", ns.srv.Addr)
			if err := ns.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s: %w", ns.name, err)
			}
		}()
	}

	var runErr error
	select {
	case runErr = <-errCh:
		cancel() // a listener failed: cancel so the sibling joins shutdown too
	case <-ctx.Done():
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	for _, ns := range servers {
		log.Info(ns.name + " shutting down")
		if err := ns.srv.Shutdown(shutdownCtx); err != nil && runErr == nil {
			runErr = fmt.Errorf("%s shutdown: %w", ns.name, err)
		}
	}
	return runErr
}
