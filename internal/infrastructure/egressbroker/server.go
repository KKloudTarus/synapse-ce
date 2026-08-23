package egressbroker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type sandboxProcessHandle interface {
	Alive() error
	NetworkNamespaceFD() int
}

type Server struct {
	socketPath string
	workerUID  int
	groupID    int
	bwrapPath  string
	applier    *egress.Applier
	setup      func(context.Context, string, int, ports.EgressPolicy, int) (*egress.Netns, error)
	verifier   *GrantVerifier
	replays    GrantReplayStore
	log        *slog.Logger
	now        func() time.Time
	mu         sync.Mutex
	active     map[string]*egress.Netns
	pending    map[string]struct{}
}

func NewServer(socketPath string, workerUID, groupID int, bwrapPath string, applier *egress.Applier, verifier *GrantVerifier, replays GrantReplayStore, log *slog.Logger) (*Server, error) {
	if socketPath == "" {
		socketPath = defaultSocketPath
	}
	if !filepath.IsAbs(socketPath) {
		return nil, errors.New("egress broker socket path must be absolute")
	}
	if workerUID < 0 {
		return nil, errors.New("egress broker worker UID must be non-negative")
	}
	if groupID < 0 {
		return nil, errors.New("egress broker group ID must be non-negative")
	}
	if !filepath.IsAbs(bwrapPath) {
		return nil, errors.New("egress broker bubblewrap path must be absolute")
	}
	if applier == nil {
		return nil, errors.New("egress applier is required")
	}
	if verifier == nil {
		return nil, errors.New("egress grant verifier is required")
	}
	if replays == nil {
		return nil, errors.New("egress grant replay store is required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		socketPath: socketPath,
		workerUID:  workerUID,
		groupID:    groupID,
		bwrapPath:  bwrapPath,
		applier:    applier,
		setup:      applier.SetupForNamespaceFD,
		verifier:   verifier,
		replays:    replays,
		log:        log,
		now:        time.Now,
		active:     make(map[string]*egress.Netns),
		pending:    make(map[string]struct{}),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("egress broker must run as root")
	}
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0o750); err != nil {
		return fmt.Errorf("create broker runtime directory: %w", err)
	}
	if err := removeStaleSocket(s.socketPath); err != nil {
		return err
	}
	if err := s.applier.RecoverStale(ctx); err != nil {
		return fmt.Errorf("recover stale egress state: %w", err)
	}
	if err := s.applier.Probe(ctx); err != nil {
		return fmt.Errorf("probe egress enforcement: %w", err)
	}
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on broker socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(s.socketPath)
	if err := os.Chown(s.socketPath, 0, s.groupID); err != nil {
		return fmt.Errorf("set broker socket ownership: %w", err)
	}
	if err := os.Chmod(s.socketPath, 0o660); err != nil {
		return fmt.Errorf("set broker socket mode: %w", err)
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	// Drain in-flight handlers before returning so a shutdown cannot orphan a privileged
	// setup/cleanup mid-flight; each handler is already ctx-bounded (30s per request), so the wait
	// is bounded.
	var handlers sync.WaitGroup
	for {
		conn, err := listener.Accept()
		if err != nil {
			handlers.Wait()
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept broker connection: %w", err)
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(serverCtx context.Context, conn net.Conn) {
	defer conn.Close()
	requestCtx, cancel := context.WithTimeout(serverCtx, 30*time.Second)
	defer cancel()
	if deadline, ok := requestCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	peer, err := peerIdentityFromConn(conn)
	if err != nil || peer.uid != s.workerUID {
		s.log.Warn("egress broker rejected peer", "err", err)
		_ = encodeResponse(conn, response{Version: protocolVersion, Error: "unauthorized peer"})
		return
	}
	req, err := decodeRequest(conn)
	if err != nil {
		s.log.Warn("egress broker rejected request", "peer_pid", peer.pid, "err", err)
		_ = encodeResponse(conn, response{Version: protocolVersion, Error: "invalid request"})
		return
	}
	var process *sandboxProcess
	if req.Action == "setup" {
		process, err = authorizeSandboxProcess(peer, req.PID, s.workerUID, s.bwrapPath)
		if err != nil {
			s.log.Warn("egress broker rejected sandbox process", "peer_pid", peer.pid, "sandbox_pid", req.PID, "err", err)
			_ = encodeResponse(conn, response{Version: protocolVersion, Error: "unauthorized sandbox process"})
			return
		}
		defer process.Close()
	}
	res, err := s.execute(requestCtx, req, process)
	if err != nil {
		s.log.Warn("egress broker operation failed", "action", req.Action, "run_id", req.RunID, "err", err)
		_ = encodeResponse(conn, response{Version: protocolVersion, Error: "operation failed"})
		return
	}
	res.Version = protocolVersion
	res.OK = true
	if err := encodeResponse(conn, res); err != nil {
		s.log.Warn("egress broker response failed", "action", req.Action, "run_id", req.RunID, "err", err)
	}
}

func (s *Server) execute(ctx context.Context, req request, process sandboxProcessHandle) (response, error) {
	switch req.Action {
	case "probe":
		if err := s.applier.Probe(ctx); err != nil {
			return response{}, err
		}
		return response{}, nil
	case "setup":
		if process == nil {
			return response{}, errors.New("sandbox process authorization is required")
		}
		now := s.now()
		claims, err := s.verifier.Verify(req.Grant, now)
		if err != nil {
			return response{}, fmt.Errorf("verify egress grant: %w", err)
		}
		if claims.TenantID != req.TenantID || claims.ExecutionKind != req.ExecutionKind ||
			claims.ExecutionID != req.ExecutionID || claims.RunID != req.RunID || claims.Slot != req.Slot ||
			claims.PID != req.PID || !CanonicalRulesEqual(claims.Rules, req.Rules) {
			return response{}, errors.New("egress grant does not match requested execution, process, or rules")
		}
		s.mu.Lock()
		_, active := s.active[req.RunID]
		_, pending := s.pending[req.RunID]
		if !active && !pending {
			s.pending[req.RunID] = struct{}{}
		}
		s.mu.Unlock()
		if active || pending {
			return response{}, errors.New("run namespace already exists")
		}
		setupSucceeded := false
		defer func() {
			if !setupSucceeded {
				s.mu.Lock()
				delete(s.pending, req.RunID)
				s.mu.Unlock()
			}
		}()
		if err := process.Alive(); err != nil {
			return response{}, fmt.Errorf("sandbox process exited before setup: %w", err)
		}
		rules, err := parseRules(req.Rules)
		if err != nil {
			return response{}, err
		}
		// Persist consumption before any privileged mutation. A failed setup burns the
		// grant and requires fresh authorization, so a broker crash cannot enable replay.
		if err := s.replays.Consume(claims.ID, time.Unix(claims.ExpiresAt, 0), now); err != nil {
			return response{}, fmt.Errorf("consume egress grant: %w", err)
		}
		ns, err := s.setup(ctx, req.RunID, req.Slot, ports.EgressPolicy{Rules: rules}, process.NetworkNamespaceFD())
		if err != nil {
			return response{}, err
		}
		if err := process.Alive(); err != nil {
			_ = ns.Teardown(context.WithoutCancel(ctx))
			return response{}, fmt.Errorf("sandbox process exited during setup: %w", err)
		}
		s.mu.Lock()
		delete(s.pending, req.RunID)
		s.active[req.RunID] = ns
		setupSucceeded = true
		s.mu.Unlock()
		s.log.Info("egress namespace configured", "run_id", req.RunID, "slot", req.Slot, "rule_count", len(req.Rules))
		return response{Rules: append([]CanonicalRule(nil), req.Rules...)}, nil
	case "cleanup":
		s.mu.Lock()
		_, pending := s.pending[req.RunID]
		ns, exists := s.active[req.RunID]
		if exists {
			delete(s.active, req.RunID)
		}
		s.mu.Unlock()
		if pending {
			return response{}, errors.New("run namespace setup is in progress")
		}
		if !exists {
			return response{}, nil
		}
		if err := ns.Teardown(ctx); err != nil {
			s.mu.Lock()
			if _, replaced := s.active[req.RunID]; !replaced {
				s.active[req.RunID] = ns
			}
			s.mu.Unlock()
			return response{}, err
		}
		s.log.Info("egress namespace removed", "run_id", req.RunID)
		return response{}, nil
	default:
		return response{}, errors.New("unsupported action")
	}
}

func (s *Server) Cleanup(ctx context.Context) error {
	s.mu.Lock()
	if len(s.pending) > 0 {
		s.mu.Unlock()
		return errors.New("egress namespace setup is in progress")
	}
	active := s.active
	s.active = make(map[string]*egress.Netns)
	s.mu.Unlock()

	var firstErr error
	for runID, ns := range active {
		if err := ns.Teardown(ctx); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.mu.Lock()
			if _, replaced := s.active[runID]; !replaced {
				s.active[runID] = ns
			}
			s.mu.Unlock()
		}
	}
	return firstErr
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect broker socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("refusing to replace non-socket broker path")
	}
	conn, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
	if dialErr == nil {
		conn.Close()
		return errors.New("egress broker is already running")
	}
	if !strings.Contains(dialErr.Error(), "connection refused") {
		return fmt.Errorf("verify stale broker socket: %w", dialErr)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale broker socket: %w", err)
	}
	return nil
}
