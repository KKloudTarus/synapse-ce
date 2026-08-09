//go:build windows

package main

import (
	"context"
	"errors"
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
)

// Windows starts a service through the Service Control Manager, not by running a binary and waiting.
// A plain binary registered with `sc create` fails to start — "the service did not respond in a timely
// fashion" — because it never answers the SCM's status protocol. That failure looks like a broken
// agent and is really a missing handshake, so it is handled here rather than left to whoever installs
// the MSI.

// runAsService reports whether this process was started by the SCM, and if so runs the agent under it.
//
// The same binary is still a normal command-line tool when a human runs it: svc.IsWindowsService is
// what distinguishes the two, so there is no separate service executable to keep in step.
func runAsService(run func(context.Context) error) (handled bool) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		// Fail towards the command line. Refusing to start because we could not tell how we were
		// launched would turn an uncertain answer into an outage.
		log.Printf("synapse-agent: could not determine whether this is a service (%v); running in the foreground", err)
		return false
	}
	if !isService {
		return false
	}
	if err := svc.Run("synapse-agent", &agentService{run: run}); err != nil {
		log.Printf("synapse-agent: service stopped: %v", err)
	}
	return true
}

// agentService answers the SCM's control protocol while the agent runs.
type agentService struct {
	run func(context.Context) error
}

// Execute is the SCM handshake. The status transitions matter: StartPending tells Windows the service
// is coming up so it is not killed for being unresponsive, Running accepts Stop and Shutdown, and
// StopPending is reported BEFORE the agent's context is cancelled so a slow shutdown is understood as
// shutting down rather than as a hang.
func (s *agentService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				// The SCM asks for the current state; echoing it back is the whole contract.
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(stopGrace):
					// The agent is mid-work order. Windows kills the process after its own timeout;
					// reporting stopped here at least leaves the SCM with an accurate final state.
					log.Printf("synapse-agent: did not stop within %s; reporting stopped", stopGrace)
				}
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				// An unexpected control is ignored rather than treated as a stop: acting on a control
				// we do not understand is how a service stops for reasons nobody can explain.
				log.Printf("synapse-agent: ignoring unexpected service control %d", request.Cmd)
			}
		case err := <-done:
			status <- svc.Status{State: svc.Stopped}
			if err != nil && !isCanceled(err) {
				log.Printf("synapse-agent: %v", err)
				// A non-zero exit code tells the SCM the service failed, so a configured recovery
				// action (restart) actually fires. Exiting 0 would look like a clean, deliberate stop.
				return false, 1
			}
			return false, 0
		}
	}
}

// stopGrace bounds how long a stop waits for the agent to finish what it is doing.
const stopGrace = 20 * time.Second

// isCanceled reports whether err is just the shutdown we asked for. A cancelled context is the normal
// end of a service stop, not a failure, and reporting it as one would make every clean stop look like
// a crash to whoever reads the event log.
func isCanceled(err error) bool { return errors.Is(err, context.Canceled) }
