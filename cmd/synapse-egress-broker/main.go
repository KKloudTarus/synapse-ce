package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egressbroker"
)

func main() {
	socketPath := flag.String("socket", "/run/synapse-egress-broker/egress-broker.sock", "root-owned broker Unix socket")
	userName := flag.String("user", "synapse-worker", "worker user permitted to connect")
	groupName := flag.String("group", "synapse-worker", "worker group owning the socket")
	bwrapPath := flag.String("bwrap", "/usr/bin/bwrap", "absolute path of the permitted Bubblewrap executable")
	grantPublicKey := flag.String("grant-public-key", "", "base64 Ed25519 control-plane grant verification key")
	grantReplayJournal := flag.String("grant-replay-journal", "/var/lib/synapse-egress-broker/grant-replays.jsonl", "root-owned durable egress grant replay journal")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "synapse-egress-broker does not accept positional arguments")
		os.Exit(2)
	}
	workerUser, err := user.Lookup(*userName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "look up worker user:", err)
		os.Exit(1)
	}
	workerUID, err := strconv.Atoi(workerUser.Uid)
	if err != nil || workerUID < 0 {
		fmt.Fprintln(os.Stderr, "worker user has an invalid numeric ID")
		os.Exit(1)
	}
	group, err := user.LookupGroup(*groupName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "look up worker group:", err)
		os.Exit(1)
	}
	groupID, err := strconv.Atoi(group.Gid)
	if err != nil || groupID < 0 {
		fmt.Fprintln(os.Stderr, "worker group has an invalid numeric ID")
		os.Exit(1)
	}
	applier, err := egress.NewApplier()
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize egress enforcement:", err)
		os.Exit(1)
	}
	verifier, err := egressbroker.NewGrantVerifier(*grantPublicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize egress grant verifier:", err)
		os.Exit(1)
	}
	replays, err := egressbroker.NewFileGrantReplayStore(*grantReplayJournal, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize egress grant replay journal:", err)
		os.Exit(1)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	server, err := egressbroker.NewServer(*socketPath, workerUID, groupID, *bwrapPath, applier, verifier, replays, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize egress broker:", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := server.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "run egress broker:", err)
		os.Exit(1)
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cleanupCancel()
	if err := server.Cleanup(cleanupCtx); err != nil {
		fmt.Fprintln(os.Stderr, "cleanup egress namespaces:", err)
		os.Exit(1)
	}
}
