package endpoint

import (
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

func fileEnv(eventID string, occ time.Time, proc shared.ID, op, path string, device, inode uint64, hash string) telemetry.TelemetryEnvelope {
	return telemetry.TelemetryEnvelope{
		SchemaVersion: telemetry.SchemaVersion,
		EventID:       shared.ID(eventID),
		EventType:     "file." + op,
		EventClass:    detection.ClassFile,
		AgentID:       testAgent, AssetID: testAsset, BootID: testBoot,
		OccurredAt: occ, ObservedAt: occ,
		Event: telemetry.TelemetryEvent{Class: detection.ClassFile, File: &telemetry.FileObservation{
			Op: op, Path: path, Device: device, Inode: inode, ContentHash: hash, ProcessEntityID: proc, Comm: "app",
		}},
	}
}

func privEnv(eventID string, occ time.Time, proc shared.ID, kind string, fromUID, toUID int, capName string) telemetry.TelemetryEnvelope {
	return telemetry.TelemetryEnvelope{
		SchemaVersion: telemetry.SchemaVersion,
		EventID:       shared.ID(eventID),
		EventType:     "privilege." + kind,
		EventClass:    detection.ClassPrivilege,
		AgentID:       testAgent, AssetID: testAsset, BootID: testBoot,
		OccurredAt: occ, ObservedAt: occ,
		Event: telemetry.TelemetryEvent{Class: detection.ClassPrivilege, Privilege: &telemetry.PrivilegeObservation{
			Kind: kind, PID: 1, ProcessEntityID: proc, FromUID: fromUID, ToUID: toUID, Cap: capName, Comm: "app",
		}},
	}
}

// --- B3 file ---

func TestFileTargetTracksLatestOpAndLogsEachAccess(t *testing.T) {
	s := mustState(t)
	proc := procEntityID(10, 1)
	if _, err := s.Observe(fileEnv("f1", base, proc, "open", "/etc/passwd", 1, 2, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(fileEnv("f2", base.Add(time.Second), proc, "write", "/etc/passwd", 1, 2, "")); err != nil {
		t.Fatal(err)
	}
	files := s.Files()
	if len(files) != 1 {
		t.Fatalf("same path/device/inode/hash must be one target, got %d", len(files))
	}
	if files[0].LastOp != "write" || files[0].LastProcessEntityID != proc {
		t.Fatalf("latest op/process not tracked: %+v", files[0])
	}
	if !files[0].FirstSeenAt.Equal(base) || !files[0].LastSeenAt.Equal(base.Add(time.Second)) {
		t.Fatalf("seen window wrong: [%s,%s]", files[0].FirstSeenAt, files[0].LastSeenAt)
	}
	if got := len(s.Timeline()); got != 2 {
		t.Fatalf("each file access is a timeline entry, got %d", got)
	}
}

func TestFileDifferentContentHashIsDistinctTarget(t *testing.T) {
	s := mustState(t)
	proc := procEntityID(10, 1)
	// Content hash is part of the A1 file-target identity, so a modified file is a distinct version.
	if _, err := s.Observe(fileEnv("f1", base, proc, "write", "/a", 1, 2, "hashA")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(fileEnv("f2", base.Add(time.Second), proc, "write", "/a", 1, 2, "hashB")); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Files()); got != 2 {
		t.Fatalf("distinct content hashes must be distinct targets, got %d", got)
	}
}

// --- B4 privilege ---

func TestPrivilegeTransitionRecordedAndAttributedToProcess(t *testing.T) {
	s := mustState(t)
	proc := procEntityID(50, 1)
	if _, err := s.Observe(procEnv("e1", base, proc, "", 50, 1, "exec", "sudo", "/usr/bin/sudo")); err != nil {
		t.Fatal(err)
	}
	entries, err := s.Observe(privEnv("p1", base.Add(time.Second), proc, "setuid", 1000, 0, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Kind != TimelinePrivilegeChange || entries[0].EntityKind != EntityIdentity || entries[0].EntityID != proc {
		t.Fatalf("privilege transition must emit an identity timeline entry attributed to the process, got %+v", entries)
	}
	trans := s.PrivilegeTransitions()
	if len(trans) != 1 || trans[0].ToUID != 0 || trans[0].Kind != "setuid" || trans[0].ProcessEntityID != proc {
		t.Fatalf("transition not recorded/attributed: %+v", trans)
	}
	// A transition folded before its process is still recorded and attributed (order-independent).
	orphanProc := procEntityID(99, 1)
	if _, err := s.Observe(privEnv("p2", base.Add(2*time.Second), orphanProc, "capset", 0, 0, "CAP_NET_ADMIN")); err != nil {
		t.Fatal(err)
	}
	if len(s.PrivilegeTransitions()) != 2 {
		t.Fatal("a transition for an unobserved process must still be recorded")
	}
	if !isPrivilegeEscalation(privEnv("x", base, proc, "setuid", 1000, 0, "").Event.Privilege) {
		t.Fatal("uid 1000->0 must be flagged an escalation")
	}
}

func TestPrivilegeCapsetRequiresCapAndRecords(t *testing.T) {
	s := mustState(t)
	proc := procEntityID(51, 1)
	if _, err := s.Observe(privEnv("p1", base, proc, "capset", 0, 0, "CAP_SYS_ADMIN")); err != nil {
		t.Fatal(err)
	}
	trans := s.PrivilegeTransitions()
	if len(trans) != 1 || trans[0].Cap != "CAP_SYS_ADMIN" {
		t.Fatalf("capset not recorded: %+v", trans)
	}
	// A capset with no capability is rejected by telemetry validation (fail-closed).
	if _, err := s.Observe(privEnv("p2", base.Add(time.Second), proc, "capset", 0, 0, "")); err == nil {
		t.Fatal("capset with no capability must be rejected")
	}
}

// --- B5 container inventory ---

func procEnvRC(eventID string, occ time.Time, entityID shared.ID, pid int, rc telemetry.ResourceContext) telemetry.TelemetryEnvelope {
	e := procEnv(eventID, occ, entityID, "", pid, 1, "exec", "app", "/app")
	e.ResourceContext = rc
	return e
}

func TestContainerInventoriedFromResourceContext(t *testing.T) {
	s := mustState(t)
	rc := telemetry.ResourceContext{ContainerID: "c1", CgroupID: 42, PodUID: "pod1", ImageDigest: "sha256:abc", Namespace: "prod", Runtime: "containerd"}
	if _, err := s.Observe(procEnvRC("e1", base, procEntityID(1, 1), 1, rc)); err != nil {
		t.Fatal(err)
	}
	// A second event from the same container at a later time widens the window, no duplicate.
	if _, err := s.Observe(procEnvRC("e2", base.Add(time.Minute), procEntityID(2, 1), 2, rc)); err != nil {
		t.Fatal(err)
	}
	cs := s.Containers()
	if len(cs) != 1 {
		t.Fatalf("same container must be one inventory entry, got %d", len(cs))
	}
	c := cs[0]
	if c.ContainerID != "c1" || c.ImageDigest != "sha256:abc" || c.Namespace != "prod" {
		t.Fatalf("container fields not captured: %+v", c)
	}
	if !c.FirstSeenAt.Equal(base) || !c.LastSeenAt.Equal(base.Add(time.Minute)) {
		t.Fatalf("container seen window wrong: [%s,%s]", c.FirstSeenAt, c.LastSeenAt)
	}
	// Container presence is not a timeline transition.
	for _, e := range s.Timeline() {
		if e.EntityKind == EntityContainer {
			t.Fatal("container presence must not appear on the timeline")
		}
	}
}

func TestDistinctContainersAreDistinctInventory(t *testing.T) {
	s := mustState(t)
	rc1 := telemetry.ResourceContext{ContainerID: "c1", ImageDigest: "img1"}
	rc2 := telemetry.ResourceContext{ContainerID: "c2", ImageDigest: "img2"}
	if _, err := s.Observe(procEnvRC("e1", base, procEntityID(1, 1), 1, rc1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(procEnvRC("e2", base, procEntityID(2, 1), 2, rc2)); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Containers()); got != 2 {
		t.Fatalf("two distinct containers expected, got %d", got)
	}
	// An event with no container context inventories nothing.
	if _, err := s.Observe(procEnv("e3", base, procEntityID(3, 1), "", 3, 1, "exec", "x", "/x")); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Containers()); got != 2 {
		t.Fatalf("host-context event must not add a container, got %d", got)
	}
}

func TestB3B5FoldIsReorderInvariant(t *testing.T) {
	pA, pB := procEntityID(1, 1), procEntityID(2, 1)
	rc1 := telemetry.ResourceContext{ContainerID: "c1", ImageDigest: "img1"}
	rc2 := telemetry.ResourceContext{ContainerID: "c2", ImageDigest: "img2"}
	e0 := procEnvRC("e1", base, pA, 1, rc1)
	e4 := procEnvRC("e2", base.Add(time.Second), pB, 2, rc2)
	envs := []telemetry.TelemetryEnvelope{
		e0,
		fileEnv("fl1", base.Add(time.Second), pA, "open", "/x", 1, 2, ""),
		fileEnv("fl2", base.Add(2*time.Second), pA, "write", "/x", 1, 2, ""),
		privEnv("p1", base.Add(3*time.Second), pA, "setuid", 1000, 0, ""),
		e4,
	}
	fold := func(order []int) *EndpointState {
		s := mustState(t)
		for _, i := range order {
			mustObserve(t, s, envs[i])
		}
		return s
	}
	fwd := fold([]int{0, 1, 2, 3, 4})
	rev := fold([]int{4, 3, 2, 1, 0})

	if !reflect.DeepEqual(fwd.Files(), rev.Files()) {
		t.Fatalf("files differ by fold order:\nfwd=%+v\nrev=%+v", fwd.Files(), rev.Files())
	}
	if !reflect.DeepEqual(fwd.Containers(), rev.Containers()) {
		t.Fatalf("containers differ by fold order:\nfwd=%+v\nrev=%+v", fwd.Containers(), rev.Containers())
	}
	if !reflect.DeepEqual(fwd.PrivilegeTransitions(), rev.PrivilegeTransitions()) {
		t.Fatalf("privilege transitions differ by fold order:\nfwd=%+v\nrev=%+v", fwd.PrivilegeTransitions(), rev.PrivilegeTransitions())
	}
	if !reflect.DeepEqual(fwd.Processes(), rev.Processes()) {
		t.Fatalf("processes differ by fold order")
	}
	if !reflect.DeepEqual(fwd.Timeline(), rev.Timeline()) {
		t.Fatalf("timeline differs by fold order:\nfwd=%+v\nrev=%+v", fwd.Timeline(), rev.Timeline())
	}
	// The file's last op is the latest by event time regardless of fold order.
	if f := fwd.Files(); len(f) != 1 || f[0].LastOp != "write" {
		t.Fatalf("file last-op not event-time resolved: %+v", f)
	}
}

func TestB3B5Validators(t *testing.T) {
	if (FileTarget{TargetID: "ft", AssetID: testAsset, Path: "/x"}).Validate() != nil {
		t.Fatal("valid file target rejected")
	}
	for _, bad := range []FileTarget{{AssetID: testAsset, Path: "/x"}, {TargetID: "ft", Path: "/x"}, {TargetID: "ft", AssetID: testAsset}} {
		if bad.Validate() == nil {
			t.Fatalf("invalid file target accepted: %+v", bad)
		}
	}
	if (ContainerInstance{TargetID: "ct", AssetID: testAsset, ContainerID: "c1"}).Validate() != nil {
		t.Fatal("valid container rejected")
	}
	for _, bad := range []ContainerInstance{{AssetID: testAsset, ContainerID: "c1"}, {TargetID: "ct", ContainerID: "c1"}, {TargetID: "ct", AssetID: testAsset}} {
		if bad.Validate() == nil {
			t.Fatalf("invalid container accepted: %+v", bad)
		}
	}
	if (PrivilegeTransition{EventID: "p", AssetID: testAsset, Kind: "setuid"}).Validate() != nil {
		t.Fatal("valid transition rejected")
	}
	for _, bad := range []PrivilegeTransition{{AssetID: testAsset, Kind: "setuid"}, {EventID: "p", Kind: "setuid"}, {EventID: "p", AssetID: testAsset, Kind: "bogus"}} {
		if bad.Validate() == nil {
			t.Fatalf("invalid transition accepted: %+v", bad)
		}
	}
}

func TestFileAndContainerAccessorNotFound(t *testing.T) {
	s := mustState(t)
	if _, ok := s.File("missing"); ok {
		t.Fatal("File must report not-found")
	}
	if _, ok := s.Container("missing"); ok {
		t.Fatal("Container must report not-found")
	}
}

func TestEqualTimestampFoldIsReorderInvariant(t *testing.T) {
	pP := procEntityID(10, 1)
	// Every event shares the SAME OccurredAt (base): the ONLY ordering signal is the EventID tiebreak, so
	// this is the collision case the reviewers flagged. The higher EventID must win, both fold orders.
	envs := []telemetry.TelemetryEnvelope{
		procEnv("pa", base, pP, "", 10, 1, "exec", "a", "/a"),
		procEnv("pb", base, pP, "", 10, 1, "exec", "b", "/b"), // pb > pa -> /b wins
		fileEnv("fa", base, pP, "open", "/x", 1, 2, ""),
		fileEnv("fb", base, pP, "write", "/x", 1, 2, ""), // fb > fa -> write wins
		procEnvRC("ca", base, procEntityID(20, 1), 20, telemetry.ResourceContext{ContainerID: "c1", ImageDigest: "img1", Namespace: "prod"}),
		procEnvRC("cb", base, procEntityID(21, 1), 21, telemetry.ResourceContext{ContainerID: "c1", ImageDigest: "img1", Namespace: "staging"}), // cb > ca -> staging wins
	}
	fold := func(order []int) *EndpointState {
		s := mustState(t)
		for _, i := range order {
			mustObserve(t, s, envs[i])
		}
		return s
	}
	fwd := fold([]int{0, 1, 2, 3, 4, 5})
	rev := fold([]int{5, 4, 3, 2, 1, 0})

	if !reflect.DeepEqual(fwd.Processes(), rev.Processes()) ||
		!reflect.DeepEqual(fwd.Files(), rev.Files()) ||
		!reflect.DeepEqual(fwd.Containers(), rev.Containers()) ||
		!reflect.DeepEqual(fwd.Timeline(), rev.Timeline()) {
		t.Fatal("equal-timestamp fold is not reorder-invariant")
	}
	// The higher EventID wins each contested field, independent of fold order.
	if pe, _ := fwd.Process(pP); pe.Path != "/b" {
		t.Fatalf("process descriptor tiebreak: got %q want /b", pe.Path)
	}
	if f := fwd.Files(); len(f) != 1 || f[0].LastOp != "write" {
		t.Fatalf("file op tiebreak: %+v", f)
	}
	cs := fwd.Containers()
	if len(cs) != 1 || cs[0].Namespace != "staging" {
		t.Fatalf("container metadata tiebreak: %+v", cs)
	}
}

func TestPrivilegeEscalationFlag(t *testing.T) {
	s := mustState(t)
	proc := procEntityID(1, 1)
	mustObserve(t, s, privEnv("p1", base, proc, "setuid", 1000, 0, ""))                              // to root -> escalation
	mustObserve(t, s, privEnv("p2", base.Add(time.Second), proc, "setuid", 0, 1000, ""))             // drop -> not
	mustObserve(t, s, privEnv("p3", base.Add(2*time.Second), proc, "capset", 0, 0, "CAP_SYS_ADMIN")) // cap gain -> escalation
	tr := s.PrivilegeTransitions()
	if len(tr) != 3 {
		t.Fatalf("want 3 transitions, got %d", len(tr))
	}
	if !tr[0].Escalation || tr[1].Escalation || !tr[2].Escalation {
		t.Fatalf("escalation flags wrong: %+v", tr)
	}
}
