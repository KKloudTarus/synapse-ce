package endpoint

import (
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ChangeKind classifies how an entity differs between two endpoint snapshots.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeChanged ChangeKind = "changed"
)

// EntityChange is one typed change between two snapshots.
type EntityChange struct {
	EntityKind EntityKind
	EntityID   shared.ID
	Change     ChangeKind
}

// EndpointDiff is the deterministic set of changes between two endpoint-state snapshots (B6). It powers
// change detection for the State Timeline and retro-hunt ("what appeared/changed/disappeared between t1
// and t2"). "changed" compares only MATERIAL fields, never the seen-window timestamps (which move on every
// re-observation), so it reports real state changes, not activity.
type EndpointDiff struct {
	Changes []EntityChange
}

// Diff computes the changes from the before snapshot to the after snapshot. A nil side is treated as an
// empty snapshot (so Diff(nil, after) reports every entity as added), keeping the function total. The
// result is deterministically ordered by (kind, entity id, change).
func Diff(before, after *EndpointState) EndpointDiff {
	var changes []EntityChange
	changes = append(changes, diffProcesses(before, after)...)
	changes = append(changes, diffConnections(before, after)...)
	changes = append(changes, diffFiles(before, after)...)
	changes = append(changes, diffContainers(before, after)...)
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].EntityKind != changes[j].EntityKind {
			return changes[i].EntityKind < changes[j].EntityKind
		}
		if changes[i].EntityID != changes[j].EntityID {
			return changes[i].EntityID < changes[j].EntityID
		}
		return changes[i].Change < changes[j].Change
	})
	return EndpointDiff{Changes: changes}
}

// snapshotOf returns the four entity slices of a snapshot, or empty slices for a nil snapshot.
func processesOf(s *EndpointState) []ProcessEntity {
	if s == nil {
		return nil
	}
	return s.Processes()
}

func connectionsOf(s *EndpointState) []NetworkConnection {
	if s == nil {
		return nil
	}
	return s.Connections()
}

func filesOf(s *EndpointState) []FileTarget {
	if s == nil {
		return nil
	}
	return s.Files()
}

func containersOf(s *EndpointState) []ContainerInstance {
	if s == nil {
		return nil
	}
	return s.Containers()
}

func diffProcesses(before, after *EndpointState) []EntityChange {
	return diffSet(EntityProcess, processesOf(before), processesOf(after),
		func(p ProcessEntity) shared.ID { return p.EntityID },
		func(a, b ProcessEntity) bool {
			return a.State == b.State && a.Path == b.Path && a.Comm == b.Comm &&
				a.UID == b.UID && a.PPID == b.PPID && a.ParentEntityID == b.ParentEntityID &&
				strings.Join(a.Args, "\x00") == strings.Join(b.Args, "\x00")
		})
}

func diffConnections(before, after *EndpointState) []EntityChange {
	// A connection's tuple is immutable, but its process attribution can move monotonically from unknown
	// to observed when an out-of-order process event arrives. That resolution is a material security-state
	// change; seen-window movement remains intentionally ignored.
	return diffSet(EntityNetwork, connectionsOf(before), connectionsOf(after),
		func(c NetworkConnection) shared.ID { return c.ConnectionID },
		func(a, b NetworkConnection) bool { return a.ProcessAttribution == b.ProcessAttribution })
}

func diffFiles(before, after *EndpointState) []EntityChange {
	return diffSet(EntityFile, filesOf(before), filesOf(after),
		func(f FileTarget) shared.ID { return f.TargetID },
		func(a, b FileTarget) bool {
			return a.LastOp == b.LastOp && a.LastProcessEntityID == b.LastProcessEntityID
		})
}

func diffContainers(before, after *EndpointState) []EntityChange {
	// A container's identity is fixed; its material state for diffing is its non-identity metadata.
	return diffSet(EntityContainer, containersOf(before), containersOf(after),
		func(c ContainerInstance) shared.ID { return c.TargetID },
		func(a, b ContainerInstance) bool {
			return a.Namespace == b.Namespace && a.WorkloadUID == b.WorkloadUID && a.Runtime == b.Runtime
		})
}

// diffSet computes added/removed/changed between two entity slices keyed by id.
func diffSet[T any](kind EntityKind, before, after []T, id func(T) shared.ID, materialEqual func(a, b T) bool) []EntityChange {
	beforeByID := make(map[shared.ID]T, len(before))
	for _, e := range before {
		beforeByID[id(e)] = e
	}
	afterByID := make(map[shared.ID]T, len(after))
	for _, e := range after {
		afterByID[id(e)] = e
	}
	var out []EntityChange
	for k, av := range afterByID {
		bv, ok := beforeByID[k]
		if !ok {
			out = append(out, EntityChange{EntityKind: kind, EntityID: k, Change: ChangeAdded})
			continue
		}
		if !materialEqual(bv, av) {
			out = append(out, EntityChange{EntityKind: kind, EntityID: k, Change: ChangeChanged})
		}
	}
	for k := range beforeByID {
		if _, ok := afterByID[k]; !ok {
			out = append(out, EntityChange{EntityKind: kind, EntityID: k, Change: ChangeRemoved})
		}
	}
	return out
}
