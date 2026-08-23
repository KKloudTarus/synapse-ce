package endpoint

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// applyFile folds a validated file envelope into a FileTarget (B3). env is already telemetry-validated by
// Observe. The target identity (path+device+inode+contentHash via A1 FileTargetID) is fixed per entity, so
// only the last op and accessing process vary across observations of the same target — both resolved
// latest-by-event-time; the seen window is a min/max. One timeline entry per file access event.
func (s *EndpointState) applyFile(env telemetry.TelemetryEnvelope) []TimelineEntry {
	obs := env.Event.File
	id := obs.TargetID()

	ft, existed := s.files[id]
	if !existed {
		ft = &FileTarget{
			TargetID:      id,
			TenantID:      s.tenantID,
			AssetID:       s.assetID,
			Path:          obs.Path,
			Device:        obs.Device,
			Inode:         obs.Inode,
			ContentHash:   obs.ContentHash,
			PathTruncated: obs.PathTruncated,
			FirstSeenAt:   env.OccurredAt,
			LastSeenAt:    env.OccurredAt,
		}
		s.files[id] = ft
	}
	if !existed || laterEvent(env.OccurredAt, env.EventID, ft.LastSeenAt, ft.lastOpEventID) {
		ft.LastOp = obs.Op
		ft.LastProcessEntityID = obs.ProcessEntityID
		ft.lastOpEventID = env.EventID
	}
	if env.OccurredAt.Before(ft.FirstSeenAt) {
		ft.FirstSeenAt = env.OccurredAt
	}
	if env.OccurredAt.After(ft.LastSeenAt) {
		ft.LastSeenAt = env.OccurredAt
	}

	return s.appendTimeline(env)
}

// applyPrivilege folds a validated privilege envelope (B4). env is already telemetry-validated by Observe.
// It records the transition as a first-class, immutable record (Observe's dedup guarantees one per event)
// attributed to the acting process entity, and emits a timeline entry. Every privilege transition is
// recorded — they are never-sampled upstream (A0.6), so an escalation always surfaces. It deliberately
// does NOT mutate the process entity: a transition can be folded before the process it names is observed,
// so mutating the entity here would make the projection fold-order-dependent. The per-process identity
// view is the set of transitions filtered by ProcessEntityID (or the EntityIdentity timeline entries).
func (s *EndpointState) applyPrivilege(env telemetry.TelemetryEnvelope) []TimelineEntry {
	obs := env.Event.Privilege

	s.privileges = append(s.privileges, PrivilegeTransition{
		EventID:         env.EventID,
		TenantID:        s.tenantID,
		AssetID:         s.assetID,
		ProcessEntityID: obs.ProcessEntityID,
		Kind:            obs.Kind,
		FromUID:         obs.FromUID,
		ToUID:           obs.ToUID,
		Cap:             obs.Cap,
		Escalation:      isPrivilegeEscalation(obs),
		OccurredAt:      env.OccurredAt,
	})

	return s.appendTimeline(env)
}

// observeContainer inventories the container an event came from (B5), from the envelope's ResourceContext.
// It only maintains the inventory (identity via A1 ContainerTargetID; a min/max seen window that is
// order-independent) and emits no timeline entry — container presence is not a transition, and every event
// carries a container context, so a per-event entry would be pure noise.
func (s *EndpointState) observeContainer(env telemetry.TelemetryEnvelope) {
	rc := env.ResourceContext
	if rc.ContainerID == "" {
		return
	}
	// containerID, cgroupID, podUID, and imageDigest are all part of ContainerTargetID, so they are fixed
	// per identity. Only Namespace/WorkloadUID/Runtime are non-identity metadata and must be resolved
	// latest-by-event-time (with an EventID tiebreak) so the inventory does not depend on fold order.
	id := telemetry.ContainerTargetID(rc.ContainerID, rc.CgroupID, rc.PodUID, rc.ImageDigest)
	c, existed := s.containers[id]
	if !existed {
		c = &ContainerInstance{
			TargetID:    id,
			TenantID:    s.tenantID,
			AssetID:     s.assetID,
			ContainerID: rc.ContainerID,
			CgroupID:    rc.CgroupID,
			PodUID:      rc.PodUID,
			ImageDigest: rc.ImageDigest,
			FirstSeenAt: env.OccurredAt,
			LastSeenAt:  env.OccurredAt,
		}
		s.containers[id] = c
	}
	if !existed || laterEvent(env.OccurredAt, env.EventID, c.LastSeenAt, c.metaEventID) {
		c.Namespace = rc.Namespace
		c.WorkloadUID = rc.WorkloadUID
		c.Runtime = rc.Runtime
		c.metaEventID = env.EventID
	}
	if env.OccurredAt.Before(c.FirstSeenAt) {
		c.FirstSeenAt = env.OccurredAt
	}
	if env.OccurredAt.After(c.LastSeenAt) {
		c.LastSeenAt = env.OccurredAt
	}
}

func fileObsSummary(obs *telemetry.FileObservation) string {
	return fmt.Sprintf("%s %s", obs.Op, obs.Path)
}

// File returns a copy of one file target by id.
func (s *EndpointState) File(id shared.ID) (FileTarget, bool) {
	ft, ok := s.files[id]
	if !ok {
		return FileTarget{}, false
	}
	return ft.clone(), true
}

// Files returns a copy of all file targets, ordered by target id for a stable result.
func (s *EndpointState) Files() []FileTarget {
	out := make([]FileTarget, 0, len(s.files))
	for _, ft := range s.files {
		out = append(out, ft.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TargetID < out[j].TargetID })
	return out
}

// Container returns a copy of one container instance by id.
func (s *EndpointState) Container(id shared.ID) (ContainerInstance, bool) {
	c, ok := s.containers[id]
	if !ok {
		return ContainerInstance{}, false
	}
	return c.clone(), true
}

// Containers returns a copy of all container instances, ordered by target id for a stable result.
func (s *EndpointState) Containers() []ContainerInstance {
	out := make([]ContainerInstance, 0, len(s.containers))
	for _, c := range s.containers {
		out = append(out, c.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TargetID < out[j].TargetID })
	return out
}

// PrivilegeTransitions returns a copy of all privilege transitions, ordered by event time then event id
// for a stable, order-independent result.
func (s *EndpointState) PrivilegeTransitions() []PrivilegeTransition {
	out := make([]PrivilegeTransition, len(s.privileges))
	copy(out, s.privileges)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		return out[i].EventID < out[j].EventID
	})
	return out
}
