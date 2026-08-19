package telemetry

import "github.com/KKloudTarus/synapse-ce/internal/domain/shared"

// ResourceContext is the host/container/Kubernetes placement of an observed event. A1 owns this type and
// reserves its FULL field set now — the node sensor + K8s topology work (X3, #632) and endpoint
// visibility (B, #637) populate these fields on every envelope, so fixing the schema here keeps them
// unblocked. A non-Kubernetes host leaves the cluster/pod/workload fields empty; that is a valid, complete
// ResourceContext, not a defect.
//
// A pod NAME is intentionally absent: it is not stable identity (a pod is recreated under a new name).
// Identity is carried by the immutable ids (PodUID, WorkloadUID, ContainerID, CgroupID, ImageDigest).
type ResourceContext struct {
	// Host is the host's stable name (== the AssetID's host, for a non-K8s or node-level view).
	Host string
	// ClusterID identifies the Kubernetes cluster; empty off-cluster.
	ClusterID string
	// NodeUID is the K8s Node object's UID (not its rename-able name).
	NodeUID string
	// Namespace is the K8s namespace.
	Namespace string
	// ServiceAccount is the workload's service account, the identity a policy binds to.
	ServiceAccount string
	// WorkloadUID is the owning controller's UID (Deployment/DaemonSet/…), stable across pod churn.
	WorkloadUID string
	// PodUID is the Pod object's UID — the durable pod identity (pod NAME is deliberately not carried).
	PodUID string
	// ContainerID is the container runtime id of the process's container.
	ContainerID string
	// CgroupID is the kernel cgroup id, the reliable in-kernel container correlator.
	CgroupID uint64
	// ImageDigest is the content-addressed image the container runs (immutable, unlike a tag).
	ImageDigest string
	// Runtime is the container runtime (containerd, cri-o, …); empty off-container.
	Runtime string
}

// IsKubernetes reports whether this context carries Kubernetes placement. It is true when any durable K8s
// identity is present; a bare host context returns false.
func (rc ResourceContext) IsKubernetes() bool {
	return rc.ClusterID != "" || rc.PodUID != "" || rc.WorkloadUID != "" || rc.Namespace != ""
}

// ContainerTargetID returns the stable container-target identity for this context, or empty when the
// event is not container-scoped. It is a convenience over the package-level ContainerTargetID and returns
// shared.ID for parity with the sibling id accessors (ProcessEntityID/FileObservation.TargetID).
func (rc ResourceContext) ContainerTargetID() shared.ID {
	if rc.ContainerID == "" && rc.CgroupID == 0 && rc.PodUID == "" && rc.ImageDigest == "" {
		return ""
	}
	return ContainerTargetID(rc.ContainerID, rc.CgroupID, rc.PodUID, rc.ImageDigest)
}
