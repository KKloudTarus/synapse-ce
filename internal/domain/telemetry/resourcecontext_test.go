package telemetry

import "testing"

func TestResourceContextIsKubernetes(t *testing.T) {
	if (ResourceContext{Host: "h1"}).IsKubernetes() {
		t.Fatalf("a bare host context is not Kubernetes")
	}
	tests := []ResourceContext{
		{PodUID: "p"},
		{ClusterID: "c"},
		{WorkloadUID: "w"},
		{Namespace: "n"},
	}
	for i, rc := range tests {
		if !rc.IsKubernetes() {
			t.Errorf("case %d: any durable K8s id must mark the context Kubernetes", i)
		}
	}
}

func TestResourceContextContainerTargetID(t *testing.T) {
	if (ResourceContext{Host: "h1"}).ContainerTargetID() != "" {
		t.Fatalf("a non-container context has no container target id")
	}
	rc := ResourceContext{ContainerID: "cid", CgroupID: 7, PodUID: "pod", ImageDigest: "sha256:x"}
	got := rc.ContainerTargetID()
	if got == "" || got[:3] != "ct_" {
		t.Fatalf("container context must yield a ct_ target id, got %q", got)
	}
	if got != ContainerTargetID("cid", 7, "pod", "sha256:x") {
		t.Fatalf("method must match the package function")
	}
}
