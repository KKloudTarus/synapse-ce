package k8sinv

import (
	"context"
	"runtime"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// TestScaleTenThousandPods exercises the collector against a synthetic namespace of 10k pods across
// 500 Deployments (20 replicas each), asserting it (a) resolves every controller correctly, (b)
// collapses the 20 replicas of each controller to a single deduped label set (so selector matching
// stays cheap), and (c) completes within a bounded heap. This is the requirement-7 scale guard; the
// kind-based CI job runs the equivalent against a real API server.
func TestScaleTenThousandPods(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in -short mode")
	}
	const controllers = 500
	const replicas = 20

	objs := []k8sruntime.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "scale"}}}
	for c := 0; c < controllers; c++ {
		name := "dep-" + itoa(c)
		objs = append(objs, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
			Name: name + "-rs", Namespace: "scale",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: name, Controller: ptrTrue()}},
		}})
		for r := 0; r < replicas; r++ {
			objs = append(objs, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: name + "-rs-" + itoa(r), Namespace: "scale", Labels: map[string]string{"app": name},
					OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: name + "-rs", Controller: ptrTrue()}},
				},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "reg/" + name + ":v1"}}},
				Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
					{Name: "c", ImageID: "reg/" + name + "@sha256:" + itoa(c)},
				}},
			})
		}
	}

	client := fake.NewSimpleClientset(objs...)
	c := mustCollector(t, client, Config{Namespaces: []string{"scale"}, PageSize: 500})

	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	snap, err := c.Snapshot(context.Background(), "prod-eu")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if got := len(snap.Namespaces[0].Workloads); got != controllers {
		t.Fatalf("expected %d workloads (one per Deployment), got %d", controllers, got)
	}
	// Every workload's 20 replicas share one pod-template label set — deduped to one container entry.
	for _, w := range snap.Namespaces[0].Workloads {
		if len(w.Containers) != 1 {
			t.Fatalf("replicas of %s must dedupe to one container, got %d", w.Name, len(w.Containers))
		}
	}
	// Heap growth must stay well under a ceiling for 10k pods (guards against per-replica retention).
	const ceilingBytes = 256 << 20
	if grew := heapDelta(before, after); grew > ceilingBytes {
		t.Fatalf("heap grew %d bytes for 10k pods, over the %d ceiling", grew, ceilingBytes)
	}
}

func heapDelta(before, after runtime.MemStats) uint64 {
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}
