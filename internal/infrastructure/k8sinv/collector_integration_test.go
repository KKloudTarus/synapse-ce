package k8sinv

import (
	"context"
	"os"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// These tests run against a REAL cluster (a kind cluster in CI). They are skipped unless
// SYNAPSE_K8S_INTEGRATION=1, so `go test ./...` stays hermetic locally and in the normal CI job. The
// CI job (`.github/workflows/k8s-integration.yml`) provisions kind, applies the read-only ClusterRole
// from deploy/k8s/cluster-agent.yaml, and runs these with the flag set.
//
// The agent's read-only access is exercised by IMPERSONATING the shipped service account, so the tests
// prove the real ClusterRole is sufficient — and that a principal without it fails loud.

const (
	agentSAUser  = "system:serviceaccount:synapse:synapse-cluster-agent"
	noAccessUser = "synapse-integration-no-access"
)

func integrationConfig(t *testing.T) *rest.Config {
	t.Helper()
	if os.Getenv("SYNAPSE_K8S_INTEGRATION") != "1" {
		t.Skip("set SYNAPSE_K8S_INTEGRATION=1 (with a reachable cluster) to run the kind integration tests")
	}
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg
	}
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("integration: load kube config: %v", err)
	}
	return cfg
}

func impersonating(t *testing.T, base *rest.Config, user string) kubernetes.Interface {
	t.Helper()
	cfg := rest.CopyConfig(base)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: user}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("integration: build impersonating client: %v", err)
	}
	return client
}

// TestIntegrationReadOnlyInventory creates a Deployment with the admin client, waits for its pod to
// resolve an image digest, then collects the inventory THROUGH the read-only service account (via
// impersonation) — proving the shipped ClusterRole is sufficient for a full workload inventory.
func TestIntegrationReadOnlyInventory(t *testing.T) {
	base := integrationConfig(t)
	admin, err := kubernetes.NewForConfig(base)
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	nsName := "synapse-int-" + itoa(int(time.Now().UnixNano()%100000))
	if _, err := admin.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName}}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.CoreV1().Namespaces().Delete(context.Background(), nsName, metav1.DeleteOptions{})
	})

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "pause", Namespace: nsName},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptrInt32(1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "pause"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "pause"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.9"}}},
			},
		},
	}
	if _, err := admin.AppsV1().Deployments(nsName).Create(ctx, dep, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create deployment: %v", err)
	}

	// Wait for a running pod with a resolved image digest.
	if !waitForResolvedDigest(ctx, t, admin, nsName) {
		t.Fatal("pod never reported a resolved image digest")
	}

	collector := mustCollector(t, impersonating(t, base, agentSAUser), Config{Namespaces: []string{nsName}})
	snap, err := collector.Snapshot(ctx, "integration-cluster")
	if err != nil {
		t.Fatalf("read-only collect via the shipped ClusterRole must succeed: %v", err)
	}
	if len(snap.Namespaces) != 1 || len(snap.Namespaces[0].Workloads) == 0 {
		t.Fatalf("expected the pause workload, got %+v", snap.Namespaces)
	}
	var digest string
	for _, w := range snap.Namespaces[0].Workloads {
		if w.Kind == "Deployment" && w.Name == "pause" {
			for _, c := range w.Containers {
				if c.Digest != "" {
					digest = c.Digest
				}
			}
		}
	}
	if digest == "" {
		t.Fatalf("the running pause container must have a resolved digest: %+v", snap.Namespaces[0].Workloads)
	}

	// Idempotent resync: a second collect yields the same workload set.
	snap2, err := collector.Snapshot(ctx, "integration-cluster")
	if err != nil {
		t.Fatalf("second collect: %v", err)
	}
	if len(snap2.Namespaces[0].Workloads) != len(snap.Namespaces[0].Workloads) {
		t.Fatalf("resync must be idempotent: %d vs %d workloads", len(snap.Namespaces[0].Workloads), len(snap2.Namespaces[0].Workloads))
	}
}

// TestIntegrationMissingPermissionFailsLoud collects as a principal with NO RBAC and asserts the
// collector fails loud (Forbidden) rather than returning an empty-but-"clean" inventory.
func TestIntegrationMissingPermissionFailsLoud(t *testing.T) {
	base := integrationConfig(t)
	collector := mustCollector(t, impersonating(t, base, noAccessUser), Config{})
	_, err := collector.Snapshot(context.Background(), "integration-cluster")
	if err == nil {
		t.Fatal("a principal without RBAC must fail loud, not return a clean inventory")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("error must be Forbidden, got %v", err)
	}
}

func waitForResolvedDigest(ctx context.Context, t *testing.T, client kubernetes.Interface, ns string) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for i := range pods.Items {
				for _, cs := range pods.Items[i].Status.ContainerStatuses {
					if digestFromImageID(cs.ImageID) != "" {
						return true
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(3 * time.Second):
		}
	}
	return false
}

func ptrInt32(v int32) *int32 { return &v }
