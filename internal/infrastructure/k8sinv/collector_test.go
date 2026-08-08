package k8sinv

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	dci "github.com/KKloudTarus/synapse-ce/internal/domain/clusterinventory"
)

func ptrTrue() *bool { b := true; return &b }

func mustCollector(t *testing.T, client kubernetes.Interface, cfg Config) *Collector {
	t.Helper()
	c, err := New(client, cfg)
	if err != nil {
		t.Fatalf("new collector: %v", err)
	}
	return c
}

// seededClient returns a fake clientset with one Deployment (api) fronted by a Service + Ingress in
// namespace "payments", plus a NetworkPolicy and a service account.
func seededClient() *fake.Clientset {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Name: "api-rs", Namespace: "payments",
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api", Controller: ptrTrue()}},
	}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api-rs-abc", Namespace: "payments", Labels: map[string]string{"app": "api"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-rs", Controller: ptrTrue()}},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "payments-sa",
			Containers:         []corev1.Container{{Name: "api", Image: "reg/api:v1"}},
		},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "api", Image: "reg/api:v1", ImageID: "docker-pullable://reg/api@sha256:aaa"},
		}},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "payments"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{"app": "api"}},
	}
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "payments"},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: "api.example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "api"}},
				}},
			}},
		}}},
	}
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "payments"}}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "payments-sa", Namespace: "payments"}}
	return fake.NewSimpleClientset(ns, rs, pod, svc, ing, np, sa)
}

func TestSnapshotMapsWorkloadDigestExposureIdentity(t *testing.T) {
	c := mustCollector(t, seededClient(), Config{Namespaces: []string{"payments"}})
	snap, err := c.Snapshot(context.Background(), "prod-eu")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.Cluster != "prod-eu" || len(snap.Namespaces) != 1 {
		t.Fatalf("unexpected snapshot shape: %+v", snap)
	}
	ns := snap.Namespaces[0]
	if !ns.HasNetworkPolicy {
		t.Error("network policy presence must be detected")
	}
	// Workload: pod's ReplicaSet owner resolved to its Deployment, digest from container status.
	if len(ns.Workloads) != 1 {
		t.Fatalf("expected 1 workload (Deployment api), got %+v", ns.Workloads)
	}
	w := ns.Workloads[0]
	if w.Kind != "Deployment" || w.Name != "api" {
		t.Fatalf("pod's ReplicaSet must resolve to its Deployment, got %s/%s", w.Kind, w.Name)
	}
	if w.ServiceAccount != "payments-sa" {
		t.Fatalf("service account = %q", w.ServiceAccount)
	}
	if len(w.Containers) != 1 || w.Containers[0].Digest != "sha256:aaa" {
		t.Fatalf("resolved digest missing: %+v", w.Containers)
	}
	// Exposures: a Service (with target) and an Ingress (host + target).
	var svc, ing *dci.Exposure
	for i := range ns.Exposures {
		switch ns.Exposures[i].Type {
		case "ClusterIP":
			svc = &ns.Exposures[i]
		case "Ingress":
			ing = &ns.Exposures[i]
		}
	}
	if svc == nil || len(svc.Targets) != 1 || svc.Targets[0].Name != "api" {
		t.Fatalf("service must target the api workload: %+v", svc)
	}
	if ing == nil || len(ing.Hosts) != 1 || ing.Hosts[0] != "api.example.com" {
		t.Fatalf("ingress host missing: %+v", ing)
	}
	if len(ing.Targets) != 1 || ing.Targets[0].Name != "api" {
		t.Fatalf("ingress must resolve to the backend service's workload: %+v", ing)
	}
}

func TestSnapshotEndToEndThroughMapper(t *testing.T) {
	// The collected snapshot must map cleanly and be coverage-honest: the running digest is unscanned.
	c := mustCollector(t, seededClient(), Config{Namespaces: []string{"payments"}})
	snap, err := c.Snapshot(context.Background(), "prod-eu")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inv := dci.Map(snap, map[string]bool{}) // nothing scanned
	found := false
	for _, g := range inv.Gaps {
		if g.Kind == dci.GapUnscannedDigest {
			found = true
		}
	}
	if !found {
		t.Fatalf("an unscanned running digest must surface as a coverage gap: %+v", inv.Gaps)
	}
}

func TestForbiddenListFailsLoud(t *testing.T) {
	client := seededClient()
	// Simulate the read-only role missing pods permission.
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", nil)
	})
	c := mustCollector(t, client, Config{Namespaces: []string{"payments"}})
	_, err := c.Snapshot(context.Background(), "prod-eu")
	if err == nil {
		t.Fatal("a forbidden list must fail loud, not return fewer objects")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("error must preserve the Forbidden cause, got %v", err)
	}
}

func TestBarePodIsItsOwnWorkload(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "lonely", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox:1"}}},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "c", ImageID: "sha256:bbb"}}},
	}
	c := mustCollector(t, fake.NewSimpleClientset(ns, pod), Config{Namespaces: []string{"default"}})
	snap, err := c.Snapshot(context.Background(), "prod-eu")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	w := snap.Namespaces[0].Workloads
	if len(w) != 1 || w[0].Kind != "Pod" || w[0].Name != "lonely" {
		t.Fatalf("a pod with no controller must be its own Pod workload, got %+v", w)
	}
}

func TestInitContainerIsCovered(t *testing.T) {
	// Init containers run real images and must not be silently dropped from the inventory.
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "migrate", Image: "reg/migrate:v1"}},
			Containers:     []corev1.Container{{Name: "app", Image: "reg/app:v1"}},
		},
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{{Name: "migrate", ImageID: "reg/migrate@sha256:init"}},
			ContainerStatuses:     []corev1.ContainerStatus{{Name: "app", ImageID: "reg/app@sha256:main"}},
		},
	}
	c := mustCollector(t, fake.NewSimpleClientset(ns, pod), Config{Namespaces: []string{"default"}})
	snap, err := c.Snapshot(context.Background(), "prod-eu")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	digests := map[string]bool{}
	for _, cont := range snap.Namespaces[0].Workloads[0].Containers {
		digests[cont.Digest] = true
	}
	if !digests["sha256:init"] || !digests["sha256:main"] {
		t.Fatalf("both init and main container digests must be covered, got %v", digests)
	}
}

func TestNilClientRejected(t *testing.T) {
	if _, err := New(nil, Config{}); err == nil {
		t.Fatal("a nil clientset must be rejected")
	}
}

func TestNonAdvancingContinueTokenFailsLoud(t *testing.T) {
	client := seededClient()
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		// Always return the same continue token: a non-advancing cursor.
		return true, &corev1.PodList{ListMeta: metav1.ListMeta{Continue: "stuck"}}, nil
	})
	c := mustCollector(t, client, Config{Namespaces: []string{"payments"}})
	if _, err := c.Snapshot(context.Background(), "prod-eu"); err == nil {
		t.Fatal("a non-advancing continue token must fail loud, not loop forever")
	}
}

func TestMaxPagesCapFailsLoud(t *testing.T) {
	client := seededClient()
	page := 0
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		page++
		// Ever-changing token: never terminates on its own -> the page cap must stop it.
		return true, &corev1.PodList{ListMeta: metav1.ListMeta{Continue: "tok-" + itoa(page)}}, nil
	})
	c := mustCollector(t, client, Config{Namespaces: []string{"payments"}, MaxPages: 3})
	if _, err := c.Snapshot(context.Background(), "prod-eu"); err == nil {
		t.Fatal("an API server paging forever must be stopped by the page cap")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestAllNamespacesWhenScopeEmpty(t *testing.T) {
	c := mustCollector(t, seededClient(), Config{}) // no scope -> discover namespaces
	snap, err := c.Snapshot(context.Background(), "prod-eu")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snap.Namespaces) != 1 || snap.Namespaces[0].Name != "payments" {
		t.Fatalf("empty scope must discover all namespaces, got %+v", snap.Namespaces)
	}
	if len(snap.InScope) != 0 {
		t.Fatalf("empty scope must leave InScope empty (all in scope), got %+v", snap.InScope)
	}
}
