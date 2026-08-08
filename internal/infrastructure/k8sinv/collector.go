// Package k8sinv is the Kubernetes infrastructure adapter for the cluster agent (#411, epic #405).
// It reads a live cluster through k8s.io/client-go and produces the vendor-neutral
// domain/clusterinventory.Snapshot that the pure mapper consumes. This is the ONLY place a
// Kubernetes type appears; no k8s type crosses into a domain or usecase package (dependency rule).
//
// Two properties matter for a security tool:
//   - Fail loud on missing permission. A List that returns Forbidden is an error naming the resource,
//     never fewer objects reported as if the namespace were clean (requirement 6). The read-only
//     ClusterRole is shipped in the deployment manifest.
//   - Bounded reads. Lists are paginated by a configurable page size, and the total number of pages
//     per resource is capped, so a large — or hostile — API server cannot drive unbounded memory
//     growth or a non-terminating Continue loop (requirement 7). Callers should also pass a ctx with a
//     deadline; the pagination loop honors cancellation every iteration.
//
// Collection is read-only: only get/list verbs are used; the agent never mutates the cluster.
package k8sinv

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	dci "github.com/KKloudTarus/synapse-ce/internal/domain/clusterinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	defaultPageSize = 500
	// defaultMaxPages caps the pages fetched per resource. With the default page size this bounds a
	// single resource to ~5M objects before the collector aborts rather than accumulate unbounded
	// memory from a huge — or hostile — API server.
	defaultMaxPages = 10000
)

// Config controls collection scope and bounds.
type Config struct {
	// Namespaces restricts collection to this list; empty means all namespaces are in scope.
	Namespaces []string
	// PageSize bounds each List response; <=0 uses the default.
	PageSize int64
	// MaxPages caps the number of pages fetched per resource (memory / infinite-loop guard); <=0 uses
	// the default.
	MaxPages int64
}

// Collector reads a cluster into a Snapshot.
type Collector struct {
	client kubernetes.Interface
	cfg    Config
}

// New builds a collector over the given clientset. It validates its dependency per the constructor
// convention: a nil clientset is rejected rather than panicking on the first List.
func New(client kubernetes.Interface, cfg Config) (*Collector, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: k8sinv requires a kubernetes client", shared.ErrValidation)
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = defaultPageSize
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = defaultMaxPages
	}
	return &Collector{client: client, cfg: cfg}, nil
}

// Snapshot reads the cluster and returns the neutral inventory snapshot for cluster identity id.
func (c *Collector) Snapshot(ctx context.Context, cluster string) (dci.Snapshot, error) {
	snap := dci.Snapshot{Cluster: cluster, InScope: append([]string(nil), c.cfg.Namespaces...)}

	namespaces, err := c.targetNamespaces(ctx)
	if err != nil {
		return dci.Snapshot{}, err
	}
	for _, ns := range namespaces {
		nsEntry, err := c.collectNamespace(ctx, ns)
		if err != nil {
			return dci.Snapshot{}, err
		}
		snap.Namespaces = append(snap.Namespaces, nsEntry)
	}
	return snap, nil
}

// targetNamespaces returns the namespaces to collect: the configured scope when set, else every
// namespace on the cluster. When a scope is set the collector lists only those namespaces (so a
// namespace-scoped role suffices), which by design means it never presents an out-of-scope namespace
// to the mapper — the operator restricted collection, so GapOutOfScopeNamespace is not produced via
// this path; Snapshot.InScope still lets the mapper flag an in-scope namespace that was not observed.
func (c *Collector) targetNamespaces(ctx context.Context) ([]string, error) {
	if len(c.cfg.Namespaces) > 0 {
		return append([]string(nil), c.cfg.Namespaces...), nil
	}
	var out []string
	err := c.pageList(ctx, "namespaces", "", func(opts metav1.ListOptions) (continueToken string, err error) {
		list, err := c.client.CoreV1().Namespaces().List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			out = append(out, list.Items[i].Name)
		}
		return list.Continue, nil
	})
	return out, err
}

func (c *Collector) collectNamespace(ctx context.Context, ns string) (dci.Namespace, error) {
	entry := dci.Namespace{Name: ns}

	// NetworkPolicy presence (exposure posture).
	npCount := 0
	if err := c.pageList(ctx, "networkpolicies", ns, func(opts metav1.ListOptions) (string, error) {
		list, err := c.client.NetworkingV1().NetworkPolicies(ns).List(ctx, opts)
		if err != nil {
			return "", err
		}
		npCount += len(list.Items)
		return list.Continue, nil
	}); err != nil {
		return dci.Namespace{}, err
	}
	entry.HasNetworkPolicy = npCount > 0

	// Service accounts.
	if err := c.pageList(ctx, "serviceaccounts", ns, func(opts metav1.ListOptions) (string, error) {
		list, err := c.client.CoreV1().ServiceAccounts(ns).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			entry.ServiceAccounts = append(entry.ServiceAccounts, list.Items[i].Name)
		}
		return list.Continue, nil
	}); err != nil {
		return dci.Namespace{}, err
	}

	// ReplicaSet -> owning controller index, so a Pod owned by a ReplicaSet resolves to its Deployment.
	rsOwner, err := c.replicaSetOwners(ctx, ns)
	if err != nil {
		return dci.Namespace{}, err
	}

	// Pods -> workloads (grouped by resolved controller) with resolved digests + service account.
	workloads, podLabels, err := c.collectWorkloads(ctx, ns, rsOwner)
	if err != nil {
		return dci.Namespace{}, err
	}
	entry.Workloads = workloads

	// Exposures: Services + Ingresses, with best-effort target resolution via observed pods.
	exposures, err := c.collectExposures(ctx, ns, podLabels)
	if err != nil {
		return dci.Namespace{}, err
	}
	entry.Exposures = exposures

	return entry, nil
}

// controllerRef is a resolved workload identity.
type controllerRef struct {
	kind string
	name string
}

// podLabelSets maps a controller to the DISTINCT label sets of its pods. Replicas share pod-template
// labels, so deduping collapses them to a handful of sets and keeps selector matching cheap.
type podLabelSets map[controllerRef][]map[string]string

func (c *Collector) replicaSetOwners(ctx context.Context, ns string) (map[string]controllerRef, error) {
	owners := map[string]controllerRef{}
	err := c.pageList(ctx, "replicasets", ns, func(opts metav1.ListOptions) (string, error) {
		list, err := c.client.AppsV1().ReplicaSets(ns).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			rs := &list.Items[i]
			if ctrl := controllerOwner(rs.OwnerReferences); ctrl != nil {
				owners[rs.Name] = *ctrl
			}
		}
		return list.Continue, nil
	})
	return owners, err
}

func (c *Collector) collectWorkloads(ctx context.Context, ns string, rsOwner map[string]controllerRef) ([]dci.Workload, podLabelSets, error) {
	// Aggregate containers per controller (deduped) and remember the service account.
	type agg struct {
		sa         string
		containers map[string]dci.Container // key: containerName|image|digest
		order      []string
		labelSets  []map[string]string
		labelSeen  map[string]bool
	}
	byCtrl := map[controllerRef]*agg{}

	err := c.pageList(ctx, "pods", ns, func(opts metav1.ListOptions) (string, error) {
		list, err := c.client.CoreV1().Pods(ns).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			p := &list.Items[i]
			ctrl := resolveController(p, rsOwner)
			a := byCtrl[ctrl]
			if a == nil {
				a = &agg{sa: serviceAccount(p), containers: map[string]dci.Container{}, labelSeen: map[string]bool{}}
				byCtrl[ctrl] = a
			}
			for _, cont := range containersOf(p) {
				k := cont.Name + "|" + cont.Image + "|" + cont.Digest
				if _, ok := a.containers[k]; !ok {
					a.containers[k] = cont
					a.order = append(a.order, k)
				}
			}
			if lk := canonLabels(p.Labels); !a.labelSeen[lk] {
				a.labelSeen[lk] = true
				a.labelSets = append(a.labelSets, p.Labels)
			}
		}
		return list.Continue, nil
	})
	if err != nil {
		return nil, nil, err
	}

	out := make([]dci.Workload, 0, len(byCtrl))
	labels := make(podLabelSets, len(byCtrl))
	for ctrl, a := range byCtrl {
		w := dci.Workload{Kind: ctrl.kind, Name: ctrl.name, ServiceAccount: a.sa}
		for _, k := range a.order {
			w.Containers = append(w.Containers, a.containers[k])
		}
		out = append(out, w)
		labels[ctrl] = a.labelSets
	}
	// Deterministic order so the Snapshot is stable/diffable at the infra edge (the mapper also sorts).
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out, labels, nil
}

func (c *Collector) collectExposures(ctx context.Context, ns string, podLabels podLabelSets) ([]dci.Exposure, error) {
	var out []dci.Exposure
	// serviceTargets maps a service name to the workloads its selector matches (via observed pods).
	serviceTargets := map[string][]dci.Target{}

	err := c.pageList(ctx, "services", ns, func(opts metav1.ListOptions) (string, error) {
		list, err := c.client.CoreV1().Services(ns).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			svc := &list.Items[i]
			targets := matchTargets(svc.Spec.Selector, podLabels)
			serviceTargets[svc.Name] = targets
			out = append(out, dci.Exposure{
				Name:    svc.Name,
				Type:    string(svc.Spec.Type),
				Targets: targets,
			})
		}
		return list.Continue, nil
	})
	if err != nil {
		return nil, err
	}

	err = c.pageList(ctx, "ingresses", ns, func(opts metav1.ListOptions) (string, error) {
		list, err := c.client.NetworkingV1().Ingresses(ns).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			ing := &list.Items[i]
			out = append(out, dci.Exposure{
				Name:    ing.Name,
				Type:    "Ingress",
				Hosts:   ingressHosts(ing),
				Targets: ingressTargets(ing, serviceTargets),
			})
		}
		return list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// pageList runs fn in a Continue loop, translating a Forbidden error into a clear, resource-named
// failure so a missing RBAC permission fails loud rather than silently returning fewer objects.
func (c *Collector) pageList(ctx context.Context, resource, ns string, fn func(metav1.ListOptions) (continueToken string, err error)) error {
	cont := ""
	for pages := int64(0); ; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if pages >= c.cfg.MaxPages {
			// Bound total accumulation: abort loudly rather than let a huge or hostile API server drive
			// unbounded memory growth by paging forever.
			return fmt.Errorf("k8sinv: list %s%s: exceeded max pages (%d)", resource, nsSuffix(ns), c.cfg.MaxPages)
		}
		token, err := fn(metav1.ListOptions{Limit: c.cfg.PageSize, Continue: cont})
		if err != nil {
			if apierrors.IsForbidden(err) {
				return fmt.Errorf("k8sinv: missing permission to list %s%s: %w", resource, nsSuffix(ns), err)
			}
			return fmt.Errorf("k8sinv: list %s%s: %w", resource, nsSuffix(ns), err)
		}
		if token == "" {
			return nil
		}
		if token == cont {
			// A repeating continue token means the API server is not advancing the cursor; stop rather
			// than loop forever.
			return fmt.Errorf("k8sinv: list %s%s: API server returned a non-advancing continue token", resource, nsSuffix(ns))
		}
		cont = token
	}
}

// --- pure helpers ---

func nsSuffix(ns string) string {
	if ns == "" {
		return ""
	}
	return " in namespace " + ns
}

func controllerOwner(refs []metav1.OwnerReference) *controllerRef {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &controllerRef{kind: refs[i].Kind, name: refs[i].Name}
		}
	}
	return nil
}

// resolveController returns the top-level controller for a pod: a ReplicaSet owner is resolved to its
// Deployment via rsOwner; other controllers (StatefulSet/DaemonSet/Job) are used directly; a pod with
// no controller owner is its own workload (kind Pod).
func resolveController(p *corev1.Pod, rsOwner map[string]controllerRef) controllerRef {
	ctrl := controllerOwner(p.OwnerReferences)
	if ctrl == nil {
		return controllerRef{kind: "Pod", name: p.Name}
	}
	if ctrl.kind == "ReplicaSet" {
		if dep, ok := rsOwner[ctrl.name]; ok {
			return dep
		}
	}
	return *ctrl
}

func serviceAccount(p *corev1.Pod) string { return p.Spec.ServiceAccountName }

// containersOf returns ALL of the pod's containers — regular, init, and ephemeral — with the resolved
// digest from the matching container status. Init containers run real (often privileged) images and
// ephemeral debug containers are a live attack surface, so excluding them would be a silent coverage
// gap, which the inventory model exists to prevent.
func containersOf(p *corev1.Pod) []dci.Container {
	digestByName := map[string]string{}
	imageByName := map[string]string{}
	record := func(name, image, imageID string) {
		digestByName[name] = digestFromImageID(imageID)
		imageByName[name] = image
	}
	for _, cs := range p.Status.ContainerStatuses {
		record(cs.Name, cs.Image, cs.ImageID)
	}
	for _, cs := range p.Status.InitContainerStatuses {
		record(cs.Name, cs.Image, cs.ImageID)
	}
	for _, cs := range p.Status.EphemeralContainerStatuses {
		record(cs.Name, cs.Image, cs.ImageID)
	}

	var out []dci.Container
	add := func(name, specImage string) {
		image := specImage
		if img := imageByName[name]; img != "" {
			image = img
		}
		out = append(out, dci.Container{Name: name, Image: image, Digest: digestByName[name]})
	}
	for _, spec := range p.Spec.Containers {
		add(spec.Name, spec.Image)
	}
	for _, spec := range p.Spec.InitContainers {
		add(spec.Name, spec.Image)
	}
	for _, spec := range p.Spec.EphemeralContainers {
		add(spec.Name, spec.Image)
	}
	return out
}

// digestFromImageID extracts the sha256 digest from a container status ImageID, which appears as
// "docker-pullable://reg/img@sha256:..", "reg/img@sha256:..", or bare "sha256:..".
func digestFromImageID(imageID string) string {
	if i := strings.LastIndex(imageID, "@"); i >= 0 {
		return imageID[i+1:]
	}
	if strings.HasPrefix(imageID, "sha256:") {
		return imageID
	}
	return ""
}

// matchTargets returns the workloads whose pods carry all of selector's labels. An empty selector
// matches nothing (headless/external services have no workload target). Output is sorted so the
// Snapshot is deterministic.
func matchTargets(selector map[string]string, podLabels podLabelSets) []dci.Target {
	if len(selector) == 0 {
		return nil
	}
	var out []dci.Target
	for ctrl, sets := range podLabels {
		for _, labels := range sets {
			if labelsContain(labels, selector) {
				out = append(out, dci.Target{Kind: ctrl.kind, Name: ctrl.name})
				break
			}
		}
	}
	sortTargets(out)
	return out
}

func sortTargets(t []dci.Target) {
	sort.Slice(t, func(i, j int) bool {
		if t[i].Kind != t[j].Kind {
			return t[i].Kind < t[j].Kind
		}
		return t[i].Name < t[j].Name
	})
}

// canonLabels renders a label set as a stable string for deduplication.
func canonLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
		b.WriteByte('\x00')
	}
	return b.String()
}

func labelsContain(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func ingressHosts(ing *networkingv1.Ingress) []string {
	var hosts []string
	for _, r := range ing.Spec.Rules {
		if r.Host != "" {
			hosts = append(hosts, r.Host)
		}
	}
	return hosts
}

// ingressTargets resolves an ingress to the workloads behind its backend services (default backend +
// per-path backends), reusing the service->targets map.
func ingressTargets(ing *networkingv1.Ingress, serviceTargets map[string][]dci.Target) []dci.Target {
	seen := map[dci.Target]bool{}
	var out []dci.Target
	add := func(name string) {
		for _, t := range serviceTargets[name] {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	if db := ing.Spec.DefaultBackend; db != nil && db.Service != nil {
		add(db.Service.Name)
	}
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for _, path := range r.HTTP.Paths {
			if path.Backend.Service != nil {
				add(path.Backend.Service.Name)
			}
		}
	}
	return out
}
