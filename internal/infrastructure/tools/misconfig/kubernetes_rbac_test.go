package misconfig

import "testing"

// The runtime already grants every container a fixed capability set, so re-adding one of those after a
// `drop: ["ALL"]` is the hardening pattern an upstream chart is written with and grants nothing. A capability
// outside that set is a privilege this workload holds and its neighbours do not. Checkov flags both, which is
// why 23 of its findings on a live estate sit on community charts doing the correct thing.
func TestKubernetesAddedCapabilityIgnoresTheRuntimeDefaultSet(t *testing.T) {
	hardened := `apiVersion: v1
kind: Pod
metadata:
  name: ingress
  namespace: prod
spec:
  containers:
    - name: controller
      image: controller:1.0@sha256:abc
      securityContext:
        capabilities:
          drop: ["ALL"]
          add: ["NET_BIND_SERVICE"]
`
	if _, ok := ruleIDs(scan(t, map[string]string{"pod.yaml": hardened}))["kubernetes-added-capability"]; ok {
		t.Error("a capability the runtime grants every container by default must not be reported")
	}

	privileged := `apiVersion: v1
kind: Pod
metadata:
  name: agent
  namespace: prod
spec:
  containers:
    - name: agent
      image: agent:1.0@sha256:abc
      securityContext:
        capabilities:
          drop: ["ALL"]
          add: ["CAP_SYS_TIME"]
`
	got := ruleIDs(scan(t, map[string]string{"pod.yaml": privileged}))
	f, ok := got["kubernetes-added-capability"]
	if !ok {
		t.Fatalf("a capability outside the default set must be reported, got %v", keys(got))
	}
	if !contains(f.Description, "SYS_TIME") {
		t.Errorf("the finding must name the capability, got %q", f.Description)
	}
}

// The two capability rules never fire on the same capability, so a SYS_ADMIN container is one finding and not
// two for one line.
func TestKubernetesDangerousCapabilityIsNotDoubleReported(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: agent
  namespace: prod
spec:
  containers:
    - name: agent
      image: agent:1.0@sha256:abc
      securityContext:
        capabilities:
          add: ["SYS_ADMIN"]
`
	got := ruleIDs(scan(t, map[string]string{"pod.yaml": manifest}))
	if _, ok := got["kubernetes-dangerous-capability"]; !ok {
		t.Errorf("the dangerous-capability rule must still fire, got %v", keys(got))
	}
	if _, ok := got["kubernetes-added-capability"]; ok {
		t.Error("a capability already reported as dangerous must not be reported a second time")
	}
}

// An admission webhook decides what the API server accepts, so write access to one is write access to every
// future object. Read access is how a controller watches them and is not the same grant.
func TestKubernetesWebhookControlNeedsAWriteVerb(t *testing.T) {
	writer := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: webhook-admin
rules:
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["mutatingwebhookconfigurations"]
    verbs: ["create", "update", "patch"]
`
	if _, ok := ruleIDs(scan(t, map[string]string{"role.yaml": writer}))["kubernetes-rbac-webhook-control"]; !ok {
		t.Error("a ClusterRole that can patch a mutating webhook configuration must be reported")
	}

	watcher := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: webhook-watcher
rules:
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["validatingwebhookconfigurations"]
    verbs: ["get", "list", "watch"]
`
	if _, ok := ruleIDs(scan(t, map[string]string{"role.yaml": watcher}))["kubernetes-rbac-webhook-control"]; ok {
		t.Error("read access to a webhook configuration is how a controller watches it and must stay silent")
	}

	// A webhook configuration is cluster-scoped, so a namespaced Role cannot grant it and must not be read as
	// if it had.
	namespaced := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: local
  namespace: dev
rules:
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["mutatingwebhookconfigurations"]
    verbs: ["patch"]
`
	if _, ok := ruleIDs(scan(t, map[string]string{"role.yaml": namespaced}))["kubernetes-rbac-webhook-control"]; ok {
		t.Error("a namespaced Role cannot grant a cluster-scoped resource and must stay silent")
	}

	// A role wildcarding every API group grants this too, and everything else with it. The wildcard rule
	// reports that role, so restating one of its consequences here would be two findings for one decision.
	blanket := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: full-access
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`
	got := ruleIDs(scan(t, map[string]string{"role.yaml": blanket}))
	if _, ok := got["kubernetes-rbac-wildcard-permissions"]; !ok {
		t.Errorf("the wildcard rule must report a blanket ClusterRole, got %v", keys(got))
	}
	if _, ok := got["kubernetes-rbac-webhook-control"]; ok {
		t.Error("a blanket wildcard role is reported once, by the wildcard rule")
	}
}

// A role that reads every Secret is only a defect once something is bound to it, and it matters most when
// that something is a workload identity whose token sits in a pod. The role and the binding are separate
// documents, so the decision waits for the whole tree.
func TestKubernetesReadAllSecretsNeedsARoleAndABinding(t *testing.T) {
	role := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
`
	binding := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-secret-reader
roleRef:
  kind: ClusterRole
  name: secret-reader
subjects:
  - kind: ServiceAccount
    name: app
    namespace: dev
`
	// The role on its own is not reported: nothing holds it yet.
	if _, ok := ruleIDs(scan(t, map[string]string{"rbac/role.yaml": role}))["kubernetes-rbac-read-all-secrets"]; ok {
		t.Error("a role nothing is bound to must not be reported")
	}

	// The two together are, and the finding lands on the binding, which is what granted it.
	got := ruleIDs(scan(t, map[string]string{"rbac/role.yaml": role, "rbac/binding.yaml": binding}))
	f, ok := got["kubernetes-rbac-read-all-secrets"]
	if !ok {
		t.Fatalf("a ServiceAccount bound to an unscoped secret reader must be reported, got %v", keys(got))
	}
	if f.File != "rbac/binding.yaml" {
		t.Errorf("the finding belongs on the binding that granted it, got %q", f.File)
	}
	if f.Resource != "ClusterRoleBinding/app-secret-reader" {
		t.Errorf("the finding must name the binding, got %q", f.Resource)
	}
}

// resourceNames is what turns "every Secret" into "these Secrets", and a human subject authenticates before
// using the permission. Neither case is reported.
func TestKubernetesReadAllSecretsScopeAndSubject(t *testing.T) {
	scoped := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: scoped-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["app-db"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: scoped-reader
roleRef:
  kind: ClusterRole
  name: scoped-reader
subjects:
  - kind: ServiceAccount
    name: app
    namespace: dev
`
	if _, ok := ruleIDs(scan(t, map[string]string{"rbac.yaml": scoped}))["kubernetes-rbac-read-all-secrets"]; ok {
		t.Error("a rule narrowed with resourceNames must stay silent")
	}

	human := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admins
roleRef:
  kind: ClusterRole
  name: secret-reader
subjects:
  - kind: Group
    name: platform-admins
`
	if _, ok := ruleIDs(scan(t, map[string]string{"rbac.yaml": human}))["kubernetes-rbac-read-all-secrets"]; ok {
		t.Error("a Group subject authenticates before using the permission and must stay silent")
	}

	// A namespaced Role is matched by namespace as well as name, so a binding naming a Role of the same name
	// in another namespace grants nothing here.
	crossNamespace := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: dev
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-reader
  namespace: prod
roleRef:
  kind: Role
  name: secret-reader
subjects:
  - kind: ServiceAccount
    name: app
    namespace: prod
`
	if _, ok := ruleIDs(scan(t, map[string]string{"rbac.yaml": crossNamespace}))["kubernetes-rbac-read-all-secrets"]; ok {
		t.Error("a Role is identified by its namespace as well as its name and must not match across namespaces")
	}
}

// A snippet is nginx configuration the Ingress author writes, rendered into the controller's shared config and
// run with the controller's identity. An ordinary annotation is not.
func TestKubernetesIngressSnippetAnnotation(t *testing.T) {
	snippet := `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
  namespace: prod
  annotations:
    nginx.ingress.kubernetes.io/server-snippet: |
      location /internal { deny all; }
spec:
  tls:
    - hosts: ["app.example.com"]
      secretName: app-tls
  rules:
    - host: app.example.com
`
	got := ruleIDs(scan(t, map[string]string{"ingress.yaml": snippet}))
	f, ok := got["kubernetes-ingress-annotation-snippet"]
	if !ok {
		t.Fatalf("a snippet annotation must be reported, got %v", keys(got))
	}
	if !contains(f.Description, "CVE-2021-25742") {
		t.Errorf("the finding must name the CVE it is, got %q", f.Description)
	}

	plain := `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
  namespace: prod
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: letsencrypt
spec:
  tls:
    - hosts: ["app.example.com"]
      secretName: app-tls
  rules:
    - host: app.example.com
`
	if _, ok := ruleIDs(scan(t, map[string]string{"ingress.yaml": plain}))["kubernetes-ingress-annotation-snippet"]; ok {
		t.Error("an ordinary annotation must not be read as a configuration snippet")
	}
}
