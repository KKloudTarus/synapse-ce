{{- define "synapse.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "synapse.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "synapse.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "synapse.labels" -}}
app.kubernetes.io/name: {{ include "synapse.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "synapse.selectorLabels" -}}
app.kubernetes.io/name: {{ include "synapse.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "synapse.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "synapse.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- /* Production pins an immutable digest. A `tag` (dev/kind/local, where a locally-loaded image has no
       registry digest) overrides it; the production render_test forbids tag-qualified images. */ -}}
{{- define "synapse.image" -}}
{{- if .tag -}}
{{- printf "%s:%s" .repository .tag }}
{{- else -}}
{{- printf "%s@%s" .repository .digest }}
{{- end -}}
{{- end }}

{{- define "synapse.podSecurityContext" -}}
{{- toYaml .Values.podSecurityContext }}
{{- end }}

{{- define "synapse.containerSecurityContext" -}}
{{- toYaml .Values.containerSecurityContext }}
{{- end }}

{{- define "synapse.topologySpreadConstraints" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- range $constraint := $root.Values.topologySpreadConstraints }}
- maxSkew: {{ $constraint.maxSkew }}
  topologyKey: {{ $constraint.topologyKey }}
  whenUnsatisfiable: {{ $constraint.whenUnsatisfiable }}
  labelSelector:
    matchLabels:
      {{- include "synapse.selectorLabels" $root | nindent 6 }}
      app.kubernetes.io/component: {{ $component }}
{{- end }}
{{- end }}

{{- /*
synapse.executionMode selects one of three placements for the untrusted-tool execution tier:
  controlPlaneOnly - API serves and runs OFFLINE scans in-process (SCA/SAST/secrets/IaC/SBOM). Non-production,
                     sandbox off, so it BOOTS on any node (managed EKS, kind, restricted PSA). No egress-enforced
                     execution: DAST, live recon, CSPM, and remote git-clone/image-pull fail closed.
  externalNative   - Production control plane on k8s; the execution tier (synapse-worker + root egress-broker)
                     runs on NATIVE hosts (ADR 0008). Requires api.grantAuthority.enabled. No worker in-cluster.
  inClusterBroker  - Production; runs the execution tier IN-cluster via a privileged egress-broker DaemonSet on
                     capable, tainted/labelled nodes (self-managed / Karpenter custom AMI permitting unprivileged
                     user namespaces). Worker pods stay capless and reach the node-local broker socket.
*/ -}}
{{- define "synapse.executionMode" -}}
{{- $m := default "controlPlaneOnly" .Values.execution.mode -}}
{{- if not (has $m (list "controlPlaneOnly" "externalNative" "inClusterBroker")) -}}
{{- fail (printf "execution.mode must be one of controlPlaneOnly|externalNative|inClusterBroker, got %q" $m) -}}
{{- end -}}
{{- $m -}}
{{- end }}

{{- /*
synapse.validate is a render-time guard that fails with a clear message instead of shipping a chart that
CrashLoopBackOffs. externalNative/inClusterBroker are production and REQUIRE the grant-authority listener so the
API can sign per-run egress grants (config.go ValidateEgressGrantPosture); inClusterBroker additionally needs the
broker DaemonSet enabled and an execution node selector.
*/ -}}
{{- define "synapse.validate" -}}
{{- $mode := include "synapse.executionMode" . -}}
{{- if or (eq $mode "externalNative") (eq $mode "inClusterBroker") -}}
{{- if not .Values.api.grantAuthority.enabled -}}
{{- fail (printf "execution.mode=%s is a production posture and requires api.grantAuthority.enabled=true so the API can sign egress grants" $mode) -}}
{{- end -}}
{{- end -}}
{{- if or (eq $mode "externalNative") (eq $mode "inClusterBroker") -}}
{{- if not .Values.objectStore.useSSL -}}
{{- fail "objectStore.useSSL must be true in a production execution.mode; plaintext blob transport is only permitted in controlPlaneOnly (local/dev)" -}}
{{- end -}}
{{- end -}}
{{- if eq $mode "inClusterBroker" -}}
{{- if not .Values.egressBroker.enabled -}}
{{- fail "execution.mode=inClusterBroker requires egressBroker.enabled=true (the privileged per-run egress broker DaemonSet)" -}}
{{- end -}}
{{- if not .Values.egressBroker.nodeSelector -}}
{{- fail "execution.mode=inClusterBroker requires egressBroker.nodeSelector to pin the broker and worker to execution-capable nodes (unprivileged userns + delegated cgroup v2)" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{- /* synapse.workerEgressEnv wires the worker to the control-plane grant authority and the node-local broker socket. */ -}}
{{- define "synapse.workerEgressEnv" -}}
- name: SYNAPSE_EGRESS_GRANT_AUTHORITY_URL
  value: {{ required "egressBroker.grantAuthorityURL is required for inClusterBroker" .Values.egressBroker.grantAuthorityURL | quote }}
- name: SYNAPSE_EGRESS_GRANT_AUTHORITY_TOKEN
  valueFrom: {secretKeyRef: {name: {{ required "existingSecrets.egressGrant.authorityToken.name is required" .Values.existingSecrets.egressGrant.authorityToken.name }}, key: {{ required "existingSecrets.egressGrant.authorityToken.key is required" .Values.existingSecrets.egressGrant.authorityToken.key }}}}
- name: SYNAPSE_EGRESS_BROKER_SOCKET
  value: {{ .Values.egressBroker.socketHostPath }}/egress-broker.sock
{{- end }}

{{- define "synapse.runtimeEnv" -}}
{{- $mode := include "synapse.executionMode" . -}}
{{- if eq $mode "controlPlaneOnly" }}
- name: SYNAPSE_ENV
  value: development
- name: SYNAPSE_SANDBOX_ENABLED
  value: "false"
{{- else }}
- name: SYNAPSE_ENV
  value: production
- name: SYNAPSE_SANDBOX_ENABLED
  value: "true"
- name: SYNAPSE_TOOL_EXECUTION_MODE
  value: dispatch-only
{{- end }}
- name: SYNAPSE_DB_AUTO_MIGRATE
  value: "false"
- name: SYNAPSE_BLOB_ENDPOINT
  value: {{ required "objectStore.endpoint is required" .Values.objectStore.endpoint | quote }}
- name: SYNAPSE_BLOB_BUCKET
  value: {{ required "objectStore.bucket is required" .Values.objectStore.bucket | quote }}
- name: SYNAPSE_BLOB_USE_SSL
  value: {{ .Values.objectStore.useSSL | quote }}
- name: SYNAPSE_API_TOKEN
  valueFrom: {secretKeyRef: {name: {{ required "existingSecrets.apiToken.name is required" .Values.existingSecrets.apiToken.name }}, key: {{ required "existingSecrets.apiToken.key is required" .Values.existingSecrets.apiToken.key }}}}
- name: SYNAPSE_DB_DSN
  valueFrom: {secretKeyRef: {name: {{ required "existingSecrets.database.runtime.name is required" .Values.existingSecrets.database.runtime.name }}, key: {{ required "existingSecrets.database.runtime.key is required" .Values.existingSecrets.database.runtime.key }}}}
- name: SYNAPSE_DB_MIGRATION_DSN
  valueFrom: {secretKeyRef: {name: {{ required "existingSecrets.database.migration.name is required" .Values.existingSecrets.database.migration.name }}, key: {{ required "existingSecrets.database.migration.key is required" .Values.existingSecrets.database.migration.key }}}}
- name: SYNAPSE_BLOB_ACCESS_KEY
  valueFrom: {secretKeyRef: {name: {{ required "existingSecrets.objectStore.accessKey.name is required" .Values.existingSecrets.objectStore.accessKey.name }}, key: {{ required "existingSecrets.objectStore.accessKey.key is required" .Values.existingSecrets.objectStore.accessKey.key }}}}
- name: SYNAPSE_BLOB_SECRET_KEY
  valueFrom: {secretKeyRef: {name: {{ required "existingSecrets.objectStore.secretKey.name is required" .Values.existingSecrets.objectStore.secretKey.name }}, key: {{ required "existingSecrets.objectStore.secretKey.key is required" .Values.existingSecrets.objectStore.secretKey.key }}}}
- name: SYNAPSE_VAULT_MASTER_KEY
  valueFrom: {secretKeyRef: {name: {{ required "existingSecrets.cryptography.vaultMasterKey.name is required" .Values.existingSecrets.cryptography.vaultMasterKey.name }}, key: {{ required "existingSecrets.cryptography.vaultMasterKey.key is required" .Values.existingSecrets.cryptography.vaultMasterKey.key }}}}
- name: SYNAPSE_EVIDENCE_SIGNING_SEED
  valueFrom: {secretKeyRef: {name: {{ required "existingSecrets.cryptography.evidenceSigningSeed.name is required" .Values.existingSecrets.cryptography.evidenceSigningSeed.name }}, key: {{ required "existingSecrets.cryptography.evidenceSigningSeed.key is required" .Values.existingSecrets.cryptography.evidenceSigningSeed.key }}}}
- name: SYNAPSE_MEASURE_CURSOR_SECRET
  valueFrom: {secretKeyRef: {name: {{ required "existingSecrets.cryptography.measureCursorSecret.name is required" .Values.existingSecrets.cryptography.measureCursorSecret.name }}, key: {{ required "existingSecrets.cryptography.measureCursorSecret.key is required" .Values.existingSecrets.cryptography.measureCursorSecret.key }}}}
{{- if .Values.oidc.enabled }}
- name: SYNAPSE_OIDC_ENABLED
  value: "true"
- name: SYNAPSE_OIDC_ISSUER
  value: {{ required "oidc.issuer is required when oidc.enabled" .Values.oidc.issuer | quote }}
- name: SYNAPSE_OIDC_CLIENT_ID
  value: {{ required "oidc.clientID is required when oidc.enabled" .Values.oidc.clientID | quote }}
- name: SYNAPSE_OIDC_REDIRECT_URL
  value: {{ required "oidc.redirectURL is required when oidc.enabled" .Values.oidc.redirectURL | quote }}
- name: SYNAPSE_OIDC_FRONTEND_URL
  value: {{ required "oidc.frontendURL is required when oidc.enabled" .Values.oidc.frontendURL | quote }}
- name: SYNAPSE_OIDC_TENANT_ID
  value: {{ required "oidc.tenantID is required when oidc.enabled" .Values.oidc.tenantID | quote }}
- name: SYNAPSE_OIDC_GROUP_ROLE_MAPPING
  value: {{ required "oidc.groupRoleMapping must map at least one provider group to a role" (join "," .Values.oidc.groupRoleMapping) | quote }}
- name: SYNAPSE_OIDC_TRANSACTION_TTL
  value: {{ .Values.oidc.transactionTTL | quote }}
- name: SYNAPSE_OIDC_SESSION_TTL
  value: {{ .Values.oidc.sessionTTL | quote }}
- name: SYNAPSE_OIDC_CLIENT_SECRET
  valueFrom: {secretKeyRef: {name: {{ required "existingSecrets.oidc.clientSecret.name is required when oidc.enabled" .Values.existingSecrets.oidc.clientSecret.name }}, key: {{ required "existingSecrets.oidc.clientSecret.key is required when oidc.enabled" .Values.existingSecrets.oidc.clientSecret.key }}}}
{{- end }}
{{- end }}
