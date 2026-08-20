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

{{- define "synapse.image" -}}
{{- printf "%s@%s" .repository .digest }}
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

{{- define "synapse.runtimeEnv" -}}
- name: SYNAPSE_ENV
  value: production
- name: SYNAPSE_DB_AUTO_MIGRATE
  value: "false"
- name: SYNAPSE_SANDBOX_ENABLED
  value: "true"
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
