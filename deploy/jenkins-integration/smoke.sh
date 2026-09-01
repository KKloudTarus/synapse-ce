#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
env_file="$(mktemp)"
project_name="synapse-integration-e2e"

for command in curl docker jq openssl; do
  command -v "$command" >/dev/null || { printf 'missing required command: %s\n' "$command" >&2; exit 1; }
done

cat >"$env_file" <<EOF
DB_ADMIN_PASSWORD=$(openssl rand -hex 24)
DB_APP_PASSWORD=$(openssl rand -hex 24)
SYNAPSE_API_TOKEN=$(openssl rand -hex 32)
SYNAPSE_VAULT_MASTER_KEY=$(openssl rand -hex 32)
JENKINS_TEST_PASSWORD=$(openssl rand -hex 24)
JENKINS_HTTPS_KEYSTORE_PASSWORD=$(openssl rand -hex 24)
EOF
chmod 600 "$env_file"

set -a
# shellcheck disable=SC1090
source "$env_file"
set +a

compose=(docker compose --env-file "$env_file" --project-name "$project_name" -f "$root/compose.yml")

cleanup() {
  status=$?
  if (( status != 0 )); then
    "${compose[@]}" ps >&2 || true
    "${compose[@]}" logs --no-color --tail=200 synapse-api synapse-worker jenkins migrate >&2 || true
  fi
  if [[ "${KEEP_INTEGRATION_STACK:-${KEEP_JENKINS:-0}}" != "1" ]]; then
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -f "$env_file"
  exit "$status"
}
trap cleanup EXIT

"${compose[@]}" up -d --build

for _ in {1..120}; do
  if curl -fsS http://localhost:18081/readyz >/dev/null; then
    break
  fi
  sleep 2
done
curl -fsS http://localhost:18081/readyz >/dev/null

worker_running() {
  [[ "$("${compose[@]}" ps --status running --services synapse-worker)" == "synapse-worker" ]]
}

if ! worker_running; then
  printf 'synapse-worker exited before integration operations started\n' >&2
  "${compose[@]}" logs --no-color --tail=100 synapse-worker >&2 || true
  exit 1
fi

jenkins_token="$("${compose[@]}" exec -T jenkins cat /var/jenkins_home/secrets/synapse-api-token)"
for _ in {1..60}; do
  builds_json="$(curl -gkfsS -u "synapse:$jenkins_token" 'https://localhost:18443/job/synapse-smoke/api/json?tree=builds[number,actions[lastBuiltRevision[SHA1,branch[SHA1,name]]]]')"
  if [[ "$(jq -r '.builds[0].actions[]?.lastBuiltRevision.SHA1 // empty' <<<"$builds_json")" == "0123456789abcdef0123456789abcdef01234567" ]]; then
    break
  fi
  sleep 1
done
[[ "$(jq -r '.builds[0].actions[]?.lastBuiltRevision.SHA1 // empty' <<<"$builds_json")" == "0123456789abcdef0123456789abcdef01234567" ]]

api() {
  local method=$1
  local path=$2
  local body=${3-}
  local args=(-fsS -X "$method" -H "Authorization: Bearer $SYNAPSE_API_TOKEN" -H 'Content-Type: application/json')
  if [[ -n "$body" ]]; then
    args+=(-d "$body")
  fi
  curl "${args[@]}" "http://localhost:18081/api/v1$path"
}

wait_operation() {
  local operation_id=$1
  local operation_json state
  for _ in {1..120}; do
    if ! worker_running; then
      printf 'synapse-worker exited while operation %s was pending\n' "$operation_id" >&2
      "${compose[@]}" logs --no-color --tail=100 synapse-worker >&2 || true
      return 1
    fi
    operation_json="$(api GET "/integration-operations/$operation_id")"
    state="$(jq -r '.state' <<<"$operation_json")"
    case "$state" in
      succeeded|partial) printf '%s' "$operation_json"; return 0 ;;
      failed|cancelled) printf '%s\n' "$operation_json" >&2; return 1 ;;
    esac
    sleep 1
  done
  printf 'operation %s did not finish\n' "$operation_id" >&2
  return 1
}

aup_json="$(api GET /aup)"
api POST /aup/accept "$(jq -nc --arg version "$(jq -r '.version' <<<"$aup_json")" '{version:$version}')" >/dev/null

project_json="$(api POST /projects '{"name":"Jenkins E2E","key":"jenkins-e2e","source_binding":{"kind":"git","value":"https://example.com/synapse-e2e.git","ref":"main"}}')"
project_id="$(jq -r '.ID' <<<"$project_json")"
[[ -n "$project_id" && "$project_id" != null ]]

integration_json="$(api POST /integrations '{"provider":"jenkins","name":"Jenkins E2E","endpoint":"https://jenkins:8443","config":{},"allow_private_network":true,"poll_interval_seconds":300}')"
integration_id="$(jq -r '.id' <<<"$integration_json")"
api PUT "/integrations/$integration_id/credentials" "$(jq -nc --arg token "$jenkins_token" '{secrets:{username:"synapse",api_token:$token}}')" >/dev/null

test_operation="$(api POST "/integrations/$integration_id/operations" '{"type":"test"}')"
wait_operation "$(jq -r '.id' <<<"$test_operation")" >/dev/null

integration_json="$(api GET "/integrations/$integration_id")"
api POST "/integrations/$integration_id/enable" "$(jq -nc --argjson version "$(jq -r '.version' <<<"$integration_json")" '{version:$version}')" >/dev/null

discover_operation="$(api POST "/integrations/$integration_id/operations" '{"type":"discover"}')"
discover_json="$(wait_operation "$(jq -r '.id' <<<"$discover_operation")")"
external_key="$(jq -r '.pipelines[] | select(.name == "synapse-smoke") | .external_key' <<<"$discover_json")"
[[ "$external_key" == "/job/synapse-smoke" ]]

api POST "/integrations/$integration_id/bindings" "$(jq -nc --arg project "$project_id" --arg key "$external_key" '{project_id:$project,external_key:$key,external_name:"synapse-smoke"}')" >/dev/null

# ponytail: seed one analysis snapshot to isolate exact-commit correlation; replace it with a real source scan when the CI harness can afford scanner runtime and artifacts.
analysis_id="analysis-jenkins-e2e"
"${compose[@]}" exec -T \
  -e PGPASSWORD="$DB_ADMIN_PASSWORD" \
  postgres psql -U synapse_admin -d synapse -v ON_ERROR_STOP=1 \
  -v project_id="$project_id" -v analysis_id="$analysis_id" <<'SQL'
INSERT INTO project_analyses (id, tenant_id, project_id, created_at, payload)
VALUES (
  :'analysis_id',
  'default',
  :'project_id',
  now(),
  jsonb_build_object(
    'id', :'analysis_id',
    'tenant_id', 'default',
    'project_id', :'project_id',
    'project_key', 'jenkins-e2e',
    'created_at', now(),
    'source_commit', '0123456789abcdef0123456789abcdef01234567'
  )
);
SQL

poll_operation="$(api POST "/integrations/$integration_id/operations" '{"type":"poll"}')"
wait_operation "$(jq -r '.id' <<<"$poll_operation")" >/dev/null
runs_json="$(api GET "/integrations/$integration_id/external-runs?limit=10")"
jq -e --arg analysis "$analysis_id" '.[] | select(.revision == "0123456789abcdef0123456789abcdef01234567" and .analysis_id == $analysis and .correlation == "linked")' <<<"$runs_json" >/dev/null

printf 'Jenkins create → test → enable → discover → bind → poll → correlate E2E passed.\n'
