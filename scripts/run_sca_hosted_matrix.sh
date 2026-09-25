#!/usr/bin/env bash
set -euo pipefail

# This script runs inside a network-disabled Linux container. /inputs is the
# digest-verified archive, /owned is the current built scanner, and /out holds
# raw outputs consumed locally by the scoring step (never uploaded directly).
test -x /owned
test -d /inputs/databases/grype
test -d /inputs/databases/trivy
test -d /inputs/databases/osv
mkdir -p /out
printf '' > /tmp/sca-empty.yaml
printf '{}\n' > /tmp/sca-empty.json
printf '' > /tmp/sca-empty.ignore
for name in grype trivy osv-scanner; do
  cp "/inputs/tools/$name" "/tmp/$name"
  chmod 0755 "/tmp/$name"
done

for target in debian-12-13-slim-amd64 rhel-9-8-ubi-amd64 sles-15-6-bci-base-45-31-amd64; do
  sbom="/inputs/sboms/${target}.cdx.json"
  test -s "$sbom"
  case "$target" in
    debian-*) database=owned-debian; format=oval ;;
    rhel-*) database=owned-redhat; format=csaf-json ;;
    sles-*) database=owned-sles; format=oval ;;
    *) exit 2 ;;
  esac
  timeout 480 /owned --owned-helper --database "/inputs/databases/$database" --database-format "$format" --sbom "$sbom" > "/out/owned-${target}.json" 2> "/out/owned-${target}.stderr"
  GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_CACHE_DIR=/inputs/databases/grype GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_VALIDATE_AGE=false GRYPE_DB_VALIDATE_BY_HASH_ON_START=true \
    timeout 480 /tmp/grype "sbom:${sbom}" -o json -q --config /tmp/sca-empty.yaml > "/out/grype-${target}.json" 2> "/out/grype-${target}.stderr"
  timeout 480 /tmp/trivy sbom --format json --scanners vuln --cache-dir /inputs/databases/trivy --config /tmp/sca-empty.json --ignorefile /tmp/sca-empty.ignore \
    --skip-db-update --skip-java-db-update --skip-version-check --skip-vex-repo-update --offline-scan --disable-telemetry --quiet --exit-code 0 "$sbom" \
    > "/out/trivy-${target}.json" 2> "/out/trivy-${target}.stderr"
  test -s "/out/owned-${target}.json"
  test -s "/out/grype-${target}.json"
  test -s "/out/trivy-${target}.json"
done

/tmp/osv-scanner --version > /out/osv-version.txt
set +e
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/inputs/databases/osv timeout 480 /tmp/osv-scanner scan source --offline --offline-vulnerabilities \
  --experimental-no-default-plugins --experimental-plugins=lockfile --experimental-plugins=sbom --format json \
  --config=/tmp/sca-empty.yaml --lockfile=/inputs/sboms/debian-12-13-slim-amd64.cdx.json \
  > /out/osv-scanner-debian-12-13-slim-amd64.json 2> /out/osv-scanner-debian-12-13-slim-amd64.stderr
osv_exit=$?
set -e
if [[ "$osv_exit" -ne 0 && "$osv_exit" -ne 1 ]]; then
  printf 'OSV scanner exited with %s\n' "$osv_exit" >&2
  exit "$osv_exit"
fi
test -s /out/osv-scanner-debian-12-13-slim-amd64.json
test -s /out/osv-version.txt
