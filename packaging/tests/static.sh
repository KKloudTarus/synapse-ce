#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd -- "$root"

bash -n packaging/scripts/build-worker-package.sh packaging/scripts/render-worker-runtime-env.sh
sh -n packaging/scripts/worker-preinstall.sh packaging/scripts/worker-preremove.sh packaging/scripts/worker-postremove.sh
grep -Fq 'install -d -o root -g root -m 0755 /run/netns' packaging/scripts/worker-preinstall.sh

grep -Fq 'User=synapse-worker' packaging/systemd/synapse-worker.service
grep -Fq 'Delegate=yes' packaging/systemd/synapse-worker.service
grep -Fq 'CapabilityBoundingSet=' packaging/systemd/synapse-worker.service
grep -Fq 'Requires=synapse-worker-runtime-env.service synapse-egress-broker.service synapse-worker-sandbox-check.service' packaging/systemd/synapse-worker.service
grep -Fq 'User=synapse-worker' packaging/systemd/synapse-worker-sandbox-check.service
grep -Fq 'ExecStart=/opt/synapse/synapse-sandbox-check -mode=full -strict' packaging/systemd/synapse-worker-sandbox-check.service
grep -Fq 'Delegate=yes' packaging/systemd/synapse-worker-sandbox-check.service
grep -Fq 'CapabilityBoundingSet=' packaging/systemd/synapse-worker-sandbox-check.service
grep -Fq 'Before=synapse-worker.service' packaging/systemd/synapse-worker-sandbox-check.service
if grep -Ev '^[[:space:]]*#' packaging/systemd/synapse-worker-sandbox-check.service | grep -Eq '(^|[[:space:]])(sudo|CAP_SYS_ADMIN|CAP_NET_ADMIN|SYS_ADMIN|NET_ADMIN)([[:space:]]|$)'; then
    printf '%s\n' 'sandbox-check unit grants a forbidden privilege' >&2
    exit 1
fi
grep -Fq 'EnvironmentFile=/etc/synapse-worker/runtime.env' packaging/systemd/synapse-worker.service

if grep -Ev '^[[:space:]]*#' packaging/systemd/synapse-worker.service | grep -Eq '(^|[[:space:]])(sudo|CAP_SYS_ADMIN|CAP_NET_ADMIN|SYS_ADMIN|NET_ADMIN)([[:space:]]|$)'; then
    printf '%s\n' 'worker unit grants a forbidden privilege' >&2
    exit 1
fi

grep -Fq '/usr/libexec/synapse/render-worker-runtime-env' packaging/nfpm-worker.yaml
grep -Fq '/etc/synapse-worker/bootstrap.env' packaging/nfpm-worker.yaml
grep -Fq 'synapse-egress-broker.service' packaging/nfpm-worker.yaml
grep -Fq 'synapse-worker-sandbox-check.service' packaging/nfpm-worker.yaml
grep -Fq 'synapse-egress-broker' packaging/scripts/build-worker-package.sh
grep -Fq 'User=root' packaging/systemd/synapse-egress-broker.service
grep -Fq 'Group=synapse-worker' packaging/systemd/synapse-egress-broker.service
grep -Fq 'RuntimeDirectoryMode=0750' packaging/systemd/synapse-egress-broker.service
grep -Fq 'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_PTRACE' packaging/systemd/synapse-egress-broker.service
grep -Fq 'SystemCallFilter=@system-service mount umount2 setns' packaging/systemd/synapse-egress-broker.service
grep -Fq 'SystemCallErrorNumber=EPERM' packaging/systemd/synapse-egress-broker.service
grep -Fq 'NoNewPrivileges=true' packaging/systemd/synapse-egress-broker.service
grep -Fq 'ExecStart=/opt/synapse/synapse-egress-broker' packaging/systemd/synapse-egress-broker.service
grep -Fq 'RuntimeDirectory=synapse-egress-broker netns' packaging/systemd/synapse-egress-broker.service
grep -Fq 'StateDirectory=synapse-egress-broker' packaging/systemd/synapse-egress-broker.service
grep -Fq 'StateDirectoryMode=0700' packaging/systemd/synapse-egress-broker.service
grep -Fq 'Requires=synapse-worker-runtime-env.service' packaging/systemd/synapse-egress-broker.service
grep -Fq 'EnvironmentFile=/etc/synapse-worker/egress-broker.env' packaging/systemd/synapse-egress-broker.service
if grep -Fq 'EnvironmentFile=/etc/synapse-worker/runtime.env' packaging/systemd/synapse-egress-broker.service; then
    printf '%s\n' 'egress broker must not load worker runtime secrets' >&2
    exit 1
fi
grep -Fq 'Before=synapse-egress-broker.service synapse-worker.service' packaging/systemd/synapse-worker-runtime-env.service
grep -Fq 'grant-replay-journal=/var/lib/synapse-egress-broker/grant-replays.jsonl' packaging/systemd/synapse-egress-broker.service
grep -Fq 'grant-public-key=${SYNAPSE_EGRESS_GRANT_PUBLIC_KEY}' packaging/systemd/synapse-egress-broker.service
grep -Fq 'ReadWritePaths=/run/synapse-egress-broker /run/netns /var/lib/synapse-egress-broker' packaging/systemd/synapse-egress-broker.service
grep -Fq 'SYNAPSE_EGRESS_BROKER_SOCKET=/run/synapse-egress-broker/egress-broker.sock' packaging/worker.env.example
grep -Fq 'SYNAPSE_EGRESS_GRANT_AUTHORITY_URL=' packaging/worker.env.example
grep -Fq '"SYNAPSE_EGRESS_GRANT_AUTHORITY_TOKEN"' packaging/scripts/render-worker-runtime-env.sh
grep -Fq '"SYNAPSE_EGRESS_GRANT_AUTHORITY_URL"' packaging/scripts/render-worker-runtime-env.sh
if grep -Fq 'SYNAPSE_EGRESS_GRANT_SIGNING_SEED' packaging/scripts/render-worker-runtime-env.sh; then
    printf '%s\n' 'worker renderer must not accept the private egress grant signing seed' >&2
    exit 1
fi
grep -Fq 'systemctl stop synapse-worker synapse-egress-broker' packaging/scripts/worker-preremove.sh
grep -Fq 'systemctl disable synapse-worker synapse-egress-broker' packaging/scripts/worker-preremove.sh
if grep -Eq '(^|[[:space:]])(sudo|NOPASSWD|ALL=\(ALL\))([[:space:]]|$)' packaging/systemd/synapse-egress-broker.service; then
    printf '%s\n' 'egress broker unit contains unrestricted privilege delegation' >&2
    exit 1
fi
grep -Fq 'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER' packaging/systemd/synapse-worker-runtime-env.service
grep -Fq 'awscli-2' packaging/nfpm-worker.yaml
grep -Fq 'iproute' packaging/nfpm-worker.yaml
grep -Fq 'iptables-nft' packaging/nfpm-worker.yaml
grep -Fq 'libpcap' packaging/nfpm-worker.yaml
grep -Fq 'python3' packaging/nfpm-worker.yaml
grep -Fq 'CGO_ENABLED=1 go build -trimpath -o dist/worker/synapse-ast' packaging/scripts/build-worker-package.sh
for tool in subfinder httpx naabu; do
    grep -Fq "SYNAPSE_${tool^^}_BIN" packaging/scripts/build-worker-package.sh
    grep -Fq "dist/worker/$tool" packaging/scripts/build-worker-package.sh
done

printf '%s\n' 'native worker packaging static checks passed'
