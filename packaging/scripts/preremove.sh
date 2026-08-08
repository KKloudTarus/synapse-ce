#!/bin/sh
# Preremove hook (#412): clean uninstall — stop and disable the service so no unit is left running or
# enabled. Package files are removed by the package manager; the documented state directory
# (/var/lib/synapse-agent) is intentionally NOT deleted here so an operator can inspect/rotate the
# agent credential deliberately (a purge removes it). Decommissioning the agent IDENTITY on the
# control plane is a separate operator action (see docs) so the fleet shows it decommissioned rather
# than silently going stale.
set -eu

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop synapse-agent >/dev/null 2>&1 || true
    systemctl disable synapse-agent >/dev/null 2>&1 || true
fi

exit 0
