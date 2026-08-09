#!/bin/sh
# In-container acceptance for #412: install the native package, assert what it placed, prove ONE real
# enrol + heartbeat against the control plane, uninstall, and assert nothing is left behind.
#
# It runs inside the target distribution image, so it is POSIX sh with no bashisms and no assumptions
# about which tools the base image ships.
#
# Contract from the caller:
#   /tmp/synapse-agent-package   the package to install
#   INSTALL_CMD / REMOVE_CMD     the package manager verbs for this row
#   SYNAPSE_FLEET_URL            the control plane, reachable as the host alias "control-plane"
#   SYNAPSE_FLEET_ENROL_TOKEN    a one-time enrolment token minted by the caller
set -eu

echo "=== 1. install ==="
# Word splitting on INSTALL_CMD is intended: it carries a verb and its flags ("dpkg -i").
# shellcheck disable=SC2086
${INSTALL_CMD} /tmp/synapse-agent-package

echo "=== 2. what the package placed ==="
test -x /usr/bin/synapse-agent || { echo "FAIL: the agent binary was not installed"; exit 1; }
test -f /lib/systemd/system/synapse-agent.service || { echo "FAIL: no service unit"; exit 1; }
test -f /etc/synapse-agent/agent.env || { echo "FAIL: no configuration file"; exit 1; }

# The configuration carries the control-plane URL and the enrolment-token path, so it must not be
# world-readable. A package that ships a 0644 credential path is the bug this asserts against.
perms="$(stat -c '%a' /etc/synapse-agent/agent.env)"
test "${perms}" = "640" || { echo "FAIL: config permissions ${perms}, want 640"; exit 1; }

# A dedicated unprivileged service account, created by the preinstall hook.
getent passwd synapse-agent >/dev/null || { echo "FAIL: no synapse-agent service account"; exit 1; }
getent group synapse-agent >/dev/null || { echo "FAIL: no synapse-agent service group"; exit 1; }

echo "=== 3. start and heartbeat ==="
# These images have no running systemd (PID 1 is this script), so the unit file is asserted above and
# the PACKAGED binary is run directly with -once: enrol, heartbeat, one claim cycle, exit. That is the
# same code path the unit starts, which is what "starts and heartbeats" has to mean here. Running the
# packaged binary rather than the build output is the point — it proves what the package shipped runs.
mkdir -p /var/lib/synapse-agent
/usr/bin/synapse-agent -once -state-dir /var/lib/synapse-agent -name "ci-$(uname -m)"

# The agent persists its issued credential on a successful enrol, so its presence is evidence the
# enrol -> heartbeat exchange actually completed rather than the binary merely exiting zero.
if [ -z "$(ls -A /var/lib/synapse-agent 2>/dev/null)" ]; then
    echo "FAIL: the agent left no credential — enrolment did not complete"
    exit 1
fi
echo "enrol + heartbeat completed; credential persisted"

echo "=== 4. uninstall ==="
# shellcheck disable=SC2086
${REMOVE_CMD}

# Explicit paths rather than a broad find: a `find / -name 'synapse-agent*'` would also match the
# documented state directory and fail the check on its own success.
for path in /usr/bin/synapse-agent /lib/systemd/system/synapse-agent.service /etc/synapse-agent/agent.env; do
    if [ -e "${path}" ]; then
        echo "FAIL: uninstall left ${path} behind"
        exit 1
    fi
done

# Anything else the package owned, anywhere outside the documented state directory, is a leftover.
leftovers="$(find /usr /etc /lib /opt /srv -name 'synapse-agent*' 2>/dev/null || true)"
if [ -n "${leftovers}" ]; then
    echo "FAIL: uninstall left files outside the documented state directory:"
    echo "${leftovers}"
    exit 1
fi

# The state directory is deliberately KEPT (documented), so an operator can inspect or rotate the
# agent credential rather than having it deleted from under them.
test -d /var/lib/synapse-agent || { echo "FAIL: the documented state directory was removed"; exit 1; }

echo "=== PASS: install, start, heartbeat, clean uninstall ==="
