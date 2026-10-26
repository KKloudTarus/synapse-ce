#!/usr/bin/env python3
"""Run real Keycloak/enterprise admission tests with disposable local dependencies."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time

POSTGRES_IMAGE = "postgres@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3"
KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak@sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b"
RUN_LABEL = "com.synapse.keycloak-conformance.run"


def docker(action: str, *args: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"{action} did not complete") from error
    if result.returncode:
        raise RuntimeError(f"{action} failed (exit {result.returncode})")
    return result.stdout.strip()


def ensure_image(image: str) -> None:
    result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=20, check=False)
    if result.returncode:
        print("Pulling pinned conformance image", flush=True)
        docker("pinned image pull", "pull", image, timeout=300)


def cleanup(run_id: str) -> None:
    """Remove only resources carrying this process's unpredictable label."""
    for kind, list_args, remove_args in [
        ("containers", ["ps", "-aq"], ["rm", "-f"]),
        ("networks", ["network", "ls", "-q"], ["network", "rm"]),
    ]:
        ids = docker(f"list conformance {kind}", *list_args, "--filter", f"label={RUN_LABEL}={run_id}").split()
        if ids:
            docker(f"remove conformance {kind}", *remove_args, *ids)


def run(go: str) -> int:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("the isolated conformance runner requires Linux Docker networking")
    root = Path(__file__).resolve().parents[1]
    run_id = secrets.token_hex(16)
    password = secrets.token_urlsafe(32)
    print(f"Conformance run: {run_id}", flush=True)
    for image in (POSTGRES_IMAGE, KEYCLOAK_IMAGE):
        ensure_image(image)
    # Always register cleanup before creating the first Docker resource.
    try:
        with tempfile.TemporaryDirectory(prefix="synapse-keycloak-conformance-") as directory:
            env_file = Path(directory) / "postgres.env"
            env_file.write_text(f"POSTGRES_USER=postgres\nPOSTGRES_PASSWORD={password}\nPOSTGRES_DB=postgres\n", encoding="utf-8")
            env_file.chmod(0o600)
            network = docker("create conformance network", "network", "create", "--internal", "--label", f"{RUN_LABEL}={run_id}", f"synapse-keycloak-conformance-{run_id}")
            container = docker(
                "create conformance PostgreSQL", "run", "-d", "--rm", "--label", f"{RUN_LABEL}={run_id}",
                "--network", network, "--env-file", str(env_file),
                "--memory", "1g", "--cpus", "2", "--pids-limit", "256", POSTGRES_IMAGE,
            )
            deadline = time.monotonic() + 60
            while True:
                state = json.loads(docker("inspect conformance PostgreSQL", "inspect", "--format", "{{json .State}}", container))
                if not state["Running"]:
                    raise RuntimeError("conformance PostgreSQL exited before readiness")
                ready = subprocess.run(["docker", "exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres"], capture_output=True, timeout=10, check=False)
                if ready.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("conformance PostgreSQL readiness timed out")
                time.sleep(0.2)
            networks = json.loads(docker("inspect conformance network", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container))
            attached = [item for item in networks.values() if item["NetworkID"] == network]
            if len(attached) != 1 or len(networks) != 1:
                raise RuntimeError("conformance PostgreSQL has an unexpected network attachment")
            address = ipaddress.ip_address(attached[0]["IPAddress"])
            if address.version != 4 or not address.is_private or address.is_loopback:
                raise RuntimeError("invalid conformance PostgreSQL network address")
            with socket.create_connection((str(address), 5432), timeout=5):
                pass
            dsn = f"postgres://postgres:{password}@{address}:5432/postgres?sslmode=disable"
            environment = os.environ.copy()
            environment.update(SYNAPSE_TEST_DB_DSN=dsn, SYNAPSE_KEYCLOAK_RUN_ID=run_id)
            print("Running real Keycloak and PostgreSQL enterprise conformance", flush=True)
            with subprocess.Popen(
                [go, "test", "-tags=keycloak_integration", "-count=1", "-timeout=15m", "-json", "./internal/infrastructure/oidc", "-run", "^TestKeycloak"],
                cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, start_new_session=True,
            ) as process:
                try:
                    output, _ = process.communicate(timeout=1000)
                except BaseException:
                    # Include the test binary, so a timed-out child cannot recreate resources
                    # after the outer cleanup has inspected its exact run label.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.communicate()
                    raise
                returncode = process.returncode
            # Generated credentials remain private even if a dependency includes a DSN in its error.
            output = output.replace(dsn, "[test database]").replace(password, "[test credential]")
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
            if returncode == 0:
                required = {
                    "TestKeycloakEnterpriseConformance",
                    "TestKeycloakEnterpriseConformance/baseRoot",
                    "TestKeycloakEnterpriseConformance/baseAuth",
                }
                passed = set()
                for line in output.splitlines():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get("Action") == "pass":
                        passed.add(event.get("Test"))
                if not required.issubset(passed):
                    raise RuntimeError("required Keycloak enterprise conformance test did not pass or was not discovered")
            return returncode
    finally:
        cleanup(run_id)


def interrupted(_signal: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", help="Go executable (defaults to go from PATH)")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        return run(args.go)
    except KeyboardInterrupt:
        print("Keycloak conformance interrupted; disposable resources removed", file=sys.stderr)
        return 130
    except (RuntimeError, OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"Keycloak conformance failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
