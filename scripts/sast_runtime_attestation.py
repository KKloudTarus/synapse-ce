#!/usr/bin/env python3
"""Observe the local GGUF and pinned llama.cpp container before SAST review."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCHEMA = "synapse-sast-local-model-attestation-v1"
IMAGE_REPOSITORY = "ghcr.io/ggml-org/llama.cpp"
SERVER_PORT = "8080"
HOST_PORT = "18080"


class AttestationError(RuntimeError):
    pass


def source_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def file_sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as content:
        while chunk := content.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _docker(args: list[str]) -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["docker", *args], check=True, capture_output=True, text=True, timeout=30
        )
        parsed = json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as err:
        raise AttestationError(f"inspect local Docker runtime: {err}") from err
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
        raise AttestationError("Docker inspect returned no unique object")
    return parsed[0]


def _expected_command(model_name: str) -> list[str]:
    return [
        "--model", f"/models/{model_name}", "--host", "0.0.0.0", "--port", SERVER_PORT,
        "--parallel", "1", "--ctx-size", "4096", "--threads", "6", "--n-gpu-layers", "0",
    ]


def _validate_endpoint(endpoint: str) -> None:
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
        or parsed.port != int(HOST_PORT) or parsed.path != "/v1/chat/completions"
        or parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment
    ):
        raise AttestationError("attested endpoint must be the pinned loopback llama.cpp endpoint")


def validate_record(
    record: Any, model_name: str, model_sha256: str, runtime_digest: str, endpoint: str
) -> None:
    _validate_endpoint(endpoint)
    image_ref = f"{IMAGE_REPOSITORY}@sha256:{runtime_digest}"
    if not isinstance(record, dict) or set(record) != {
        "schema", "model_filename", "model_sha256", "model_size",
        "image_reference", "image_id", "container_id", "container_started_at",
        "entrypoint", "command", "model_mount", "endpoint", "host_binding",
        "readonly_rootfs", "cap_drop_all", "no_new_privileges",
        "checker_sha256",
    }:
        raise AttestationError("attestation has an invalid shape")
    if (
        record["schema"] != SCHEMA or record["model_filename"] != model_name
        or record["model_sha256"] != model_sha256
        or record["image_reference"] != image_ref
        or record["image_id"] != "sha256:" + runtime_digest
        or record["endpoint"] != endpoint
        or record["entrypoint"] != ["/app/llama-server"]
        or record["command"] != _expected_command(model_name)
        or record["model_mount"] != "/models"
        or record["host_binding"] != {"ip": "127.0.0.1", "port": HOST_PORT}
        or record["readonly_rootfs"] is not True
        or record["cap_drop_all"] is not True
        or record["no_new_privileges"] is not True
        or record["checker_sha256"] != source_sha256()
        or not isinstance(record["model_size"], int) or record["model_size"] <= 0
        or not isinstance(record["container_started_at"], str)
        or not record["container_started_at"]
        or not isinstance(record["container_id"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", record["container_id"])
    ):
        raise AttestationError("attestation does not match pinned model runtime")


def require_live_container(
    model_path: Path, model_name: str, model_sha256: str,
    runtime_digest: str, container_name: str, endpoint: str,
) -> dict[str, Any]:
    _validate_endpoint(endpoint)
    if Path(model_name).name != model_name or not model_name.endswith(".gguf"):
        raise AttestationError("model name must be a GGUF basename")
    if not container_name or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", container_name):
        raise AttestationError("container name is invalid")
    model_path = model_path.resolve(strict=True)
    if model_path.name != model_name:
        raise AttestationError("GGUF path does not match request model name")
    observed_sha, observed_size = file_sha256(model_path)
    if observed_sha != model_sha256:
        raise AttestationError("local GGUF SHA-256 does not match the pinned digest")

    image_ref = f"{IMAGE_REPOSITORY}@sha256:{runtime_digest}"
    image = _docker(["image", "inspect", image_ref])
    container = _docker(["inspect", container_name])
    if image.get("Id") != "sha256:" + runtime_digest or image_ref not in image.get("RepoDigests", []):
        raise AttestationError("local image does not match the pinned OCI digest")
    if (
        container.get("Image") != image["Id"]
        or container.get("Config", {}).get("Image") != image_ref
        or container.get("Config", {}).get("Entrypoint") != ["/app/llama-server"]
        or container.get("Config", {}).get("Cmd") != _expected_command(model_name)
        or container.get("Config", {}).get("Env") != image.get("Config", {}).get("Env")
        or container.get("State", {}).get("Running") is not True
    ):
        raise AttestationError("running container is not the pinned llama.cpp model server")

    mounts = container.get("Mounts")
    if (
        not isinstance(mounts, list) or len(mounts) != 1
        or not isinstance(mounts[0], dict)
        or mounts[0].get("Type") != "bind"
        or mounts[0].get("Destination") != "/models"
        or mounts[0].get("RW") is not False
        or Path(mounts[0].get("Source", "")).resolve() != model_path.parent
    ):
        raise AttestationError("running container must have only the verified read-only GGUF mount")
    host = container.get("HostConfig", {})
    if host.get("PortBindings", {}).get("8080/tcp") != [{"HostIp": "127.0.0.1", "HostPort": HOST_PORT}]:
        raise AttestationError("model server is not published solely on pinned loopback port")
    if (
        host.get("ReadonlyRootfs") is not True
        or "ALL" not in host.get("CapDrop", [])
        or "no-new-privileges" not in host.get("SecurityOpt", [])
    ):
        raise AttestationError("model server hardening does not match the pinned launch")

    record = {
        "schema": SCHEMA,
        "model_filename": model_name,
        "model_sha256": observed_sha,
        "model_size": observed_size,
        "image_reference": image_ref,
        "image_id": image["Id"],
        "container_id": container.get("Id"),
        "container_started_at": container.get("State", {}).get("StartedAt"),
        "entrypoint": container["Config"]["Entrypoint"],
        "command": container["Config"]["Cmd"],
        "model_mount": "/models",
        "endpoint": endpoint,
        "host_binding": {"ip": "127.0.0.1", "port": HOST_PORT},
        "readonly_rootfs": True,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "checker_sha256": source_sha256(),
    }
    validate_record(record, model_name, model_sha256, runtime_digest, endpoint)
    return record
