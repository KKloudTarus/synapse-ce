#!/usr/bin/env python3
"""Checks that model evidence is bound to inspected local runtime state."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sast_runtime_attestation as attestation


class RuntimeAttestationTests(unittest.TestCase):
    def test_observes_model_image_container_and_rejects_changed_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            model = Path(temp) / "test.gguf"
            model.write_bytes(b"synthetic GGUF")
            digest = hashlib.sha256(model.read_bytes()).hexdigest()
            image_digest = "b" * 64
            image_ref = f"{attestation.IMAGE_REPOSITORY}@sha256:{image_digest}"
            endpoint = "http://127.0.0.1:18080/v1/chat/completions"
            image = {"Id": "sha256:" + image_digest, "RepoDigests": [image_ref], "Config": {"Env": ["PATH=/app"]}}
            container = {
                "Id": "a" * 64,
                "Image": image["Id"],
                "Config": {
                    "Image": image_ref,
                    "Entrypoint": ["/app/llama-server"],
                    "Cmd": attestation._expected_command(model.name),
                    "Env": ["PATH=/app"],
                },
                "State": {"Running": True, "StartedAt": "2026-01-01T00:00:00Z"},
                "Mounts": [{"Type": "bind", "Source": str(model.parent), "Destination": "/models", "RW": False}],
                "HostConfig": {
                    "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]},
                    "ReadonlyRootfs": True,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges"],
                },
            }

            def inspect(args: list[str]) -> dict:
                return image if args[:2] == ["image", "inspect"] else container

            with patch.object(attestation, "_docker", side_effect=inspect):
                record = attestation.require_live_container(model, model.name, digest, image_digest, "test-container", endpoint)
                attestation.validate_record(record, model.name, digest, image_digest, endpoint)
                container["Mounts"][0]["RW"] = True
                with self.assertRaises(attestation.AttestationError):
                    attestation.require_live_container(model, model.name, digest, image_digest, "test-container", endpoint)
                container["Mounts"][0]["RW"] = False
                container["Mounts"].append({"Type": "bind", "Source": str(model), "Destination": "/app/llama-server", "RW": False})
                with self.assertRaises(attestation.AttestationError):
                    attestation.require_live_container(model, model.name, digest, image_digest, "test-container", endpoint)
                container["Mounts"].pop()
                container["Config"]["Env"].append("LD_PRELOAD=/models/override.so")
                with self.assertRaises(attestation.AttestationError):
                    attestation.require_live_container(model, model.name, digest, image_digest, "test-container", endpoint)

    def test_rejects_self_reported_digest_without_matching_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            model = Path(temp) / "test.gguf"
            model.write_bytes(b"synthetic GGUF")
            with self.assertRaises(attestation.AttestationError):
                attestation.require_live_container(
                    model, model.name, "0" * 64, "b" * 64,
                    "test-container", "http://127.0.0.1:18080/v1/chat/completions",
                )


if __name__ == "__main__":
    unittest.main()
