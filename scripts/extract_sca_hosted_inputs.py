#!/usr/bin/env python3
"""Verify and extract the frozen public SCA inputs into a fresh directory."""

import argparse
import hashlib
import json
import pathlib
import re
import tarfile


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_ARCHIVE_BYTES = 32 << 20
MAX_TOTAL_BYTES = 64 << 20


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def extract(archive_path, manifest_path, output_path):
    archive_path = pathlib.Path(archive_path)
    manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "synapse-sca-hosted-inputs-v1":
        raise ValueError("unsupported input manifest")
    expected = manifest.get("archive_sha256")
    if not isinstance(expected, str) or not DIGEST.fullmatch(expected):
        raise ValueError("invalid archive digest")
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES or sha256(archive_path.read_bytes()) != expected:
        raise ValueError("frozen input archive digest or size mismatch")
    declared = manifest.get("members")
    if not isinstance(declared, dict) or len(declared) != 8:
        raise ValueError("frozen input inventory must contain eight files")
    output_path = pathlib.Path(output_path)
    output_path.mkdir(parents=True, exist_ok=False)
    seen = set()
    total = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            name = member.name
            parts = pathlib.PurePosixPath(name).parts
            if not member.isfile() or name not in declared or name in seen or "\\" in name or not parts or any(part in (".", "..") for part in parts) or parts[0] not in ("databases", "sboms"):
                raise ValueError("unsafe or undeclared archive member: " + name)
            record = declared[name]
            if not isinstance(record, dict) or member.size != record.get("bytes") or member.size > 20 << 20:
                raise ValueError("archive member size mismatch: " + name)
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("frozen input archive exceeds size limit")
            data = archive.extractfile(member).read()
            if sha256(data) != record.get("sha256"):
                raise ValueError("archive member digest mismatch: " + name)
            destination = output_path.joinpath(*parts)
            if not destination.resolve().is_relative_to(output_path.resolve()):
                raise ValueError("archive member escapes output directory: " + name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            seen.add(name)
    if seen != set(declared):
        raise ValueError("frozen input archive is incomplete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    extract(args.archive, args.manifest, args.output)


if __name__ == "__main__":
    main()
