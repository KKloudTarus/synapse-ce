#!/usr/bin/env python3
"""Verify and stream the pinned offline SCA matrix into a fresh directory."""

import argparse
import hashlib
import json
import pathlib
import re
import tarfile


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_ARCHIVE_BYTES = 1 << 30
MAX_TOTAL_BYTES = 5 << 30
MAX_MEMBER_BYTES = 3 << 30
EXPECTED_MEMBERS = 20
ALLOWED_ROOTS = {"databases", "sboms", "tools", "repository", "capability"}


def hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def extract(archive_path, manifest_path, output_path):
    archive_path = pathlib.Path(archive_path)
    manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "synapse-sca-hosted-matrix-inputs-v1":
        raise ValueError("unsupported matrix input manifest")
    expected = manifest.get("archive_sha256")
    archive_bytes = manifest.get("archive_bytes")
    if not isinstance(expected, str) or not DIGEST.fullmatch(expected):
        raise ValueError("invalid archive digest")
    if not isinstance(archive_bytes, int) or not 0 < archive_bytes <= MAX_ARCHIVE_BYTES:
        raise ValueError("invalid archive size")
    if archive_path.stat().st_size != archive_bytes or hash_file(archive_path) != expected:
        raise ValueError("offline matrix archive digest or size mismatch")
    declared = manifest.get("members")
    if not isinstance(declared, dict) or len(declared) != EXPECTED_MEMBERS:
        raise ValueError("offline matrix inventory must contain exactly 20 files")
    output_path = pathlib.Path(output_path)
    output_path.mkdir(parents=True, exist_ok=False)
    root = output_path.resolve()
    seen = set()
    total = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            name = member.name
            parts = pathlib.PurePosixPath(name).parts
            if (
                not member.isfile()
                or name not in declared
                or name in seen
                or "\\" in name
                or not parts
                or parts[0] not in ALLOWED_ROOTS
                or any(part in ("", ".", "..") for part in parts)
                or pathlib.PurePosixPath(name).is_absolute()
            ):
                raise ValueError("unsafe or undeclared archive member: " + name)
            record = declared[name]
            if not isinstance(record, dict) or member.size != record.get("bytes") or not 0 < member.size <= MAX_MEMBER_BYTES:
                raise ValueError("archive member size mismatch: " + name)
            want = record.get("sha256")
            if not isinstance(want, str) or not DIGEST.fullmatch(want):
                raise ValueError("invalid member digest: " + name)
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("offline matrix exceeds expanded size limit")
            destination = root.joinpath(*parts)
            if not destination.resolve().is_relative_to(root):
                raise ValueError("archive member escapes output directory: " + name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            written = 0
            with archive.extractfile(member) as source, destination.open("xb") as target:
                while block := source.read(1024 * 1024):
                    written += len(block)
                    if written > member.size:
                        raise ValueError("archive member expanded beyond its size: " + name)
                    digest.update(block)
                    target.write(block)
            if written != member.size or "sha256:" + digest.hexdigest() != want:
                raise ValueError("archive member digest mismatch: " + name)
            seen.add(name)
    if seen != set(declared):
        raise ValueError("offline matrix archive is incomplete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    extract(args.archive, args.manifest, args.output)


if __name__ == "__main__":
    main()
