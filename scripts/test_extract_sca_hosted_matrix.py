import gzip
import hashlib
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

from scripts.extract_sca_hosted_matrix import extract


class HostedMatrixExtractionTest(unittest.TestCase):
    def write_archive(self, root, names):
        archive_path = root / "inputs.tar.gz"
        members = {}
        with archive_path.open("wb") as target:
            with gzip.GzipFile(fileobj=target, mode="wb", filename="", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|") as archive:
                    for name in names:
                        payload = name.encode("utf-8")
                        info = tarfile.TarInfo(name)
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))
                        members[name] = {
                            "bytes": len(payload),
                            "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
                        }
        manifest = {
            "schema_version": "synapse-sca-hosted-matrix-inputs-v1",
            "archive_sha256": "sha256:" + hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            "archive_bytes": archive_path.stat().st_size,
            "members": members,
        }
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return archive_path, manifest_path, manifest

    def test_extracts_exact_inventory_and_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            names = [f"sboms/target-{index}.json" for index in range(20)]
            archive, manifest, _ = self.write_archive(root, names)
            output = root / "extracted"
            extract(archive, manifest, output)
            self.assertEqual(sorted(path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()), sorted(names))
            self.assertEqual((output / names[0]).read_bytes(), names[0].encode("utf-8"))

    def test_rejects_digest_mismatch_before_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            names = [f"sboms/target-{index}.json" for index in range(20)]
            archive, manifest, document = self.write_archive(root, names)
            document["archive_sha256"] = "sha256:" + "0" * 64
            manifest.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "archive digest or size mismatch"):
                extract(archive, manifest, root / "extracted")
            self.assertFalse((root / "extracted").exists())

    def test_rejects_traversal_even_when_manifest_declares_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            names = [f"sboms/target-{index}.json" for index in range(19)] + ["sboms/../../outside.json"]
            archive, manifest, _ = self.write_archive(root, names)
            with self.assertRaisesRegex(ValueError, "unsafe or undeclared archive member"):
                extract(archive, manifest, root / "extracted")
            self.assertFalse((root / "outside.json").exists())


if __name__ == "__main__":
    unittest.main()
