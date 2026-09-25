import gzip
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "extract_sca_hosted_inputs", pathlib.Path(__file__).with_name("extract_sca_hosted_inputs.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FrozenInputExtractionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def fixture(self, bad_name=None, missing=False):
        names = [f"databases/owned-redhat/file-{i}.json" for i in range(5)] + [
            f"sboms/target-{i}.cdx.json" for i in range(3)
        ]
        if bad_name:
            names[0] = bad_name
        archive_path = self.root / "inputs.tar.gz"
        with archive_path.open("wb") as output:
            with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    for name in names[:7] if missing else names:
                        data = name.encode()
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
        manifest = {
            "schema_version": "synapse-sca-hosted-inputs-v1",
            "archive_sha256": MODULE.sha256(archive_path.read_bytes()),
            "members": {
                name: {"bytes": len(name.encode()), "sha256": MODULE.sha256(name.encode())}
                for name in names
            },
        }
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return archive_path, manifest_path

    def test_extracts_exact_inventory(self):
        archive, manifest = self.fixture()
        output = self.root / "out"
        MODULE.extract(archive, manifest, output)
        self.assertEqual(len(list(output.rglob("*.json"))), 8)

    def test_rejects_missing_member(self):
        archive, manifest = self.fixture(missing=True)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            MODULE.extract(archive, manifest, self.root / "out")

    def test_rejects_unsafe_member(self):
        archive, manifest = self.fixture(bad_name="../escape.json")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            MODULE.extract(archive, manifest, self.root / "out")

    def test_rejects_windows_style_traversal(self):
        archive, manifest = self.fixture(
            bad_name="databases/owned-redhat/..\\..\\..\\escape.json"
        )
        with self.assertRaisesRegex(ValueError, "unsafe"):
            MODULE.extract(archive, manifest, self.root / "out")

    def test_rejects_archive_digest_mismatch(self):
        archive, manifest = self.fixture()
        archive.write_bytes(archive.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "digest"):
            MODULE.extract(archive, manifest, self.root / "out")


if __name__ == "__main__":
    unittest.main()
