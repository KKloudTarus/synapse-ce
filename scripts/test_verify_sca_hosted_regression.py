import copy
import importlib.util
import pathlib
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_sca_hosted_regression",
    pathlib.Path(__file__).with_name("verify_sca_hosted_regression.py"),
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class HostedRegressionTest(unittest.TestCase):
    def setUp(self):
        digest = "sha256:" + "a" * 64
        self.digests = {key: digest for key in ("catalog", "oracle", "ratchet", "policy")}
        self.owned = {
            "schema_version": "synapse-accuracy-report-v1",
            "cases": 13,
            "groups": [{"group": "fixture", "cases": 13}],
            "overall": {"true_positives": 1, "false_positives": 0, "false_negatives": 0},
        }
        self.capture = {
            "schema_version": "synapse-sca-trusted-acceptance-report-v1",
            "accepted": True,
            "observations": 24,
            "input_digests": self.digests.copy(),
            "publication_sha256": digest,
            "run_sha256": digest,
            "source_sha": "b" * 40,
            "workflow_run_id": "123",
        }

    def verify(self):
        return MODULE.verify(self.owned, self.digests, self.capture, "c" * 40)

    def test_labels_current_measurement_and_frozen_comparison(self):
        result = self.verify()
        self.assertEqual(result["measurement"], "current-owned-embedded-corpus")
        self.assertEqual(result["comparison"], "frozen-accepted-capture")
        self.assertEqual(result["comparison_observations"], 24)

    def test_rejects_missing_owned_cases(self):
        self.owned["cases"] = 0
        with self.assertRaises(ValueError):
            self.verify()

    def test_rejects_unaccepted_capture(self):
        self.capture["accepted"] = False
        with self.assertRaises(ValueError):
            self.verify()

    def test_rejects_corpus_drift(self):
        self.digests = copy.deepcopy(self.digests)
        self.digests["oracle"] = "sha256:" + "f" * 64
        with self.assertRaises(ValueError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
