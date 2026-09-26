import json
import tempfile
import unittest
from pathlib import Path

from scripts.collect_benchmark_accuracy import build_result


SHA = "a" * 40
ROOT = Path(__file__).resolve().parents[1]


def event(test, marker, values):
    return {"Action": "output", "Test": test, "Output": f"    bench_test.go:1: {marker} {values}\n"}


class CollectBenchmarkAccuracyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.log_dir = Path(self.temp.name)
        self.write_log("dast-accuracy.jsonl", "TestDASTOwnedAccuracy", "dast owned:",
                       "cases=2 tp=1 fp=0 fn=0 recall=1.000 precision=1.000")
        self.write_log("cspm-accuracy.jsonl", "TestCSPMOwnedAccuracy", "cspm owned:",
                       "resources=2 tp=1 fp=0 fn=0 recall=1.000 precision=1.000")

    def write_log(self, name, test, marker, values, extra=()):
        rows = [event(test, marker, values), *extra, {"Action": "pass", "Test": test}]
        (self.log_dir / name).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def test_result_contains_only_metrics_and_input_identity(self):
        secret = "do-not-publish-test-output"
        self.write_log("dast-accuracy.jsonl", "TestDASTOwnedAccuracy", "dast owned:",
                       "cases=2 tp=1 fp=0 fn=0 recall=1.000 precision=1.000",
                       ({"Action": "output", "Test": "TestDASTOwnedAccuracy", "Output": secret},))
        result = build_result("dynamic-security-benchmark", SHA, self.log_dir, ROOT)
        self.assertEqual(result["cell_count"], 2)
        self.assertEqual(result["source_sha"], SHA)
        self.assertEqual(result["decision"], "pass")
        self.assertEqual(len(result["input_digests"]), 2)
        self.assertNotIn(secret, json.dumps(result))

    def test_missing_or_repeated_metric_fails(self):
        (self.log_dir / "dast-accuracy.jsonl").write_text(
            json.dumps({"Action": "pass", "Test": "TestDASTOwnedAccuracy"}) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing, repeated"):
            build_result("dynamic-security-benchmark", SHA, self.log_dir, ROOT)
        metric = event("TestDASTOwnedAccuracy", "dast owned:",
                       "cases=2 tp=1 fp=0 fn=0 recall=1.000 precision=1.000")
        (self.log_dir / "dast-accuracy.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in
                    (metric, metric, {"Action": "pass", "Test": "TestDASTOwnedAccuracy"})), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing, repeated"):
            build_result("dynamic-security-benchmark", SHA, self.log_dir, ROOT)

    def test_zero_corpus_or_missing_pass_fails(self):
        self.write_log("dast-accuracy.jsonl", "TestDASTOwnedAccuracy", "dast owned:",
                       "cases=0 tp=1 fp=0 fn=0 recall=1.000 precision=1.000")
        with self.assertRaisesRegex(ValueError, "zero corpus"):
            build_result("dynamic-security-benchmark", SHA, self.log_dir, ROOT)
        (self.log_dir / "dast-accuracy.jsonl").write_text(
            json.dumps(event("TestDASTOwnedAccuracy", "dast owned:",
                             "cases=2 tp=1 fp=0 fn=0 recall=1.000 precision=1.000")) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "did not pass"):
            build_result("dynamic-security-benchmark", SHA, self.log_dir, ROOT)

    def test_security_requires_both_comparators(self):
        secrets_test = "TestSecretsOwnedAccuracyAndGitleaksDifferential"
        iac_test = "TestIaCOwnedAccuracyAndCheckovDifferential"
        scores = "tp=1 fp=0 fn=0 recall=1.000 precision=1.000"
        self.write_log("secrets-accuracy.jsonl", secrets_test, "owned secrets:", scores,
                       (event(secrets_test, "gitleaks secrets:", scores),))
        self.write_log("iac-accuracy.jsonl", iac_test, "owned iac:",
                       "categories=1 " + scores,
                       (event(iac_test, "checkov iac:", scores),))
        self.write_log("host-cve-accuracy.jsonl", "TestHostCVECorrelationAccuracy",
                       "host-cve correlation:", "cases=2 " + scores + " tn=1")
        result = build_result("security-accuracy", SHA, self.log_dir, ROOT)
        self.assertEqual(result["cell_count"], 3)
        self.assertIn("gitleaks", result["cells"][0]["metrics"])
        self.assertIn("checkov", result["cells"][1]["metrics"])
        self.assertIn("docs/benchmarks/competitor-identity.json", result["input_digests"])
        self.write_log("secrets-accuracy.jsonl", secrets_test, "owned secrets:", scores)
        with self.assertRaisesRegex(ValueError, "missing, repeated"):
            build_result("security-accuracy", SHA, self.log_dir, ROOT)

    def test_unrecognized_numeric_field_is_not_published(self):
        self.write_log("dast-accuracy.jsonl", "TestDASTOwnedAccuracy", "dast owned:",
                       "cases=2 tp=1 fp=0 fn=0 recall=1.000 precision=1.000 secret=1234")
        with self.assertRaisesRegex(ValueError, "unexpected metric fields"):
            build_result("dynamic-security-benchmark", SHA, self.log_dir, ROOT)

    def test_inconsistent_counts_and_ratios_fail(self):
        self.write_log("dast-accuracy.jsonl", "TestDASTOwnedAccuracy", "dast owned:",
                       "cases=2 tp=3 fp=0 fn=1 recall=0.750 precision=1.000")
        with self.assertRaisesRegex(ValueError, "exceeds corpus"):
            build_result("dynamic-security-benchmark", SHA, self.log_dir, ROOT)
        self.write_log("dast-accuracy.jsonl", "TestDASTOwnedAccuracy", "dast owned:",
                       "cases=4 tp=3 fp=0 fn=1 recall=1.000 precision=1.000")
        with self.assertRaisesRegex(ValueError, "inconsistent accuracy ratio"):
            build_result("dynamic-security-benchmark", SHA, self.log_dir, ROOT)
        self.write_log("dast-accuracy.jsonl", "TestDASTOwnedAccuracy", "dast owned:",
                       "cases=2 tp=1 fp=99 fn=0 recall=1.000 precision=0.010")
        with self.assertRaisesRegex(ValueError, "confusion count exceeds corpus"):
            build_result("dynamic-security-benchmark", SHA, self.log_dir, ROOT)


if __name__ == "__main__":
    unittest.main()
