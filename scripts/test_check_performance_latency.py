#!/usr/bin/env python3
import json
from pathlib import Path
import tempfile
import unittest

import check_performance_latency as gate


class PerformanceLatencyGateTest(unittest.TestCase):
    control_sha = "a" * 40
    candidate_sha = "b" * 40
    digest = "sha256:" + "c" * 64

    def write_fixture(self, root, candidate_p50="12ms", control_p50="10ms", candidate_throughput=42.0, candidate_digest=None, omit_measurement=False):
        candidate_baselines = root / "candidate-baselines"
        control_baselines = root / "control-baselines"
        candidate_logs = root / "candidate"
        control_logs = root / "control"
        for directory in (candidate_baselines, control_baselines, candidate_logs, control_logs):
            directory.mkdir()
        for name in gate.BENCHMARKS:
            baseline = {"schema": "synapse-scan-perf-v2", "target": name, "release_digest": self.control_sha,
                        "dataset_digest": self.digest, "warmup_samples": 3, "samples": 20,
                        "alloc_bytes_median": 100, "alloc_ceiling_bytes": 130,
                        "throughput_ops_per_second": 42.0}
            (candidate_baselines / name).write_text(json.dumps(baseline), encoding="utf-8")
            (control_baselines / name).write_text(json.dumps({**baseline, "release_digest": "(devel)"}), encoding="utf-8")
        for number in range(1, 4):
            for directory in (control_logs, candidate_logs):
                (directory / f"round-{number}").mkdir()
            for _, (test_name, log_name) in gate.BENCHMARKS.items():
                control = self.jsonl(test_name, self.control_sha, control_p50, self.digest)
                candidate = self.jsonl(test_name, self.candidate_sha, candidate_p50, candidate_digest or self.digest,
                                       throughput=candidate_throughput, include_measurement=not omit_measurement)
                # The image tests intentionally share their JSONL file.
                for directory, content in ((control_logs, control), (candidate_logs, candidate)):
                    path = directory / f"round-{number}" / log_name
                    path.write_text((path.read_text(encoding="utf-8") if path.exists() else "") + content, encoding="utf-8")
        return candidate_baselines, control_baselines, candidate_logs, control_logs

    @staticmethod
    def jsonl(test, release, p50, digest, throughput=42.0, include_measurement=True):
        events = [{"Action": "run", "Package": "example/perf", "Test": test}]
        if include_measurement:
            events.append({"Action": "output", "Package": "example/perf", "Test": test,
                           "Output": f"perf: release={release} env=env samples=20 alloc_bytes(median)=100 peak_mem=10 latency_p50={p50} latency_p95=13ms dataset={digest} throughput_ops_per_second={throughput:.6f}\n"})
        events.extend([{"Action": "pass", "Package": "example/perf", "Test": test}, {"Action": "pass", "Package": "example/perf"}])
        return "".join(json.dumps(event) + "\n" for event in events)

    def verify(self, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.write_fixture(Path(directory), **kwargs)
            return gate.verify(*paths, self.candidate_sha)

    def test_accepts_same_runner_measurements_and_reports_p95_and_rss(self):
        result = self.verify()
        self.assertEqual(len(result["comparisons"]), 6)
        self.assertEqual(result["comparisons"][0]["candidate_p95_millis"], 13.0)
        self.assertEqual(result["comparisons"][0]["candidate_peak_memory_bytes"], 10)
        self.assertEqual(result["comparisons"][0]["candidate_throughput_ops_per_second"], 42.0)

    def test_rejects_missing_live_throughput(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.write_fixture(Path(directory))
            log = paths[2] / "round-2" / "owned-sbom.jsonl"
            log.write_text(log.read_text(encoding="utf-8").replace(" throughput_ops_per_second=42.000000", ""), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "measurement is absent"):
                gate.verify(*paths, self.candidate_sha)

    def test_rejects_missing_measurement(self):
        with self.assertRaisesRegex(ValueError, "measurement is absent"):
            self.verify(omit_measurement=True)

    def test_rejects_dataset_mismatch(self):
        with self.assertRaisesRegex(ValueError, "dataset mismatch"):
            self.verify(candidate_digest="sha256:" + "d" * 64)

    def test_rejects_slowed_candidate(self):
        with self.assertRaisesRegex(ValueError, "p50 regression"):
            self.verify(candidate_p50="16ms")

    def test_rejects_fast_workload_fourfold_slowdown(self):
        with self.assertRaisesRegex(ValueError, "p50 regression"):
            self.verify(control_p50="1.5ms", candidate_p50="6ms")

    def test_rejects_throughput_collapse_even_when_median_latency_passes(self):
        with self.assertRaisesRegex(ValueError, "throughput regression"):
            self.verify(candidate_throughput=4.2)

    def test_missing_pair_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.write_fixture(Path(directory))
            (paths[2] / "round-3" / "owned-sbom.jsonl").unlink()
            with self.assertRaisesRegex(ValueError, "read measurement log"):
                gate.verify(*paths, self.candidate_sha)

    def test_single_disturbed_pair_does_not_override_two_normal_pairs(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.write_fixture(Path(directory))
            log = paths[2] / "round-1" / "owned-sbom.jsonl"
            log.write_text(log.read_text(encoding="utf-8").replace("latency_p50=12ms", "latency_p50=100ms"), encoding="utf-8")
            summary = gate.verify(*paths, self.candidate_sha)
            ownsbom = next(row for row in summary["comparisons"] if row["baseline"] == "ownsbom-perf.json")
            self.assertEqual(ownsbom["median_p50_ratio"], 1.2)

    def test_allows_measured_allocation_increase_without_raising_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.write_fixture(Path(directory))
            baseline = paths[0] / next(iter(gate.BENCHMARKS))
            data = json.loads(baseline.read_text(encoding="utf-8"))
            data["alloc_bytes_median"] = 110
            baseline.write_text(json.dumps(data), encoding="utf-8")
            gate.verify(*paths, self.candidate_sha)

    def test_rejects_allocation_ceiling_increase(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.write_fixture(Path(directory))
            baseline = paths[0] / next(iter(gate.BENCHMARKS))
            data = json.loads(baseline.read_text(encoding="utf-8"))
            data["alloc_ceiling_bytes"] = 131
            baseline.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "allocation ceiling rose"):
                gate.verify(*paths, self.candidate_sha)

    def test_allocation_ceiling_cannot_increase_from_previous_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.write_fixture(Path(directory))
            gate.verify_allocation_ratchet(paths[0], paths[1])
            baseline = paths[0] / next(iter(gate.BENCHMARKS))
            data = json.loads(baseline.read_text(encoding="utf-8"))
            data["alloc_ceiling_bytes"] = 131
            baseline.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "allocation ceiling increased"):
                gate.verify_allocation_ratchet(paths[0], paths[1])

    def test_rejects_missing_committed_throughput(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.write_fixture(Path(directory))
            baseline = paths[0] / next(iter(gate.BENCHMARKS))
            content = json.loads(baseline.read_text(encoding="utf-8"))
            del content["throughput_ops_per_second"]
            baseline.write_text(json.dumps(content), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "throughput_ops_per_second"):
                gate.verify(*paths, self.candidate_sha)


if __name__ == "__main__":
    unittest.main()
