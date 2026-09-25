#!/usr/bin/env python3
"""Fail closed when a hosted performance candidate regresses against its control."""

import argparse
import json
import math
import re
import statistics
import sys
from pathlib import Path


BENCHMARKS = {
    "image-extract-perf.json": ("TestImageExtractPerfGate", "image-extraction.jsonl"),
    "image-extract-large-perf.json": ("TestImageExtractLargeImagePerfGate", "image-extraction.jsonl"),
    "ownsbom-perf.json": ("TestOwnsbomPerfGate", "owned-sbom.jsonl"),
    "ospkg-catalog-perf.json": ("TestOSPkgCatalogPerfGate", "os-package-catalog.jsonl"),
    "cyclonedx-import-perf.json": ("TestSBOMImportPerfGate", "sbom-import.jsonl"),
    "secretscan-perf.json": ("TestSecretScanPerfGate", "secret-scan.jsonl"),
}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MEASUREMENT_RE = re.compile(
    r"\brelease=(?P<release>[0-9a-f]{40})\b.*?\bsamples=(?P<samples>[1-9][0-9]*)\b"
    r".*?\balloc_bytes\(median\)=(?P<alloc>[1-9][0-9]*)\b.*?\bpeak_mem=(?P<peak>[1-9][0-9]*)\b"
    r".*?\blatency_p50=(?P<p50>[^\s]+)\s+latency_p95=(?P<p95>[^\s]+)"
    r"\s+dataset=(?P<dataset>sha256:[0-9a-f]{64})\b"
    r"\s+throughput_ops_per_second=(?P<throughput>[0-9]+(?:\.[0-9]+)?)\b"
)
DURATION_RE = re.compile(r"^(?P<value>[0-9]+(?:\.[0-9]+)?)(?P<unit>ns|us|µs|ms|s|m|h)$")
DURATION_TO_MILLIS = {"ns": 1e-6, "us": 1e-3, "µs": 1e-3, "ms": 1.0, "s": 1000.0, "m": 60000.0, "h": 3600000.0}


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as source:
            return json.load(source, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"read JSON {path}: {error}") from error


def load_baselines(directory, require_release_sha=True, require_throughput=True, require_alloc_ceiling=True):
    directory = Path(directory)
    found = {path.name for path in directory.glob("*perf*.json") if path.is_file()}
    expected = set(BENCHMARKS)
    if found != expected:
        raise ValueError(f"baseline set in {directory} is {sorted(found)}, want {sorted(expected)}")
    baselines = {name: load_json(directory / name) for name in BENCHMARKS}
    for name, baseline in baselines.items():
        required = ("schema", "target", "release_digest", "dataset_digest", "warmup_samples", "samples")
        if not isinstance(baseline, dict) or any(field not in baseline for field in required):
            raise ValueError(f"baseline {name} lacks its measurement identity")
        if baseline["schema"] != "synapse-scan-perf-v2" or not isinstance(baseline["target"], str) or not baseline["target"]:
            raise ValueError(f"baseline {name} has an invalid schema or target")
        if not isinstance(baseline["release_digest"], str) or (require_release_sha and not SHA_RE.fullmatch(baseline["release_digest"])):
            raise ValueError(f"baseline {name} has an invalid release_digest")
        if not isinstance(baseline["dataset_digest"], str) or not DIGEST_RE.fullmatch(baseline["dataset_digest"]):
            raise ValueError(f"baseline {name} has an invalid dataset_digest")
        if not isinstance(baseline["warmup_samples"], int) or baseline["warmup_samples"] < 0:
            raise ValueError(f"baseline {name} has an invalid warmup_samples")
        if not isinstance(baseline["samples"], int) or baseline["samples"] < 1:
            raise ValueError(f"baseline {name} has an invalid samples")
        if require_throughput:
            throughput = baseline.get("throughput_ops_per_second")
            if isinstance(throughput, bool) or not isinstance(throughput, (int, float)) or not math.isfinite(throughput) or throughput <= 0:
                raise ValueError(f"baseline {name} has an invalid throughput_ops_per_second")
        if require_alloc_ceiling:
            ceiling = baseline.get("alloc_ceiling_bytes")
            if isinstance(ceiling, bool) or not isinstance(ceiling, int) or ceiling <= 0:
                raise ValueError(f"baseline {name} has an invalid alloc_ceiling_bytes")
    return baselines


def control_sha(baselines):
    shas = {baseline["release_digest"] for baseline in baselines.values()}
    if len(shas) != 1:
        raise ValueError("all six committed baselines must name one control release_digest")
    return shas.pop()


def verify_allocation_ratchet(candidate_dir, previous_dir):
    candidate = load_baselines(candidate_dir)
    previous = load_baselines(previous_dir, require_release_sha=False, require_throughput=False,
                              require_alloc_ceiling=False)
    for name, current in candidate.items():
        prior = previous[name]
        for field in ("schema", "target", "dataset_digest", "warmup_samples", "samples"):
            if current[field] != prior[field]:
                raise ValueError(f"allocation ratchet identity changed for {name}: {field}")
        prior_ceiling = prior.get("alloc_ceiling_bytes")
        if prior_ceiling is None:
            measured = prior.get("alloc_bytes_median")
            if isinstance(measured, bool) or not isinstance(measured, int) or measured <= 0:
                raise ValueError(f"previous baseline {name} lacks measured allocation")
            prior_ceiling = int(measured * 1.30)
        if isinstance(prior_ceiling, bool) or not isinstance(prior_ceiling, int) or prior_ceiling <= 0:
            raise ValueError(f"previous baseline {name} has invalid allocation ceiling")
        if current["alloc_ceiling_bytes"] > prior_ceiling:
            raise ValueError(f"allocation ceiling increased for {name}: {current['alloc_ceiling_bytes']} > {prior_ceiling}")


def duration_millis(text):
    match = DURATION_RE.fullmatch(text)
    if not match:
        raise ValueError(f"unsupported Go duration {text!r}")
    return float(match["value"]) * DURATION_TO_MILLIS[match["unit"]]


def read_measurement(path, test_name):
    outputs = []
    passed = False
    package_passed = False
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError(f"read measurement log {path}: {error}") from error
    if not lines:
        raise ValueError(f"measurement log {path} is empty")
    for number, line in enumerate(lines, start=1):
        try:
            event = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, ValueError) as error:
            raise ValueError(f"measurement log {path}:{number} is not safe JSON: {error}") from error
        if not isinstance(event, dict):
            raise ValueError(f"measurement log {path}:{number} is not a JSON object")
        if event.get("Action") == "pass" and event.get("Test") == test_name:
            passed = True
        if event.get("Action") == "pass" and event.get("Test") is None and isinstance(event.get("Package"), str):
            package_passed = True
        if event.get("Action") == "output" and event.get("Test") == test_name and isinstance(event.get("Output"), str):
            match = MEASUREMENT_RE.search(event["Output"])
            if match:
                outputs.append(match.groupdict())
    if not passed:
        raise ValueError(f"required benchmark test did not pass: {test_name} ({path})")
    if not package_passed:
        raise ValueError(f"benchmark package did not pass: {path}")
    if len(outputs) != 1:
        raise ValueError(f"required benchmark measurement is absent or ambiguous: {test_name} ({path})")
    measurement = outputs[0]
    measurement["samples"] = int(measurement["samples"])
    measurement["alloc"] = int(measurement["alloc"])
    measurement["peak"] = int(measurement["peak"])
    measurement["throughput"] = float(measurement["throughput"])
    if not math.isfinite(measurement["throughput"]) or measurement["throughput"] <= 0:
        raise ValueError(f"required benchmark throughput is invalid: {test_name} ({path})")
    measurement["p50_millis"] = duration_millis(measurement.pop("p50"))
    measurement["p95_millis"] = duration_millis(measurement.pop("p95"))
    return measurement


def verify(candidate_baselines_dir, control_baselines_dir, candidate_dir, control_dir, candidate_sha):
    candidate = load_baselines(candidate_baselines_dir)
    # The control revision can predate exact-SHA baseline publication. Its live
    # measurements are bound to the candidate's pinned control SHA below.
    control = load_baselines(control_baselines_dir, require_release_sha=False, require_throughput=False, require_alloc_ceiling=False)
    control_source = control_sha(candidate)
    if candidate_sha and not SHA_RE.fullmatch(candidate_sha):
        raise ValueError("candidate source SHA must be a full lowercase Git SHA")
    rows = []
    for name, (test_name, log_name) in BENCHMARKS.items():
        candidate_baseline = candidate[name]
        control_baseline = control[name]
        for field in ("schema", "target", "dataset_digest", "warmup_samples", "samples"):
            if candidate_baseline[field] != control_baseline[field]:
                raise ValueError(f"control baseline identity mismatch for {name}: {field}")
        control_alloc = control_baseline.get("alloc_bytes_median")
        if isinstance(control_alloc, bool) or not isinstance(control_alloc, int) or control_alloc <= 0:
            raise ValueError(f"control baseline {name} lacks measured allocation")
        if candidate_baseline["alloc_ceiling_bytes"] > int(control_alloc * 1.30):
            raise ValueError(f"allocation ceiling rose above pinned control for {name}")
        rounds = []
        for number in range(1, 4):
            candidate_measurement = read_measurement(Path(candidate_dir) / f"round-{number}" / log_name, test_name)
            control_measurement = read_measurement(Path(control_dir) / f"round-{number}" / log_name, test_name)
            for label, measurement, expected_release in (("candidate", candidate_measurement, candidate_sha), ("control", control_measurement, control_source)):
                if measurement["release"] != expected_release:
                    raise ValueError(f"{label} measurement release mismatch for {name} round {number}")
                if measurement["dataset"] != candidate_baseline["dataset_digest"]:
                    raise ValueError(f"{label} measurement dataset mismatch for {name} round {number}")
                if measurement["samples"] != candidate_baseline["samples"]:
                    raise ValueError(f"{label} measurement sampling policy mismatch for {name} round {number}")
            if control_measurement["p50_millis"] <= 0:
                raise ValueError(f"control p50 must be positive for {name} round {number}")
            rounds.append({"round": number, "control": control_measurement, "candidate": candidate_measurement,
                           "p50_ratio": candidate_measurement["p50_millis"] / control_measurement["p50_millis"],
                           "throughput_ratio": candidate_measurement["throughput"] / control_measurement["throughput"]})
        median_ratio = statistics.median(item["p50_ratio"] for item in rounds)
        if median_ratio > 1.5:
            raise ValueError(f"candidate p50 regression for {name}: median paired ratio {median_ratio:.3f} exceeds 1.500")
        median_throughput_ratio = statistics.median(item["throughput_ratio"] for item in rounds)
        if median_throughput_ratio < 1 / 1.5:
            raise ValueError(f"candidate throughput regression for {name}: median paired ratio {median_throughput_ratio:.3f} is below 0.667")
        rows.append({
            "baseline": name, "test": test_name, "median_p50_ratio": median_ratio,
            "median_throughput_ratio": median_throughput_ratio,
            "control_p50_millis": statistics.median(item["control"]["p50_millis"] for item in rounds),
            "candidate_p50_millis": statistics.median(item["candidate"]["p50_millis"] for item in rounds),
            "control_p95_millis": statistics.median(item["control"]["p95_millis"] for item in rounds),
            "candidate_p95_millis": statistics.median(item["candidate"]["p95_millis"] for item in rounds),
            "control_peak_memory_bytes": max(item["control"]["peak"] for item in rounds),
            "candidate_peak_memory_bytes": max(item["candidate"]["peak"] for item in rounds),
            "control_alloc_bytes_median": statistics.median(item["control"]["alloc"] for item in rounds),
            "candidate_alloc_bytes_median": statistics.median(item["candidate"]["alloc"] for item in rounds),
            "control_throughput_ops_per_second": statistics.median(item["control"]["throughput"] for item in rounds),
            "candidate_throughput_ops_per_second": statistics.median(item["candidate"]["throughput"] for item in rounds),
            "rounds": rounds,
        })
    return {"schema": "synapse-performance-latency-comparison-v2", "control_release_digest": control_source, "candidate_release_digest": candidate_sha, "comparisons": rows}


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    control_sha_parser = commands.add_parser("control-sha")
    control_sha_parser.add_argument("--baselines", type=Path, required=True)
    ratchet = commands.add_parser("ratchet")
    ratchet.add_argument("--candidate-baselines", type=Path, required=True)
    ratchet.add_argument("--previous-baselines", type=Path, required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("--candidate-baselines", type=Path, required=True)
    compare.add_argument("--control-baselines", type=Path, required=True)
    compare.add_argument("--candidate-measurements", type=Path, required=True)
    compare.add_argument("--control-measurements", type=Path, required=True)
    compare.add_argument("--candidate-sha", required=True)
    compare.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "control-sha":
            print(control_sha(load_baselines(args.baselines)))
            return 0
        if args.command == "ratchet":
            verify_allocation_ratchet(args.candidate_baselines, args.previous_baselines)
            print("allocation ceiling ratchet passed")
            return 0
        summary = verify(args.candidate_baselines, args.control_baselines, args.candidate_measurements, args.control_measurements, args.candidate_sha)
        args.summary.write_text(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    except ValueError as error:
        print(f"performance latency gate failed: {error}", file=sys.stderr)
        return 1
    print(f"performance latency gate passed: control={summary['control_release_digest']} candidate={summary['candidate_release_digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
