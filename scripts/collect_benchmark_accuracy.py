#!/usr/bin/env python3
"""Publish only measured, numeric accuracy results from hosted benchmark logs."""

import hashlib
import json
import re
import sys
from pathlib import Path


CELLS = {
    "security-accuracy": (
        ("secrets", "secrets-accuracy.jsonl", "TestSecretsOwnedAccuracyAndGitleaksDifferential",
         "internal/infrastructure/tools/secretscan/gitleaks_differential_test.go",
         {"owned": "owned secrets:", "gitleaks": "gitleaks secrets:"}),
        ("iac", "iac-accuracy.jsonl", "TestIaCOwnedAccuracyAndCheckovDifferential",
         "internal/infrastructure/tools/misconfig/checkov_differential_test.go",
         {"owned": "owned iac:", "checkov": "checkov iac:"}),
        ("host_cve", "host-cve-accuracy.jsonl", "TestHostCVECorrelationAccuracy",
         "internal/domain/advisory/hostcve_bench_test.go",
         {"owned": "host-cve correlation:"}),
    ),
    "dynamic-security-benchmark": (
        ("dast", "dast-accuracy.jsonl", "TestDASTOwnedAccuracy",
         "internal/infrastructure/dastchecks/dast_bench_test.go",
         {"owned": "dast owned:"}),
        ("cspm", "cspm-accuracy.jsonl", "TestCSPMOwnedAccuracy",
         "internal/domain/cloudposture/cspm_bench_test.go",
         {"owned": "cspm owned:"}),
    ),
}
EXTRA_INPUTS = {"security-accuracy": ("docs/benchmarks/competitor-identity.json",)}
METRIC_PATTERN = re.compile(r"(?:[a-z_]+=[0-9]+(?:\.[0-9]+)?)(?: [a-z_]+=[0-9]+(?:\.[0-9]+)?)*")
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
BASE_FIELDS = {"tp", "fp", "fn", "recall", "precision"}
EXPECTED_FIELDS = {
    "owned secrets:": BASE_FIELDS,
    "gitleaks secrets:": BASE_FIELDS,
    "owned iac:": BASE_FIELDS | {"categories"},
    "checkov iac:": BASE_FIELDS,
    "host-cve correlation:": BASE_FIELDS | {"cases", "tn"},
    "dast owned:": BASE_FIELDS | {"cases"},
    "cspm owned:": BASE_FIELDS | {"resources"},
}


def extract_metric(records, test_name, marker):
    if not any(row.get("Action") == "pass" and row.get("Test") == test_name for row in records):
        raise ValueError(f"required test did not pass: {test_name}")
    outputs = [row.get("Output", "").split(marker, 1)[1].strip()
               for row in records if row.get("Action") == "output"
               and row.get("Test") == test_name and marker in row.get("Output", "")]
    if len(outputs) != 1 or not METRIC_PATTERN.fullmatch(outputs[0]):
        raise ValueError(f"missing, repeated, or invalid metric: {test_name} {marker}")
    metrics = {}
    for pair in outputs[0].split():
        key, value = pair.split("=", 1)
        if key in metrics:
            raise ValueError(f"duplicate metric field: {key}")
        metrics[key] = float(value) if "." in value else int(value)
    if set(metrics) != EXPECTED_FIELDS[marker]:
        raise ValueError(f"unexpected metric fields: {test_name} {marker}")
    for key in ("recall", "precision"):
        if key not in metrics or not 0 <= metrics[key] <= 1:
            raise ValueError(f"invalid {key}: {test_name} {marker}")
    if not all(key in metrics for key in ("tp", "fp", "fn")):
        raise ValueError(f"incomplete confusion matrix: {test_name} {marker}")
    if metrics["tp"] + metrics["fn"] == 0:
        raise ValueError(f"zero positive cases: {test_name} {marker}")
    recall = metrics["tp"] / (metrics["tp"] + metrics["fn"])
    predicted = metrics["tp"] + metrics["fp"]
    precision = metrics["tp"] / predicted if predicted else 0
    if abs(metrics["recall"] - recall) > 0.00051 or abs(metrics["precision"] - precision) > 0.00051:
        raise ValueError(f"inconsistent accuracy ratio: {test_name} {marker}")
    for key in ("cases", "categories", "resources"):
        if key in metrics:
            if metrics[key] <= 0:
                raise ValueError(f"zero corpus: {test_name} {marker}")
            if metrics["tp"] + metrics["fn"] > metrics[key]:
                raise ValueError(f"positive count exceeds corpus: {test_name} {marker}")
            if key in ("cases", "resources") and metrics["tp"] + metrics["fp"] + metrics["fn"] > metrics[key]:
                raise ValueError(f"confusion count exceeds corpus: {test_name} {marker}")
            if key in ("categories", "resources") and metrics["fp"] > metrics[key]:
                raise ValueError(f"false-positive count exceeds corpus: {test_name} {marker}")
    if "cases" in metrics and "tn" in metrics and sum(metrics[key] for key in ("tp", "fp", "fn", "tn")) != metrics["cases"]:
        raise ValueError(f"confusion matrix differs from corpus: {test_name} {marker}")
    return metrics


def build_result(workflow, source_sha, log_dir, repo_root):
    if workflow not in CELLS:
        raise ValueError(f"unknown workflow: {workflow}")
    if not SHA_PATTERN.fullmatch(source_sha):
        raise ValueError("source SHA must be 40 lower-case hexadecimal characters")
    cells = []
    inputs = set(EXTRA_INPUTS.get(workflow, ()))
    for name, log_name, test_name, source_path, markers in CELLS[workflow]:
        with (log_dir / log_name).open(encoding="utf-8") as stream:
            records = [json.loads(line) for line in stream if line.strip()]
        inputs.add(source_path)
        metrics = {label: extract_metric(records, test_name, marker)
                   for label, marker in markers.items()}
        cells.append({"name": name, "test": test_name, "metrics": metrics, "decision": "pass"})
    digests = {path: hashlib.sha256((repo_root / path).read_bytes()).hexdigest()
               for path in sorted(inputs)}
    return {"schema": "synapse.benchmark-accuracy.v1", "workflow": workflow,
            "source_sha": source_sha, "input_digests": digests,
            "cell_count": len(cells), "cells": cells, "decision": "pass"}


def main(argv):
    if len(argv) != 5:
        raise SystemExit("usage: collect_benchmark_accuracy.py WORKFLOW SOURCE_SHA LOG_DIR OUTPUT")
    result = build_result(argv[1], argv[2], Path(argv[3]), Path(__file__).resolve().parents[1])
    output = Path(argv[4])
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"benchmark result unavailable: {error}") from error
