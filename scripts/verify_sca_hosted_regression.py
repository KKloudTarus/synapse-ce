#!/usr/bin/env python3
"""Bind a live owned-corpus measurement to the last accepted SCA comparison."""

import argparse
import json
import pathlib
import re
import sys


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def read_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def verify(owned, digests, capture, source_sha):
    if not SHA.fullmatch(source_sha):
        raise ValueError("source revision is not a full SHA")
    if owned.get("schema_version") != "synapse-accuracy-report-v1":
        raise ValueError("owned measurement has the wrong schema")
    cases = owned.get("cases")
    groups = owned.get("groups")
    if not isinstance(cases, int) or cases < 13 or not isinstance(groups, list) or not groups:
        raise ValueError("owned measurement is missing required corpus cases")
    if sum(group.get("cases", 0) for group in groups) != cases:
        raise ValueError("owned measurement group coverage is incomplete")
    overall = owned.get("overall", {})
    if overall.get("true_positives", 0) <= 0:
        raise ValueError("owned measurement contains no positive detection")
    if capture.get("schema_version") != "synapse-sca-trusted-acceptance-report-v1" or capture.get("accepted") is not True or capture.get("observations") != 24:
        raise ValueError("frozen comparison is not an accepted 24-observation capture")
    if not isinstance(capture.get("source_sha"), str) or not SHA.fullmatch(capture["source_sha"]):
        raise ValueError("frozen comparison lacks a valid source revision")
    if not isinstance(capture.get("workflow_run_id"), str) or not capture["workflow_run_id"].isdigit():
        raise ValueError("frozen comparison lacks a valid workflow run ID")
    captured = capture.get("input_digests", {})
    for key in ("catalog", "oracle", "ratchet", "policy"):
        value = digests.get(key)
        if not isinstance(value, str) or not DIGEST.fullmatch(value) or captured.get(key) != value:
            raise ValueError("frozen comparison does not match current " + key + " input")
    for key in ("publication_sha256", "run_sha256"):
        if not isinstance(capture.get(key), str) or not DIGEST.fullmatch(capture[key]):
            raise ValueError("frozen comparison lacks " + key)
    return {
        "schema_version": "synapse-sca-hosted-regression-v1",
        "source_sha": source_sha,
        "measurement": "current-owned-embedded-corpus",
        "owned_cases": cases,
        "owned_overall": overall,
        "input_digests": {key: digests[key] for key in ("catalog", "oracle", "ratchet", "policy")},
        "comparison": "frozen-accepted-capture",
        "comparison_source_sha": capture["source_sha"],
        "comparison_workflow_run_id": capture["workflow_run_id"],
        "comparison_observations": capture["observations"],
        "comparison_publication_sha256": capture["publication_sha256"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--owned-report", required=True)
    parser.add_argument("--digests", required=True)
    parser.add_argument("--capture", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = verify(read_json(args.owned_report), read_json(args.digests), read_json(args.capture), args.source_sha)
    pathlib.Path(args.output).write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("SCA hosted regression: " + str(error), file=sys.stderr)
        sys.exit(1)
