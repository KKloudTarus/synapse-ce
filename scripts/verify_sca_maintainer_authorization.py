#!/usr/bin/env python3
"""Verify and hand off a maintainer SCA authorization without trusting input JSON."""

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


SCHEMA = "github-maintainer-issue-comment-capture-v1"
AUTHORIZATION_SCHEMA = "maintainer-authorization-v2"
HANDOFF_SCHEMA = "synapse-sca-maintainer-authorization-handoff-v1"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def fail(message):
    raise ValueError(message)


def sha256_digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_body(source_sha, digests):
    return "\n".join((
        "decision: approved",
        "implementation_commit: " + source_sha,
        "catalog_digest: " + digests["catalog"],
        "oracle_digest: " + digests["oracle"],
        "ratchet_digest: " + digests["ratchet"],
        "policy_digest: " + digests["policy"],
    ))


def parse_timestamp(value):
    if not isinstance(value, str):
        fail("timestamp must be a string")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        fail("timestamp is not RFC3339: " + str(error))
    if parsed.tzinfo is None:
        fail("timestamp must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def load_json(path):
    try:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail("read JSON %s: %s" % (path, error))


def require_digests(raw):
    if not isinstance(raw, dict) or set(raw) != {"catalog", "oracle", "ratchet", "policy"}:
        fail("digest input must contain exactly catalog, oracle, ratchet, policy")
    for name, value in raw.items():
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            fail("%s digest is invalid" % name)
    return raw


def api_get(api_base, token, path):
    request = urllib.request.Request(
        api_base.rstrip("/") + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as error:
        fail("GitHub API GET %s failed: %s" % (path, error))


def issue_comments(api_base, token, repository, pull_number):
    comments = []
    for page in range(1, 101):
        path = "/repos/%s/issues/%s/comments?per_page=100&page=%s" % (repository, pull_number, page)
        batch = api_get(api_base, token, path)
        if not isinstance(batch, list):
            fail("GitHub issue comments response is not a list")
        comments.extend(batch)
        if len(batch) < 100:
            return comments
    fail("GitHub issue comments exceed the bounded pagination limit")


def capture(args):
    if not SHA.fullmatch(args.source_sha):
        fail("source SHA must be a lower-case 40-character SHA")
    if not args.token:
        fail("GitHub API token is required")
    digests = require_digests(load_json(args.digests))
    pull = api_get(args.api_base, args.token, "/repos/%s/pulls/%s" % (args.repository, args.pull_number))
    if pull.get("number") != args.pull_number or pull.get("head", {}).get("sha") != args.source_sha:
        fail("pull request does not currently point to the authorized source SHA")
    expected_body = canonical_body(args.source_sha, digests)
    expected_issue_url = "%s/repos/%s/issues/%s" % (args.api_base.rstrip("/"), args.repository, args.pull_number)
    candidates = []
    for comment in issue_comments(args.api_base, args.token, args.repository, args.pull_number):
        if comment.get("body") == expected_body:
            candidates.append(comment)
    if len(candidates) != 1:
        fail("exactly one current issue comment must bind the final decision and inputs")
    comment = candidates[0]
    comment_id = comment.get("id")
    login = comment.get("user", {}).get("login")
    html_url = comment.get("html_url")
    if not isinstance(comment_id, int) or comment_id <= 0 or not isinstance(login, str) or not login:
        fail("matched issue comment lacks an immutable ID or author")
    expected_html_url = "https://github.com/%s/pull/%s#issuecomment-%s" % (args.repository, args.pull_number, comment_id)
    if html_url != expected_html_url or comment.get("issue_url") != expected_issue_url:
        fail("matched comment is not attached to the expected pull request")
    created_at, updated_at = comment.get("created_at"), comment.get("updated_at")
    if created_at != updated_at:
        fail("maintainer authorization comment has been edited")
    parse_timestamp(created_at)
    permission = api_get(args.api_base, args.token, "/repos/%s/collaborators/%s/permission" % (args.repository, urllib.parse.quote(login, safe="")))
    if permission.get("permission") != "admin" and permission.get("role_name") != "maintain":
        fail("comment author does not currently hold admin or maintain permission")
    approval = {
        "schema_version": SCHEMA,
        "id": str(comment_id),
        "url": html_url,
        "head_url": "https://github.com/%s/commit/%s" % (args.repository, args.source_sha),
        "login": login,
        "created_at": created_at,
        "updated_at": updated_at,
        "decision": "approved",
        "implementation_commit": args.source_sha,
        "body": expected_body,
    }
    approval_bytes = canonical_json(approval)
    captured_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "approval_id": approval["id"],
        "approval_digest": sha256_digest(approval_bytes),
        "maintainer_login": login,
        "implementation_commit": args.source_sha,
        "catalog_digest": digests["catalog"],
        "oracle_digest": digests["oracle"],
        "ratchet_digest": digests["ratchet"],
        "policy_digest": digests["policy"],
        "decision": "approved",
        "transcribed_by": "github-actions-hosted-provenance",
        "transcribed_at": captured_at,
        "body": "GitHub API capture of immutable maintainer authorization comment " + approval["id"],
    }
    authorization_bytes = canonical_json(authorization)
    handoff = {
        "schema_version": HANDOFF_SCHEMA,
        "repository": args.repository,
        "pull_number": args.pull_number,
        "source_sha": args.source_sha,
        "workflow_run_id": args.workflow_run_id,
        "workflow_run_attempt": args.workflow_run_attempt,
        "generated_at": captured_at,
        "approval_sha256": sha256_digest(approval_bytes),
        "authorization_sha256": sha256_digest(authorization_bytes),
    }
    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=False)
    write_json(out / "approval.json", approval)
    write_json(out / "authorization.json", authorization)
    write_json(out / "handoff.json", handoff)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def write_json(path, value):
    path.write_bytes(canonical_json(value))


def verify_handoff(args):
    if not SHA.fullmatch(args.source_sha):
        fail("source SHA must be a lower-case 40-character SHA")
    root = pathlib.Path(args.handoff_dir)
    expected_names = {"approval.json", "authorization.json", "handoff.json"}
    actual_names = {item.name for item in root.iterdir() if item.is_file()}
    if actual_names != expected_names:
        fail("handoff artifact contains an unexpected file set")
    approval_bytes = (root / "approval.json").read_bytes()
    authorization_bytes = (root / "authorization.json").read_bytes()
    handoff = load_json(root / "handoff.json")
    if handoff.get("schema_version") != HANDOFF_SCHEMA or handoff.get("repository") != args.repository:
        fail("handoff repository binding is invalid")
    if handoff.get("pull_number") != args.pull_number or handoff.get("source_sha") != args.source_sha:
        fail("handoff source binding is invalid")
    if str(handoff.get("workflow_run_id")) != str(args.workflow_run_id) or str(handoff.get("workflow_run_attempt")) != str(args.workflow_run_attempt):
        fail("handoff run or attempt binding is invalid")
    if handoff.get("approval_sha256") != sha256_digest(approval_bytes) or handoff.get("authorization_sha256") != sha256_digest(authorization_bytes):
        fail("handoff content hash is invalid")
    generated = parse_timestamp(handoff.get("generated_at"))
    now = parse_timestamp(args.now) if args.now else dt.datetime.now(dt.timezone.utc)
    age = (now - generated).total_seconds()
    if age < 0 or age > args.max_age_seconds:
        fail("handoff evidence is outside its freshness bound")
    approval = load_json(root / "approval.json")
    authorization = load_json(root / "authorization.json")
    required_approval = {"schema_version": SCHEMA, "implementation_commit": args.source_sha, "decision": "approved"}
    if any(approval.get(key) != value for key, value in required_approval.items()):
        fail("approval record is invalid")
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA or authorization.get("approval_id") != approval.get("id") or authorization.get("approval_digest") != sha256_digest(approval_bytes):
        fail("authorization record is invalid")


def parser():
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--api-base", default="https://api.github.com")
    capture_parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    capture_parser.add_argument("--repository", required=True)
    capture_parser.add_argument("--pull-number", type=int, required=True)
    capture_parser.add_argument("--source-sha", required=True)
    capture_parser.add_argument("--digests", required=True)
    capture_parser.add_argument("--workflow-run-id", required=True)
    capture_parser.add_argument("--workflow-run-attempt", required=True)
    capture_parser.add_argument("--out-dir", required=True)
    capture_parser.set_defaults(handler=capture)
    verify_parser = commands.add_parser("verify-handoff")
    verify_parser.add_argument("--repository", required=True)
    verify_parser.add_argument("--pull-number", type=int, required=True)
    verify_parser.add_argument("--source-sha", required=True)
    verify_parser.add_argument("--workflow-run-id", required=True)
    verify_parser.add_argument("--workflow-run-attempt", required=True)
    verify_parser.add_argument("--handoff-dir", required=True)
    verify_parser.add_argument("--max-age-seconds", type=int, default=900)
    verify_parser.add_argument("--now")
    verify_parser.set_defaults(handler=verify_handoff)
    return result


def main():
    args = parser().parse_args()
    if args.max_age_seconds <= 0 if hasattr(args, "max_age_seconds") else False:
        fail("max-age-seconds must be positive")
    args.handler(args)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("authorization verification failed: " + str(error), file=sys.stderr)
        sys.exit(1)
