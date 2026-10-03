#!/usr/bin/env python3
"""Generate playground fallback fixtures from api/openapi.yaml.

The hand-written handlers in src/mocks/handlers.ts stay authoritative: they carry the realistic data
the main screens are demoed with. This generator covers everything they do not, so no screen in the
playground can hit the unmocked 404 path. Values are synthesised from the response schema and biased
by field name so a generated screen reads as plausible rather than as "string" repeated.

Usage: python3 scripts/gen-playground-fixtures.py > src/mocks/generated.ts
"""
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "api" / "openapi.yaml"

NOW = "2026-10-03T09:00:00Z"
EARLIER = "2026-10-01T14:30:00Z"
MAX_DEPTH = 7
ARRAY_ITEMS = 3

# Name-biased string values. First match wins, so order matters.
STRING_BY_NAME = [
    (r"(^|_)(created|updated|started|finished|observed|seen|at|expires|deadline|remediate_by)$", NOW),
    (r"_at$|_time$|_timestamp$|^timestamp$", NOW),
    (r"^(first_seen|origin_at|authenticated_at)$", EARLIER),
    (r"severity$", "high"),
    (r"(^|_)status$|(^|_)state$|phase$", "active"),
    (r"email$", "demo@synapse.example"),
    (r"(url|uri|endpoint|href|link)$", "https://synapse.example/demo"),
    (r"(^|_)digest$|(^|_)hash$|sha256$", "sha256:3f786850e387550fdab836ed7e6dc881de23001b"),
    (r"(^|_)commit$|(^|_)sha$", "9f1c2b7d4e5a6f8091a2b3c4d5e6f708192a3b4c"),
    (r"(^|_)ref$|branch$", "main"),
    (r"(^|_)cve|advisory_id$", "CVE-2026-10101"),
    (r"(^|_)purl$|package$|component$", "pkg:npm/demo-package@1.4.2"),
    (r"(^|_)path$|file$|location$", "src/service/handler.go"),
    (r"(^|_)version$", "1.4.2"),
    (r"(^|_)actor$|(^|_)owner$|user|assignee|author", "demo.operator"),
    (r"(^|_)tenant", "demo-tenant"),
    (r"(^|_)name$|title$|label$|display", "__NAME__"),
    (r"(^|_)description$|summary$|reason$|message$|note", "Seeded playground record, not a real result."),
    (r"(^|_)key$|slug$", "demo-key"),
    (r"(^|_)id$", "__ID__"),
    (r"kind$|type$|class$", "demo"),
]

INT_BY_NAME = [
    (r"(count|total|items|findings|hosts|assets|agents)$", 3),
    (r"(port)$", 443),
    (r"(percent|percentage|coverage)$", 82),
    (r"(score)$", 7),
    (r"(seq|revision|version|generation|epoch|attempt)$", 1),
    (r"(size|bytes|length)$", 2048),
]


def pick(table, name, default):
    for pattern, value in table:
        if re.search(pattern, name or "", re.I):
            return value
    return default


class Generator:
    def __init__(self, spec):
        self.spec = spec

    def deref(self, node, seen=()):
        if isinstance(node, dict) and "$ref" in node:
            ref = node["$ref"]
            if ref in seen:
                return {"type": "object"}
            target = self.spec
            for part in ref.lstrip("#/").split("/"):
                target = target.get(part, {}) if isinstance(target, dict) else {}
            return self.deref(target, seen + (ref,))
        return node

    # pick_enum avoids the values that make a screen render as switched off. Taking enum[0] gave the
    # ownership module mode "off", which is a correct value and a useless demo.
    OFFISH = {"off", "none", "disabled", "unknown", "unspecified", "inactive", "never", "", "no"}
    PREFERRED = ["enforce", "active", "enabled", "healthy", "on", "ready", "succeeded", "passed", "high"]

    def pick_enum(self, values, name):
        strings = [v for v in values if isinstance(v, str)]
        if not strings:
            return values[0]
        for want in self.PREFERRED:
            for v in strings:
                if v.lower() == want:
                    return v
        for v in strings:
            if v.lower() not in self.OFFISH:
                return v
        return strings[0]

    # Pools used to vary a generated list. The index is the array position, so three rows of a
    # generated collection read as three different records rather than one record repeated.
    NAME_POOL = [
        "Platform Security", "Payments Core", "Edge Delivery", "Identity Services", "Data Platform",
        "Checkout API", "Orders API", "Billing Worker", "Search Indexer", "Notification Relay",
        "prod-use1 cluster", "staging-euw1 cluster", "web01.prod", "db01.prod", "cache02.prod",
    ]

    def named(self, index):
        return self.NAME_POOL[index % len(self.NAME_POOL)]

    def example(self, schema, name="", depth=0, seen=(), index=0):
        schema = self.deref(schema, seen)
        if not isinstance(schema, dict) or depth > MAX_DEPTH:
            return None
        if "example" in schema:
            return schema["example"]
        if "default" in schema:
            return schema["default"]
        for key in ("allOf",):
            if key in schema:
                merged = {}
                for part in schema[key]:
                    value = self.example(part, name, depth, seen)
                    if isinstance(value, dict):
                        merged.update(value)
                return merged
        for key in ("oneOf", "anyOf"):
            if key in schema and schema[key]:
                return self.example(schema[key][0], name, depth, seen)
        if "enum" in schema and schema["enum"]:
            return self.pick_enum(schema["enum"], name)
        kind = schema.get("type")
        if kind == "array":
            item = schema.get("items", {})
            out = []
            for position in range(ARRAY_ITEMS if depth < 3 else 1):
                value = self.example(item, name, depth + 1, seen, position)
                if value is None:
                    break
                out.append(value)
            return out
        if kind == "object" or "properties" in schema:
            out = {}
            for prop, sub in (schema.get("properties") or {}).items():
                value = self.example(sub, prop, depth + 1, seen, index)
                if value is not None:
                    out[prop] = value
            if not out and schema.get("additionalProperties"):
                out["demo"] = self.example(schema["additionalProperties"], name, depth + 1, seen)
            return out
        if kind == "boolean":
            return not re.search(r"archived|disabled|deleted|revoked|failed|truncated", name or "", re.I)
        if kind == "integer":
            return pick(INT_BY_NAME, name, 2)
        if kind == "number":
            return 7.4 if re.search(r"score|cvss|rate|ratio", name or "", re.I) else 1.5
        if kind == "string":
            fmt = schema.get("format", "")
            if fmt in ("date-time", "date"):
                return NOW if fmt == "date-time" else NOW[:10]
            if fmt == "uuid":
                return "9f1c2b7d-4e5a-6f80-91a2-b3c4d5e6f708"
            if fmt == "email":
                return "demo@synapse.example"
            if fmt in ("uri", "url"):
                return "https://synapse.example/demo"
            if fmt == "byte":
                return "ZGVtbw=="
            value = pick(STRING_BY_NAME, name, "demo")
            if value == "__NAME__":
                return self.named(index)
            if value == "__ID__":
                return f"{(name or 'id').removesuffix('_id').replace('_', '-')}-{index + 1:03d}"
            return value
        # A schema with no type and no properties carries no shape to synthesise.
        return None


def main():
    spec = yaml.safe_load(SPEC.read_text())
    gen = Generator(spec)
    out = {}
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            responses = (op or {}).get("responses") or {}
            code = next((c for c in ("200", "201", "202") if c in responses), None)
            if code is None:
                continue
            content = (gen.deref(responses[code]) or {}).get("content") or {}
            schema = (content.get("application/json") or {}).get("schema")
            if schema is None:
                out[f"{method.upper()} {path}"] = None  # 204-style: body-less success
                continue
            out[f"{method.upper()} {path}"] = gen.example(schema, path.rsplit("/", 1)[-1])

    body = json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False)
    print("// GENERATED by web/scripts/gen-playground-fixtures.py from api/openapi.yaml.")
    print("// Do not edit. Hand-written handlers in handlers.ts take precedence over everything here;")
    print("// this map only answers requests they do not cover, so the playground has no unmocked route.")
    print("")
    print(f"export const GENERATED_FIXTURES: Record<string, unknown> = {body}")
    print("")
    print("""
// matchGenerated turns a concrete request into its OpenAPI path template. Templates are tried
// longest-first so a literal segment wins over a parameter of the same arity.
const KEYS = Object.keys(GENERATED_FIXTURES)
  .map((k) => {
    const [method, template] = k.split(' ')
    return { key: k, method, segments: template.split('/') }
  })
  .sort((a, b) => b.segments.filter((s) => !s.startsWith('{')).length - a.segments.filter((s) => !s.startsWith('{')).length)

export function matchGenerated(method: string, pathname: string): { found: boolean; body: unknown } {
  const segments = pathname.split('/')
  for (const candidate of KEYS) {
    if (candidate.method !== method || candidate.segments.length !== segments.length) continue
    const ok = candidate.segments.every((s, i) => s.startsWith('{') || s === segments[i])
    if (ok) return { found: true, body: GENERATED_FIXTURES[candidate.key] }
  }
  return { found: false, body: null }
}
""".strip())


if __name__ == "__main__":
    sys.exit(main())
