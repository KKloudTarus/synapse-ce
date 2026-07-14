def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", "")  # reference directives are comment lines; do not skip comment-only lines
    return k


RULES = [
    r(id="ts-triple-slash-reference", type="smell", qual="maint", sev="low", cwe="",
      title="Triple-slash reference directive", desc="/// <reference> directives are a legacy module system.",
      rationale="Triple-slash references predate ES modules; import statements are clearer and tool-friendly.",
      remediation="Use an import statement instead of a /// <reference> directive.",
      source="https://typescript-eslint.io/rules/triple-slash-reference/",
      re=r'^\s*///\s*<reference', nc='/// <reference path="./types.d.ts" />', c='import { Types } from "./types";'),
]
