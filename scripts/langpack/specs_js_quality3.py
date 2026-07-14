CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# JS/TS quality pack, batch 3: ESLint / eslint-plugin-n idioms. Clean-room prose.
RULES = [
    r(id="js-no-path-concat", type="smell", qual="maint", sev="low", cwe="",
      title="Path built by string concatenation", desc="Concatenating __dirname/__filename with a separator is not portable.",
      rationale="Manual path concatenation breaks across platforms; path.join handles separators.",
      remediation="Use path.join(__dirname, ...).",
      source="https://github.com/eslint-community/eslint-plugin-n",
      re=r"(__dirname|__filename)\s*\+", nc='const p = __dirname + "/config.json";', c='const p = path.join(__dirname, "config.json");'),
    r(id="js-no-process-exit", type="smell", qual="maint", sev="low", cwe="",
      title="process.exit() in library code", desc="process.exit terminates abruptly, skipping cleanup and pending I/O.",
      rationale="Calling process.exit in a module kills the whole process; libraries should throw or return instead.",
      remediation="Throw an error (or set process.exitCode) and let the entry point decide.",
      source="https://github.com/eslint-community/eslint-plugin-n",
      re=r"process\.exit\s*\(", nc="process.exit(1);", c='throw new Error("fatal");'),
    r(id="js-prefer-regex-literal", type="smell", qual="maint", sev="low", cwe="",
      title="RegExp built from a string literal", desc="new RegExp(\"...\") with a constant is clearer as a regex literal.",
      rationale="A constant pattern reads better as /.../ and avoids double-escaping.",
      remediation="Use a regex literal: /pattern/.",
      source="https://eslint.org/docs/latest/rules/prefer-regex-literals",
      re=r'''new\s+RegExp\s*\(\s*["']''', nc='const re = new RegExp("abc");', c="const re = /abc/;"),
    r(id="js-prefer-rest-params", type="smell", qual="maint", sev="low", cwe="",
      title="Use of the arguments object", desc="Indexing arguments is superseded by rest parameters.",
      rationale="Rest parameters (...args) are a real array and clearer than the arguments object.",
      remediation="Declare a rest parameter: function f(...args).",
      source="https://eslint.org/docs/latest/rules/prefer-rest-params",
      re=r"\barguments\[", nc="const first = arguments[0];", c="const first = args[0];"),
    r(id="js-implicit-string-coercion", type="smell", qual="maint", sev="low", cwe="",
      title="Implicit string coercion with + \"\"", desc="value + \"\" coerces to string in an obscure way.",
      rationale="Concatenating an empty string to coerce is unclear; String(value) states the intent.",
      remediation="Use String(value).",
      source="https://eslint.org/docs/latest/rules/no-implicit-coercion",
      re=r'''\+\s*""|""\s*\+''', nc='const s = value + "";', c="const s = String(value);"),
]
