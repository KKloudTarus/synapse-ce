CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "smell")
    k.setdefault("qual", "maint")
    k.setdefault("sev", "low")
    k.setdefault("cwe", "")
    return k


# JS/TS quality pack: correctness idioms + Node removed APIs.
RULES = [
    r(id="js-push-no-args", title="push() with no arguments", desc="Array.push() with no arguments does nothing.",
      rationale="A no-argument push is a no-op, usually a leftover or mistake.",
      remediation="Pass the element(s) to push, or remove the call.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/push",
      re=r"\.push\s*\(\s*\)", nc="queue.push();", c="queue.push(item);"),
    r(id="js-delete-var", type="bug", qual="rel", sev="medium", title="delete on a variable", desc="delete on a variable is a no-op and a strict-mode error.",
      rationale="delete only removes object properties; deleting a variable throws in strict mode (eslint no-delete-var).",
      remediation="Assign undefined/null, or narrow the variable's scope.", source="https://eslint.org/docs/latest/rules/no-delete-var",
      re=r"\bdelete\s+[a-zA-Z_$]\w*\s*;", nc="delete cached;", c="cached = undefined;"),
    r(id="ts-double-assertion", title="Double assertion through unknown", desc="`as unknown as T` bypasses all type checking.",
      rationale="Chaining assertions through unknown forces an unrelated type, defeating the type system.",
      remediation="Use a type guard or a proper conversion function.", source="https://typescript-eslint.io/rules/no-explicit-any/",
      re=r"\bas\s+unknown\s+as\b", nc="const user = payload as unknown as User;", c="const user = toUser(payload);"),
    r(id="js-node-constants-module", type="bug", qual="rel", sev="medium", title="Deprecated constants module", desc="The top-level constants module is deprecated.",
      rationale="require('constants') is deprecated in favor of fs.constants / os.constants.",
      remediation="Use fs.constants / os.constants.", source="https://nodejs.org/api/deprecations.html",
      re=r'''require\s*\(\s*["']constants["']\s*\)''', nc='const c = require("constants");', c='const { constants } = require("node:fs");'),
    r(id="js-node-process-eventemitter", type="bug", qual="rel", sev="medium", title="process.EventEmitter", desc="process.EventEmitter was removed.",
      rationale="process.EventEmitter was removed; require the events module.",
      remediation="Use require('node:events').EventEmitter.", source="https://nodejs.org/api/deprecations.html",
      re=r"\bprocess\.EventEmitter\b", nc="const E = process.EventEmitter;", c='const { EventEmitter } = require("node:events");'),
]
