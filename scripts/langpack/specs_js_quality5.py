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


# JS/TS quality pack, batch 5: eslint-plugin-unicorn / core modern-API idioms and deprecations.
RULES = [
    r(id="js-instanceof-array", title="instanceof Array", desc="instanceof Array fails across realms (iframes/workers).",
      rationale="Array.isArray works across execution contexts where instanceof Array does not (unicorn no-instanceof-array).",
      remediation="Use Array.isArray(value).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\binstanceof\s+Array\b", nc="if (value instanceof Array) {", c="if (Array.isArray(value)) {"),
    r(id="js-prefer-date-now", title="new Date().getTime()", desc="Date.now() is clearer for the current timestamp.",
      rationale="Creating a Date just to call getTime is wasteful; Date.now() is direct (unicorn prefer-date-now).",
      remediation="Use Date.now().", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"new\s+Date\s*\(\s*\)\s*\.\s*getTime\s*\(\s*\)", nc="const t = new Date().getTime();", c="const t = Date.now();"),
    r(id="js-substr-deprecated", title="String.substr()", desc="substr is a deprecated legacy method.",
      rationale="String.prototype.substr is deprecated; slice/substring are the standard methods.",
      remediation="Use slice() or substring().", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/substr",
      re=r"\.substr\s*\(", nc='const p = name.substr(0, 3);', c="const p = name.slice(0, 3);"),
    r(id="js-indexof-startswith", title="indexOf(...) === 0", desc="Comparing indexOf to 0 is a prefix check.",
      rationale="startsWith states the intent of a prefix test more clearly (unicorn prefer-string-starts-ends-with).",
      remediation="Use startsWith(...).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.indexOf\s*\([^)]*\)\s*===?\s*0\b", nc='if (path.indexOf("/api") === 0) {', c='if (path.startsWith("/api")) {'),
    r(id="js-throw-new-error", title="throw Error() without new", desc="Errors should be thrown with new.",
      rationale="Throwing Error(...) without new is inconsistent; always use new Error(...) (unicorn throw-new-error).",
      remediation="Use throw new Error(...).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"throw\s+Error\s*\(", nc='throw Error("failed");', c='throw new Error("failed");'),
    r(id="js-prefer-node-protocol", title="require without node: protocol", desc="Built-in modules should use the node: protocol.",
      rationale="The node: prefix makes built-in imports unambiguous and future-proof (unicorn prefer-node-protocol).",
      remediation='Use require("node:fs") etc.', source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r'''require\s*\(\s*["'](fs|path|http|https|crypto|os|util|stream|events|url|zlib|child_process)["']\s*\)''',
      nc='const fs = require("fs");', c='const fs = require("node:fs");'),
    r(id="js-map-flat", title="map().flat()", desc="map().flat() should be a single flatMap().",
      rationale="flatMap does the map-then-flatten in one pass (unicorn prefer-array-flat-map).",
      remediation="Use flatMap(...).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.map\s*\([^)]*\)\s*\.\s*flat\s*\(\s*\)", nc="const out = items.map(fn).flat();", c="const out = items.flatMap(fn);"),
    r(id="js-keycode-deprecated", title="KeyboardEvent.keyCode", desc="keyCode is deprecated.",
      rationale="event.keyCode is deprecated; use event.key (unicorn prefer-keyboard-event-key).",
      remediation="Use event.key.", source="https://developer.mozilla.org/en-US/docs/Web/API/KeyboardEvent/keyCode",
      re=r"\.keyCode\b", nc="if (event.keyCode === 13) submit();", c='if (event.key === "Enter") submit();'),
    r(id="js-trim-left-right", title="trimLeft / trimRight", desc="trimLeft/trimRight are legacy aliases.",
      rationale="trimStart/trimEnd are the standard names (unicorn prefer-string-trim-start-end).",
      remediation="Use trimStart() / trimEnd().", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/trimStart",
      re=r"\.(trimLeft|trimRight)\s*\(", nc="const s = value.trimLeft();", c="const s = value.trimStart();"),
    r(id="js-useless-undefined", title="return undefined", desc="return undefined is the same as a bare return.",
      rationale="Explicitly returning undefined adds noise (unicorn no-useless-undefined).",
      remediation="Use a bare return;.", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"return\s+undefined\s*;", nc="return undefined;", c="return;"),
    r(id="js-new-array", title="new Array(...)", desc="The Array constructor is error-prone.",
      rationale="new Array(n) vs new Array(a, b) is confusing; use a literal or Array.from (unicorn no-new-array).",
      remediation="Use [] / [a, b] or Array.from({length: n}).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"new\s+Array\s*\(", nc="const a = new Array(1, 2, 3);", c="const a = [1, 2, 3];"),
]
