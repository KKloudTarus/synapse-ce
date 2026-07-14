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


# JS/TS quality pack, batch 6: array-method idioms, DOM, deprecated globals, Promise misuse.
RULES = [
    r(id="js-prefer-array-find", title="filter(...)[0]", desc="Taking the first filtered element should use find().",
      rationale="find() stops at the first match instead of building a whole filtered array (unicorn prefer-array-find).",
      remediation="Use find(...).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.filter\s*\([^)]*\)\s*\[\s*0\s*\]", nc="const first = users.filter(isActive)[0];", c="const first = users.find(isActive);"),
    r(id="js-prefer-array-some", title="filter(...).length > 0", desc="Testing for any match should use some().",
      rationale="some() short-circuits instead of filtering the whole array (unicorn prefer-array-some).",
      remediation="Use some(...).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.filter\s*\([^)]*\)\s*\.\s*length\s*(>|>=|!==|===)\s*0", nc="if (users.filter(isActive).length > 0) {", c="if (users.some(isActive)) {"),
    r(id="js-prefer-text-content", title="innerText", desc="innerText triggers reflow; textContent does not.",
      rationale="textContent is faster and layout-independent (unicorn prefer-dom-node-text-content).",
      remediation="Use textContent.", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.innerText\b", nc="el.innerText = label;", c="el.textContent = label;"),
    r(id="js-tofixed-no-digits", title="toFixed() without digits", desc="toFixed() defaults to 0 fractional digits.",
      rationale="Omitting the digits argument is easy to misread; state it explicitly (unicorn require-number-to-fixed-digits-argument).",
      remediation="Pass the digit count, e.g. toFixed(2).", source="https://github.com/sindresorhus/eslint-plugin-unicorn",
      re=r"\.toFixed\s*\(\s*\)", nc="const s = price.toFixed();", c="const s = price.toFixed(2);"),
    r(id="js-promise-new-static", type="bug", qual="rel", sev="medium", title="new Promise.resolve()",
      desc="Promise.resolve/reject/all are static methods, not constructors.", rationale="new Promise.resolve(...) throws TypeError because the static method is not a constructor.",
      remediation="Call the static method without new: Promise.resolve(...).", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise",
      re=r"new\s+Promise\.(resolve|reject|all|race|allSettled|any)\b", nc="return new Promise.resolve(value);", c="return Promise.resolve(value);"),
    r(id="js-legacy-escape", title="Deprecated escape() / unescape()", desc="The global escape/unescape functions are deprecated.",
      rationale="escape/unescape mishandle non-ASCII; use encodeURIComponent/decodeURIComponent (MDN).",
      remediation="Use encodeURIComponent / decodeURIComponent.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/escape",
      re=r"(^|[^.\w])(escape|unescape)\s*\(", nc="const q = escape(userInput);", c="const q = encodeURIComponent(userInput);"),
]
