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


MDN = "https://developer.mozilla.org/en-US/docs/Web/API"

# JS/TS quality pack: node:assert loose comparisons, indexOf membership idioms, removed web APIs.
RULES = [
    r(id="js-assert-equal-loose", type="bug", qual="rel", sev="medium", title="assert.equal (loose)", desc="assert.equal uses == and can mask type bugs.",
      rationale="node:assert.equal compares with ==; use strictEqual to catch type mismatches.",
      remediation="Use assert.strictEqual.", source="https://nodejs.org/api/assert.html#assertequalactual-expected-message",
      re=r"\bassert\.equal\s*\(", nc="assert.equal(result, 1);", c="assert.strictEqual(result, 1);"),
    r(id="js-assert-notequal-loose", type="bug", qual="rel", sev="medium", title="assert.notEqual (loose)", desc="assert.notEqual uses !=.",
      rationale="node:assert.notEqual compares with !=; use notStrictEqual.",
      remediation="Use assert.notStrictEqual.", source="https://nodejs.org/api/assert.html",
      re=r"\bassert\.notEqual\s*\(", nc="assert.notEqual(result, 1);", c="assert.notStrictEqual(result, 1);"),
    r(id="js-assert-deepequal-loose", type="bug", qual="rel", sev="medium", title="assert.deepEqual (loose)", desc="assert.deepEqual compares leaves with ==.",
      rationale="node:assert.deepEqual is loose; use deepStrictEqual for exact structural equality.",
      remediation="Use assert.deepStrictEqual.", source="https://nodejs.org/api/assert.html",
      re=r"\bassert\.deepEqual\s*\(", nc="assert.deepEqual(actual, expected);", c="assert.deepStrictEqual(actual, expected);"),
    r(id="js-indexof-gt-minus-one", title="indexOf(...) > -1", desc="indexOf() > -1 is a membership test.",
      rationale="includes() states the intent of a membership test more clearly.",
      remediation="Use includes(...).", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/includes",
      re=r"\.indexOf\s*\([^)]*\)\s*>\s*-1", nc="if (list.indexOf(x) > -1) {", c="if (list.includes(x)) {"),
    r(id="js-indexof-gte-zero", title="indexOf(...) >= 0", desc="indexOf() >= 0 is a membership test.",
      rationale="includes() states the intent of a membership test more clearly.",
      remediation="Use includes(...).", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/includes",
      re=r"\.indexOf\s*\([^)]*\)\s*>=\s*0", nc="if (name.indexOf(prefix) >= 0) {", c="if (name.includes(prefix)) {"),
    r(id="js-web-tolocaleformat", type="bug", qual="rel", sev="medium", title="Date.toLocaleFormat()", desc="toLocaleFormat was removed.",
      rationale="Date.prototype.toLocaleFormat is a removed non-standard method.", remediation="Use toLocaleDateString / Intl.DateTimeFormat.",
      source=MDN, re=r"\.toLocaleFormat\s*\(", nc='d.toLocaleFormat("%Y-%m-%d");', c="d.toLocaleDateString();"),
    r(id="js-web-prefixed-slice", title="Vendor-prefixed Blob slice", desc="mozSlice/webkitSlice are obsolete.",
      rationale="The prefixed Blob.slice methods are obsolete.", remediation="Use blob.slice(...).",
      source=MDN, re=r"\.(moz|webkit)Slice\s*\(", nc="const part = blob.webkitSlice(0, 1024);", c="const part = blob.slice(0, 1024);"),
    r(id="js-web-getmatchedcssrules", type="bug", qual="rel", sev="medium", title="getMatchedCSSRules()", desc="getMatchedCSSRules was removed.",
      rationale="window.getMatchedCSSRules was removed from browsers.", remediation="Use getComputedStyle or inspect stylesheets.",
      source=MDN, re=r"\.getMatchedCSSRules\s*\(", nc="const rules = getMatchedCSSRules(el);", c="const style = getComputedStyle(el);"),
    r(id="js-web-create-touch", type="bug", qual="rel", sev="medium", title="document.createTouch()", desc="createTouch was removed.",
      rationale="document.createTouch is a removed legacy touch API.", remediation="Use the Touch constructor.",
      source=MDN, re=r"\.createTouch\s*\(", nc="const t = document.createTouch(view, target, 1, 0, 0, 0, 0);", c="const t = new Touch({ identifier: 1, target });"),
    r(id="js-web-create-touchlist", type="bug", qual="rel", sev="medium", title="document.createTouchList()", desc="createTouchList was removed.",
      rationale="document.createTouchList is a removed legacy touch API.", remediation="Use a TouchList via the Touch constructor.",
      source=MDN, re=r"\.createTouchList\s*\(", nc="const l = document.createTouchList(t1, t2);", c="const l = [t1, t2];"),
]
