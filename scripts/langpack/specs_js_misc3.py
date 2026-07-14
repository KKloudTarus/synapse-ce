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


# JS/TS quality pack: testing hygiene + legacy argument/array idioms.
RULES = [
    r(id="js-mocha-timeout-zero", title="Disabled test timeout", desc="this.timeout(0) removes the test timeout entirely.",
      rationale="A zero timeout lets a hung test block the suite indefinitely.",
      remediation="Set a finite timeout appropriate for the test.", source="https://mochajs.org/#timeouts",
      re=r"\.timeout\s*\(\s*0\s*\)", nc="this.timeout(0);", c="this.timeout(5000);"),
    r(id="js-slice-call-arguments", title="slice.call(arguments)", desc="Copying arguments via slice.call is legacy.",
      rationale="Rest parameters or spread produce a real array more clearly.",
      remediation="Use a rest parameter (...args) or [...arguments].", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions/rest_parameters",
      re=r"Array\.prototype\.slice\.call\s*\(\s*arguments", nc="const args = Array.prototype.slice.call(arguments);", c="function f(...args) {}"),
    r(id="js-concat-apply-flatten", title="[].concat.apply for flattening", desc="concat.apply is an obscure way to flatten.",
      rationale="Array.prototype.flat flattens arrays clearly.",
      remediation="Use arrays.flat().", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/flat",
      re=r"\.concat\.apply\s*\(\s*\[\s*\]", nc="const flat = [].concat.apply([], rows);", c="const flat = rows.flat();"),
]
