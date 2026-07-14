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


# JS/TS quality pack: legacy/deprecated JavaScript language and DOM APIs.
RULES = [
    r(id="js-arguments-callee", type="bug", qual="rel", sev="medium", title="arguments.callee",
      desc="arguments.callee is forbidden in strict mode.", rationale="arguments.callee throws in strict mode and blocks optimization.",
      remediation="Use a named function expression instead.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions/arguments/callee",
      re=r"\barguments\.callee\b", nc="setTimeout(arguments.callee, 100);", c="setTimeout(function tick() { /* ... */ }, 100);"),
    r(id="js-arguments-caller", type="bug", qual="rel", sev="medium", title="arguments.caller",
      desc="arguments.caller is deprecated and forbidden in strict mode.", rationale="arguments.caller is removed/forbidden and unreliable.",
      remediation="Restructure so the caller is passed explicitly.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions/arguments",
      re=r"\barguments\.caller\b", nc="const c = arguments.caller;", c="const c = explicitCaller;"),
    r(id="js-date-getyear", title="Date.getYear()", desc="getYear is deprecated (returns year minus 1900).",
      rationale="getYear is deprecated and error-prone; getFullYear returns the four-digit year.",
      remediation="Use getFullYear().", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/getYear",
      re=r"\.getYear\s*\(", nc="const y = d.getYear();", c="const y = d.getFullYear();"),
    r(id="js-date-setyear", title="Date.setYear()", desc="setYear is deprecated.",
      rationale="setYear is deprecated; setFullYear is the standard method.",
      remediation="Use setFullYear().", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/setYear",
      re=r"\.setYear\s*\(", nc="d.setYear(99);", c="d.setFullYear(1999);"),
    r(id="js-string-html-methods", title="Deprecated String HTML methods", desc="String.bold()/italics()/etc are deprecated.",
      rationale="These HTML-wrapper string methods are deprecated and produce invalid markup.",
      remediation="Build markup explicitly or with a template.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String#html_wrapper_methods",
      re=r"\.(blink|bold|italics|strike|fontcolor|fontsize)\s*\(", nc="const s = title.bold();", c="const s = `<b>${title}</b>`;"),
    r(id="js-object-observe", type="bug", qual="rel", sev="medium", title="Object.observe()",
      desc="Object.observe was removed from browsers.", rationale="Object.observe raises TypeError; it was removed from the language.",
      remediation="Use a Proxy or explicit setters.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/observe",
      re=r"Object\.observe\s*\(", nc="Object.observe(model, onChange);", c="const model = new Proxy(target, handler);"),
    r(id="js-define-getter-setter", title="__defineGetter__ / __defineSetter__", desc="These legacy accessors are deprecated.",
      rationale="__defineGetter__/__defineSetter__ are deprecated in favor of Object.defineProperty / get-set syntax.",
      remediation="Use Object.defineProperty or a get/set accessor.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/__defineGetter__",
      re=r"\.__define(Getter|Setter)__\s*\(", nc='obj.__defineGetter__("x", fn);', c='Object.defineProperty(obj, "x", { get: fn });'),
    r(id="js-void-zero", title="void 0", desc="void 0 is an obscure way to write undefined.",
      rationale="undefined is now safe to reference and clearer than void 0.",
      remediation="Use undefined.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/void",
      re=r"\bvoid\s+0\b", nc="if (value === void 0) {", c="if (value === undefined) {"),
]
