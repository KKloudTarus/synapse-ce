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


# JS/TS quality pack: deprecated/removed jQuery utilities (native equivalents exist).
RULES = [
    r(id="js-jquery-andself", type="bug", qual="rel", sev="medium", title="jQuery .andSelf()", desc="andSelf was removed in jQuery 3.",
      rationale="andSelf was renamed addBack in jQuery 1.8 and removed in 3.0.", remediation="Use .addBack().",
      source="https://api.jquery.com/addBack/", re=r"\.andSelf\s*\(", nc="$(el).nextAll().andSelf();", c="$(el).nextAll().addBack();"),
    r(id="js-jquery-browser", type="bug", qual="rel", sev="medium", title="jQuery.browser", desc="$.browser was removed in jQuery 1.9.",
      rationale="$.browser (UA sniffing) was removed; use feature detection.", remediation="Use feature detection.",
      source="https://api.jquery.com/jQuery.browser/", re=r"\$\.browser\b", nc="if ($.browser.msie) {", c="if ('IntersectionObserver' in window) {"),
    r(id="js-jquery-trim", title="jQuery.trim()", desc="$.trim is redundant with String.prototype.trim.",
      rationale="Native String.trim covers all supported environments.", remediation="Use str.trim().",
      source="https://api.jquery.com/jQuery.trim/", re=r"\$\.trim\s*\(", nc="const s = $.trim(input);", c="const s = input.trim();"),
    r(id="js-jquery-isarray", title="jQuery.isArray()", desc="$.isArray is deprecated.",
      rationale="$.isArray is deprecated in favor of Array.isArray.", remediation="Use Array.isArray(x).",
      source="https://api.jquery.com/jQuery.isArray/", re=r"\$\.isArray\s*\(", nc="if ($.isArray(x)) {", c="if (Array.isArray(x)) {"),
    r(id="js-jquery-isfunction", title="jQuery.isFunction()", desc="$.isFunction is deprecated.",
      rationale="$.isFunction is deprecated; use typeof.", remediation='Use typeof x === "function".',
      source="https://api.jquery.com/jQuery.isFunction/", re=r"\$\.isFunction\s*\(", nc="if ($.isFunction(cb)) {", c='if (typeof cb === "function") {'),
    r(id="js-jquery-isnumeric", title="jQuery.isNumeric()", desc="$.isNumeric is deprecated.",
      rationale="$.isNumeric is deprecated; use Number.isFinite or explicit parsing.", remediation="Use Number.isFinite(Number(x)).",
      source="https://api.jquery.com/jQuery.isNumeric/", re=r"\$\.isNumeric\s*\(", nc="if ($.isNumeric(x)) {", c="if (Number.isFinite(Number(x))) {"),
    r(id="js-jquery-type", title="jQuery.type()", desc="$.type is deprecated.",
      rationale="$.type is deprecated; use typeof or Array.isArray.", remediation="Use typeof / Array.isArray.",
      source="https://api.jquery.com/jQuery.type/", re=r"\$\.type\s*\(", nc="const t = $.type(value);", c="const t = typeof value;"),
    r(id="js-jquery-now", title="jQuery.now()", desc="$.now is redundant with Date.now.",
      rationale="$.now is just Date.now.", remediation="Use Date.now().",
      source="https://api.jquery.com/jQuery.now/", re=r"\$\.now\s*\(", nc="const t = $.now();", c="const t = Date.now();"),
    r(id="js-jquery-parsejson", title="jQuery.parseJSON()", desc="$.parseJSON is deprecated.",
      rationale="$.parseJSON is deprecated in favor of the native JSON.parse.", remediation="Use JSON.parse(str).",
      source="https://api.jquery.com/jQuery.parseJSON/", re=r"\$\.parseJSON\s*\(", nc="const o = $.parseJSON(text);", c="const o = JSON.parse(text);"),
    r(id="js-jquery-ajax-sync", type="hotspot", qual="sec", sev="low", cwe="", owasp="", title="Synchronous jQuery ajax", desc="async: false blocks the main thread.",
      rationale="Synchronous XHR freezes the UI and is deprecated on the main thread.", remediation="Use an asynchronous request (promise/async).",
      source="https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/open", re=r"\$\.ajax\s*\([^)]*async\s*:\s*false",
      nc='$.ajax({ url: u, async: false });', c="$.ajax({ url: u });"),
]
