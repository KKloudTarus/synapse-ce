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

# JS/TS quality pack: constant/always-* bug idioms + deprecated event/window APIs.
RULES = [
    r(id="js-double-await", type="bug", qual="rel", sev="medium", title="Double await", desc="await await is redundant.",
      rationale="Awaiting an already-awaited value adds a needless microtask and reads as a typo.",
      remediation="Await once.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/await",
      re=r"\bawait\s+await\b", nc="const data = await await fetchJson();", c="const data = await fetchJson();"),
    r(id="js-typeof-typeof", type="bug", qual="rel", sev="medium", title="typeof typeof", desc="typeof typeof x is always \"string\".",
      rationale="typeof always yields a string, so a nested typeof is a mistake.",
      remediation="Remove the extra typeof.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/typeof",
      re=r"\btypeof\s+typeof\b", nc='if (typeof typeof x === "string") {', c='if (typeof x === "number") {'),
    r(id="js-length-lt-zero", type="bug", qual="rel", sev="medium", title="length < 0", desc="A length is never negative.",
      rationale="A .length comparison to < 0 is always false, so the branch is dead.",
      remediation="Compare with === 0 for empty.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/length",
      re=r"\.length\s*<\s*0", nc="if (items.length < 0) {", c="if (items.length === 0) {"),
    r(id="js-length-gte-zero", type="bug", qual="rel", sev="medium", title="length >= 0", desc="A length is always >= 0.",
      rationale="A .length comparison to >= 0 is always true, so the guard does nothing.",
      remediation="Compare with > 0 for non-empty.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/length",
      re=r"\.length\s*>=\s*0", nc="if (items.length >= 0) {", c="if (items.length > 0) {"),
    r(id="js-triple-negation", title="Triple negation", desc="!!! is a confusing way to negate.",
      rationale="Three logical-not operators equal a single not; write it once.",
      remediation="Use a single ! (or Boolean() to coerce).", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Logical_NOT",
      re=r"!!!", nc="if (!!!ready) {", c="if (!ready) {"),
    r(id="js-web-event-layerxy", title="event.layerX / layerY", desc="layerX/layerY are non-standard and deprecated.",
      rationale="event.layerX/layerY are non-standard; use offsetX/offsetY.", remediation="Use offsetX / offsetY.",
      source=MDN, re=r"\bevent\.layer[XY]\b", nc="const x = event.layerX;", c="const x = event.offsetX;"),
    r(id="js-web-key-identifier", type="bug", qual="rel", sev="medium", title="event.keyIdentifier", desc="keyIdentifier was removed.",
      rationale="KeyboardEvent.keyIdentifier is a removed non-standard property.", remediation="Use event.key.",
      source=MDN, re=r"\.keyIdentifier\b", nc="const k = event.keyIdentifier;", c="const k = event.key;"),
    r(id="js-web-char-code", title="event.charCode", desc="charCode is deprecated.",
      rationale="KeyboardEvent.charCode is deprecated in favor of key.", remediation="Use event.key.",
      source=MDN, re=r"\.charCode\b", nc="const c = event.charCode;", c="const c = event.key;"),
    r(id="js-web-window-orientation", title="window.orientation", desc="window.orientation is deprecated.",
      rationale="window.orientation is deprecated in favor of the Screen Orientation API.", remediation="Use screen.orientation.",
      source=MDN, re=r"\bwindow\.orientation\b", nc="if (window.orientation === 90) {", c="if (screen.orientation.angle === 90) {"),
    r(id="js-web-scroll-into-view-if-needed", title="scrollIntoViewIfNeeded()", desc="scrollIntoViewIfNeeded is non-standard.",
      rationale="Element.scrollIntoViewIfNeeded is non-standard (WebKit-only).", remediation="Use scrollIntoView(options).",
      source=MDN, re=r"\.scrollIntoViewIfNeeded\s*\(", nc="el.scrollIntoViewIfNeeded();", c='el.scrollIntoView({ block: "nearest" });'),
]
