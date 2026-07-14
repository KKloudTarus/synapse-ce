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

# JS/TS quality pack: more removed/deprecated Node + DOM APIs.
RULES = [
    r(id="js-node-mainmodule", title="process.mainModule", desc="process.mainModule is deprecated.",
      rationale="process.mainModule is deprecated in favor of require.main.", remediation="Use require.main.",
      source="https://nodejs.org/api/process.html", re=r"\bprocess\.mainModule\b", nc="const entry = process.mainModule;", c="const entry = require.main;"),
    r(id="js-node-allocunsafeslow", type="hotspot", qual="sec", sev="medium", cwe="CWE-665", owasp="A05:2021",
      tags=["sast", "javascript", "security"], title="Buffer.allocUnsafeSlow()", desc="allocUnsafeSlow returns uninitialized memory.",
      rationale="allocUnsafeSlow may expose stale memory contents.", remediation="Use Buffer.alloc unless every byte is overwritten.",
      source="https://cwe.mitre.org/data/definitions/665.html", re=r"Buffer\.allocUnsafeSlow\s*\(", nc="const b = Buffer.allocUnsafeSlow(128);", c="const b = Buffer.alloc(128);"),
    r(id="js-node-process-assert", type="bug", qual="rel", sev="medium", title="process.assert()", desc="process.assert was removed.",
      rationale="process.assert was deprecated and removed.", remediation="Use the assert module.",
      source="https://nodejs.org/api/process.html", re=r"\bprocess\.assert\s*\(", nc='process.assert(ok, "must be ok");', c='assert(ok, "must be ok");'),
    r(id="js-array-observe", type="bug", qual="rel", sev="medium", title="Array.observe()", desc="Array.observe was removed.",
      rationale="Array.observe was removed from the language.", remediation="Use a Proxy.",
      source=MDN, re=r"\bArray\.observe\s*\(", nc="Array.observe(list, onChange);", c="const list = new Proxy(target, handler);"),
    r(id="js-object-getnotifier", type="bug", qual="rel", sev="medium", title="Object.getNotifier()", desc="Object.getNotifier was removed.",
      rationale="Object.getNotifier (Object.observe machinery) was removed.", remediation="Use a Proxy.",
      source=MDN, re=r"\bObject\.getNotifier\s*\(", nc="const n = Object.getNotifier(obj);", c="const obj = new Proxy(target, handler);"),
    r(id="js-object-unobserve", type="bug", qual="rel", sev="medium", title="Object.unobserve()", desc="Object.unobserve was removed.",
      rationale="Object.unobserve (Object.observe machinery) was removed.", remediation="Use a Proxy.",
      source=MDN, re=r"\bObject\.unobserve\s*\(", nc="Object.unobserve(obj, cb);", c="// use a Proxy instead of observe"),
    r(id="js-css-getpropertycssvalue", title="getPropertyCSSValue()", desc="getPropertyCSSValue was removed.",
      rationale="CSSStyleDeclaration.getPropertyCSSValue was removed.", remediation="Use getPropertyValue().",
      source=MDN, re=r"\.getPropertyCSSValue\s*\(", nc='style.getPropertyCSSValue("width");', c='style.getPropertyValue("width");'),
    r(id="js-dom-create-entity-reference", type="bug", qual="rel", sev="medium", title="createEntityReference()", desc="createEntityReference was removed.",
      rationale="document.createEntityReference was removed from the DOM.", remediation="Do not use entity-reference nodes.",
      source=MDN, re=r"\.createEntityReference\s*\(", nc='document.createEntityReference("amp");', c='// entity reference nodes are removed'),
    r(id="js-dom-init-mouse-event", title="initMouseEvent()", desc="initMouseEvent is deprecated.",
      rationale="initMouseEvent is deprecated in favor of the MouseEvent constructor.", remediation="Use new MouseEvent(type, options).",
      source=MDN, re=r"\.initMouseEvent\s*\(", nc='e.initMouseEvent("click", true, true, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);', c='const e = new MouseEvent("click", { bubbles: true });'),
    r(id="js-dom-init-keyboard-event", title="initKeyboardEvent()", desc="initKeyboardEvent is deprecated.",
      rationale="initKeyboardEvent is deprecated in favor of the KeyboardEvent constructor.", remediation="Use new KeyboardEvent(type, options).",
      source=MDN, re=r"\.initKeyboardEvent\s*\(", nc='e.initKeyboardEvent("keydown", true, true, window, "a", 0, "", false, "");', c='const e = new KeyboardEvent("keydown", { key: "a" });'),
    r(id="js-dom-init-custom-event", title="initCustomEvent()", desc="initCustomEvent is deprecated.",
      rationale="initCustomEvent is deprecated in favor of the CustomEvent constructor.", remediation="Use new CustomEvent(type, { detail }).",
      source=MDN, re=r"\.initCustomEvent\s*\(", nc='e.initCustomEvent("build", true, true, data);', c='const e = new CustomEvent("build", { detail: data });'),
]
