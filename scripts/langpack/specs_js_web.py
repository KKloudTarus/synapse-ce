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

# JS/TS quality pack: deprecated / removed web-platform (DOM/BOM) APIs.
RULES = [
    r(id="js-web-document-all", title="document.all", desc="document.all is a deprecated legacy collection.",
      rationale="document.all is a non-standard legacy feature kept only for compatibility.", remediation="Use getElementById/querySelector.",
      source=MDN, re=r"\bdocument\.all\b", nc="const el = document.all[0];", c='const el = document.querySelector("#first");'),
    r(id="js-web-execcommand", title="document.execCommand()", desc="execCommand is deprecated.",
      rationale="execCommand is deprecated and unreliable across browsers.", remediation="Use the Clipboard API or specific DOM APIs.",
      source=MDN, re=r"\.execCommand\s*\(", nc='document.execCommand("copy");', c="navigator.clipboard.writeText(text);"),
    r(id="js-web-window-event", title="Global window.event", desc="The global window.event is deprecated.",
      rationale="Relying on the global event object is deprecated; use the handler's event argument.", remediation="Accept the event as a parameter.",
      source=MDN, re=r"\bwindow\.event\b", nc="const target = window.event.target;", c="function onClick(event) { const target = event.target; }"),
    r(id="js-web-create-event", title="document.createEvent()", desc="createEvent is deprecated.",
      rationale="document.createEvent is deprecated in favor of the Event constructors.", remediation="Use new Event(...) / new CustomEvent(...).",
      source=MDN, re=r"\.createEvent\s*\(", nc='const e = document.createEvent("Event");', c='const e = new Event("build");'),
    r(id="js-web-init-event", title="Event.initEvent()", desc="initEvent is deprecated.",
      rationale="initEvent is deprecated alongside createEvent.", remediation="Pass options to the Event constructor.",
      source=MDN, re=r"\.initEvent\s*\(", nc='e.initEvent("click", true, true);', c='new Event("click", { bubbles: true, cancelable: true });'),
    r(id="js-web-prefixed-raf", title="Vendor-prefixed requestAnimationFrame", desc="Prefixed rAF is obsolete.",
      rationale="webkit/moz/ms requestAnimationFrame prefixes are obsolete.", remediation="Use requestAnimationFrame.",
      source=MDN, re=r"\b(webkit|moz|ms|o)RequestAnimationFrame\b", nc="webkitRequestAnimationFrame(draw);", c="requestAnimationFrame(draw);"),
    r(id="js-web-get-prevent-default", title="Event.getPreventDefault()", desc="getPreventDefault is deprecated.",
      rationale="getPreventDefault is deprecated in favor of the defaultPrevented property.", remediation="Use event.defaultPrevented.",
      source=MDN, re=r"\.getPreventDefault\s*\(", nc="if (e.getPreventDefault()) {", c="if (e.defaultPrevented) {"),
    r(id="js-web-attach-event", type="bug", qual="rel", sev="medium", title="attachEvent()", desc="attachEvent is an IE-only removed API.",
      rationale="attachEvent was removed; standard browsers use addEventListener.", remediation="Use addEventListener.",
      source=MDN, re=r"\.attachEvent\s*\(", nc='el.attachEvent("onclick", handler);', c='el.addEventListener("click", handler);'),
    r(id="js-web-detach-event", type="bug", qual="rel", sev="medium", title="detachEvent()", desc="detachEvent is an IE-only removed API.",
      rationale="detachEvent was removed; standard browsers use removeEventListener.", remediation="Use removeEventListener.",
      source=MDN, re=r"\.detachEvent\s*\(", nc='el.detachEvent("onclick", handler);', c='el.removeEventListener("click", handler);'),
    r(id="js-web-show-modal-dialog", type="bug", qual="rel", sev="medium", title="window.showModalDialog()", desc="showModalDialog was removed.",
      rationale="window.showModalDialog was removed from browsers.", remediation="Use a <dialog> element or window.open.",
      source=MDN, re=r"\.showModalDialog\s*\(", nc="window.showModalDialog(url);", c="dialog.showModal();"),
    r(id="js-web-prefixed-matches", title="Vendor-prefixed matchesSelector", desc="Prefixed matchesSelector is obsolete.",
      rationale="webkit/moz matchesSelector prefixes are obsolete.", remediation="Use element.matches(selector).",
      source=MDN, re=r"\b(webkit|moz|ms|o)MatchesSelector\b", nc='el.webkitMatchesSelector(".active");', c='el.matches(".active");'),
    r(id="js-web-register-element", type="bug", qual="rel", sev="medium", title="document.registerElement()", desc="registerElement was removed.",
      rationale="document.registerElement (v0 custom elements) was removed.", remediation="Use customElements.define(...).",
      source=MDN, re=r"\.registerElement\s*\(", nc='document.registerElement("my-el", proto);', c='customElements.define("my-el", MyEl);'),
    r(id="js-for-empty-init-while", title="for(;cond;) instead of while", desc="A for loop with only a condition is a while loop.",
      rationale="An empty init and update make a for loop a disguised while (sonarjs prefer-while).",
      remediation="Use a while loop.", source="https://github.com/SonarSource/eslint-plugin-sonarjs",
      re=r"for\s*\(\s*;[^;]+;\s*\)", nc="for (; i < n;) { step(); }", c="while (i < n) { step(); }"),
]
