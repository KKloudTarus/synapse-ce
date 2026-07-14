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

# JS/TS quality pack: more deprecated/removed web-platform + RxJS APIs.
RULES = [
    r(id="js-web-to-gmt-string", title="Date.toGMTString()", desc="toGMTString is deprecated.",
      rationale="toGMTString is deprecated in favor of toUTCString.", remediation="Use toUTCString().",
      source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/toGMTString",
      re=r"\.toGMTString\s*\(", nc="const s = d.toGMTString();", c="const s = d.toUTCString();"),
    r(id="js-web-capture-events", type="bug", qual="rel", sev="medium", title="window.captureEvents()", desc="captureEvents was removed.",
      rationale="captureEvents is a removed legacy event API.", remediation="Use addEventListener.",
      source=MDN, re=r"\.captureEvents\s*\(", nc="window.captureEvents(Event.CLICK);", c='el.addEventListener("click", fn);'),
    r(id="js-web-release-events", type="bug", qual="rel", sev="medium", title="window.releaseEvents()", desc="releaseEvents was removed.",
      rationale="releaseEvents is a removed legacy event API.", remediation="Use removeEventListener.",
      source=MDN, re=r"\.releaseEvents\s*\(", nc="window.releaseEvents(Event.CLICK);", c='el.removeEventListener("click", fn);'),
    r(id="js-web-navigator-getusermedia", title="navigator.getUserMedia()", desc="The callback getUserMedia is deprecated.",
      rationale="navigator.getUserMedia is deprecated in favor of the promise-based mediaDevices.getUserMedia.",
      remediation="Use navigator.mediaDevices.getUserMedia(...).", source=MDN, re=r"navigator\.getUserMedia\s*\(",
      nc="navigator.getUserMedia(constraints, ok, err);", c="navigator.mediaDevices.getUserMedia(constraints);"),
    r(id="js-web-prefixed-fullscreen", title="Vendor-prefixed requestFullscreen", desc="Prefixed fullscreen APIs are obsolete.",
      rationale="webkit/moz/ms requestFullscreen prefixes are obsolete.", remediation="Use element.requestFullscreen().",
      source=MDN, re=r"\b(webkit|moz|ms)RequestFullscreen\b", nc="el.webkitRequestFullscreen();", c="el.requestFullscreen();"),
    r(id="js-web-document-charset", title="document.charset", desc="document.charset is deprecated.",
      rationale="document.charset is deprecated in favor of document.characterSet.", remediation="Use document.characterSet.",
      source=MDN, re=r"\bdocument\.charset\b", nc="const cs = document.charset;", c="const cs = document.characterSet;"),
    r(id="js-web-create-attribute", title="document.createAttribute()", desc="createAttribute is a legacy attribute API.",
      rationale="createAttribute/attribute nodes are legacy; use setAttribute.", remediation="Use element.setAttribute(name, value).",
      source=MDN, re=r"\.createAttribute\s*\(", nc='const a = document.createAttribute("data-id");', c='el.setAttribute("data-id", id);'),
    r(id="js-web-get-attribute-node", title="getAttributeNode()", desc="getAttributeNode is a legacy attribute API.",
      rationale="Attribute nodes are legacy; use getAttribute.", remediation="Use element.getAttribute(name).",
      source=MDN, re=r"\.getAttributeNode\s*\(", nc='const a = el.getAttributeNode("id");', c='const a = el.getAttribute("id");'),
    r(id="js-web-set-attribute-node", title="setAttributeNode()", desc="setAttributeNode is a legacy attribute API.",
      rationale="Attribute nodes are legacy; use setAttribute.", remediation="Use element.setAttribute(name, value).",
      source=MDN, re=r"\.setAttributeNode\s*\(", nc="el.setAttributeNode(attr);", c='el.setAttribute("id", value);'),
    r(id="js-rxjs-observable-frompromise", title="Observable.fromPromise()", desc="Observable.fromPromise was removed.",
      rationale="RxJS removed the static Observable.fromPromise in favor of the from creation function.",
      remediation="Use from(promise).", source="https://rxjs.dev/deprecations/breaking-changes",
      re=r"\bObservable\.fromPromise\s*\(", nc="Observable.fromPromise(fetchData());", c="from(fetchData());"),
]
