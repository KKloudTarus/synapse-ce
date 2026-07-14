CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "bug")
    k.setdefault("qual", "rel")
    k.setdefault("sev", "medium")
    k.setdefault("cwe", "")
    return k


MDN = "https://developer.mozilla.org/en-US/docs/Web/API"

# JS/TS quality pack: removed legacy Internet Explorer DOM APIs (no-ops / errors in modern browsers).
RULES = [
    r(id="js-ie-create-event-object", title="createEventObject()", desc="createEventObject was an IE-only API.",
      rationale="document.createEventObject does not exist in standard browsers.", remediation="Use the Event constructor.",
      source=MDN, re=r"\.createEventObject\s*\(", nc="const e = document.createEventObject();", c='const e = new Event("click");'),
    r(id="js-ie-fire-event", title="fireEvent()", desc="fireEvent was an IE-only API.",
      rationale="element.fireEvent does not exist in standard browsers.", remediation="Use dispatchEvent(new Event(...)).",
      source=MDN, re=r"\.fireEvent\s*\(", nc='el.fireEvent("onclick");', c='el.dispatchEvent(new Event("click"));'),
    r(id="js-ie-set-capture", title="setCapture()", desc="setCapture was removed.",
      rationale="element.setCapture was a non-standard API and is removed.", remediation="Use setPointerCapture.",
      source=MDN, re=r"\.setCapture\s*\(", nc="el.setCapture();", c="el.setPointerCapture(e.pointerId);"),
    r(id="js-ie-release-capture", title="releaseCapture()", desc="releaseCapture was removed.",
      rationale="element.releaseCapture was a non-standard API and is removed.", remediation="Use releasePointerCapture.",
      source=MDN, re=r"\.releaseCapture\s*\(", nc="el.releaseCapture();", c="el.releasePointerCapture(e.pointerId);"),
    r(id="js-ie-select-nodes", title="selectNodes()", desc="selectNodes was an IE-only XML DOM API.",
      rationale="selectNodes does not exist in standard browsers.", remediation="Use querySelectorAll or an XPath evaluator.",
      source=MDN, re=r"\.selectNodes\s*\(", nc='const items = xml.selectNodes("//item");', c='const items = xml.querySelectorAll("item");'),
    r(id="js-ie-select-single-node", title="selectSingleNode()", desc="selectSingleNode was an IE-only XML DOM API.",
      rationale="selectSingleNode does not exist in standard browsers.", remediation="Use querySelector or an XPath evaluator.",
      source=MDN, re=r"\.selectSingleNode\s*\(", nc='const item = xml.selectSingleNode("//item");', c='const item = xml.querySelector("item");'),
    r(id="js-ie-get-box-object-for", title="getBoxObjectFor()", desc="getBoxObjectFor was removed.",
      rationale="document.getBoxObjectFor was a non-standard Gecko API and is removed.", remediation="Use getBoundingClientRect().",
      source=MDN, re=r"\.getBoxObjectFor\s*\(", nc="const box = document.getBoxObjectFor(el);", c="const box = el.getBoundingClientRect();"),
    r(id="js-ie-xdomainrequest", title="XDomainRequest", desc="XDomainRequest was an IE-only CORS object.",
      rationale="XDomainRequest does not exist outside old IE.", remediation="Use XMLHttpRequest or fetch with CORS.",
      source=MDN, re=r"\bXDomainRequest\b", nc="const req = new XDomainRequest();", c="const req = new XMLHttpRequest();"),
    r(id="js-ie-show-modeless-dialog", title="showModelessDialog()", desc="showModelessDialog was removed.",
      rationale="window.showModelessDialog was an IE-only API and is removed.", remediation="Use a modeless UI (window.open or an in-page panel).",
      source=MDN, re=r"\.showModelessDialog\s*\(", nc="window.showModelessDialog(url);", c="window.open(url);"),
    r(id="js-ie-do-scroll", title="doScroll()", desc="doScroll was an IE-only readiness hack.",
      rationale="element.doScroll was an IE-only API used for ready detection and is removed.", remediation="Use the DOMContentLoaded event.",
      source=MDN, re=r"\.doScroll\s*\(", nc='document.documentElement.doScroll("left");', c='document.addEventListener("DOMContentLoaded", init);'),
]
