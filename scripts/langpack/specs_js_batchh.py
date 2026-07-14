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

# JS/TS quality pack: deprecated DOM mutation events, legacy RegExp statics, removed language extras.
RULES = [
    r(id="js-dom-mutation-events", type="bug", qual="rel", sev="medium", title="DOM mutation events", desc="DOMNodeInserted and friends are deprecated.",
      rationale="The synchronous DOM mutation events are deprecated and slow; use MutationObserver.", remediation="Use a MutationObserver.",
      source=MDN, re=r"\bDOM(NodeInserted|NodeRemoved|SubtreeModified|AttrModified|CharacterDataModified)\b",
      nc='el.addEventListener("DOMNodeInserted", onInsert);', c="new MutationObserver(onMutate).observe(el, { childList: true });"),
    r(id="js-dom-user-data", type="bug", qual="rel", sev="medium", title="getUserData / setUserData", desc="Node userData APIs were removed.",
      rationale="Node.getUserData/setUserData (DOM Level 3) were removed.", remediation="Use a WeakMap keyed by the node.",
      source=MDN, re=r"\.(getUserData|setUserData)\s*\(", nc='node.setUserData("meta", data, null);', c="nodeMeta.set(node, data);"),
    r(id="js-dom-is-same-node", title="isSameNode()", desc="isSameNode is redundant with ===.",
      rationale="Node.isSameNode is equivalent to the === identity check.", remediation="Use === to compare nodes.",
      source=MDN, re=r"\.isSameNode\s*\(", nc="if (a.isSameNode(b)) {", c="if (a === b) {"),
    r(id="js-dom-has-feature", title="implementation.hasFeature()", desc="hasFeature is deprecated and always returns true.",
      rationale="DOMImplementation.hasFeature is deprecated and unreliable.", remediation="Feature-detect the specific API you need.",
      source=MDN, re=r"\.hasFeature\s*\(", nc='document.implementation.hasFeature("Core", "2.0");', c='const ok = "querySelector" in document;'),
    r(id="js-dom-xml-encoding", type="bug", qual="rel", sev="medium", title="document.xmlEncoding", desc="document.xmlEncoding was removed.",
      rationale="document.xmlEncoding was removed from the DOM.", remediation="Read the encoding from the document's headers/prolog if needed.",
      source=MDN, re=r"\bdocument\.xmlEncoding\b", nc="const enc = document.xmlEncoding;", c="const enc = document.characterSet;"),
    r(id="js-dom-xml-version", type="bug", qual="rel", sev="medium", title="document.xmlVersion", desc="document.xmlVersion was removed.",
      rationale="document.xmlVersion was removed from the DOM.", remediation="Do not rely on document.xmlVersion.",
      source=MDN, re=r"\bdocument\.xmlVersion\b", nc="const v = document.xmlVersion;", c='const v = "1.0";'),
    r(id="js-dom-xml-standalone", type="bug", qual="rel", sev="medium", title="document.xmlStandalone", desc="document.xmlStandalone was removed.",
      rationale="document.xmlStandalone was removed from the DOM.", remediation="Do not rely on document.xmlStandalone.",
      source=MDN, re=r"\bdocument\.xmlStandalone\b", nc="const s = document.xmlStandalone;", c="const s = false;"),
    r(id="js-regexp-dollar", title="RegExp.$1 static", desc="RegExp.$1..$9 legacy statics are deprecated.",
      rationale="The RegExp.$n statics are deprecated and not thread/async-safe.", remediation="Use the match result array.",
      source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/n", re=r"\bRegExp\.\$[1-9]\b",
      nc="const g = RegExp.$1;", c="const g = match[1];"),
    r(id="js-regexp-context", title="RegExp.lastMatch / leftContext", desc="Legacy RegExp static context properties are deprecated.",
      rationale="RegExp.lastMatch/leftContext/rightContext/input are deprecated legacy statics.", remediation="Use the match result.",
      source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp", re=r"\bRegExp\.(leftContext|rightContext|lastMatch|lastParen|input)\b",
      nc="const before = RegExp.leftContext;", c="const before = input.slice(0, match.index);"),
    r(id="js-to-source", type="bug", qual="rel", sev="medium", title="toSource()", desc="toSource is a removed non-standard method.",
      rationale="Object.prototype.toSource was non-standard and is removed.", remediation="Use JSON.stringify for serialization.",
      source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/toSource", re=r"\.toSource\s*\(",
      nc="const s = config.toSource();", c="const s = JSON.stringify(config);"),
    r(id="js-uneval", type="bug", qual="rel", sev="medium", title="uneval()", desc="uneval is a removed non-standard function.",
      rationale="The global uneval was non-standard and is removed.", remediation="Use JSON.stringify.",
      source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/uneval", re=r"\buneval\s*\(",
      nc="const s = uneval(state);", c="const s = JSON.stringify(state);"),
]
