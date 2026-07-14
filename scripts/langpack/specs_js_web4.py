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

# JS/TS quality pack: deprecated / removed and vendor-prefixed browser APIs.
RULES = [
    r(id="js-web-pagexoffset", title="window.pageXOffset", desc="pageXOffset is an alias for scrollX.",
      rationale="window.pageXOffset is a deprecated alias of scrollX.", remediation="Use window.scrollX.",
      source=MDN, re=r"\bwindow\.pageXOffset\b", nc="const x = window.pageXOffset;", c="const x = window.scrollX;"),
    r(id="js-web-pageyoffset", title="window.pageYOffset", desc="pageYOffset is an alias for scrollY.",
      rationale="window.pageYOffset is a deprecated alias of scrollY.", remediation="Use window.scrollY.",
      source=MDN, re=r"\bwindow\.pageYOffset\b", nc="const y = window.pageYOffset;", c="const y = window.scrollY;"),
    r(id="js-web-scroll-by-lines", type="bug", qual="rel", sev="medium", title="scrollByLines()", desc="scrollByLines is non-standard.",
      rationale="window.scrollByLines is a non-standard, removed method.", remediation="Use scrollBy with pixel offsets.",
      source=MDN, re=r"\.scrollByLines\s*\(", nc="window.scrollByLines(2);", c="window.scrollBy(0, 2 * lineHeight);"),
    r(id="js-web-scroll-by-pages", type="bug", qual="rel", sev="medium", title="scrollByPages()", desc="scrollByPages is non-standard.",
      rationale="window.scrollByPages is a non-standard, removed method.", remediation="Use scrollBy with pixel offsets.",
      source=MDN, re=r"\.scrollByPages\s*\(", nc="window.scrollByPages(1);", c="window.scrollBy(0, window.innerHeight);"),
    r(id="js-web-webkit-url", title="webkitURL", desc="webkitURL is a prefixed alias of URL.",
      rationale="webkitURL is a deprecated prefixed alias of the URL object.", remediation="Use the standard URL object.",
      source=MDN, re=r"\bwebkitURL\b", nc="const u = webkitURL.createObjectURL(blob);", c="const u = URL.createObjectURL(blob);"),
    r(id="js-web-webkit-storage-info", type="bug", qual="rel", sev="medium", title="webkitStorageInfo", desc="webkitStorageInfo was removed.",
      rationale="navigator.webkitStorageInfo was removed.", remediation="Use navigator.storage.estimate().",
      source=MDN, re=r"\bwebkitStorageInfo\b", nc="navigator.webkitStorageInfo.queryUsageAndQuota(t, ok);", c="const q = await navigator.storage.estimate();"),
    r(id="js-web-webkit-request-filesystem", type="bug", qual="rel", sev="medium", title="webkitRequestFileSystem", desc="webkitRequestFileSystem was removed.",
      rationale="window.webkitRequestFileSystem was removed.", remediation="Use the File System Access API.",
      source=MDN, re=r"\bwebkitRequestFileSystem\b", nc="window.webkitRequestFileSystem(TEMPORARY, size, ok);", c="const handle = await window.showSaveFilePicker();"),
    r(id="js-web-prefixed-getusermedia", title="Prefixed getUserMedia", desc="webkit/moz getUserMedia is deprecated.",
      rationale="The prefixed getUserMedia is deprecated in favor of mediaDevices.getUserMedia.", remediation="Use navigator.mediaDevices.getUserMedia.",
      source=MDN, re=r"\b(webkit|moz)GetUserMedia\b", nc="navigator.webkitGetUserMedia(c, ok, err);", c="navigator.mediaDevices.getUserMedia(c);"),
    r(id="js-web-moz-websocket", type="bug", qual="rel", sev="medium", title="MozWebSocket", desc="MozWebSocket was a prefixed WebSocket.",
      rationale="MozWebSocket was a temporary prefixed WebSocket and is removed.", remediation="Use WebSocket.",
      source=MDN, re=r"\bMozWebSocket\b", nc="const ws = new MozWebSocket(url);", c="const ws = new WebSocket(url);"),
    r(id="js-web-prefixed-indexeddb", title="Prefixed indexedDB", desc="webkit/moz/ms indexedDB prefixes are obsolete.",
      rationale="The prefixed IndexedDB objects are obsolete.", remediation="Use window.indexedDB.",
      source=MDN, re=r"\b(webkit|moz|ms)IndexedDB\b", nc="const db = window.webkitIndexedDB;", c="const db = window.indexedDB;"),
    r(id="js-web-webkit-audio-context", title="webkitAudioContext", desc="webkitAudioContext is a prefixed alias.",
      rationale="webkitAudioContext is a deprecated prefixed alias of AudioContext.", remediation="Use AudioContext.",
      source=MDN, re=r"\bwebkitAudioContext\b", nc="const ctx = new webkitAudioContext();", c="const ctx = new AudioContext();"),
    r(id="js-web-webkit-notifications", type="bug", qual="rel", sev="medium", title="webkitNotifications", desc="webkitNotifications was removed.",
      rationale="window.webkitNotifications was removed in favor of the Notification API.", remediation="Use the Notification API.",
      source=MDN, re=r"\bwebkitNotifications\b", nc="webkitNotifications.requestPermission();", c="Notification.requestPermission();"),
    r(id="js-web-create-shadow-root", type="bug", qual="rel", sev="medium", title="createShadowRoot()", desc="createShadowRoot (v0) was removed.",
      rationale="Element.createShadowRoot (Shadow DOM v0) was removed.", remediation="Use attachShadow({ mode }).",
      source=MDN, re=r"\.createShadowRoot\s*\(", nc="const root = host.createShadowRoot();", c='const root = host.attachShadow({ mode: "open" });'),
    r(id="js-web-application-cache", type="bug", qual="rel", sev="medium", title="applicationCache", desc="AppCache was removed.",
      rationale="window.applicationCache (AppCache) was removed from browsers.", remediation="Use a Service Worker.",
      source=MDN, re=r"\bapplicationCache\b", nc="window.applicationCache.update();", c='navigator.serviceWorker.register("/sw.js");'),
    r(id="js-web-register-content-handler", type="bug", qual="rel", sev="medium", title="registerContentHandler()", desc="registerContentHandler was removed.",
      rationale="navigator.registerContentHandler was removed.", remediation="This capability was removed; no direct replacement.",
      source=MDN, re=r"\.registerContentHandler\s*\(", nc='navigator.registerContentHandler(type, url, title);', c="// registerContentHandler was removed"),
]
