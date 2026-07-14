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


MDN = "https://developer.mozilla.org/en-US/docs/Web/API/Navigator"

# JS/TS quality pack: deprecated navigator properties + vendor-prefixed DOM APIs.
RULES = [
    r(id="js-nav-appname", title="navigator.appName", desc="navigator.appName is deprecated.",
      rationale="navigator.appName returns a constant legacy value and is deprecated.", remediation="Use feature detection instead of the app name.",
      source=MDN, re=r"\bnavigator\.appName\b", nc="const n = navigator.appName;", c="const ok = 'fetch' in window;"),
    r(id="js-nav-appversion", title="navigator.appVersion", desc="navigator.appVersion is deprecated.",
      rationale="navigator.appVersion is an unreliable UA string and is deprecated.", remediation="Use feature detection or userAgentData.",
      source=MDN, re=r"\bnavigator\.appVersion\b", nc="const v = navigator.appVersion;", c="const v = navigator.userAgentData;"),
    r(id="js-nav-platform", title="navigator.platform", desc="navigator.platform is deprecated.",
      rationale="navigator.platform is deprecated and unreliable for detecting the OS.", remediation="Use navigator.userAgentData.platform (with a fallback).",
      source=MDN, re=r"\bnavigator\.platform\b", nc="const p = navigator.platform;", c="const p = navigator.userAgentData?.platform;"),
    r(id="js-nav-product", title="navigator.product", desc="navigator.product is deprecated.",
      rationale="navigator.product always returns 'Gecko' and is deprecated.", remediation="Do not rely on navigator.product.",
      source=MDN, re=r"\bnavigator\.product\b", nc="const p = navigator.product;", c="const supported = 'IntersectionObserver' in window;"),
    r(id="js-nav-vendor", title="navigator.vendor", desc="navigator.vendor is deprecated.",
      rationale="navigator.vendor is deprecated and returns near-constant values.", remediation="Use feature detection.",
      source=MDN, re=r"\bnavigator\.vendor\b", nc="const v = navigator.vendor;", c="const v = navigator.userAgentData;"),
    r(id="js-web-prefixed-hidden", title="Vendor-prefixed document.hidden", desc="Prefixed hidden is obsolete.",
      rationale="webkit/moz/ms Hidden prefixes are obsolete.", remediation="Use document.hidden.",
      source="https://developer.mozilla.org/en-US/docs/Web/API/Document/hidden", re=r"\b(webkit|moz|ms)Hidden\b",
      nc="if (document.webkitHidden) pause();", c="if (document.hidden) pause();"),
    r(id="js-web-prefixed-visibility-state", title="Vendor-prefixed visibilityState", desc="Prefixed visibilityState is obsolete.",
      rationale="webkit/moz/ms VisibilityState prefixes are obsolete.", remediation="Use document.visibilityState.",
      source="https://developer.mozilla.org/en-US/docs/Web/API/Document/visibilityState", re=r"\b(webkit|moz|ms)VisibilityState\b",
      nc='if (document.webkitVisibilityState === "visible") {', c='if (document.visibilityState === "visible") {'),
    r(id="js-web-prefixed-cancel-fullscreen", title="Vendor-prefixed cancelFullScreen", desc="Prefixed exit-fullscreen is obsolete.",
      rationale="webkitCancelFullScreen and friends are obsolete.", remediation="Use document.exitFullscreen().",
      source="https://developer.mozilla.org/en-US/docs/Web/API/Document/exitFullscreen", re=r"\b(webkit|moz|ms)CancelFullScreen\b",
      nc="document.webkitCancelFullScreen();", c="document.exitFullscreen();"),
    r(id="js-web-prefixed-fullscreen-element", title="Vendor-prefixed fullscreenElement", desc="Prefixed fullscreenElement is obsolete.",
      rationale="webkitFullscreenElement and friends are obsolete.", remediation="Use document.fullscreenElement.",
      source="https://developer.mozilla.org/en-US/docs/Web/API/Document/fullscreenElement", re=r"\b(webkit|moz|ms)FullscreenElement\b",
      nc="if (document.webkitFullscreenElement) {", c="if (document.fullscreenElement) {"),
]
