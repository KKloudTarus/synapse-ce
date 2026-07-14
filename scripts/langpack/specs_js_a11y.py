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


# JS/TS quality pack: JSX accessibility (jsx-a11y) + a language-misuse bug.
RULES = [
    r(id="js-a11y-anchor-href-hash", title="Anchor with href=\"#\"", desc="An anchor to \"#\" is not a real link.",
      rationale="href=\"#\" scrolls to the top and misuses a link as a button (jsx-a11y anchor-is-valid).",
      remediation="Use a real href, or a <button> for actions.", source="https://github.com/jsx-eslint/eslint-plugin-jsx-a11y",
      re=r'''<a\s[^>]*href\s*=\s*["']#["']''', nc='<a href="#">Open</a>', c='<a href="/open">Open</a>'),
    r(id="js-a11y-no-autofocus", title="autoFocus attribute", desc="autoFocus disorients screen-reader and keyboard users.",
      rationale="Automatically moving focus on load harms accessibility (jsx-a11y no-autofocus).",
      remediation="Manage focus intentionally in response to user action.", source="https://github.com/jsx-eslint/eslint-plugin-jsx-a11y",
      re=r"\bauto[fF]ocus\b", nc="<input autoFocus />", c="<input ref={inputRef} />"),
    r(id="js-a11y-no-access-key", title="accessKey attribute", desc="accessKey conflicts with assistive-technology shortcuts.",
      rationale="Access keys clash with screen-reader and browser shortcuts (jsx-a11y no-access-key).",
      remediation="Remove accessKey.", source="https://github.com/jsx-eslint/eslint-plugin-jsx-a11y",
      re=r"\baccessKey\s*=", nc='<button accessKey="s">Save</button>', c="<button>Save</button>"),
    r(id="js-a11y-positive-tabindex", title="Positive tabIndex", desc="A positive tabIndex breaks the natural tab order.",
      rationale="Positive tabindex values force an unnatural focus order (jsx-a11y tabindex-no-positive).",
      remediation="Use tabIndex={0} or -1, and rely on DOM order.", source="https://github.com/jsx-eslint/eslint-plugin-jsx-a11y",
      re=r'''\btabIndex\s*=\s*["'{]?\s*[1-9]''', nc='<div tabIndex="3">', c='<div tabIndex="0">'),
    r(id="js-a11y-distracting-element", title="Distracting element (marquee/blink)", desc="marquee and blink are distracting and obsolete.",
      rationale="These elements are obsolete and cause accessibility problems (jsx-a11y no-distracting-elements).",
      remediation="Use CSS animations with prefers-reduced-motion support if motion is needed.", source="https://github.com/jsx-eslint/eslint-plugin-jsx-a11y",
      re=r"<(marquee|blink)\b", nc="<marquee>News</marquee>", c="<div className=\"ticker\">News</div>"),
    r(id="js-no-new-bigint", type="bug", qual="rel", sev="medium", title="new BigInt()",
      desc="BigInt is not a constructor.", rationale="new BigInt(...) throws TypeError; BigInt is called as a function.",
      remediation="Call BigInt(...) without new.", source="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt",
      re=r"new\s+BigInt\s*\(", nc="const n = new BigInt(5);", c="const n = BigInt(5);"),
]
