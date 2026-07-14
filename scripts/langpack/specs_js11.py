CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# JS/TS security pack, fourth batch: CORS reflect-origin, AngularJS trustAsHtml, sensitive
# sessionStorage, innerHTML append sink.
RULES = [
    r(id="js-cors-reflect-origin", type="hotspot", qual="sec", sev="medium", cwe="CWE-942", owasp="A05:2021",
      title="CORS reflects any origin", desc="origin: true in the cors middleware echoes back the request Origin.",
      rationale="Reflecting any origin with credentials effectively allows all sites cross-origin access.",
      remediation="Pass an explicit origin string or an allowlist function.",
      source="https://cwe.mitre.org/data/definitions/942.html",
      re=r"\borigin\s*:\s*true\b", nc="app.use(cors({ origin: true }));", c='app.use(cors({ origin: "https://app.example.com" }));'),
    r(id="js-angular-trust-as-html", type="hotspot", qual="sec", sev="medium", cwe="CWE-79", owasp="A03:2021",
      title="AngularJS trustAsHtml", desc="$sce.trustAsHtml marks a string as safe HTML, bypassing sanitization.",
      rationale="Trusting untrusted HTML disables AngularJS's contextual escaping, causing XSS.",
      remediation="Sanitize with $sanitize, or bind as text.",
      source="https://cwe.mitre.org/data/definitions/79.html",
      re=r"trustAsHtml\s*\(", nc="$scope.html = $sce.trustAsHtml(userHtml);", c="$scope.html = $sanitize(userHtml);"),
    r(id="js-sessionstorage-sensitive", type="hotspot", qual="sec", sev="medium", cwe="CWE-522", owasp="A05:2021",
      title="Sensitive data in sessionStorage", desc="Storing tokens/secrets in sessionStorage exposes them to any script (XSS).",
      rationale="Web storage is readable by any JavaScript on the origin, so a token there is XSS-exfiltratable.",
      remediation="Keep session tokens in HttpOnly cookies, not web storage.",
      source="https://cwe.mitre.org/data/definitions/522.html",
      re=r'''sessionStorage\.setItem\s*\(\s*["'](token|password|secret|jwt|apiKey|api_key)''',
      nc='sessionStorage.setItem("token", jwt);', c='sessionStorage.setItem("theme", "dark");'),
    r(id="js-inner-html-append", type="hotspot", qual="sec", sev="medium", cwe="CWE-79", owasp="A03:2021",
      title="Append to innerHTML", desc="innerHTML += renders markup and is a DOM-XSS sink.",
      rationale="Appending untrusted data to innerHTML injects and executes attacker markup.",
      remediation="Append text with textContent, or sanitize the HTML first.",
      source="https://cwe.mitre.org/data/definitions/79.html",
      re=r"\.innerHTML\s*\+=", nc="el.innerHTML += userInput;", c="el.textContent += userInput;"),
]
