CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


RULES = [
    r(id="js-cors-header-wildcard", type="hotspot", qual="sec", sev="medium", cwe="CWE-942", owasp="A05:2021",
      title="Wildcard CORS header", desc="Setting Access-Control-Allow-Origin to * allows any site.",
      rationale="A wildcard ACAO header lets any origin read the response, defeating the same-origin policy.",
      remediation="Echo a validated allowlisted origin instead of \"*\".",
      source="https://cwe.mitre.org/data/definitions/942.html",
      re=r'''Access-Control-Allow-Origin["']\s*,\s*["']\*["']''', nc='res.setHeader("Access-Control-Allow-Origin", "*");',
      c='res.setHeader("Access-Control-Allow-Origin", allowedOrigin);'),
    r(id="js-exec-template-literal", type="hotspot", qual="sec", sev="high", cwe="CWE-78", owasp="A03:2021",
      title="Shell exec with an interpolated string", desc="child_process.exec with a template literal risks command injection.",
      rationale="A template literal passed to exec interpolates values into a shell command, enabling injection.",
      remediation="Use execFile/spawn with an argument array, not a shell string.",
      source="https://cwe.mitre.org/data/definitions/78.html",
      re=r"\bexec(Sync)?\s*\(\s*`", nc="exec(`rm -rf ${dir}`);", c='execFile("rm", ["-rf", dir]);'),
]
