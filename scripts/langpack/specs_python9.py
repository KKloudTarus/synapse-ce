CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


RULES = [
    r(id="python-flask-cors-wildcard", type="hotspot", qual="sec", sev="medium", cwe="CWE-942", owasp="A05:2021",
      title="Wildcard CORS (flask-cors)", desc='origins="*" allows any site to make cross-origin requests.',
      rationale="A wildcard origin lets any website read authenticated cross-origin responses.",
      remediation="Pass an explicit list of allowed origins.",
      source="https://cwe.mitre.org/data/definitions/942.html",
      re=r'''origins\s*=\s*["']\*["']''', nc='CORS(app, origins="*")', c='CORS(app, origins=["https://app.example.com"])'),
]
