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
    r(id="python-django-rawsql", type="hotspot", qual="sec", sev="medium", cwe="CWE-89", owasp="A03:2021",
      title="Django RawSQL", desc="RawSQL embeds a raw SQL fragment into the query.",
      rationale="Building a RawSQL expression from input is a SQL-injection path.",
      remediation="Use ORM expressions, or pass parameters to RawSQL.",
      source="https://cwe.mitre.org/data/definitions/89.html",
      re=r"\bRawSQL\s*\(", nc="qs = qs.annotate(v=RawSQL(sql, []))", c='qs = qs.annotate(v=F("field"))'),
    r(id="python-flask-wtf-csrf-disabled", type="hotspot", qual="sec", sev="medium", cwe="CWE-352", owasp="A05:2021",
      title="Flask-WTF CSRF disabled", desc="WTF_CSRF_ENABLED = False turns off CSRF protection.",
      rationale="Disabling CSRF lets a third-party site forge authenticated form submissions.",
      remediation="Leave WTF_CSRF_ENABLED = True.",
      source="https://cwe.mitre.org/data/definitions/352.html",
      re=r"WTF_CSRF_ENABLED\s*=\s*False\b", nc="WTF_CSRF_ENABLED = False", c="WTF_CSRF_ENABLED = True"),
]
