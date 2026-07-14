CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python security pack, batch 8: Django cookie/HSTS hardening, sqlite executescript.
RULES = [
    r(id="python-django-session-httponly-off", type="hotspot", qual="sec", sev="medium", cwe="CWE-1004", owasp="A05:2021",
      title="Django session cookie not HttpOnly", desc="SESSION_COOKIE_HTTPONLY = False exposes the cookie to scripts.",
      rationale="A non-HttpOnly session cookie can be read by JavaScript, aiding token theft via XSS.",
      remediation="Set SESSION_COOKIE_HTTPONLY = True.",
      source="https://cwe.mitre.org/data/definitions/1004.html",
      re=r"SESSION_COOKIE_HTTPONLY\s*=\s*False\b", nc="SESSION_COOKIE_HTTPONLY = False", c="SESSION_COOKIE_HTTPONLY = True"),
    r(id="python-django-hsts-zero", type="hotspot", qual="sec", sev="medium", cwe="CWE-319", owasp="A05:2021",
      title="Django HSTS disabled", desc="SECURE_HSTS_SECONDS = 0 disables HTTP Strict Transport Security.",
      rationale="Without HSTS, browsers may connect over plaintext HTTP and be downgraded.",
      remediation="Set SECURE_HSTS_SECONDS to a positive value (e.g. 31536000) once HTTPS is stable.",
      source="https://cwe.mitre.org/data/definitions/319.html",
      re=r"SECURE_HSTS_SECONDS\s*=\s*0\b", nc="SECURE_HSTS_SECONDS = 0", c="SECURE_HSTS_SECONDS = 31536000"),
    r(id="python-sqlite-executescript", type="hotspot", qual="sec", sev="medium", cwe="CWE-89", owasp="A03:2021",
      title="sqlite executescript", desc="executescript runs a whole SQL script and cannot be parameterized.",
      rationale="Building an executescript body from input allows SQL injection with no parameter binding.",
      remediation="Use execute() with parameters, one statement at a time.",
      source="https://cwe.mitre.org/data/definitions/89.html",
      re=r"\.executescript\s*\(", nc="cur.executescript(user_sql)", c="cur.execute(sql, params)"),
]
