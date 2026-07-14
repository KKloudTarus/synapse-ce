CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python security pack, second batch: Django/Flask config, SQL string-building, archive extraction,
# more crypto and TLS sinks. Bandit-family, precise dotted-call/keyword anchors, clean-room prose.
RULES = [
    r(id="python-tar-zip-extractall", type="hotspot", qual="sec", sev="medium", cwe="CWE-22", owasp="A01:2021",
      title="Archive extractall without validation", desc="extractall can write outside the target directory (path traversal / zip-slip).",
      rationale="A crafted archive entry (../ or absolute path) can overwrite arbitrary files.",
      remediation="Validate each member path before extracting, or use a vetted safe-extract helper.",
      source="https://cwe.mitre.org/data/definitions/22.html",
      re=r"\.extractall\s*\(", nc="tar.extractall(dest)", c="safe_extract(tar, dest)"),
    r(id="python-crypto-mode-ecb", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="ECB cipher mode", desc="MODE_ECB leaks plaintext structure because equal blocks encrypt equally.",
      rationale="ECB uses no IV, so patterns in plaintext survive into ciphertext.",
      remediation="Use an authenticated mode such as GCM.",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r"\bMODE_ECB\b", nc="cipher = AES.new(key, AES.MODE_ECB)", c="cipher = AES.new(key, AES.MODE_GCM, nonce)"),
    r(id="python-django-csrf-exempt", type="hotspot", qual="sec", sev="medium", cwe="CWE-352", owasp="A01:2021",
      title="Django csrf_exempt", desc="@csrf_exempt disables CSRF protection for the view.",
      rationale="Exempting a state-changing view from CSRF lets a third-party site forge requests.",
      remediation="Remove csrf_exempt, or protect the endpoint another way (e.g. token auth).",
      source="https://cwe.mitre.org/data/definitions/352.html",
      re=r"@csrf_exempt\b", nc="@csrf_exempt", c="@login_required"),
    r(id="python-subprocess-getoutput", type="hotspot", qual="sec", sev="medium", cwe="CWE-78", owasp="A03:2021",
      title="subprocess.getoutput runs a shell", desc="subprocess.getoutput executes its command through the shell.",
      rationale="getoutput/getstatusoutput invoke the shell, enabling command injection.",
      remediation="Use subprocess.run([...], shell=False) with an argument list.",
      source="https://cwe.mitre.org/data/definitions/78.html",
      re=r"subprocess\.getoutput\s*\(", nc="out = subprocess.getoutput(cmd)", c="out = subprocess.run(args, capture_output=True).stdout"),
    r(id="python-django-allowed-hosts-wildcard", type="hotspot", qual="sec", sev="medium", cwe="CWE-346", owasp="A05:2021",
      title="Wildcard ALLOWED_HOSTS", desc="ALLOWED_HOSTS = [\"*\"] accepts any Host header.",
      rationale="A wildcard host allowlist enables Host-header poisoning (cache, password-reset links).",
      remediation="List the exact hostnames the site serves.",
      source="https://cwe.mitre.org/data/definitions/346.html",
      re=r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*", nc='ALLOWED_HOSTS = ["*"]', c='ALLOWED_HOSTS = ["example.com"]'),
    r(id="python-cors-allow-all", type="hotspot", qual="sec", sev="medium", cwe="CWE-942", owasp="A05:2021",
      title="Wildcard CORS (django-cors-headers)", desc="CORS_ORIGIN_ALLOW_ALL = True allows every origin.",
      rationale="Allowing all origins lets any site read authenticated cross-origin responses.",
      remediation="Set an explicit allowlist via CORS_ALLOWED_ORIGINS.",
      source="https://cwe.mitre.org/data/definitions/942.html",
      re=r"CORS_ORIGIN_ALLOW_ALL\s*=\s*True\b", nc="CORS_ORIGIN_ALLOW_ALL = True", c="CORS_ORIGIN_ALLOW_ALL = False"),
    r(id="python-sql-fstring-execute", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="SQL query built with an f-string", desc="Passing an f-string to execute() interpolates values into SQL (injection).",
      rationale="An f-string embeds untrusted values directly into the SQL text.",
      remediation="Use parameterized queries: execute(sql, params).",
      source="https://cwe.mitre.org/data/definitions/89.html",
      re=r"\.execute\s*\(\s*f[\"']", nc='cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
      c='cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))'),
    r(id="python-sql-percent-execute", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="SQL query built with % formatting", desc="String % formatting inside execute() interpolates values into SQL.",
      rationale="The % operator on the SQL string embeds untrusted values, enabling injection.",
      remediation="Use parameterized queries: execute(sql, params).",
      source="https://cwe.mitre.org/data/definitions/89.html",
      re=r"\.execute\s*\(\s*[\"'][^\"']*[\"']\s*%", nc="cursor.execute(\"SELECT * FROM t WHERE id = '%s'\" % uid)",
      c='cursor.execute("SELECT * FROM t WHERE id = %s", (uid,))'),
    r(id="python-ssl-check-hostname-false", type="vuln", qual="sec", sev="high", cwe="CWE-295", owasp="A07:2021",
      title="TLS hostname check disabled", desc="check_hostname = False stops verifying the certificate hostname.",
      rationale="Disabling the hostname check lets any valid certificate impersonate the host (MITM).",
      remediation="Leave check_hostname = True (the default for create_default_context).",
      source="https://cwe.mitre.org/data/definitions/295.html",
      re=r"check_hostname\s*=\s*False\b", nc="ctx.check_hostname = False", c="ctx.check_hostname = True"),
    r(id="python-crypto-blowfish", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="Blowfish cipher (PyCryptodome)", desc="Blowfish's 64-bit block is vulnerable to birthday attacks on bulk data.",
      rationale="Blowfish's small block size makes it unsuitable for modern encryption; use AES.",
      remediation="Use AES (128-bit block) instead of Blowfish.",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r"\bBlowfish\.new\s*\(", nc="cipher = Blowfish.new(key, Blowfish.MODE_CBC)", c="cipher = AES.new(key, AES.MODE_GCM)"),
]
