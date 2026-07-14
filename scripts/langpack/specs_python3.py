CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python security pack, third batch: process execution, weak crypto, TLS, Django/Flask sinks.
RULES = [
    r(id="python-flask-bind-all", type="hotspot", qual="sec", sev="low", cwe="CWE-668", owasp="A05:2021",
      title="Flask bound to all interfaces", desc='host="0.0.0.0" exposes the dev server on every network interface.',
      rationale="Binding to 0.0.0.0 makes the app reachable beyond localhost, often unintentionally.",
      remediation="Bind to 127.0.0.1 for local use, or front the app with a hardened server.",
      source="https://cwe.mitre.org/data/definitions/668.html",
      re=r'\.run\s*\([^)]*host\s*=\s*["\']0\.0\.0\.0', nc='app.run(host="0.0.0.0", port=5000)', c='app.run(host="127.0.0.1")'),
    r(id="python-hashlib-new-md5", type="hotspot", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="MD5 via hashlib.new", desc='hashlib.new("md5") selects the broken MD5 algorithm.',
      rationale="Requesting md5 through hashlib.new is unfit for security use.",
      remediation='Use hashlib.new("sha256") or hashlib.sha256.',
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'hashlib\.new\s*\(\s*["\']md5', nc='h = hashlib.new("md5")', c='h = hashlib.new("sha256")'),
    r(id="python-os-exec-family", type="hotspot", qual="sec", sev="medium", cwe="CWE-78", owasp="A03:2021",
      title="os.exec* process replacement", desc="os.execv/execl replace the process with a command.",
      rationale="The os.exec* family runs an external program; untrusted arguments risk command injection.",
      remediation="Validate arguments and prefer subprocess with an explicit argument list.",
      source="https://cwe.mitre.org/data/definitions/78.html",
      re=r"\bos\.exec[lv][pe]*\s*\(", nc="os.execv(path, args)", c="subprocess.run(args, shell=False)"),
    r(id="python-pty-spawn", type="hotspot", qual="sec", sev="medium", cwe="CWE-78", owasp="A03:2021",
      title="pty.spawn command execution", desc="pty.spawn launches a program in a pseudo-terminal.",
      rationale="pty.spawn on an untrusted command is a command-execution vector often seen in shells/backdoors.",
      remediation="Avoid pty.spawn for untrusted input; use subprocess with a fixed argument list.",
      source="https://cwe.mitre.org/data/definitions/78.html",
      re=r"\bpty\.spawn\s*\(", nc='pty.spawn("/bin/sh")', c='subprocess.run(["/bin/sh", "-c", script])'),
    r(id="python-django-extra", type="hotspot", qual="sec", sev="medium", cwe="CWE-89", owasp="A03:2021",
      title="Django QuerySet.extra()", desc="QuerySet.extra() injects raw SQL fragments into the query.",
      rationale="Building .extra() clauses from input is a classic Django SQL-injection path.",
      remediation="Use ORM filters, or pass parameters via the params argument.",
      source="https://cwe.mitre.org/data/definitions/89.html",
      re=r"\.extra\s*\(", nc="qs = User.objects.extra(where=[clause])", c="qs = User.objects.filter(active=True)"),
    r(id="python-ssl-wrap-socket", type="hotspot", qual="sec", sev="medium", cwe="CWE-295", owasp="A07:2021",
      title="Deprecated ssl.wrap_socket", desc="ssl.wrap_socket does not verify certificates or hostnames by default.",
      rationale="The module-level ssl.wrap_socket skips verification and SNI, enabling MITM.",
      remediation="Use ssl.create_default_context().wrap_socket(sock, server_hostname=host).",
      source="https://cwe.mitre.org/data/definitions/295.html",
      re=r"ssl\.wrap_socket\s*\(", nc="s = ssl.wrap_socket(sock)", c="s = ctx.wrap_socket(sock, server_hostname=host)"),
    r(id="python-crypto-des3", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="Triple DES cipher (PyCryptodome)", desc="DES3 (3DES) is deprecated and offers weak effective security.",
      rationale="Triple DES is deprecated by NIST; use AES.",
      remediation="Use AES (e.g. AES.new(key, AES.MODE_GCM)).",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r"\bDES3\.new\s*\(", nc="cipher = DES3.new(key, DES3.MODE_CBC)", c="cipher = AES.new(key, AES.MODE_GCM)"),
    r(id="python-jwt-algorithms-none", type="hotspot", qual="sec", sev="high", cwe="CWE-347", owasp="A02:2021",
      title="JWT 'none' algorithm accepted", desc='algorithms=["none"] accepts unsigned JWTs.',
      rationale="Permitting the none algorithm lets an attacker forge tokens with no signature.",
      remediation="Pin a real algorithm list (e.g. [\"HS256\"]) and never include none.",
      source="https://cwe.mitre.org/data/definitions/347.html",
      re=r'algorithms\s*=\s*\[\s*["\']none', nc='payload = jwt.decode(token, key, algorithms=["none"])',
      c='payload = jwt.decode(token, key, algorithms=["HS256"])'),
]
