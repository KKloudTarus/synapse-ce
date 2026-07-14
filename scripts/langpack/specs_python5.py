CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python security pack, fifth batch: Django hardening flags, ML/data pickle deserialization, JWT.
RULES = [
    r(id="python-hashlib-new-sha1", type="hotspot", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="SHA-1 via hashlib.new", desc='hashlib.new("sha1") selects the deprecated SHA-1 algorithm.',
      rationale="Requesting sha1 through hashlib.new has practical collisions and is unfit for security.",
      remediation='Use hashlib.new("sha256") or hashlib.sha256.',
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'''hashlib\.new\s*\(\s*["']sha1''', nc='h = hashlib.new("sha1")', c='h = hashlib.new("sha256")'),
    r(id="python-django-ssl-redirect-off", type="hotspot", qual="sec", sev="medium", cwe="CWE-319", owasp="A05:2021",
      title="Django SECURE_SSL_REDIRECT disabled", desc="SECURE_SSL_REDIRECT = False allows plaintext HTTP.",
      rationale="Without an HTTPS redirect, requests can be served (and credentials sent) over plaintext HTTP.",
      remediation="Set SECURE_SSL_REDIRECT = True in production settings.",
      source="https://cwe.mitre.org/data/definitions/319.html",
      re=r"SECURE_SSL_REDIRECT\s*=\s*False\b", nc="SECURE_SSL_REDIRECT = False", c="SECURE_SSL_REDIRECT = True"),
    r(id="python-django-session-cookie-insecure", type="hotspot", qual="sec", sev="medium", cwe="CWE-614", owasp="A05:2021",
      title="Django session cookie not secure", desc="SESSION_COOKIE_SECURE = False sends the session cookie over HTTP.",
      rationale="A non-secure session cookie can travel over plaintext HTTP and be intercepted.",
      remediation="Set SESSION_COOKIE_SECURE = True.",
      source="https://cwe.mitre.org/data/definitions/614.html",
      re=r"SESSION_COOKIE_SECURE\s*=\s*False\b", nc="SESSION_COOKIE_SECURE = False", c="SESSION_COOKIE_SECURE = True"),
    r(id="python-django-csrf-cookie-insecure", type="hotspot", qual="sec", sev="medium", cwe="CWE-614", owasp="A05:2021",
      title="Django CSRF cookie not secure", desc="CSRF_COOKIE_SECURE = False sends the CSRF cookie over HTTP.",
      rationale="A non-secure CSRF cookie can be intercepted over plaintext HTTP.",
      remediation="Set CSRF_COOKIE_SECURE = True.",
      source="https://cwe.mitre.org/data/definitions/614.html",
      re=r"CSRF_COOKIE_SECURE\s*=\s*False\b", nc="CSRF_COOKIE_SECURE = False", c="CSRF_COOKIE_SECURE = True"),
    r(id="python-jwt-verify-signature-off", type="vuln", qual="sec", sev="high", cwe="CWE-347", owasp="A02:2021",
      title="JWT signature verification disabled (options)", desc='options={"verify_signature": False} accepts forged tokens.',
      rationale="Turning off verify_signature lets an attacker forge arbitrary JWT claims.",
      remediation="Verify with the expected key and algorithms; keep verify_signature on.",
      source="https://cwe.mitre.org/data/definitions/347.html",
      re=r'''verify_signature["']?\s*:\s*False''', nc='jwt.decode(token, options={"verify_signature": False})',
      c='jwt.decode(token, key, algorithms=["HS256"])'),
    r(id="python-pandas-read-pickle", type="hotspot", qual="sec", sev="medium", cwe="CWE-502", owasp="A08:2021",
      title="pandas read_pickle", desc="read_pickle deserializes with pickle and can execute arbitrary code.",
      rationale="pandas.read_pickle uses pickle under the hood; untrusted files can run code.",
      remediation="Load untrusted data from a safe format (CSV, Parquet).",
      source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"\bread_pickle\s*\(", nc="df = pd.read_pickle(path)", c="df = pd.read_parquet(path)"),
    r(id="python-numpy-allow-pickle", type="hotspot", qual="sec", sev="medium", cwe="CWE-502", owasp="A08:2021",
      title="numpy load allow_pickle=True", desc="allow_pickle=True lets numpy.load execute pickle from the file.",
      rationale="Enabling allow_pickle deserializes arbitrary objects, enabling code execution.",
      remediation="Keep allow_pickle=False (the default) for untrusted .npy/.npz files.",
      source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"allow_pickle\s*=\s*True\b", nc="data = np.load(path, allow_pickle=True)", c="data = np.load(path)"),
    r(id="python-torch-load", type="hotspot", qual="sec", sev="medium", cwe="CWE-502", owasp="A08:2021",
      title="torch.load of untrusted data", desc="torch.load uses pickle and can execute code from a crafted checkpoint.",
      rationale="PyTorch's default torch.load unpickles arbitrary objects, a known RCE vector.",
      remediation="Use weights_only=True (PyTorch 2.6+) or a safetensors loader for untrusted files.",
      source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"\btorch\.load\s*\(", nc="model = torch.load(path)", c="model = load_safetensors(path)"),
]
