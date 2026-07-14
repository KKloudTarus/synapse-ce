CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python security pack, fourth batch: TLS trust, process spawn, weak RSA key size.
RULES = [
    r(id="python-ssl-cert-none", type="vuln", qual="sec", sev="high", cwe="CWE-295", owasp="A07:2021",
      title="TLS certificate validation off (CERT_NONE)", desc="ssl.CERT_NONE disables certificate verification.",
      rationale="Setting verify_mode to CERT_NONE accepts any certificate, enabling MITM.",
      remediation="Use ssl.CERT_REQUIRED (the default for create_default_context).",
      source="https://cwe.mitre.org/data/definitions/295.html",
      re=r"ssl\.CERT_NONE\b", nc="context.verify_mode = ssl.CERT_NONE", c="context.verify_mode = ssl.CERT_REQUIRED"),
    r(id="python-os-spawn", type="hotspot", qual="sec", sev="medium", cwe="CWE-78", owasp="A03:2021",
      title="os.spawn* process launch", desc="os.spawnv/spawnl launch an external program.",
      rationale="The os.spawn* family runs an external command; untrusted arguments risk command injection.",
      remediation="Validate arguments and prefer subprocess with an explicit argument list.",
      source="https://cwe.mitre.org/data/definitions/78.html",
      re=r"\bos\.spawn[lv]", nc="os.spawnv(os.P_WAIT, path, args)", c="subprocess.run(args, shell=False)"),
    r(id="python-rsa-key-size-weak", type="hotspot", qual="sec", sev="medium", cwe="CWE-326", owasp="A02:2021",
      title="Weak RSA key size", desc="key_size of 512 or 1024 bits is too small for RSA.",
      rationale="RSA keys below 2048 bits are considered weak and are being deprecated.",
      remediation="Generate at least a 2048-bit RSA key (3072+ preferred).",
      source="https://cwe.mitre.org/data/definitions/326.html",
      re=r"key_size\s*=\s*(512|1024)\b", nc="rsa.generate_private_key(public_exponent=65537, key_size=1024)",
      c="rsa.generate_private_key(public_exponent=65537, key_size=2048)"),
]
