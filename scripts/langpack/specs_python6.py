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
    r(id="python-yaml-unsafe-loader", type="vuln", qual="sec", sev="high", cwe="CWE-502", owasp="A08:2021",
      title="Unsafe YAML loader", desc="yaml.Loader / yaml.UnsafeLoader construct arbitrary Python objects.",
      rationale="These loaders honor YAML tags that instantiate arbitrary types, enabling code execution.",
      remediation="Use yaml.SafeLoader (or yaml.safe_load) for untrusted input.",
      source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"yaml\.(Loader|UnsafeLoader)\b", nc="data = yaml.load(text, Loader=yaml.UnsafeLoader)",
      c="data = yaml.load(text, Loader=yaml.SafeLoader)"),
]
