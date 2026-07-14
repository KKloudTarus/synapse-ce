CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "py")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "python", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Python security pack, batch 7: SSTI, deserialization, XSS sinks.
RULES = [
    r(id="python-flask-render-template-string", type="vuln", qual="sec", sev="high", cwe="CWE-94", owasp="A03:2021",
      title="Flask render_template_string", desc="Rendering a template built from input allows server-side template injection.",
      rationale="render_template_string compiles its argument as a Jinja template; untrusted input yields SSTI/RCE.",
      remediation="Render a fixed template file and pass data as context variables.",
      source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"render_template_string\s*\(", nc="return render_template_string(user_template)", c='return render_template("page.html", data=data)'),
    r(id="python-django-safestring", type="hotspot", qual="sec", sev="medium", cwe="CWE-79", owasp="A03:2021",
      title="Django SafeString/SafeText", desc="Wrapping a value in SafeString marks it as trusted HTML, disabling escaping.",
      rationale="SafeString/SafeText tell the template engine not to escape, so untrusted content becomes XSS.",
      remediation="Escape the value, or use format_html with placeholders.",
      source="https://cwe.mitre.org/data/definitions/79.html",
      re=r"\b(SafeString|SafeText)\s*\(", nc="html = SafeString(user_input)", c="html = escape(user_input)"),
    r(id="python-jsonpickle-decode", type="hotspot", qual="sec", sev="medium", cwe="CWE-502", owasp="A08:2021",
      title="jsonpickle.decode", desc="jsonpickle.decode can instantiate arbitrary Python objects.",
      rationale="jsonpickle reconstructs arbitrary types from its input, enabling deserialization attacks.",
      remediation="Use json.loads for untrusted data, or restrict jsonpickle to safe types.",
      source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"jsonpickle\.decode\s*\(", nc="obj = jsonpickle.decode(payload)", c="obj = json.loads(payload)"),
    r(id="python-dill-load", type="hotspot", qual="sec", sev="medium", cwe="CWE-502", owasp="A08:2021",
      title="dill deserialization", desc="dill.load/loads deserializes with pickle semantics and can run code.",
      rationale="dill extends pickle, so loading untrusted data can execute arbitrary code.",
      remediation="Use a safe format such as JSON for untrusted data.",
      source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"\bdill\.loads?\s*\(", nc="obj = dill.loads(blob)", c="obj = json.loads(blob)"),
]
