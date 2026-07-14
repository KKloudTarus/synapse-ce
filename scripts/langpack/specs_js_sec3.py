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
    r(id="js-helmet-csp-disabled", type="hotspot", qual="sec", sev="medium", cwe="CWE-1021", owasp="A05:2021",
      title="Helmet CSP disabled", desc="contentSecurityPolicy: false turns off the Content-Security-Policy header.",
      rationale="Disabling CSP removes a key XSS/clickjacking mitigation.",
      remediation="Configure a Content Security Policy instead of disabling it.",
      source="https://cwe.mitre.org/data/definitions/1021.html",
      re=r"contentSecurityPolicy\s*:\s*false", nc="app.use(helmet({ contentSecurityPolicy: false }));",
      c="app.use(helmet({ contentSecurityPolicy: { directives } }));"),
    r(id="js-libxml-noent", type="hotspot", qual="sec", sev="medium", cwe="CWE-611", owasp="A05:2021",
      title="libxmljs entity substitution", desc="noent: true enables external entity substitution (XXE).",
      rationale="Enabling entity substitution on untrusted XML allows XXE attacks.",
      remediation="Leave noent disabled (the default) for untrusted XML.",
      source="https://cwe.mitre.org/data/definitions/611.html",
      re=r"\bnoent\s*:\s*true", nc="libxmljs.parseXml(xml, { noent: true });", c="libxmljs.parseXml(xml, { noent: false });"),
    r(id="js-vm-run-in-context", type="hotspot", qual="sec", sev="high", cwe="CWE-94", owasp="A03:2021",
      title="vm.runIn*Context()", desc="The vm module does not provide a security sandbox.",
      rationale="Running untrusted code with vm.runInNewContext can escape the sandbox and execute arbitrary code.",
      remediation="Do not run untrusted code; use a real isolate (e.g. a separate process/worker with limits).",
      source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"\bvm\.runIn\w*Context\s*\(", nc="vm.runInNewContext(userCode);", c="await runInWorker(userCode);"),
    r(id="js-lodash-chain", type="smell", qual="maint", sev="low", cwe="", owasp="",
      tags=["sast", "javascript"], title="lodash chain()", desc="_.chain pulls in the whole lodash library and is hard to tree-shake.",
      rationale="Explicit lodash calls (or native array methods) tree-shake better than _.chain sequences.",
      remediation="Use discrete lodash calls or native array methods.",
      source="https://lodash.com/docs/#chain", re=r"_\.chain\s*\(",
      nc="const r = _.chain(users).map(fn).value();", c="const r = users.map(fn);"),
]
