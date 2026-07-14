CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: expression-language / deserialization RCE + Android WebView/storage/SQL sinks.
RULES = [
    r(id="java-mvel-eval", type="hotspot", qual="sec", sev="high", cwe="CWE-94", owasp="A03:2021",
      title="MVEL expression evaluation", desc="MVEL.eval runs an expression that may be attacker-controlled.",
      rationale="Evaluating an MVEL expression from input allows expression-language injection and RCE.",
      remediation="Do not evaluate MVEL from untrusted input.", source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"\bMVEL\.eval\s*\(", nc="Object r = MVEL.eval(expr, context);", c="Object r = COMPILED.getValue(context);"),
    r(id="java-velocity-evaluate", type="hotspot", qual="sec", sev="high", cwe="CWE-94", owasp="A03:2021",
      title="Velocity.evaluate with input", desc="Velocity.evaluate renders a template that may be attacker-controlled.",
      rationale="Rendering an attacker-controlled Velocity template enables SSTI/RCE.",
      remediation="Use a fixed template resource; never evaluate input as a template.", source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"\bVelocity\.evaluate\s*\(", nc='Velocity.evaluate(ctx, writer, "tag", userTemplate);', c="template.merge(ctx, writer);"),
    r(id="java-hessian-input", type="hotspot", qual="sec", sev="medium", cwe="CWE-502", owasp="A08:2021",
      title="Hessian deserialization", desc="HessianInput.readObject can instantiate arbitrary types.",
      rationale="Hessian deserialization of untrusted data is a known RCE vector.",
      remediation="Avoid Hessian for untrusted data, or apply a type allowlist.", source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"new\s+HessianInput\s*\(", nc="Object o = new HessianInput(in).readObject();", c="Object o = safeMapper.readValue(in, Dto.class);"),
    r(id="java-android-webview-js", type="hotspot", qual="sec", sev="medium", cwe="CWE-79", owasp="A03:2021",
      title="WebView JavaScript enabled", desc="setJavaScriptEnabled(true) allows script execution in the WebView.",
      rationale="Enabling JavaScript in a WebView that loads untrusted content exposes XSS/RCE surface.",
      remediation="Leave JavaScript disabled, or only enable it for trusted content.", source="https://cwe.mitre.org/data/definitions/79.html",
      re=r"setJavaScriptEnabled\s*\(\s*true\s*\)", nc="webView.getSettings().setJavaScriptEnabled(true);", c="webView.getSettings().setJavaScriptEnabled(false);"),
    r(id="java-android-webview-file-access", type="hotspot", qual="sec", sev="medium", cwe="CWE-200", owasp="A01:2021",
      title="WebView file access enabled", desc="setAllowFileAccess(true) lets the WebView read local files.",
      rationale="Allowing file access in a WebView can expose local files to loaded content.",
      remediation="Disable file access unless strictly required.", source="https://cwe.mitre.org/data/definitions/200.html",
      re=r"setAllowFileAccess\s*\(\s*true\s*\)", nc="settings.setAllowFileAccess(true);", c="settings.setAllowFileAccess(false);"),
    r(id="java-android-js-interface", type="hotspot", qual="sec", sev="high", cwe="CWE-749", owasp="A03:2021",
      title="WebView addJavascriptInterface", desc="addJavascriptInterface exposes Java methods to page JavaScript.",
      rationale="An exposed JS interface on untrusted content can be abused to invoke app code.",
      remediation="Only add interfaces for trusted content; annotate methods with @JavascriptInterface and minimize surface.", source="https://cwe.mitre.org/data/definitions/749.html",
      re=r"addJavascriptInterface\s*\(", nc='webView.addJavascriptInterface(bridge, "Android");', c="// avoid JS interfaces on untrusted content"),
    r(id="java-android-world-readable", type="hotspot", qual="sec", sev="medium", cwe="CWE-732", owasp="A01:2021",
      title="MODE_WORLD_READABLE", desc="World-readable files are visible to other apps.",
      rationale="MODE_WORLD_READABLE exposes app files to any other app (deprecated and unsafe).",
      remediation="Use MODE_PRIVATE and a content provider for sharing.", source="https://cwe.mitre.org/data/definitions/732.html",
      re=r"\bMODE_WORLD_READABLE\b", nc='openFileOutput("d", MODE_WORLD_READABLE);', c='openFileOutput("d", MODE_PRIVATE);'),
    r(id="java-android-world-writeable", type="hotspot", qual="sec", sev="high", cwe="CWE-732", owasp="A01:2021",
      title="MODE_WORLD_WRITEABLE", desc="World-writable files can be tampered with by other apps.",
      rationale="MODE_WORLD_WRITEABLE lets any other app modify the file (deprecated and unsafe).",
      remediation="Use MODE_PRIVATE.", source="https://cwe.mitre.org/data/definitions/732.html",
      re=r"\bMODE_WORLD_WRITEABLE\b", nc='openFileOutput("d", MODE_WORLD_WRITEABLE);', c='openFileOutput("d", MODE_PRIVATE);'),
    r(id="java-android-rawquery-concat", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="SQLite rawQuery concatenation", desc="rawQuery with a concatenated string enables SQL injection.",
      rationale="An Android SQLite query built with + from input is injectable.",
      remediation="Use ? placeholders and the selectionArgs parameter.", source="https://cwe.mitre.org/data/definitions/89.html",
      re=r'rawQuery\s*\(\s*"[^"]*"\s*\+', nc='db.rawQuery("SELECT * FROM u WHERE id=" + id, null);', c='db.rawQuery("SELECT * FROM u WHERE id=?", new String[]{id});'),
]
