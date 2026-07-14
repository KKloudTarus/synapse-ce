CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: more Android WebView / storage hardening sinks.
RULES = [
    r(id="java-android-mixed-content", type="hotspot", qual="sec", sev="medium", cwe="CWE-319", owasp="A05:2021",
      title="WebView allows mixed content", desc="MIXED_CONTENT_ALWAYS_ALLOW loads HTTP content on HTTPS pages.",
      rationale="Allowing mixed content lets plaintext HTTP resources load into a secure page.",
      remediation="Use MIXED_CONTENT_NEVER_ALLOW.", source="https://cwe.mitre.org/data/definitions/319.html",
      re=r"MIXED_CONTENT_ALWAYS_ALLOW", nc="settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);", c="settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);"),
    r(id="java-android-universal-file-access", type="hotspot", qual="sec", sev="high", cwe="CWE-200", owasp="A01:2021",
      title="WebView universal file access", desc="setAllowUniversalAccessFromFileURLs(true) lets file:// pages read any origin.",
      rationale="Universal access from file URLs enables cross-origin reads and local file exfiltration.",
      remediation="Leave universal file access disabled.", source="https://cwe.mitre.org/data/definitions/200.html",
      re=r"setAllowUniversalAccessFromFileURLs\s*\(\s*true", nc="settings.setAllowUniversalAccessFromFileURLs(true);", c="settings.setAllowUniversalAccessFromFileURLs(false);"),
    r(id="java-android-file-access-from-file", type="hotspot", qual="sec", sev="medium", cwe="CWE-200", owasp="A01:2021",
      title="WebView file access from file URLs", desc="setAllowFileAccessFromFileURLs(true) lets file:// pages read other files.",
      rationale="Allowing file access from file URLs enables local file disclosure.",
      remediation="Leave this disabled.", source="https://cwe.mitre.org/data/definitions/200.html",
      re=r"setAllowFileAccessFromFileURLs\s*\(\s*true", nc="settings.setAllowFileAccessFromFileURLs(true);", c="settings.setAllowFileAccessFromFileURLs(false);"),
    r(id="java-android-external-storage", type="hotspot", qual="sec", sev="low", cwe="CWE-312", owasp="A04:2021",
      title="Writing to external storage", desc="External storage is world-readable and not sandboxed.",
      rationale="Files on external storage are accessible to other apps and users; sensitive data should stay in app-private storage.",
      remediation="Use context.getFilesDir() / app-private storage.", source="https://cwe.mitre.org/data/definitions/312.html",
      re=r"getExternalStorageDirectory\s*\(", nc="File dir = Environment.getExternalStorageDirectory();", c="File dir = context.getFilesDir();"),
    r(id="java-android-webview-debugging", type="hotspot", qual="sec", sev="medium", cwe="CWE-489", owasp="A05:2021",
      title="WebView contents debugging enabled", desc="setWebContentsDebuggingEnabled(true) exposes the WebView to remote debugging.",
      rationale="Leaving WebView debugging on in production exposes app internals.",
      remediation="Gate it behind BuildConfig.DEBUG.", source="https://cwe.mitre.org/data/definitions/489.html",
      re=r"setWebContentsDebuggingEnabled\s*\(\s*true", nc="WebView.setWebContentsDebuggingEnabled(true);", c="WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG);"),
]
