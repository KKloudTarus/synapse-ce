CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: Android device-identifier privacy, WebView javascript: URL, saved passwords,
# and exception-message disclosure.
RULES = [
    r(id="java-android-device-id", type="hotspot", qual="sec", sev="medium", cwe="CWE-359", owasp="A04:2021",
      title="Reading the device IMEI", desc="getDeviceId returns a persistent hardware identifier.",
      rationale="Device IDs (IMEI) are sensitive persistent identifiers restricted on modern Android.",
      remediation="Use a resettable identifier (ANDROID_ID / an app-generated UUID).", source="https://cwe.mitre.org/data/definitions/359.html",
      re=r"\.getDeviceId\s*\(", nc="String id = tm.getDeviceId();", c="String id = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID);"),
    r(id="java-android-sim-serial", type="hotspot", qual="sec", sev="medium", cwe="CWE-359", owasp="A04:2021",
      title="Reading the SIM serial number", desc="getSimSerialNumber returns a persistent identifier.",
      rationale="The SIM serial is a sensitive identifier restricted on modern Android.",
      remediation="Do not use hardware identifiers for tracking.", source="https://cwe.mitre.org/data/definitions/359.html",
      re=r"\.getSimSerialNumber\s*\(", nc="String s = tm.getSimSerialNumber();", c="String s = appInstanceId;"),
    r(id="java-android-line1-number", type="hotspot", qual="sec", sev="medium", cwe="CWE-359", owasp="A04:2021",
      title="Reading the phone number", desc="getLine1Number exposes the device phone number.",
      rationale="The phone number is sensitive PII restricted on modern Android.",
      remediation="Avoid reading the phone number; ask the user if needed.", source="https://cwe.mitre.org/data/definitions/359.html",
      re=r"\.getLine1Number\s*\(", nc="String n = tm.getLine1Number();", c="// prompt the user for their number if required"),
    r(id="java-android-loadurl-javascript", type="hotspot", qual="sec", sev="medium", cwe="CWE-79", owasp="A03:2021",
      title="WebView loadUrl(\"javascript:\")", desc="Loading a javascript: URL injects and runs script.",
      rationale="A javascript: URL built from input runs attacker script in the WebView.",
      remediation="Use evaluateJavascript with a fixed script.", source="https://cwe.mitre.org/data/definitions/79.html",
      re=r'loadUrl\s*\(\s*"javascript:', nc='webView.loadUrl("javascript:show(" + data + ")");', c="webView.evaluateJavascript(script, null);"),
    r(id="java-android-save-password", type="hotspot", qual="sec", sev="medium", cwe="CWE-522", owasp="A07:2021",
      title="WebView setSavePassword(true)", desc="Saving passwords in the WebView stores them insecurely.",
      rationale="setSavePassword persists credentials in plaintext and is deprecated.",
      remediation="Disable password saving; use a secure credential store.", source="https://cwe.mitre.org/data/definitions/522.html",
      re=r"setSavePassword\s*\(\s*true", nc="settings.setSavePassword(true);", c="settings.setSavePassword(false);"),
    r(id="java-response-exception-message", type="hotspot", qual="sec", sev="low", cwe="CWE-209", owasp="A05:2021",
      title="Exception message written to output", desc="Writing an exception message can leak internal details.",
      rationale="Exposing exception messages to responses can disclose stack/internal information.",
      remediation="Log the detail server-side and return a generic message to the client.", source="https://cwe.mitre.org/data/definitions/209.html",
      re=r"\.print(ln)?\s*\([^)]*\.getMessage\s*\(", nc="out.println(e.getMessage());", c='out.println("An internal error occurred");'),
]
