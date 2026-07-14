CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java pack: bare-transform cipher defaults + Spring/TLS config, plus two precise correctness rules.
# Concept origins cited (CWE, OWASP, find-sec-bugs, PMD, framework docs); prose authored clean-room.
RULES = [
    r(id="java-cipher-aes-default-ecb", type="vuln", qual="sec", sev="medium", cwe="CWE-327", owasp="A02:2021",
      title="AES with the default (ECB) mode", desc='Cipher.getInstance("AES") defaults to ECB, which leaks plaintext structure.',
      rationale="A bare \"AES\" transform uses ECB mode with no IV, so equal blocks encrypt equally.",
      remediation='Specify an authenticated mode, e.g. "AES/GCM/NoPadding".',
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r'Cipher\.getInstance\s*\(\s*"AES"\s*\)', nc='Cipher c = Cipher.getInstance("AES");', c='Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'),
    r(id="java-cipher-rsa-default", type="vuln", qual="sec", sev="medium", cwe="CWE-780", owasp="A02:2021",
      title="RSA with the default padding", desc='Cipher.getInstance("RSA") uses PKCS#1 v1.5 padding by default.',
      rationale="A bare \"RSA\" transform defaults to PKCS#1 v1.5, which is padding-oracle vulnerable.",
      remediation='Specify OAEP: "RSA/ECB/OAEPWithSHA-256AndMGF1Padding".',
      source="https://cwe.mitre.org/data/definitions/780.html",
      re=r'Cipher\.getInstance\s*\(\s*"RSA"\s*\)', nc='Cipher c = Cipher.getInstance("RSA");', c='Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");'),
    r(id="java-spring-crossorigin-default", type="hotspot", qual="sec", sev="medium", cwe="CWE-942", owasp="A05:2021",
      title="@CrossOrigin with no origins", desc="A bare @CrossOrigin annotation allows requests from any origin.",
      rationale="@CrossOrigin without an origins list defaults to allowing all origins.",
      remediation="Specify the allowed origins, e.g. @CrossOrigin(origins = \"https://app.example.com\").",
      source="https://cwe.mitre.org/data/definitions/942.html",
      re=r"^\s*@CrossOrigin\s*$", nc="@CrossOrigin", c='@CrossOrigin(origins = "https://app.example.com")'),
    r(id="java-set-default-hostname-verifier", type="hotspot", qual="sec", sev="medium", cwe="CWE-295", owasp="A07:2021",
      title="Custom default hostname verifier", desc="Overriding the default hostname verifier is a common way to disable TLS identity checks.",
      rationale="A custom global hostname verifier frequently accepts all hosts, enabling MITM.",
      remediation="Keep the platform default verifier; if customizing, still enforce hostname matching.",
      source="https://cwe.mitre.org/data/definitions/295.html",
      re=r"setDefaultHostnameVerifier\s*\(", nc="HttpsURLConnection.setDefaultHostnameVerifier(allowAll);",
      c="conn.connect();"),
    r(id="java-substring-zero", type="smell", qual="maint", sev="low", cwe="", title="Redundant substring(0)",
      desc="substring(0) returns the same string and does nothing.",
      rationale="Calling substring(0) is a no-op that clutters the code, often a leftover from an edit.",
      remediation="Remove the redundant substring(0) call.",
      source="https://pmd.github.io/pmd/pmd_rules_java_errorprone.html",
      re=r"\.substring\s*\(\s*0\s*\)", nc="String s = value.substring(0);", c="String s = value.substring(1);"),
    r(id="java-nan-comparison", type="bug", qual="rel", sev="medium", cwe="CWE-697", owasp="",
      title="Comparison with NaN", desc="Any == / != comparison with Double.NaN or Float.NaN is always false.",
      rationale="NaN is unequal to everything including itself, so a NaN comparison never behaves as intended.",
      remediation="Use Double.isNaN(x) / Float.isNaN(x).",
      source="https://cwe.mitre.org/data/definitions/697.html",
      re=r"(==|!=)\s*(Double|Float)\.NaN|(Double|Float)\.NaN\s*(==|!=)", nc="if (ratio == Double.NaN) reset();", c="if (Double.isNaN(ratio)) reset();"),
]
