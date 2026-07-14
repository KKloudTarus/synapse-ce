CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# JS/TS security pack, third batch: cookie flags, TLS verification bypass, NoSQL/JWT, constructor
# prototype pollution, plus a TS unsafe-cast smell. Precise keyword/property anchors, clean-room prose.
RULES = [
    r(id="js-mongo-where", type="hotspot", qual="sec", sev="high", cwe="CWE-943", owasp="A03:2021",
      title="MongoDB $where operator", desc="$where runs a JavaScript expression on the server (injection).",
      rationale="A $where clause built from input executes attacker JavaScript in the database.",
      remediation="Use standard query operators; never build $where from user input.",
      source="https://cwe.mitre.org/data/definitions/943.html",
      re=r'''["']\$where["']''', nc='db.users.find({ "$where": "this.name == input" });', c="db.users.find({ name: input });"),
    r(id="js-jwt-alg-none", type="hotspot", qual="sec", sev="high", cwe="CWE-347", owasp="A02:2021",
      title="JWT 'none' algorithm", desc="Accepting the \"none\" algorithm means tokens are unsigned.",
      rationale="Allowing alg \"none\" lets an attacker forge tokens with no signature.",
      remediation="Pin an explicit signing algorithm (e.g. HS256/RS256) and reject none.",
      source="https://cwe.mitre.org/data/definitions/347.html",
      re=r'''algorithms?\s*:\s*\[?\s*["']none["']''', nc='jwt.verify(t, k, { algorithms: ["none"] });', c='jwt.verify(t, k, { algorithms: ["HS256"] });'),
    r(id="js-cookie-samesite-none", type="hotspot", qual="sec", sev="low", cwe="CWE-1275", owasp="A05:2021",
      title="Cookie SameSite=None", desc="SameSite=None sends the cookie on cross-site requests.",
      rationale="SameSite=None weakens CSRF defense and must be paired with Secure and clear intent.",
      remediation="Use SameSite=Lax or Strict unless cross-site delivery is truly required.",
      source="https://cwe.mitre.org/data/definitions/1275.html",
      re=r'''sameSite\s*:\s*["']none["']''', nc='res.cookie("s", v, { sameSite: "none" });', c='res.cookie("s", v, { sameSite: "lax" });'),
    r(id="js-cookie-secure-false", type="hotspot", qual="sec", sev="medium", cwe="CWE-614", owasp="A05:2021",
      title="Cookie secure flag disabled", desc="secure: false lets the cookie travel over plaintext HTTP.",
      rationale="A cookie without the Secure attribute can be sent over HTTP and intercepted.",
      remediation="Set secure: true for session/auth cookies.",
      source="https://cwe.mitre.org/data/definitions/614.html",
      re=r"\bsecure\s*:\s*false\b", nc='res.cookie("sid", v, { secure: false });', c='res.cookie("sid", v, { secure: true });'),
    r(id="js-cookie-httponly-false", type="hotspot", qual="sec", sev="medium", cwe="CWE-1004", owasp="A05:2021",
      title="Cookie HttpOnly disabled", desc="httpOnly: false exposes the cookie to client-side scripts.",
      rationale="A non-HttpOnly cookie can be read by JavaScript, aiding token theft via XSS.",
      remediation="Set httpOnly: true for session/auth cookies.",
      source="https://cwe.mitre.org/data/definitions/1004.html",
      re=r"\bhttpOnly\s*:\s*false\b", nc='res.cookie("sid", v, { httpOnly: false });', c='res.cookie("sid", v, { httpOnly: true });'),
    r(id="js-document-domain-write", type="hotspot", qual="sec", sev="low", cwe="CWE-346", owasp="A05:2021",
      title="Assignment to document.domain", desc="Setting document.domain relaxes the same-origin policy.",
      rationale="Lowering document.domain lets sibling subdomains script the page, widening attack surface.",
      remediation="Avoid document.domain; use postMessage with origin checks for cross-frame messaging.",
      source="https://cwe.mitre.org/data/definitions/346.html",
      re=r"document\.domain\s*=\s*[^=]", nc='document.domain = "example.com";', c="if (document.domain === expected) ok();"),
    r(id="js-proto-constructor-bracket", type="hotspot", qual="sec", sev="medium", cwe="CWE-1321", owasp="A03:2021",
      title="Bracket access to \"constructor\"", desc="Indexing with the \"constructor\" key can reach the prototype (pollution).",
      rationale="obj[\"constructor\"][\"prototype\"] is a prototype-pollution path from untrusted keys.",
      remediation="Reject constructor/__proto__/prototype keys, or use a Map / null-prototype object.",
      source="https://cwe.mitre.org/data/definitions/1321.html",
      re=r'''\[\s*["']constructor["']\s*\]''', nc='target["constructor"]["prototype"].polluted = true;', c='target["value"] = input;'),
    r(id="js-tls-reject-unauthorized-env", type="vuln", qual="sec", sev="high", cwe="CWE-295", owasp="A07:2021",
      title="NODE_TLS_REJECT_UNAUTHORIZED disabled", desc="Setting this variable to 0 disables all TLS certificate validation.",
      rationale="Turning off certificate validation process-wide accepts any certificate (MITM).",
      remediation="Never set NODE_TLS_REJECT_UNAUTHORIZED=0; fix the trust store instead.",
      source="https://cwe.mitre.org/data/definitions/295.html",
      re=r'''NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0''', nc='process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";', c='process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";'),
    r(id="js-reject-unauthorized-false", type="vuln", qual="sec", sev="high", cwe="CWE-295", owasp="A07:2021",
      title="TLS rejectUnauthorized disabled", desc="rejectUnauthorized: false accepts invalid TLS certificates.",
      rationale="Disabling rejectUnauthorized on a request accepts any certificate, enabling MITM.",
      remediation="Leave rejectUnauthorized on; supply a CA bundle for private certificates.",
      source="https://cwe.mitre.org/data/definitions/295.html",
      re=r"rejectUnauthorized\s*:\s*false", nc="https.request({ rejectUnauthorized: false });", c="https.request({ rejectUnauthorized: true });"),
    r(id="ts-as-any-cast", type="smell", qual="maint", sev="low", cwe="", title="Cast to any",
      desc="`as any` discards type checking for the expression.",
      rationale="Casting through any defeats TypeScript's guarantees and hides real type errors.",
      remediation="Cast to the specific type, or narrow with a type guard.",
      source="https://typescript-eslint.io/rules/no-explicit-any/",
      re=r"\bas\s+any\b", nc="const user = payload as any;", c="const user = payload as User;"),
]
