CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","js");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","node"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="node-mongo-find-req-body",type="hotspot",qual="sec",sev="high",cwe="CWE-943",owasp="A03:2021",title="Mongo query built from request body",
   desc="Passing req.body/query/params straight into a Mongo query allows operator injection.",
   rationale="A raw request object as a Mongo filter lets an attacker inject operators like $ne/$gt/$where to bypass logic or run JS.",
   remediation="Extract and validate/cast individual fields; never pass the raw request object as a filter.",
   source="https://cwe.mitre.org/data/definitions/943.html",
   re=r"\.find(One|OneAndUpdate|OneAndDelete)?\s*\(\s*req\.(body|query|params)\b",nc="const u = await User.find(req.body);",c="const u = await User.find({ id: safeId });"),
 r(id="node-fast-hash-password",type="hotspot",qual="sec",sev="medium",cwe="CWE-916",owasp="A02:2021",title="Fast hash used for a password",
   desc="Hashing a password with a general-purpose hash (createHash) is brute-forceable.",
   rationale="SHA-family hashes are fast, so a leaked digest of a password is cheap to crack; passwords need a slow, salted KDF.",
   remediation="Use bcrypt, scrypt, or argon2 with a per-password salt.",
   source="https://cwe.mitre.org/data/definitions/916.html",
   re=r"createHash\s*\([^)]*\)\.update\s*\([^)]*password",nc='const h = crypto.createHash("sha256").update(password).digest("hex");',c="const h = await bcrypt.hash(password, 12);"),
 r(id="node-timing-unsafe-compare",type="hotspot",qual="sec",sev="low",cwe="CWE-208",owasp="A02:2021",title="Non-constant-time secret comparison",
   desc="Comparing a secret with === leaks length/prefix timing.",
   rationale="=== short-circuits on the first mismatched byte, so response timing can leak how much of a token/HMAC matched.",
   remediation="Use crypto.timingSafeEqual for secret/token/HMAC comparisons.",
   source="https://cwe.mitre.org/data/definitions/208.html",
   re=r"(?i)\b(token|secret|password|api[_-]?key|signature|hmac)\s*===",nc="if (apiKey === expected) grant();",c="if (crypto.timingSafeEqual(a, b)) grant();"),
]
