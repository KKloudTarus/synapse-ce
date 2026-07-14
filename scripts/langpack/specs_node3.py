CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","js");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","node"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="node-cors-reflect-origin",type="hotspot",qual="sec",sev="medium",cwe="CWE-346",owasp="A05:2021",title="CORS reflecting any origin",
   desc="cors({ origin: true }) reflects the caller's Origin, allowing any site.",
   rationale="origin:true echoes back the request Origin, so every website can make credentialed cross-origin requests to the API.",
   remediation="Set origin to an explicit allow-list of trusted origins.",
   source="https://cwe.mitre.org/data/definitions/346.html",
   re=r"origin\s*:\s*true\b",nc="app.use(cors({ origin: true }));",c='app.use(cors({ origin: "https://app.internal" }));'),
 r(id="node-set-insecure-cookie-samesite-none",type="hotspot",qual="sec",sev="low",cwe="CWE-1275",owasp="A05:2021",title="SameSite=None cookie",
   desc="SameSite=None sends the cookie on cross-site requests (CSRF surface).",
   rationale="SameSite=None attaches the cookie to cross-site requests, widening CSRF exposure unless strictly required and paired with Secure.",
   remediation="Use SameSite=Lax or Strict unless a cross-site cookie is genuinely required.",
   source="https://cwe.mitre.org/data/definitions/1275.html",
   re=r"sameSite\s*:\s*['\"]none['\"]",nc='res.cookie("s", v, { sameSite: "none" });',c='res.cookie("s", v, { sameSite: "lax" });'),
]
