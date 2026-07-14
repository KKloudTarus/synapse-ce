CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","js");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","node"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="node-legacy-url-parse",type="hotspot",qual="sec",sev="low",cwe="CWE-20",owasp="A03:2021",title="Legacy url.parse()",
   desc="The legacy url.parse() is lenient and parses hostnames differently from the WHATWG URL, enabling SSRF bypasses.",
   rationale="url.parse is deprecated and its lenient parsing diverges from the WHATWG URL used by fetch, so allow-list checks on its output can be bypassed.",
   remediation="Use the WHATWG URL constructor: new URL(input).",
   source="https://nodejs.org/api/url.html#urlparseurlstring-parsequerystring-slashesdenotehost",
   re=r"\burl\.parse\s*\(",nc="const u = url.parse(target);",c="const u = new URL(target);"),
]
