CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","js");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","node"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="node-header-injection-user",type="hotspot",qual="sec",sev="medium",cwe="CWE-113",owasp="A03:2021",title="Response header from request input",
   desc="Setting a response header from request data enables header/response splitting.",
   rationale="Unsanitized request input in setHeader can inject CRLF sequences, splitting the response or poisoning caches.",
   remediation="Validate/encode the value, or use a fixed allow-list.",
   source="https://cwe.mitre.org/data/definitions/113.html",
   re=r"\.setHeader\s*\([^,]+,\s*req\.",nc='res.setHeader("X-Ref", req.query.ref);',c='res.setHeader("X-Ref", allowList(ref));'),
 r(id="node-jwt-alg-none",type="vuln",qual="sec",sev="high",cwe="CWE-347",owasp="A02:2021",title="JWT algorithm 'none' allowed",
   desc="Allowing the 'none' algorithm lets unsigned tokens be accepted.",
   rationale="The none algorithm means no signature, so an attacker can forge any token; it must never be in the accepted list.",
   remediation="Pin a strong algorithm (e.g. RS256/ES256) in the algorithms option.",
   source="https://cwe.mitre.org/data/definitions/347.html",
   re=r"algorithms?\s*:\s*\[?\s*['\"]none['\"]",nc='jwt.verify(t, k, { algorithms: ["none"] });',c='jwt.verify(t, k, { algorithms: ["RS256"] });'),
 r(id="node-vm2-usage",type="hotspot",qual="sec",sev="medium",cwe="CWE-1188",owasp="A06:2021",title="vm2 sandbox used",
   desc="vm2 has a history of sandbox-escape CVEs and is discontinued.",
   rationale="vm2 was widely used as a JS sandbox but had repeated escape vulnerabilities and is no longer maintained.",
   remediation="Use an out-of-process isolate (e.g. isolated-vm) or a separate process/container.",
   source="https://github.com/patriksimek/vm2/security/advisories",
   re=r"require\s*\(\s*['\"]vm2['\"]\s*\)",nc='const { VM } = require("vm2");',c="const ivm = require(\"isolated-vm\");"),
 r(id="node-process-binding",type="bug",qual="rel",sev="low",cwe="",title="process.binding used",
   desc="process.binding accesses internal, unstable, deprecated bindings.",
   rationale="process.binding exposes internal C++ bindings that are undocumented, deprecated, and can change or be removed without notice.",
   remediation="Use the corresponding public core module (net, fs, ...).",
   source="https://nodejs.org/api/deprecations.html#DEP0111",
   re=r"\bprocess\.binding\s*\(",nc='const tcp = process.binding("tcp_wrap");',c='const net = require("net");'),
]
