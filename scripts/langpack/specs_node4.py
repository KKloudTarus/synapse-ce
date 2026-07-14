CC="commentOnlyLine"
def r(**k):
    k.setdefault("lang","js");k.setdefault("owasp","");k.setdefault("effort",15)
    k.setdefault("tags",["sast","node"]);k.setdefault("cat_desc",k["desc"]);k.setdefault("skip",CC)
    return k
RULES=[
 r(id="node-deprecated-request-lib",type="smell",qual="maint",sev="low",cwe="",title="Deprecated request library",
   desc="The `request` package is deprecated and unmaintained.",
   rationale="request has been deprecated since 2020 and receives no fixes, including security fixes; new code should use a maintained client.",
   remediation="Use a maintained HTTP client (e.g. the built-in fetch, undici, or axios).",
   source="https://github.com/request/request/issues/3142",
   re=r"require\s*\(\s*['\"]request['\"]\s*\)",nc='const request = require("request");',c='const { request } = require("undici");'),
 r(id="node-domain-module",type="smell",qual="maint",sev="low",cwe="",title="Deprecated domain module",
   desc="The `domain` core module is deprecated.",
   rationale="The domain module is deprecated and pending removal; its error-handling model is unreliable.",
   remediation="Use async_hooks or structured error handling instead.",
   source="https://nodejs.org/api/domain.html",
   re=r"require\s*\(\s*['\"]domain['\"]\s*\)",nc='const domain = require("domain");',c='const async_hooks = require("async_hooks");'),
]
