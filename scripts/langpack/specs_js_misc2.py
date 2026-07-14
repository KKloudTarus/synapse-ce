CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "javascript"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "smell")
    k.setdefault("qual", "maint")
    k.setdefault("sev", "low")
    k.setdefault("cwe", "")
    return k


# JS/TS quality pack: Node + jQuery deprecations.
RULES = [
    r(id="js-node-module-parent", title="module.parent", desc="module.parent is deprecated.",
      rationale="module.parent is deprecated; it is unreliable with the module cache.",
      remediation="Use require.main === module to detect the entry point.", source="https://nodejs.org/api/modules.html#moduleparent",
      re=r"\bmodule\.parent\b", nc="if (module.parent) {", c="if (require.main !== module) {"),
    r(id="js-jquery-holdready", title="jQuery.holdReady()", desc="$.holdReady is deprecated.",
      rationale="$.holdReady is deprecated; structure initialization to avoid holding ready.",
      remediation="Load dependencies before invoking ready logic.", source="https://api.jquery.com/jQuery.holdReady/",
      re=r"\$\.holdReady\s*\(", nc="$.holdReady(true);", c="await loadDependencies();"),
    r(id="js-jquery-proxy", title="jQuery.proxy()", desc="$.proxy is deprecated.",
      rationale="$.proxy is deprecated in favor of Function.bind and arrow functions.",
      remediation="Use fn.bind(context) or an arrow function.", source="https://api.jquery.com/jQuery.proxy/",
      re=r"\$\.proxy\s*\(", nc="const bound = $.proxy(handler, this);", c="const bound = handler.bind(this);"),
]
