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


# JS/TS quality pack: Node and Angular deprecations/removals.
RULES = [
    r(id="js-node-os-tmpdir", title="os.tmpDir()", desc="os.tmpDir was renamed os.tmpdir.",
      rationale="The camelCase os.tmpDir is deprecated.", remediation="Use os.tmpdir().",
      source="https://nodejs.org/api/os.html#ostmpdir", re=r"\bos\.tmpDir\s*\(",
      nc="const dir = os.tmpDir();", c="const dir = os.tmpdir();"),
    r(id="js-node-process-binding", type="bug", qual="rel", sev="medium", title="process.binding()",
      desc="process.binding is a deprecated internal API.", rationale="process.binding exposes internals and is deprecated/pending removal.",
      remediation="Use the public module API instead.", source="https://nodejs.org/api/process.html",
      re=r"\bprocess\.binding\s*\(", nc='const natives = process.binding("natives");', c='const util = require("node:util");'),
    r(id="js-node-punycode-module", title="Deprecated punycode module", desc="The built-in punycode module is deprecated.",
      rationale="The bundled punycode module is deprecated; use the userland package or the WHATWG URL API.",
      remediation="Use the punycode userland package or new URL(...).", source="https://nodejs.org/api/punycode.html",
      re=r'''require\s*\(\s*["']punycode["']\s*\)''', nc='const punycode = require("punycode");', c='const { domainToASCII } = require("node:url");'),
    r(id="js-node-sys-module", type="bug", qual="rel", sev="medium", title="Removed sys module",
      desc="The sys module was removed in favor of util.", rationale="require('sys') fails on modern Node; it was renamed util.",
      remediation="Use the util module.", source="https://nodejs.org/api/util.html",
      re=r'''require\s*\(\s*["']sys["']\s*\)''', nc='const sys = require("sys");', c='const util = require("node:util");'),
    r(id="js-angular-http-module", title="Angular HttpModule", desc="HttpModule was removed in Angular.",
      rationale="HttpModule/@angular/http were removed; use HttpClientModule.", remediation="Use HttpClientModule.",
      source="https://angular.io/guide/http", re=r"\bHttpModule\b",
      nc="imports: [HttpModule],", c="imports: [HttpClientModule],"),
    r(id="js-angular-component-factory-resolver", title="Angular ComponentFactoryResolver", desc="ComponentFactoryResolver is deprecated.",
      rationale="ComponentFactoryResolver is deprecated since Angular 13's Ivy dynamic creation.", remediation="Use ViewContainerRef.createComponent.",
      source="https://angular.io/api/core/ComponentFactoryResolver", re=r"\bComponentFactoryResolver\b",
      nc="constructor(private resolver: ComponentFactoryResolver) {}", c="constructor(private vcr: ViewContainerRef) {}"),
    r(id="js-angular-entry-components", title="Angular entryComponents", desc="entryComponents was removed in Angular.",
      rationale="entryComponents became unnecessary with Ivy and was removed.", remediation="Remove entryComponents (Ivy handles dynamic components).",
      source="https://angular.io/guide/deprecations", re=r"\bentryComponents\b",
      nc="entryComponents: [DialogComponent],", c="declarations: [DialogComponent],"),
]
