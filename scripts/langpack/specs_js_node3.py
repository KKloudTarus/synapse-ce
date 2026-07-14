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


# JS/TS quality pack: more Node deprecated/removed APIs (+ one security rule).
RULES = [
    r(id="js-buffer-allocunsafe", type="hotspot", qual="sec", sev="medium", cwe="CWE-665", owasp="A05:2021",
      tags=["sast", "javascript", "security"], title="Buffer.allocUnsafe()", desc="allocUnsafe returns uninitialized memory.",
      rationale="allocUnsafe may expose stale memory contents if not fully overwritten.",
      remediation="Use Buffer.alloc (zero-filled) unless you immediately overwrite every byte.",
      source="https://cwe.mitre.org/data/definitions/665.html", re=r"Buffer\.allocUnsafe\s*\(",
      nc="const b = Buffer.allocUnsafe(256);", c="const b = Buffer.alloc(256);"),
    r(id="js-node-fs-rmdir-recursive", title="fs.rmdir recursive option", desc="The recursive option on fs.rmdir is deprecated.",
      rationale="Recursive fs.rmdir is deprecated in favor of fs.rm.", remediation="Use fs.rm(path, { recursive: true }).",
      source="https://nodejs.org/api/fs.html#fsrmdirpath-options-callback", re=r"fs\.rmdir\s*\([^)]*recursive\s*:\s*true",
      nc="fs.rmdir(dir, { recursive: true }, cb);", c="fs.rm(dir, { recursive: true }, cb);"),
    r(id="js-node-require-extensions", type="bug", qual="rel", sev="medium", title="require.extensions", desc="require.extensions is deprecated.",
      rationale="Mutating require.extensions is deprecated and pending removal.", remediation="Use a loader or a transpile step.",
      source="https://nodejs.org/api/modules.html#requireextensions", re=r"\brequire\.extensions\b",
      nc='require.extensions[".ts"] = compile;', c="// register a loader via --experimental-loader"),
    r(id="js-node-crypto-default-encoding", type="bug", qual="rel", sev="medium", title="crypto.DEFAULT_ENCODING", desc="crypto.DEFAULT_ENCODING was removed.",
      rationale="crypto.DEFAULT_ENCODING was removed in Node 12.", remediation="Pass the encoding explicitly to digest()/etc.",
      source="https://nodejs.org/api/deprecations.html", re=r"crypto\.DEFAULT_ENCODING\b",
      nc='crypto.DEFAULT_ENCODING = "hex";', c='hash.digest("hex");'),
    r(id="js-node-crypto-createcredentials", type="bug", qual="rel", sev="medium", title="crypto.createCredentials()", desc="createCredentials was removed.",
      rationale="crypto.createCredentials was removed in favor of tls.createSecureContext.", remediation="Use tls.createSecureContext.",
      source="https://nodejs.org/api/deprecations.html", re=r"crypto\.createCredentials\s*\(",
      nc="const c = crypto.createCredentials(opts);", c="const c = tls.createSecureContext(opts);"),
    r(id="js-node-tls-createsecurepair", title="tls.createSecurePair()", desc="createSecurePair is deprecated.",
      rationale="tls.createSecurePair is deprecated in favor of tls.TLSSocket.", remediation="Use new tls.TLSSocket(...).",
      source="https://nodejs.org/api/tls.html", re=r"tls\.createSecurePair\s*\(",
      nc="const pair = tls.createSecurePair(ctx);", c="const socket = new tls.TLSSocket(raw, options);"),
    r(id="js-node-util-isarray", title="util.isArray()", desc="util.isArray is deprecated.",
      rationale="util.isArray is deprecated in favor of Array.isArray.", remediation="Use Array.isArray(x).",
      source="https://nodejs.org/api/util.html#utilisarrayobject", re=r"\butil\.isArray\s*\(",
      nc="if (util.isArray(x)) {", c="if (Array.isArray(x)) {"),
    r(id="js-node-util-types", title="Deprecated util.is* type checks", desc="util.isDate/isError/etc are deprecated.",
      rationale="The util.is* type predicates are deprecated in favor of instanceof / typeof.", remediation="Use instanceof or typeof.",
      source="https://nodejs.org/api/util.html", re=r"\butil\.(isDate|isError|isRegExp|isNull|isNullOrUndefined|isNumber|isString|isBoolean|isObject|isPrimitive|isBuffer|isSymbol|isFunction)\s*\(",
      nc="if (util.isDate(x)) {", c="if (x instanceof Date) {"),
    r(id="js-node-util-print", type="bug", qual="rel", sev="medium", title="util.print / util.puts", desc="util.print/puts/debug were removed.",
      rationale="These util output helpers were removed in Node 12.", remediation="Use console.* or process.stdout.write.",
      source="https://nodejs.org/api/deprecations.html", re=r"\butil\.(print|puts|debug|pump)\s*\(",
      nc='util.print("hello");', c='process.stdout.write("hello");'),
    r(id="js-node-util-extend", title="util._extend()", desc="util._extend is deprecated.",
      rationale="util._extend is deprecated in favor of Object.assign.", remediation="Use Object.assign(target, source).",
      source="https://nodejs.org/api/util.html#util_extendtarget-source", re=r"\butil\._extend\s*\(",
      nc="util._extend(target, source);", c="Object.assign(target, source);"),
]
