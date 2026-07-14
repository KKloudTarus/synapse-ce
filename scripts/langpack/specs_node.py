# Node.js language-pack rule specs (#195). Server-side patterns not already covered by the
# language-agnostic security core. Gated to JS/TS files; tagged "node".
CC = "commentOnlyLine"

def r(**k):
    k.setdefault("lang", "js")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "node"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k

RULES = [
    r(id="node-vm-run-dynamic", type="vuln", qual="sec", sev="high", cwe="CWE-95", owasp="A03:2021",
      title="Code executed via the vm module",
      desc="vm.runInNewContext/runInThisContext executes arbitrary JavaScript, like eval.",
      rationale="The vm module compiles and runs source text; if any part is influenced by input it is code injection, and vm is not a security sandbox.",
      remediation="Do not execute dynamic source; parse data with JSON.parse or use a real sandbox with strict limits.",
      source="https://cwe.mitre.org/data/definitions/95.html",
      re=r"\bvm\.(runInThisContext|runInNewContext|runInContext|compileFunction)\s*\(", nc="vm.runInNewContext(payload);", c="const data = JSON.parse(payload);"),
    r(id="node-child-shell-true", type="hotspot", qual="sec", sev="medium", cwe="CWE-78", owasp="A03:2021",
      title="spawn/execFile with shell:true",
      desc="shell:true runs the command through a shell, re-enabling command injection.",
      rationale="Setting shell:true makes spawn/execFile interpret the command line via a shell, so metacharacters in arguments can inject commands.",
      remediation="Use shell:false (the default) and pass arguments as an array.",
      source="https://cwe.mitre.org/data/definitions/78.html",
      re=r"shell\s*:\s*true", nc="spawn(cmd, args, { shell: true });", c="spawn(cmd, args, { shell: false });"),
    r(id="node-crypto-createcipher", type="vuln", qual="sec", sev="high", cwe="CWE-327", owasp="A02:2021",
      title="Deprecated crypto.createCipher",
      desc="createCipher derives a key with no IV and a weak KDF; use createCipheriv.",
      rationale="crypto.createCipher derives the key from a password with MD5 and uses no explicit IV, producing weak, deterministic ciphertext.",
      remediation="Use crypto.createCipheriv with a random IV and a properly derived key.",
      source="https://cwe.mitre.org/data/definitions/327.html",
      re=r"crypto\.createCipher\s*\(", nc='const c = crypto.createCipher("aes256", pass);', c='const c = crypto.createCipheriv("aes-256-gcm", key, iv);'),
    r(id="node-tls-reject-unauthorized-env", type="hotspot", qual="sec", sev="high", cwe="CWE-295", owasp="A07:2021",
      title="NODE_TLS_REJECT_UNAUTHORIZED disabled",
      desc="Setting NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS verification process-wide.",
      rationale="This environment variable turns off certificate validation for every TLS connection in the process, enabling machine-in-the-middle attacks.",
      remediation="Never disable it; fix the trust store or pass a CA to the specific client instead.",
      source="https://cwe.mitre.org/data/definitions/295.html",
      re=r"NODE_TLS_REJECT_UNAUTHORIZED", nc='process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";', c="// certificate trust configured via a CA bundle"),
    r(id="node-new-buffer", type="bug", qual="rel", sev="medium", cwe="CWE-1188",
      title="Deprecated Buffer constructor",
      desc="new Buffer() is deprecated and can allocate uninitialized memory.",
      rationale="The Buffer() constructor is deprecated: passing a number allocates uninitialized (old) memory, and the overloads are ambiguous.",
      remediation="Use Buffer.from(...) for data or Buffer.alloc(size) for a zeroed buffer.",
      source="https://nodejs.org/api/buffer.html#buffer_buffer_from_buffer_alloc_and_buffer_allocunsafe",
      re=r"\bnew\s+Buffer\s*\(", nc="const b = new Buffer(input);", c="const b = Buffer.from(input);"),
    r(id="node-buffer-allocunsafe", type="hotspot", qual="sec", sev="low", cwe="CWE-201",
      title="Buffer.allocUnsafe used",
      desc="allocUnsafe returns memory that may contain old data until overwritten.",
      rationale="Buffer.allocUnsafe skips zeroing for speed, so the buffer can expose previously freed memory if it is read before being fully written.",
      remediation="Use Buffer.alloc (zeroed) unless the buffer is guaranteed to be fully overwritten first.",
      source="https://cwe.mitre.org/data/definitions/201.html",
      re=r"Buffer\.allocUnsafe\s*\(", nc="const b = Buffer.allocUnsafe(len);", c="const b = Buffer.alloc(len);"),
    r(id="node-fs-chmod-world-writable", type="hotspot", qual="sec", sev="medium", cwe="CWE-732", owasp="A01:2021",
      title="World-writable chmod",
      desc="chmod 0777 grants everyone write access to the file.",
      rationale="Mode 0777 lets any local user modify the file, enabling tampering or privilege abuse.",
      remediation="Grant the least permissions needed (e.g. 0640 / 0750).",
      source="https://cwe.mitre.org/data/definitions/732.html",
      re=r"chmod(Sync)?\s*\([^,]+,\s*0o?777", nc="fs.chmodSync(path, 0o777);", c="fs.chmodSync(path, 0o640);"),
    r(id="node-dynamic-require", type="hotspot", qual="sec", sev="low", cwe="CWE-95",
      title="Dynamic require of a non-literal",
      desc="require() of a variable can load an attacker-influenced module path.",
      rationale="A require whose argument is computed from data can be steered to load an unexpected module, and it defeats static dependency analysis.",
      remediation="require static string paths; use an explicit allow-list map for plugin loading.",
      source="https://cwe.mitre.org/data/definitions/95.html",
      re=r"\brequire\s*\(\s*[A-Za-z_$][\w$.]*\s*\)", nc="const mod = require(pluginName);", c='const mod = require("lodash");'),
    r(id="node-process-exit-lib", type="smell", qual="maint", sev="medium", cwe="",
      title="process.exit() in library code",
      desc="process.exit terminates the whole process, skipping pending I/O and cleanup.",
      rationale="Calling process.exit from library/handler code kills the process abruptly, dropping buffered output and bypassing graceful shutdown.",
      remediation="Throw or return an error and let the entry point decide whether to exit.",
      source="https://nodejs.org/api/process.html#processexitcode",
      re=r"\bprocess\.exit\s*\(", nc="if (bad) process.exit(1);", c="if (bad) throw new Error(\"startup failed\");"),
]
