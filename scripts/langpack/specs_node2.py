CC = "commentOnlyLine"
def r(**k):
    k.setdefault("lang","js"); k.setdefault("owasp",""); k.setdefault("effort",15)
    k.setdefault("tags",["sast","node"]); k.setdefault("cat_desc",k["desc"]); k.setdefault("skip",CC)
    return k
RULES = [
    r(id="node-unsafe-yaml-load", type="hotspot", qual="sec", sev="medium", cwe="CWE-502", owasp="A08:2021", title="Unsafe YAML load",
      desc="yaml.load on untrusted input can instantiate arbitrary types (older js-yaml).",
      rationale="With permissive schemas, YAML loading can construct arbitrary objects from tags, leading to code execution or unexpected types on untrusted input.",
      remediation="Parse with a safe schema (js-yaml's default load is safe in v4; pin the schema) and validate the result.",
      source="https://cwe.mitre.org/data/definitions/502.html",
      re=r"\byaml\.load\s*\(", nc="const cfg = yaml.load(untrusted);", c="const cfg = yaml.safeLoad(untrusted);"),
    r(id="node-execsync-dynamic", type="hotspot", qual="sec", sev="high", cwe="CWE-78", owasp="A03:2021", title="execSync with a non-literal command",
      desc="child_process.execSync on a variable/template runs a shell command line.",
      rationale="execSync interprets its argument as a shell command line, so any input in a dynamic string can inject commands.",
      remediation="Use execFileSync/spawnSync with a fixed argv and no shell, and validate inputs.",
      source="https://cwe.mitre.org/data/definitions/78.html",
      re=r"\bexecSync\s*\(\s*[A-Za-z_$]", nc="const out = execSync(userCmd);", c='const out = execFileSync("git", ["status"]);'),
]
