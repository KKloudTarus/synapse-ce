CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: more expression-language/script RCE engines + insecure PRNG helpers.
RULES = [
    r(id="java-jexl-createscript", type="hotspot", qual="sec", sev="high", cwe="CWE-94", owasp="A03:2021",
      title="JEXL createScript()", desc="createScript compiles an expression that may be attacker-controlled.",
      rationale="Compiling/running a JEXL script from input allows expression-language injection and RCE.",
      remediation="Do not build JEXL scripts from untrusted input; use a restricted sandbox.", source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"\bcreateScript\s*\(", nc="jexl.createScript(userExpression).execute(ctx);", c="// use a fixed, sandboxed expression"),
    r(id="java-beanshell-interpreter", type="hotspot", qual="sec", sev="high", cwe="CWE-94", owasp="A03:2021",
      title="BeanShell Interpreter", desc="bsh.Interpreter.eval runs arbitrary Java-like code.",
      rationale="Evaluating a BeanShell script from input allows arbitrary code execution.",
      remediation="Avoid BeanShell on untrusted input.", source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"new\s+bsh\.Interpreter\s*\(", nc="new bsh.Interpreter().eval(script);", c="// avoid dynamic script evaluation"),
    r(id="java-jython-interpreter", type="hotspot", qual="sec", sev="high", cwe="CWE-94", owasp="A03:2021",
      title="Jython PythonInterpreter", desc="PythonInterpreter.exec runs arbitrary Python code.",
      rationale="Executing Python through Jython on untrusted input allows RCE.",
      remediation="Avoid Jython on untrusted input.", source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"new\s+PythonInterpreter\s*\(", nc="new PythonInterpreter().exec(code);", c="// avoid executing untrusted scripts"),
    r(id="java-el-processor", type="hotspot", qual="sec", sev="high", cwe="CWE-94", owasp="A03:2021",
      title="Jakarta ELProcessor eval", desc="ELProcessor.eval evaluates an expression-language string.",
      rationale="Evaluating EL from input allows expression-language injection.",
      remediation="Do not evaluate EL from untrusted input.", source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"new\s+ELProcessor\s*\(", nc="Object r = new ELProcessor().eval(expr);", c="// avoid EL evaluation of untrusted input"),
    r(id="java-rhino-evaluate-string", type="hotspot", qual="sec", sev="high", cwe="CWE-94", owasp="A03:2021",
      title="Rhino evaluateString()", desc="Context.evaluateString runs arbitrary JavaScript.",
      rationale="Evaluating JavaScript through Rhino on untrusted input allows RCE.",
      remediation="Avoid Rhino on untrusted input; use a sandboxed engine.", source="https://cwe.mitre.org/data/definitions/94.html",
      re=r"\.evaluateString\s*\(", nc='cx.evaluateString(scope, userScript, "src", 1, null);', c="// avoid evaluating untrusted scripts"),
    r(id="java-commons-random-string", type="hotspot", qual="sec", sev="medium", cwe="CWE-330", owasp="A02:2021",
      title="Commons RandomStringUtils.random", desc="RandomStringUtils uses a non-secure PRNG by default.",
      rationale="RandomStringUtils.random* is backed by java.util.Random and is unfit for tokens/secrets.",
      remediation="Generate tokens with SecureRandom.", source="https://cwe.mitre.org/data/definitions/330.html",
      re=r"RandomStringUtils\.random\w*\s*\(", nc="String token = RandomStringUtils.randomAlphanumeric(32);", c="String token = secureRandomToken(32);"),
    r(id="java-commons-random-utils", type="hotspot", qual="sec", sev="medium", cwe="CWE-330", owasp="A02:2021",
      title="Commons RandomUtils", desc="RandomUtils uses a non-secure PRNG.",
      rationale="RandomUtils.next* is backed by java.util.Random and is unfit for security-sensitive values.",
      remediation="Use SecureRandom for security-sensitive values.", source="https://cwe.mitre.org/data/definitions/330.html",
      re=r"RandomUtils\.next\w+\s*\(", nc="int n = RandomUtils.nextInt(0, 1000);", c="int n = secureRandom.nextInt(1000);"),
]
