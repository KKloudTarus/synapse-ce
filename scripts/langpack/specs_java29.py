CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java", "security"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


# Java security pack: JDBC/JdbcTemplate SQL concatenation + JNDI-lookup string (Log4Shell shape).
RULES = [
    r(id="java-preparestatement-concat", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="PreparedStatement built by concatenation", desc="Concatenating input into a prepared statement defeats its purpose.",
      rationale="Building the SQL text of a PreparedStatement with + from input is still SQL injection.",
      remediation="Use ? placeholders and setXxx bindings.", source="https://cwe.mitre.org/data/definitions/89.html",
      re=r'prepareStatement\s*\(\s*"[^"]*"\s*\+', nc='conn.prepareStatement("SELECT * FROM u WHERE id=" + id);', c='PreparedStatement ps = conn.prepareStatement("SELECT * FROM u WHERE id=?");'),
    r(id="java-preparecall-concat", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="CallableStatement built by concatenation", desc="Concatenating input into a callable statement enables SQL injection.",
      rationale="A stored-procedure call assembled with + from input is injectable.",
      remediation="Use ? placeholders in the call and bind parameters.", source="https://cwe.mitre.org/data/definitions/89.html",
      re=r'prepareCall\s*\(\s*"[^"]*"\s*\+', nc='conn.prepareCall("{call find(" + id + ")}");', c='conn.prepareCall("{call find(?)}");'),
    r(id="java-jdbctemplate-concat", type="vuln", qual="sec", sev="high", cwe="CWE-89", owasp="A03:2021",
      title="JdbcTemplate query built by concatenation", desc="Concatenating input into a JdbcTemplate query enables SQL injection.",
      rationale="A Spring JdbcTemplate query assembled with + from input is injectable.",
      remediation="Use ? placeholders and pass args to the JdbcTemplate call.", source="https://cwe.mitre.org/data/definitions/89.html",
      re=r'jdbcTemplate\.query\w*\s*\(\s*"[^"]*"\s*\+', nc='jdbcTemplate.queryForObject("SELECT * FROM u WHERE id=" + id, User.class);', c='jdbcTemplate.queryForObject("SELECT * FROM u WHERE id=?", User.class, id);'),
    r(id="java-jndi-lookup-string", type="hotspot", qual="sec", sev="high", cwe="CWE-917", owasp="A03:2021",
      title="JNDI lookup expression in a string", desc="A ${jndi:...} expression can trigger remote class loading (Log4Shell).",
      rationale="A JNDI lookup expression reaching a logger/interpolator can load remote code (Log4Shell-style).",
      remediation="Never interpolate untrusted input into logged/JNDI-evaluated strings; patch/limit JNDI lookups.", source="https://cwe.mitre.org/data/definitions/917.html",
      re=r"\$\{jndi:", nc='String probe = "${jndi:ldap://host/a}";', c='String probe = sanitize(value);'),
]
