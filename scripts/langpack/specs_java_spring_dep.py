CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "java"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "smell")
    k.setdefault("qual", "maint")
    k.setdefault("sev", "low")
    k.setdefault("cwe", "")
    return k


SS = "https://docs.spring.io/spring-security/reference/migration-7/configuration.html"

# Java quality pack: Spring Security 5.8 / 6 request-matcher deprecations.
RULES = [
    r(id="java-spring-antmatchers", title="Spring Security antMatchers()", desc="antMatchers is deprecated.",
      rationale="antMatchers was deprecated in Spring Security 5.8 in favor of requestMatchers.", remediation="Use requestMatchers(...).",
      source=SS, re=r"\.antMatchers\s*\(", nc='http.authorizeRequests().antMatchers("/admin").hasRole("ADMIN");', c='http.authorizeHttpRequests(a -> a.requestMatchers("/admin").hasRole("ADMIN"));'),
    r(id="java-spring-mvcmatchers", title="Spring Security mvcMatchers()", desc="mvcMatchers is deprecated.",
      rationale="mvcMatchers was deprecated in Spring Security 5.8 in favor of requestMatchers.", remediation="Use requestMatchers(...).",
      source=SS, re=r"\.mvcMatchers\s*\(", nc='http.authorizeRequests().mvcMatchers("/api/**").authenticated();', c='http.authorizeHttpRequests(a -> a.requestMatchers("/api/**").authenticated());'),
    r(id="java-spring-authorize-requests", title="Spring Security authorizeRequests()", desc="authorizeRequests is deprecated.",
      rationale="authorizeRequests was deprecated in favor of authorizeHttpRequests (Spring Security 6).", remediation="Use authorizeHttpRequests(...).",
      source=SS, re=r"\.authorizeRequests\s*\(", nc="http.authorizeRequests().anyRequest().authenticated();", c="http.authorizeHttpRequests(a -> a.anyRequest().authenticated());"),
]
