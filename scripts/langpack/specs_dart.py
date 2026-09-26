# Dart language-pack rule specs (#1135, EPIC #1120). Clean-room, line-detectable Dart rules derived
# from the concepts in the Dart lints (avoid_print, empty_catches), Flutter guidance, and CWE — our own
# wording, examples, and detection. Dart has no other coverage in Synapse today, so these are greenfield.
CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "dart")
    k.setdefault("owasp", "")
    k.setdefault("effort", 15)
    k.setdefault("tags", ["sast", "dart"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    return k


RULES = [
    r(id="dart-avoid-print", type="smell", qual="maint", sev="low",
      title="print used instead of a logger",
      desc="print writes to stdout unconditionally; production code should log through a configurable logger.",
      rationale="print cannot be filtered, routed, or disabled per environment and is stripped inconsistently from release builds, so diagnostic output either leaks or disappears. Use a logging framework (package:logging) or debugPrint.",
      remediation="Replace print with a logger call (e.g. package:logging) or debugPrint for Flutter.",
      source="https://dart.dev/tools/linter-rules/avoid_print",
      re=r'\bprint\s*\(',
      nc="print('user id: $id');",
      c="log.info('user id: $id');",
      effort=5),
    r(id="dart-empty-catch", type="bug", qual="rel", sev="medium", cwe="CWE-390",
      title="Empty catch swallows the exception",
      desc="A catch block has an empty body, so the caught error is discarded with no logging or handling.",
      rationale="An empty catch hides a failure: the program continues in an unknown state and the error is never surfaced for diagnosis (CWE-390). Handle the exception or at least log it and rethrow.",
      remediation="Handle or log the exception (and rethrow if it cannot be handled here) instead of swallowing it.",
      source="https://cwe.mitre.org/data/definitions/390.html",
      re=r'catch\s*\([^)]*\)\s*\{\s*\}',
      nc='try { risky(); } catch (e) {}',
      c='try { risky(); } catch (e) { log.warning(e); }'),
    r(id="dart-cleartext-http", type="hotspot", qual="sec", sev="medium", cwe="CWE-319", owasp="A02:2021",
      title="Cleartext HTTP request",
      desc="A URI is parsed from an http:// literal, so the request is sent unencrypted.",
      rationale="An http:// request transmits data in cleartext and is open to interception and tampering on the network path (CWE-319). Use https:// so the connection is encrypted.",
      remediation="Use an https:// URL, or document why cleartext is acceptable for this endpoint.",
      source="https://cwe.mitre.org/data/definitions/319.html",
      re=r'''Uri\.parse\(\s*['"]http://''',
      nc='final r = await http.get(Uri.parse("http://api.example.com/v1"));',
      c='final r = await http.get(Uri.parse("https://api.example.com/v1"));'),
    r(id="dart-hardcoded-secret", type="hotspot", qual="sec", sev="high", cwe="CWE-798", owasp="A07:2021",
      title="Hard-coded credential in Dart",
      desc="A password/secret/API key is assigned a string literal, so the secret ships inside the compiled app.",
      rationale="A credential written into Dart source is embedded in the shipped binary and easily extracted from it (CWE-798). Read secrets from the environment, secure storage, or a backend the app authenticates to.",
      remediation="Read the secret from the environment, platform secure storage, or a server; never hard-code it.",
      source="https://cwe.mitre.org/data/definitions/798.html",
      skip="skipCommentOrPlaceholderSecret",
      re=r'''(?i)(password|secret|apikey|api_key|token)\s*=\s*['"][^'"${}]{8,}['"]''',
      nc='const apiKey = "sk_live_0123456789abcdef";',
      c="final apiKey = Platform.environment['API_KEY'];"),
    r(id="dart-bad-certificate-callback", type="hotspot", qual="sec", sev="high", cwe="CWE-295", owasp="A02:2021",
      title="TLS certificate validation overridden",
      desc="badCertificateCallback is assigned on an HttpClient, which replaces the platform's certificate check with the app's own decision.",
      rationale="The callback decides whether to accept a certificate the platform already rejected, and the shape it is almost always written in returns true for every host, which accepts any certificate including an attacker's and removes the protection TLS provides (CWE-295). A build that needs a self-signed certificate should pin that certificate through SecurityContext instead, so only the one expected certificate is trusted.",
      remediation="Remove the callback and trust the platform store, or pin the expected certificate with SecurityContext.setTrustedCertificates. Never return true unconditionally.",
      source="https://cwe.mitre.org/data/definitions/295.html",
      re=r'\bbadCertificateCallback\s*=',
      nc="client.badCertificateCallback = (cert, host, port) => true;",
      c="final context = SecurityContext()..setTrustedCertificates('lets-encrypt.pem');",
      effort=30),
]
