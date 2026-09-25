# Rule catalog coverage matrix

This matrix is generated from the shipped first-party rule catalog. The drift test fails whenever the catalog and this snapshot diverge.

OWASP coverage is required for security-quality rules. An empty OWASP list on a non-security rule means not applicable. Direct CWE mappings follow OWASP Top 10:2021's published mapped-CWE lists where available; CWEs outside those lists use explicit Synapse-reviewed Top 10 classifications and are not presented as OWASP-published CWE crosswalks.

Catalogued rules: **3331**. Security-quality rules with an OWASP mapping: **1184/1184**.

## Sonar-equivalent type mapping

| Synapse type | Sonar-equivalent category |
| --- | --- |
| bug | BUG |
| vulnerability | VULNERABILITY |
| security_hotspot | SECURITY_HOTSPOT |
| code_smell | CODE_SMELL |

## Coverage by language and type

| Language | Bug | Vulnerability | Security hotspot | Code smell | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| Azure Resource Manager | 0 | 9 | 18 | 8 | 35 |
| C | 53 | 55 | 14 | 45 | 167 |
| C# | 46 | 76 | 28 | 155 | 305 |
| C++ | 66 | 50 | 13 | 113 | 242 |
| C/C++/Objective-C | 0 | 1 | 0 | 0 | 1 |
| CSS | 8 | 0 | 0 | 22 | 30 |
| CloudFormation | 4 | 10 | 18 | 2 | 34 |
| Dart | 1 | 0 | 3 | 1 | 5 |
| Docker Compose | 1 | 9 | 0 | 0 | 10 |
| Dockerfile | 7 | 8 | 5 | 15 | 35 |
| General | 5 | 35 | 0 | 4 | 44 |
| GitHub Actions | 0 | 4 | 0 | 0 | 4 |
| Go | 7 | 17 | 6 | 16 | 46 |
| HTML | 10 | 2 | 6 | 32 | 50 |
| IPython Notebooks | 0 | 3 | 8 | 4 | 15 |
| Java | 56 | 58 | 95 | 241 | 450 |
| JavaScript/TypeScript | 128 | 33 | 72 | 235 | 468 |
| Kotlin | 22 | 8 | 17 | 83 | 130 |
| Kubernetes | 3 | 20 | 6 | 1 | 30 |
| PHP | 32 | 22 | 44 | 84 | 182 |
| Python | 122 | 35 | 53 | 106 | 316 |
| Ruby | 9 | 14 | 10 | 8 | 41 |
| Rust | 68 | 17 | 26 | 53 | 164 |
| Scala | 18 | 1 | 3 | 19 | 41 |
| Secrets | 0 | 124 | 0 | 0 | 124 |
| Swift | 39 | 7 | 19 | 55 | 120 |
| Terraform | 10 | 21 | 24 | 9 | 64 |
| Text | 0 | 1 | 1 | 6 | 8 |
| VB.NET | 51 | 15 | 32 | 42 | 140 |
| XML | 8 | 4 | 4 | 14 | 30 |
