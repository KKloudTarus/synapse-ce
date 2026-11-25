package secretscan

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The rules that read a database password out of a JDBC URL or a Spring datasource property.
var datasourcePasswordRuleIDs = []string{"jdbc-connection-string", "jdbc-oracle-connection-string", "spring-datasource-password"}

// Fixtures are BUILT BY CONCATENATION so no complete credential appears in this source file, the same
// convention the rest of the package's tests keep.
const jdbcTestPassword = "Summer" + "2026!"

func scanOneFileFindings(t *testing.T, name, content string) []ports.SecretRawFinding {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	return report.Findings
}

func isDatasourcePasswordRule(id string) bool {
	for _, want := range datasourcePasswordRuleIDs {
		if id == want {
			return true
		}
	}
	return false
}

// A JDBC URL carries its password as a connection property, or in Oracle's user/password@ prefix, and a
// Spring application names it spring.datasource.password. Only the user:password@ authority form was
// detected, so a short or ordinary password in any of these shapes was reported by nothing (#1665).
// Each case must be reported once, by the rule for its shape, with the PASSWORD as the captured secret,
// which is what the fingerprint and the redacted preview are computed from.
func TestDatasourcePasswordsAreReported(t *testing.T) {
	pw := jdbcTestPassword
	at := "\x40" // '@', kept out of the source text like the package's other connection-string fixtures
	cases := []struct {
		name, file, content, rule string
	}{
		{"sqlserver semicolon property", "Db.java",
			`String a = "jdbc:sqlserver://db.internal:1433;databaseName=app;user=svc;password=` + pw + `";`, "jdbc-connection-string"},
		{"postgresql query after user", "Db.java",
			`String c = "jdbc:postgresql://db.internal:5432/app?user=svc&password=` + pw + `";`, "jdbc-connection-string"},
		{"postgresql query first parameter", "db.py",
			`url = "jdbc:postgresql://db.internal:5432/app?password=` + pw + `&user=svc"`, "jdbc-connection-string"},
		{"mysql value ends at the next parameter", "app.conf",
			`url = "jdbc:mysql://db.internal:3306/app?user=svc&password=` + pw + `&useSSL=true"`, "jdbc-connection-string"},
		{"mariadb", "Db.kt",
			`val url = "jdbc:mariadb://db.internal:3306/app?user=svc&password=` + pw + `"`, "jdbc-connection-string"},
		{"db2 colon then semicolon properties", "Db.java",
			`String d = "jdbc:db2://db.internal:50000/APP:user=svc;password=` + pw + `;";`, "jdbc-connection-string"},
		{"xml escaped ampersand", "context.xml",
			`<Resource url="jdbc:mysql://db.internal:3306/app?user=svc&amp;password=` + pw + `"/>`, "jdbc-connection-string"},
		{"uppercase property name", "Db.java",
			`String e = "jdbc:sqlserver://db.internal;User=svc;Password=` + pw + `";`, "jdbc-connection-string"},
		{"PWD property", "Db.java",
			`String f = "jdbc:databricks://adb.example.net:443/default;AuthMech=3;UID=token;PWD=` + pw + `";`, "jdbc-connection-string"},
		{"spring url property", "application.properties",
			`spring.datasource.url=jdbc:postgresql://db.internal:5432/app?user=svc&password=` + pw, "jdbc-connection-string"},
		{"oracle thin", "Db.java",
			`String b = "jdbc:oracle:thin:svc/` + pw + at + `db.internal:1521/ORCL";`, "jdbc-oracle-connection-string"},
		{"oracle thin service name", "Db.java",
			`String b = "jdbc:oracle:thin:svc/` + pw + at + `//db.internal:1521/ORCL";`, "jdbc-oracle-connection-string"},
		{"oracle oci", "Db.java",
			`String b = "jdbc:oracle:oci:svc/` + pw + at + `ORCL";`, "jdbc-oracle-connection-string"},
		{"spring properties", "application.properties",
			"spring.datasource.password=" + pw, "spring-datasource-password"},
		{"spring properties spaced", "application.properties",
			"spring.datasource.password = " + pw, "spring-datasource-password"},
		{"spring flat yaml key", "application.yml",
			"spring.datasource.password: " + pw, "spring-datasource-password"},
		{"spring flat yaml key quoted", "application.yml",
			`spring.datasource.password: "` + pw + `"`, "spring-datasource-password"},
		{"spring pool sub-key", "application.properties",
			"spring.datasource.hikari.password=" + pw, "spring-datasource-password"},
		{"spring named datasource", "application.properties",
			"spring.datasource.primary.password=" + pw, "spring-datasource-password"},
		{"spring env file", ".env",
			"SPRING_DATASOURCE_PASSWORD=" + pw, "spring-datasource-password"},
		{"spring env compose map", "compose.yaml",
			"      SPRING_DATASOURCE_PASSWORD: " + pw, "spring-datasource-password"},
		{"spring env compose list", "compose.yaml",
			"      - SPRING_DATASOURCE_PASSWORD=" + pw, "spring-datasource-password"},
		{"spring jvm system property", "run.sh",
			"java -Dspring.datasource.password=" + pw + " -jar app.jar", "spring-datasource-password"},
		{"spring json key", "config.json",
			`{"spring.datasource.password": "` + pw + `"}`, "spring-datasource-password"},
		{"spring set property call", "Boot.java",
			`System.setProperty("spring.datasource.password", "` + pw + `");`, "spring-datasource-password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []ports.SecretRawFinding
			for _, f := range scanOneFileFindings(t, tc.file, tc.content) {
				if isDatasourcePasswordRule(f.RuleID) {
					got = append(got, f)
				}
			}
			if len(got) != 1 || got[0].RuleID != tc.rule {
				t.Fatalf("want exactly one %s finding, got %+v", tc.rule, got)
			}
			if got[0].Fingerprint != secretFingerprint(pw) || got[0].Match != redactMatch(pw) {
				t.Errorf("the captured secret must be the password alone: match %q, want %q", got[0].Match, redactMatch(pw))
			}
			if got[0].Line != 1 || got[0].Severity != shared.SeverityHigh {
				t.Errorf("want line 1 at high severity, got line %d at %s", got[0].Line, got[0].Severity)
			}
		})
	}
}

// A placeholder, a mask, a reference to the environment, or ciphertext stands where the password goes; none
// of them is the password. The same shapes the user:password@ rule stands down are stood down here.
func TestDatasourcePasswordPlaceholdersAreNotReported(t *testing.T) {
	cases := []struct{ name, file, content string }{
		{"documented sqlserver template", "README.md", "`jdbc:sqlserver://<host>;password=<password>`"},
		{"sqlserver docs mask", "setup.md", "jdbc:sqlserver://localhost;encrypt=true;user=MyUserName;password=*****;"},
		{"jdbc env reference", "Db.java", `String a = "jdbc:sqlserver://db.internal:1433;user=svc;password=${DB_PASSWORD}";`},
		{"jdbc shell variable", "run.sh", `URL="jdbc:postgresql://db.internal:5432/app?user=svc&password=$DB_PASSWORD"`},
		{"jdbc windows variable", "run.bat", `set URL=jdbc:postgresql://db.internal:5432/app?user=svc^&password=%DB_PASSWORD%`},
		{"jdbc mustache", "values.tpl", `url: "jdbc:mysql://db.internal/app?user=svc&password={{password}}"`},
		{"jdbc python format", "db.py", `url = "jdbc:mysql://db.internal/app?user=svc&password={password}".format(password=pw)`},
		{"jdbc python percent", "db.py", `url = "jdbc:mysql://db.internal/app?user=svc&password=%(password)s" % cfg`},
		{"jdbc ruby interpolation", "db.rb", `url = "jdbc:mysql://db.internal/app?user=svc&password=#{password}"`},
		{"jdbc maven filter", "jdbc.properties", `db.url=jdbc:mysql://db.internal/app?user=svc&password=@db.password@`},
		{"jdbc mask", "Db.java", `String a = "jdbc:sqlserver://db.internal;user=svc;password=****";`},
		{"jdbc empty value", "Db.java", `String a = "jdbc:sqlserver://db.internal;user=svc;password=;encrypt=true";`},
		{"jdbc value concatenated", "Db.java", `String a = "jdbc:sqlserver://db.internal;user=svc;password=" + secret;`},
		{"jdbc documented words", "Db.java", `String a = "jdbc:sqlserver://db.internal:1433;user=username;password=password";`},
		{"jdbc documented words query", "README.md", "jdbc:mysql://localhost:3306/app?user=user&password=password"},
		{"oracle documented words", "Db.java", `String b = "jdbc:oracle:thin:username/password@localhost:1521:orcl";`},
		{"oracle documented words service", "README.md", "jdbc:oracle:thin:user/password@//localhost:1521/XEPDB1"},
		{"oracle env reference", "Db.java", `String b = "jdbc:oracle:thin:svc/${DB_PASSWORD}@db.internal:1521/ORCL";`},
		{"oracle mask", "Db.java", `String b = "jdbc:oracle:thin:svc/****@db.internal:1521/ORCL";`},
		{"oracle without credentials", "Db.java", `String b = "jdbc:oracle:thin:@//db.internal:1521/ORCL";`},
		{"spring env reference", "application.properties", "spring.datasource.password=${DB_PASSWORD}"},
		{"spring empty", "application.properties", "spring.datasource.password="},
		{"spring empty does not take the next line", "application.properties", "spring.datasource.password=\nspring.jpa.show-sql=true"},
		{"spring empty quoted", "application.yml", `spring.datasource.password: ""`},
		{"spring angle template", "application.properties", "spring.datasource.password=<your database password>"},
		{"spring mustache", "application.yml", "spring.datasource.password: {{password}}"},
		{"spring python percent", "application.properties", "spring.datasource.password=%(password)s"},
		{"spring mask", "application.properties", "spring.datasource.password=****"},
		{"spring maven filter", "application.properties", "spring.datasource.password=@db.password@"},
		{"spring jasypt ciphertext", "application.properties", "spring.datasource.password=ENC(bm90LWEtcmVhbC1jaXBoZXI=)"},
		{"spring config server ciphertext", "application.yml", "spring.datasource.password: '{cipher}bm90LWEtcmVhbC1jaXBoZXI='"},
		{"spring env shell variable", ".env", "SPRING_DATASOURCE_PASSWORD=$DB_PASSWORD"},
		{"spring env actions secret", "deploy.yml", "      SPRING_DATASOURCE_PASSWORD: ${{ secrets.DB_PASSWORD }}"},
		{"spring env terraform reference", "main.tf", "    SPRING_DATASOURCE_PASSWORD = var.db_password"},
		{"spring env python call", "settings.py", `SPRING_DATASOURCE_PASSWORD = os.getenv("DB_PASSWORD")`},
		{"spring env python index", "settings.py", `SPRING_DATASOURCE_PASSWORD = os.environ["DB_PASSWORD"]`},
		{"spring set property from variable", "Boot.java", `System.setProperty("spring.datasource.password", dbPassword);`},
		{"spring json key from variable", "config.js", `const props = {"spring.datasource.password": dbPassword};`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range scanOneFileFindings(t, tc.file, tc.content) {
				if isDatasourcePasswordRule(f.RuleID) {
					t.Errorf("not a credential, but %s reported %q", f.RuleID, f.Match)
				}
			}
		})
	}
}

// A Kubernetes Secret carries its values base64-encoded, so a JDBC URL there is reached through the decode
// pass, which runs every keyword rule over the decoded bytes.
func TestEncodedJDBCURLIsReported(t *testing.T) {
	url := "jdbc:sqlserver://db.internal:1433;user=svc;password=" + jdbcTestPassword
	content := "kind: Secret\ndata:\n  DB_URL: " + base64.StdEncoding.EncodeToString([]byte(url))
	for _, f := range scanOneFileFindings(t, "secret.yaml", content) {
		if f.RuleID == "jdbc-connection-string" && f.Match == redactMatch(jdbcTestPassword) && f.Line == 3 {
			return
		}
	}
	t.Errorf("a base64-encoded JDBC URL with a password must be reported at the encoded value's line")
}

// The words-only stand-down mirrors the user:password@ rule: BOTH the account and the password must be
// generic. A real account beside a weak password is a credential, and a documented example on the same
// line as a real credential does not hide the line. The scanner keeps one finding per rule per line, so on
// that mixed line the finding is the line's, not a particular URL's.
func TestJDBCDocumentedAccountNeedsBothPartsGeneric(t *testing.T) {
	at := "\x40"
	weak := "pass" + "word"
	cases := []struct{ name, content, rule string }{
		{"oracle real account weak password",
			`String b = "jdbc:oracle:thin:admin/` + weak + at + `db.internal:1521/ORCL";`, "jdbc-oracle-connection-string"},
		{"property real account weak password",
			`String a = "jdbc:sqlserver://db.internal;user=admin;password=` + weak + `";`, "jdbc-connection-string"},
		{"oracle example beside a real credential",
			`String b = "jdbc:oracle:thin:username/password@localhost:1521:orcl" + "jdbc:oracle:thin:svc/` +
				jdbcTestPassword + at + `db.internal:1521/ORCL";`, "jdbc-oracle-connection-string"},
		{"property example beside a real credential",
			`String a = "jdbc:mysql://localhost/app?user=user&password=password" + "jdbc:mysql://db.internal/app?user=svc&password=` +
				jdbcTestPassword + `";`, "jdbc-connection-string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range scanOneFileFindings(t, "Db.java", tc.content) {
				if f.RuleID == tc.rule && f.Line == 1 {
					return
				}
			}
			t.Errorf("a credential that is not the documented pair must be reported by %s", tc.rule)
		})
	}
}

// The new rules are anchored on a JDBC URL or on the Spring datasource key. A password assigned anywhere else
// stays with the entropy-gated generic rule, so these rules never become a generic password= detector, and the
// user:password@ URI form stays with db-connection-string alone, reported once.
func TestDatasourcePasswordRulesStayAnchored(t *testing.T) {
	pw := jdbcTestPassword
	at := "\x40"
	for _, tc := range []struct{ name, file, content string }{
		{"bare password key", "application.properties", "password=" + pw},
		{"other component password", "application.properties", "spring.mail.password=" + pw},
		{"other datasource-like key", "application.properties", "app.datasource.password=" + pw},
		{"password key on the line after a jdbc url", "db.properties", "url=jdbc:postgresql://db.internal/app\npassword=" + pw},
		{"keystore password inside a jdbc url", "Db.java", `String a = "jdbc:sqlserver://db.internal;trustStorePassword=` + pw + `";`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range scanOneFileFindings(t, tc.file, tc.content) {
				if isDatasourcePasswordRule(f.RuleID) {
					t.Errorf("%s fired outside its anchor: %q", f.RuleID, f.Match)
				}
			}
		})
	}
	for _, line := range []string{
		`String d = "postgres://svc:` + pw + at + `db.internal:5432/app";`,
		`String d = "jdbc:mysql://svc:` + pw + at + `db.internal:3306/app";`,
	} {
		var ids []string
		for _, f := range scanOneFileFindings(t, "Db.java", line) {
			ids = append(ids, f.RuleID)
		}
		if len(ids) != 1 || ids[0] != "db-connection-string" {
			t.Errorf("a user:password@ URI must be reported once, by db-connection-string: %q gave %v", line, ids)
		}
	}
}
