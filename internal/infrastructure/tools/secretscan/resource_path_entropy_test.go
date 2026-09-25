package secretscan

import "testing"

// TestLineDeclaresResourcePath pins the Liquibase/Flyway false positive found on a real JHipster service:
// a generated migration file name clears the 4.5 bits/char entropy floor on the base64 alphabet, so every
// <include file="classpath:db/migration/V89__seed_..._bom20260714.xml"/> produced one keyword-free secret
// hit. Both halves of the predicate are required, which is what stops it from swallowing a real credential.
func TestLineDeclaresResourcePath(t *testing.T) {
	skipped := []string{
		`    <include file="classpath:db/migration/V89__seed_ppe075gna_23s01_bom20260714.xml"/>`,
		`<include file="classpath:db/changelog/V12__add_kjZ8xQ2mNp4rLw7sTv3yBc6dEf1gHi0.sql"/>`,
		`spring.liquibase.change-log=classpath:db/changelog/db.changelog-master.xml`,
		`  <script src="/static/js/main.4f9aKq2XbN7pRtY8uZ3vC6mWdE1sG0hJ.js"></script>`,
	}
	for _, line := range skipped {
		if !lineDeclaresResourcePath(line) {
			t.Errorf("resource declaration should stand the keyword-free entropy rule down: %s", line)
		}
	}

	// A credential must still fire. None of these is a resource declaration, and the third proves the
	// predicate needs BOTH halves: it names a file but carries no non-credential extension.
	kept := []string{
		`AUTH_BLOB = "kjZ8xQ2mNp4rLw7sTv3yBc6dEf1gHi0aB"`,
		`  - name: DEPLOY_CREDENTIAL_BLOB\n    value: aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV`,
		`writeFile(path="/etc/app/creds", value="kjZ8xQ2mNp4rLw7sTv3yBc6dEf1gHi0aB")`,
	}
	for _, line := range kept {
		if lineDeclaresResourcePath(line) {
			t.Errorf("credential line must not be treated as a resource declaration: %s", line)
		}
	}
}
