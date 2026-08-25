package privacy

import (
	"regexp"
	"strings"
)

// credentialAssignmentArg matches a whole argv element whose key is a known credential name and whose
// value follows '=' or ':'. The value capture deliberately accepts spaces: after shell parsing a quoted
// value such as DB_PASSWORD="two words" is one argv element with the quotes removed, and redacting only
// the first token would leak the remainder.
var credentialAssignmentArg = regexp.MustCompile(`(?i)^((?:(?:[A-Za-z0-9]+[_-])*)?(?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|secret[-_]?key|auth[-_]?token|client[-_]?secret|credential)\s*[=:]\s*)(.*)$`)

// credentialFlagValueArg is the same whole-value guard for a credential flag and value carried in ONE argv
// element (for example an unusual collector representation of "--password two words"). Normal split argv
// ("--password", "two words") remains handled by RedactArgv's cross-element rule.
var credentialFlagValueArg = regexp.MustCompile(`(?i)^(--?(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|secret[-_]?key|auth[-_]?token|client[-_]?secret|credential)(?:[=:]\s*|\s+))(.*)$`)

func scrubWholeCredentialArg(value string) (string, bool) {
	for _, re := range []*regexp.Regexp{credentialAssignmentArg, credentialFlagValueArg} {
		m := re.FindStringSubmatch(value)
		if len(m) != 3 || m[2] == "" || m[2] == RedactionPlaceholder {
			continue
		}
		return m[1] + RedactionPlaceholder, true
	}
	return value, false
}

// isMySQLPasswordClient limits ambiguous short -pVALUE handling to command families where lowercase -p is
// specifically the password option. PostgreSQL and many unrelated tools use -p for a port or another flag,
// so a global ^-p rule would destroy legitimate forensic context.
func isMySQLPasswordClient(argv0 string) bool {
	name := strings.ReplaceAll(argv0, `\`, "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".exe")
	switch name {
	case "mysql", "mysqldump", "mysqladmin", "mysqlcheck", "mysqlimport", "mysqlshow", "mysqlslap",
		"mariadb", "mariadb-dump", "mariadb-admin", "mariadb-check", "mariadb-import", "mariadb-show", "mariadb-slap":
		return true
	default:
		return false
	}
}

// scrubMySQLGluedPassword handles the documented MySQL/MariaDB short form -pPASSWORD. The command check is
// intentionally outside this helper (RedactArgv has argv0); within those client families any lowercase
// -p suffix is password material. -p=PASSWORD is accepted defensively too.
func scrubMySQLGluedPassword(arg string) (string, bool) {
	if len(arg) <= 2 || !strings.HasPrefix(arg, "-p") || strings.HasPrefix(arg, "--") {
		return arg, false
	}
	prefix, value := "-p", arg[2:]
	if strings.HasPrefix(value, "=") {
		prefix, value = "-p=", value[1:]
	}
	if value == "" || value == RedactionPlaceholder {
		return arg, false
	}
	return prefix + RedactionPlaceholder, true
}
