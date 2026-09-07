package detection

import (
	"time"

	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// catalogue is the built-in, clean-room detection rule set. Each rule is a typed matcher over one event
// class — never a shell expression. Five of the ids are the detection ids the emulation catalogue (#421)
// names as expected observables, so an executed emulation technique can be reconciled against a real
// detection by id (the purple ledger, #426); the sixth is a privilege-class rule that gives that class a
// shipped detection and is not tied to an emulation technique.
//
// Rule matchers are intentionally coarse for milestone one: they fire on the observable an emulation
// technique produces. Rate- and sequence-based refinement (e.g. a true DNS beacon cadence) waits for the
// on-host event window the engine assembles; a single-event matcher cannot count.
var catalogue = []Rule{
	{
		ID: "det.process_enumeration", Version: 1, Class: ClassProcess,
		Title: "Process enumeration (T1057)", Severity: shared.SeverityLow,
		Matcher: Matcher{Class: ClassProcess, All: []Predicate{
			{Field: FieldProcComm, Op: OpIn, Values: []string{"ps", "pgrep", "top", "htop", "tasklist"}},
		}},
	},
	{
		ID: "det.network_config_discovery", Version: 1, Class: ClassProcess,
		Title: "Network configuration discovery (T1016)", Severity: shared.SeverityLow,
		Matcher: Matcher{Class: ClassProcess, All: []Predicate{
			{Field: FieldProcComm, Op: OpIn, Values: []string{"ip", "ifconfig", "ipconfig", "route", "netstat", "ss", "arp"}},
		}},
	},
	{
		// v2: a rate, not a packet. v1 fired on every outbound DNS datagram, which is not beaconing and
		// buried the console. The window counts DNS egress per destination; a sustained two queries per
		// second to one address for a minute is tunnelling or a beacon, not name resolution.
		ID: "det.suspicious_dns_beacon", Version: 2, Class: ClassNetwork,
		Title: "DNS beaconing to one destination (T1071.004)", Severity: shared.SeverityMedium,
		Matcher: Matcher{Class: ClassNetwork, All: []Predicate{
			{Field: FieldNetProto, Op: OpEquals, Value: "udp"},
			{Field: FieldNetRemotePort, Op: OpEquals, Value: "53"},
			{Field: FieldNetDirection, Op: OpEquals, Value: "egress"},
		}},
		Window: &Window{Count: 120, Within: time.Minute, GroupBy: []Field{FieldNetRemoteAddr}},
	},
	{
		ID: "det.credential_file_access", Version: 1, Class: ClassFile,
		Title: "Credential file access (T1552.001)", Severity: shared.SeverityHigh,
		Matcher: Matcher{Class: ClassFile, All: []Predicate{
			{Field: FieldFilePath, Op: OpIn, Values: []string{"/etc/shadow", "/etc/gshadow", "/root/.ssh/id_rsa", "/root/.aws/credentials"}},
			{Field: FieldFileOp, Op: OpIn, Values: []string{"read", "open"}},
		}},
	},
	{
		ID: "det.unexpected_service_restart", Version: 1, Class: ClassProcess,
		Title: "Service restart (T1569.002)", Severity: shared.SeverityMedium,
		Matcher: Matcher{Class: ClassProcess, All: []Predicate{
			{Field: FieldProcComm, Op: OpEquals, Value: "systemctl"},
			{Field: FieldProcArg, Op: OpEquals, Value: "restart"},
		}},
	},
	{
		ID: "det.privilege_escalation_to_root", Version: 1, Class: ClassPrivilege,
		Title: "Privilege escalation to root (T1548)", Severity: shared.SeverityHigh,
		Matcher: Matcher{Class: ClassPrivilege, All: []Predicate{
			{Field: FieldPrivToUID, Op: OpEquals, Value: "0"},
			{Field: FieldPrivKind, Op: OpIn, Values: []string{"setuid", "capset"}},
		}},
	},
	{
		// A sequence, not a single event: a downloader (ingress tooling, T1105) followed by a
		// remote-shell tool on the same host within two minutes is staging then use. Neither process on
		// its own is a detection — curl is ordinary, and nc is ordinary — but the ordered pair is the
		// behaviour a single-event or rate rule cannot express. Grouped by host (the default).
		ID: "det.tool_staging_sequence", Version: 1, Class: ClassProcess,
		Title: "Tool staging then remote shell (T1105 -> T1059)", Severity: shared.SeverityHigh,
		Sequence: &Sequence{
			Within: 2 * time.Minute,
			Steps: []Matcher{
				{Class: ClassProcess, All: []Predicate{
					{Field: FieldProcComm, Op: OpIn, Values: []string{"curl", "wget", "tftp", "ftp"}},
				}},
				{Class: ClassProcess, All: []Predicate{
					{Field: FieldProcComm, Op: OpIn, Values: []string{"nc", "ncat", "socat"}},
				}},
			},
		},
	},
}

// Catalogue returns a validated copy of the built-in rule set, deterministically ordered by id so a
// coverage report and its trend compare like with like. It validates on every call rather than trusting
// the literal above, so a malformed rule fails the build via the catalogue drift test rather than
// shipping a rule that cannot produce a trustworthy detection.
func Catalogue() ([]Rule, error) {
	seen := make(map[string]struct{}, len(catalogue))
	out := make([]Rule, 0, len(catalogue))
	for _, r := range catalogue {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate rule id %q", shared.ErrValidation, r.ID)
		}
		seen[r.ID] = struct{}{}
		out = append(out, r.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Lookup returns a catalogued rule by id. The second result is false for an unknown id, which the caller
// MUST treat as "not a known detection" rather than fabricating one.
func Lookup(id string) (Rule, bool) {
	for _, r := range catalogue {
		if r.ID == id {
			if r.Validate() != nil {
				return Rule{}, false
			}
			return r.clone(), true
		}
	}
	return Rule{}, false
}

// CatalogueByClass returns the catalogued rules for one event class, deterministically ordered. The
// agent-side engine (issue #422, later phase) evaluates only the rules for the classes it can actually
// observe on a given host, so a disabled or degraded class runs no rules and reports a coverage gap.
func CatalogueByClass(c Class) ([]Rule, error) {
	all, err := Catalogue()
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(all))
	for _, r := range all {
		if r.Class == c {
			out = append(out, r)
		}
	}
	return out, nil
}
