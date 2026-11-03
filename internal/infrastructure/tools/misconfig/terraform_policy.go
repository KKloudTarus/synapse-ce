package misconfig

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AWS policy documents, read as statements rather than as lines.
//
// A wildcard token on its own says nothing. "Principal": "*" on a VPC endpoint policy is the documented
// default and grants no access by itself; the same token on a bucket policy with no condition makes the
// bucket public. An organization-constrained statement is not public, and a condition on a key that has
// nothing to do with the caller does not make one safe. This file reads Effect, Principal, Action,
// Resource and Condition together, with the policy kind the attribute's resource type establishes, and
// says which of those it could not establish instead of guessing.
//
// References:
//   - VPC endpoint policies are an additional boundary, not an independent grant:
//     https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html
//   - STS federation callers carry no principal-org context:
//     https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sts_vpc_endpoint_policies.html
//   - aws:PrincipalOrgID availability:
//     https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalorgid

// policyKind is what the document attaches to, which decides what each element means.
type policyKind int

const (
	policyUnknownKind   policyKind = iota
	policyIdentity                 // attached to a user, group, or role: no Principal element
	policyResource                 // attached to the resource it protects: Principal names who may reach it
	policyTrust                    // a role's assume-role policy: Principal names who may assume it
	policyEndpoint                 // a VPC endpoint policy: a boundary on traffic through the endpoint
	policyOrganizations            // a service control policy: a boundary, never a grant
)

func (k policyKind) usesPrincipal() bool {
	return k == policyResource || k == policyTrust || k == policyEndpoint
}

func (k policyKind) String() string {
	switch k {
	case policyIdentity:
		return "identity policy"
	case policyResource:
		return "resource policy"
	case policyTrust:
		return "role trust policy"
	case policyEndpoint:
		return "VPC endpoint policy"
	case policyOrganizations:
		return "service control policy"
	}
	return "policy"
}

// tfPolicyAttributes maps a resource type and attribute to the kind of policy it carries. An attribute
// that is not listed is not read as a policy document, so an ordinary string is never parsed as one.
var tfPolicyAttributes = map[string]map[string]policyKind{
	"aws_iam_policy":                   {"policy": policyIdentity},
	"aws_iam_role_policy":              {"policy": policyIdentity},
	"aws_iam_user_policy":              {"policy": policyIdentity},
	"aws_iam_group_policy":             {"policy": policyIdentity},
	"aws_iam_role":                     {"assume_role_policy": policyTrust, "inline_policy": policyIdentity},
	"aws_s3_bucket_policy":             {"policy": policyResource},
	"aws_s3_bucket":                    {"policy": policyResource},
	"aws_sqs_queue_policy":             {"policy": policyResource},
	"aws_sqs_queue":                    {"policy": policyResource},
	"aws_sns_topic_policy":             {"policy": policyResource},
	"aws_kms_key":                      {"policy": policyResource},
	"aws_ecr_repository_policy":        {"policy": policyResource},
	"aws_efs_file_system_policy":       {"policy": policyResource},
	"aws_secretsmanager_secret_policy": {"policy": policyResource},
	"aws_secretsmanager_secret":        {"policy": policyResource},
	"aws_glacier_vault":                {"access_policy": policyResource},
	"aws_api_gateway_rest_api":         {"policy": policyResource},
	"aws_lambda_function":              {"policy": policyResource},
	"aws_vpc_endpoint":                 {"policy": policyEndpoint},
	"aws_organizations_policy":         {"content": policyOrganizations},
}

// policyDocument is one parsed AWS policy document.
type policyDocument struct {
	Version   string            `json:"Version,omitempty"`
	Statement []policyStatement `json:"Statement"`
}

// policyStatement is one statement, with each element kept as the document wrote it. A missing element and
// an element that could not be read are different things, and the predicates below depend on the
// difference.
type policyStatement struct {
	Sid          string          `json:"Sid,omitempty"`
	Effect       string          `json:"Effect,omitempty"`
	Principal    json.RawMessage `json:"Principal,omitempty"`
	NotPrincipal json.RawMessage `json:"NotPrincipal,omitempty"`
	Action       json.RawMessage `json:"Action,omitempty"`
	NotAction    json.RawMessage `json:"NotAction,omitempty"`
	Resource     json.RawMessage `json:"Resource,omitempty"`
	NotResource  json.RawMessage `json:"NotResource,omitempty"`
	Condition    json.RawMessage `json:"Condition,omitempty"`
}

// allows reports whether the statement grants rather than restricts. AWS requires Effect; a statement that
// omits it is malformed and is read as the Allow its author meant, because reading it as Deny would hide a
// grant that a corrected document would make. An Effect that is present and is not Allow restricts.
func (s policyStatement) allows() bool {
	return s.Effect == "" || strings.EqualFold(s.Effect, "Allow")
}

// policyStrings reads an element that AWS accepts as either a string or an array of strings.
func policyStrings(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, true
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, true
	}
	return nil, false
}

// policyPrincipals flattens the Principal element. wildcard is true only when the element names every
// principal: the bare "*", or a service/AWS entry whose whole value is "*". An ARN that merely CONTAINS a
// wildcard (arn:aws:iam::123456789012:role/app-*) names a scoped set, not everyone.
func policyPrincipals(raw json.RawMessage) (ids []string, wildcard, readable bool) {
	if len(raw) == 0 {
		return nil, false, false
	}
	if vals, ok := policyStrings(raw); ok {
		for _, v := range vals {
			if v == "*" {
				wildcard = true
			}
		}
		return vals, wildcard, true
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false, false
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vals, ok := policyStrings(obj[k])
		if !ok {
			return nil, false, false
		}
		for _, v := range vals {
			ids = append(ids, k+":"+v)
			if v == "*" {
				wildcard = true
			}
		}
	}
	return ids, wildcard, true
}

// policyCondition is one condition entry, already flattened to operator/key/values.
type policyCondition struct {
	operator string
	key      string
	values   []string
	// unreadable marks a condition whose values could not be read, so it can neither restrict nor be
	// dismissed.
	unreadable bool
}

func policyConditions(raw json.RawMessage) ([]policyCondition, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	var byOp map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byOp); err != nil {
		return nil, false
	}
	var out []policyCondition
	ops := make([]string, 0, len(byOp))
	for op := range byOp {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		keys := make([]string, 0, len(byOp[op]))
		for k := range byOp[op] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vals, ok := policyStrings(byOp[op][k])
			out = append(out, policyCondition{operator: op, key: k, values: vals, unreadable: !ok || policyHasUnresolved(vals)})
		}
	}
	return out, true
}

// principalScopingKeys are the condition keys that constrain WHO the statement applies to.
var principalScopingKeys = map[string]bool{
	"aws:principalorgid":         true,
	"aws:principalorgpaths":      true,
	"aws:principalaccount":       true,
	"aws:principalarn":           true,
	"aws:principalistawsservice": true,
	"aws:principaltag":           true,
	"aws:sourceaccount":          true,
	"aws:sourceowner":            true,
	"aws:sourcearn":              true,
	"aws:sourcevpce":             true,
	"aws:sourcevpc":              true,
	"aws:sourceorgid":            true,
	"aws:useragent":              false,
}

// resourceScopingKeys constrain WHAT the statement reaches, which is how a federation statement is scoped
// when its principal cannot be.
var resourceScopingKeys = map[string]bool{
	"aws:resourceorgid":    true,
	"aws:resourceaccount":  true,
	"aws:resourceorgpaths": true,
	"aws:resourcetag":      true,
}

// positiveMatchOperators restrict a value to a set. A negated operator (StringNotEquals) excludes members
// rather than naming the allowed ones, and a null check says only whether the key is present.
func positiveMatchOperator(op string) bool {
	l := strings.ToLower(strings.TrimPrefix(strings.ToLower(op), "forallvalues:"))
	l = strings.TrimPrefix(l, "foranyvalue:")
	switch l {
	case "stringequals", "stringequalsignorecase", "stringlike",
		"arnequals", "arnlike", "bool", "numericequals", "ipaddress",
		"dateequals", "binaryequals", "stringequalsifexists", "arnlikeifexists":
		return true
	}
	return false
}

// restriction is what a statement's conditions were found to do.
type restriction int

const (
	restrictionNone    restriction = iota // no condition narrows the statement
	restrictionUnknown                    // a condition could narrow it, but its value is not established here
	restrictionNetwork                    // narrowed to a network perimeter (source IP, VPC, endpoint)
	restrictionCaller                     // narrowed to a named set of callers (an org, an account, an ARN)
)

// assessConditions decides what the statement's conditions actually do to the caller set. A condition on a
// key that does not scope the caller leaves the statement as open as it was written.
func assessConditions(conds []policyCondition, keys map[string]bool) (restriction, []string) {
	best := restrictionNone
	var effective []string
	for _, c := range conds {
		key := strings.ToLower(c.key)
		if !positiveMatchOperator(c.operator) {
			continue
		}
		scoping := keys[key]
		network := key == "aws:sourceip" || key == "aws:sourcevpc" || key == "aws:sourcevpce"
		if !scoping && !network {
			continue
		}
		if c.unreadable || len(c.values) == 0 || tfAllWildcard(c.values) {
			if best < restrictionUnknown {
				best = restrictionUnknown
			}
			continue
		}
		level := restrictionCaller
		if network && !scoping {
			level = restrictionNetwork
		}
		if level > best {
			best = level
		}
		effective = append(effective, c.operator+" on "+c.key)
	}
	return best, effective
}

func tfAllWildcard(vals []string) bool {
	for _, v := range vals {
		if v != "*" {
			return false
		}
	}
	return len(vals) > 0
}

// stsFederationOnly reports whether every action is a federated AssumeRole call. Such a caller is
// authenticated by an external identity provider and carries no aws:PrincipalOrgID, so recommending a
// principal-org restriction would break the federation rather than secure it.
func stsFederationOnly(actions []string) bool {
	if len(actions) == 0 {
		return false
	}
	for _, a := range actions {
		switch strings.ToLower(a) {
		case "sts:assumerolewithwebidentity", "sts:assumerolewithsaml":
		default:
			return false
		}
	}
	return true
}

func containsWildcardToken(vals []string) bool {
	for _, v := range vals {
		if v == "*" {
			return true
		}
	}
	return false
}

// tfPolicyFinding is one assessed statement, located at the attribute that carries the document.
type tfPolicySite struct {
	file string
	line int
	res  string
	kind policyKind
	doc  policyDocument
	// endLine bounds the source the document occupies, so the line rules do not report the same tokens.
	endLine int
}

// assess turns one policy site into findings. Every claim it makes is backed by the elements it read; what
// it could not read is reported as unresolved rather than as either safe or exposed.
func (s tfPolicySite) assess() []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	add := func(rule, title string, sev shared.Severity, desc string) {
		out = append(out, ports.MisconfigRawFinding{
			File: s.file, Line: s.line, RuleID: rule, Title: title, Severity: sev,
			Resource: "Terraform " + clip(s.res), Description: desc,
		})
	}
	for _, st := range s.doc.Statement {
		if !st.allows() {
			continue // a Deny statement restricts; it never exposes
		}
		if len(st.NotAction) > 0 || len(st.NotResource) > 0 || len(st.NotPrincipal) > 0 {
			continue // an inverted element names what is excluded; this evaluator does not claim its effect
		}
		actions, actionsOK := policyStrings(st.Action)
		resources, resourcesOK := policyStrings(st.Resource)
		principals, wildcardPrincipal, principalsOK := policyPrincipals(st.Principal)
		conds, condsOK := policyConditions(st.Condition)
		federation := stsFederationOnly(actions)
		where := s.kind.String()
		if st.Sid != "" {
			where = "the statement " + clip(st.Sid) + " of this " + where
		} else {
			where = "a statement of this " + where
		}

		if actionsOK && containsWildcardToken(actions) {
			add("terraform-iam-wildcard", "IAM policy grants a wildcard action", shared.SeverityMedium,
				"In "+where+", Action is \"*\", so the statement grants every action the policy can grant rather than the ones the workload performs. List the actions required.")
		}

		callerLevel := restrictionUnknown
		if condsOK {
			callerLevel, _ = assessConditions(conds, principalScopingKeys)
		}

		if s.kind.usesPrincipal() && principalsOK && wildcardPrincipal {
			switch {
			case callerLevel == restrictionCaller:
				// A named organization, account, ARN, or service: the statement is constrained, so no
				// public-access claim is made. A least-privilege concern can still stand on its own.
			case callerLevel == restrictionUnknown:
				add("terraform-wildcard-principal", "Policy grants any principal under an unresolved restriction", shared.SeverityMedium,
					"In "+where+", Principal is \"*\" and the condition that would narrow it has a value this scan could not establish. Whether the statement is constrained is UNKNOWN: confirm the condition value, and keep the principal scoped to the accounts, roles, or services that need it.")
			case callerLevel == restrictionNetwork:
				add("terraform-wildcard-principal", "Policy grants any principal within a network boundary", shared.SeverityMedium,
					"In "+where+", Principal is \"*\" and only a network condition (source IP, VPC, or endpoint) narrows it, so every identity reaching from that network is granted. Scope the principal to the accounts, roles, or services that need it.")
			case s.kind == policyEndpoint:
				add("terraform-wildcard-principal", "Endpoint policy adds no boundary", shared.SeverityMedium,
					"This VPC endpoint policy allows any principal with no condition, so it adds no boundary to traffic through the endpoint. It does not by itself grant access to the target service, which still enforces its own identity and resource policies. Constrain the endpoint policy to the organization, accounts, or roles that use it.")
			case federation:
				add("terraform-wildcard-principal", "Federation statement allows any principal", shared.SeverityMedium,
					"In "+where+", Principal is \"*\" for a federated AssumeRole action. A web-identity or SAML caller carries no aws:PrincipalOrgID, so a principal-org condition would break the federation; scope the DESTINATION instead with aws:ResourceOrgID, aws:ResourceAccount, or an explicit role ARN in Resource.")
			default:
				add("terraform-wildcard-principal", "Policy grants access to any principal", shared.SeverityHigh,
					"In "+where+", Principal is \"*\" with no condition that narrows the caller, so the resource is reachable by every AWS principal. Scope the principal to specific accounts, roles, or services, or add an aws:PrincipalOrgID / aws:SourceAccount condition.")
			}
		}

		if resourcesOK && containsWildcardToken(resources) && s.kind != policyTrust {
			resourceLevel := restrictionNone
			if condsOK {
				resourceLevel, _ = assessConditions(conds, resourceScopingKeys)
			}
			switch {
			case resourceLevel == restrictionCaller:
				// Narrowed by aws:ResourceOrgID / aws:ResourceAccount: the wildcard reaches a named scope.
			case federation:
				add("terraform-iam-wildcard-resource", "Federation statement has no destination scope", shared.SeverityMedium,
					"In "+where+", Resource is \"*\" for a federated AssumeRole action, so the statement names no destination role. Scope it with an explicit role ARN, aws:ResourceOrgID, or aws:ResourceAccount; this is the restriction that applies when the caller carries no principal-org context.")
			case s.kind == policyEndpoint:
				add("terraform-iam-wildcard-resource", "Endpoint policy targets every resource", shared.SeverityMedium,
					"This VPC endpoint policy sets Resource to \"*\", so it narrows nothing about what traffic through the endpoint may reach. Name the buckets, tables, or ARNs the endpoint is for.")
			case resourceLevel == restrictionUnknown:
				add("terraform-iam-wildcard-resource", "Wildcard resource under an unresolved restriction", shared.SeverityMedium,
					"In "+where+", Resource is \"*\" and the condition that would narrow it has a value this scan could not establish. Whether the statement is scoped is UNKNOWN: confirm the condition value, and scope Resource to the ARNs the workload needs.")
			default:
				add("terraform-iam-wildcard-resource", "IAM policy grants a wildcard resource", shared.SeverityHigh,
					"In "+where+", Resource is \"*\" with no condition that narrows it, so the granted actions apply to every resource the policy can reach rather than to specific ARNs. Scope Resource to the ARNs the workload needs.")
			}
		}
		_ = principals
	}
	return out
}

// tfPolicyDocData renders every `data "aws_iam_policy_document"` block in the module as the JSON string its
// `.json` attribute produces, so a resource that references one is assessed as the document it will carry.
// A block whose values do not evaluate is skipped, leaving the reference unresolved.
func tfPolicyDocData(m *tfModule, ctx *hcl.EvalContext) cty.Value {
	docs := map[string]cty.Value{}
	for _, src := range m.sources {
		body, ok := src.file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, blk := range body.Blocks {
			if blk.Type != "data" || len(blk.Labels) != 2 || blk.Labels[0] != "aws_iam_policy_document" {
				continue
			}
			doc, ok := policyDocFromHCL(blk.Body, ctx)
			if !ok {
				continue
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				continue
			}
			docs[blk.Labels[1]] = cty.ObjectVal(map[string]cty.Value{
				"json":          cty.StringVal(string(raw)),
				"minified_json": cty.StringVal(string(raw)),
				"id":            cty.StringVal(blk.Labels[1]),
			})
		}
	}
	if len(docs) == 0 {
		return cty.NilVal
	}
	return cty.ObjectVal(map[string]cty.Value{"aws_iam_policy_document": cty.ObjectVal(docs)})
}

// policyDocFromHCL converts an aws_iam_policy_document body into the same statement model the JSON form
// produces. An attribute that does not evaluate makes the whole document unavailable, because a statement
// read with a missing element would be assessed as something the operator did not write.
func policyDocFromHCL(body *hclsyntax.Body, ctx *hcl.EvalContext) (policyDocument, bool) {
	doc := policyDocument{Version: "2012-10-17"}
	str := func(b *hclsyntax.Body, name string) (string, bool, bool) {
		attr, ok := b.Attributes[name]
		if !ok {
			return "", false, true
		}
		v, d := attr.Expr.Value(ctx)
		if d.HasErrors() || !v.IsWhollyKnown() || v.IsNull() || v.Type() != cty.String {
			return "", false, false
		}
		return v.AsString(), true, true
	}
	list := func(b *hclsyntax.Body, name string) ([]string, bool, bool) {
		attr, ok := b.Attributes[name]
		if !ok {
			return nil, false, true
		}
		v, d := attr.Expr.Value(ctx)
		if d.HasErrors() || !v.IsWhollyKnown() || v.IsNull() {
			return nil, false, false
		}
		var out []string
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			if ev.IsNull() || ev.Type() != cty.String {
				return nil, false, false
			}
			out = append(out, ev.AsString())
		}
		return out, true, true
	}
	for _, blk := range body.Blocks {
		if blk.Type != "statement" {
			continue
		}
		st := policyStatement{Effect: "Allow"}
		if v, present, ok := str(blk.Body, "sid"); !ok {
			return doc, false
		} else if present {
			st.Sid = v
		}
		if v, present, ok := str(blk.Body, "effect"); !ok {
			return doc, false
		} else if present {
			st.Effect = v
		}
		for _, pair := range []struct {
			attr string
			dst  *json.RawMessage
		}{
			{"actions", &st.Action}, {"not_actions", &st.NotAction},
			{"resources", &st.Resource}, {"not_resources", &st.NotResource},
		} {
			vals, present, ok := list(blk.Body, pair.attr)
			if !ok {
				return doc, false
			}
			if present {
				raw, err := json.Marshal(vals)
				if err != nil {
					return doc, false
				}
				*pair.dst = raw
			}
		}
		principals := map[string][]string{}
		notPrincipals := map[string][]string{}
		conds := map[string]map[string][]string{}
		for _, sub := range blk.Body.Blocks {
			switch sub.Type {
			case "principals", "not_principals":
				typ, present, ok := str(sub.Body, "type")
				if !ok || !present {
					return doc, false
				}
				ids, present, ok := list(sub.Body, "identifiers")
				if !ok || !present {
					return doc, false
				}
				if sub.Type == "principals" {
					principals[typ] = append(principals[typ], ids...)
				} else {
					notPrincipals[typ] = append(notPrincipals[typ], ids...)
				}
			case "condition":
				test, tOK, ok1 := str(sub.Body, "test")
				variable, vOK, ok2 := str(sub.Body, "variable")
				values, valOK, ok3 := list(sub.Body, "values")
				if !ok1 || !ok2 || !ok3 || !tOK || !vOK || !valOK {
					return doc, false
				}
				if conds[test] == nil {
					conds[test] = map[string][]string{}
				}
				conds[test][variable] = append(conds[test][variable], values...)
			}
		}
		if len(principals) > 0 {
			raw, err := json.Marshal(principals)
			if err != nil {
				return doc, false
			}
			st.Principal = raw
		}
		if len(notPrincipals) > 0 {
			raw, err := json.Marshal(notPrincipals)
			if err != nil {
				return doc, false
			}
			st.NotPrincipal = raw
		}
		if len(conds) > 0 {
			raw, err := json.Marshal(conds)
			if err != nil {
				return doc, false
			}
			st.Condition = raw
		}
		doc.Statement = append(doc.Statement, st)
	}
	return doc, true
}

// tfCollectPolicySites finds every attribute that carries a policy document, evaluates it, and returns the
// sites it could read plus the attributes it could not. A site that was read is also a source span the line
// rules must leave alone, so the same tokens are not reported twice under different reasoning.
func tfCollectPolicySites(m *tfModule, ctx *hcl.EvalContext) (sites []tfPolicySite, unresolved []string, docSpans tfPolicySpans) {
	docSpans = tfPolicySpans{}
	consumed := map[string]bool{}
	for _, src := range m.sources {
		body, ok := src.file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, blk := range body.Blocks {
			if blk.Type != "resource" || len(blk.Labels) != 2 {
				continue
			}
			attrsOfType, known := tfPolicyAttributes[blk.Labels[0]]
			if !known {
				continue
			}
			for name, kind := range attrsOfType {
				attr, ok := blk.Body.Attributes[name]
				if !ok {
					continue
				}
				rng := attr.SrcRange
				var raw []byte
				if v, d := attr.Expr.Value(ctx); !d.HasErrors() && v.IsWhollyKnown() && !v.IsNull() && v.Type() == cty.String {
					raw = []byte(v.AsString())
				} else if partial, ok := policyJSONFromExpr(attr.Expr, ctx); ok {
					raw = partial
					unresolved = append(unresolved, fmt.Sprintf("%s:%d: %s (%s, partially evaluated)", src.rel, rng.Start.Line, name, kind))
				}
				var doc policyDocument
				if len(raw) == 0 || json.Unmarshal(raw, &doc) != nil || len(doc.Statement) == 0 {
					unresolved = append(unresolved, fmt.Sprintf("%s:%d: %s (%s)", src.rel, rng.Start.Line, name, kind))
					continue
				}
				for _, ref := range policyDocumentRefs(attr.Expr) {
					consumed[ref] = true
				}
				sites = append(sites, tfPolicySite{
					file: src.rel, line: rng.Start.Line, res: blk.Labels[0], kind: kind, doc: doc,
					endLine: rng.End.Line,
				})
			}
		}
	}
	// A policy document data source that a site actually carries is assessed through that site, so its own
	// lines must not be reported again from their literal tokens. One that no site consumes keeps its line
	// rules: it attaches to nothing this scanner recognises, and dropping it would be a silent gap.
	for _, src := range m.sources {
		body, ok := src.file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, blk := range body.Blocks {
			if blk.Type != "data" || len(blk.Labels) != 2 || blk.Labels[0] != "aws_iam_policy_document" {
				continue
			}
			if !consumed[blk.Labels[1]] {
				continue
			}
			docSpans.add(src.rel, blk.DefRange().Start.Line, blk.Body.SrcRange.End.Line)
		}
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}
		return sites[i].line < sites[j].line
	})
	return sites, unresolved, docSpans
}

// tfPolicySpans is the set of source lines a structurally assessed policy occupies, per file.
type tfPolicySpans map[string][][2]int

func (s tfPolicySpans) add(file string, from, to int) {
	s[file] = append(s[file], [2]int{from, to})
}

func (s tfPolicySpans) covers(file string, line int) bool {
	for _, r := range s[file] {
		if line >= r[0] && line <= r[1] {
			return true
		}
	}
	return false
}

// policyUnresolvedToken marks an element of a policy document whose value could not be established within
// the bounded evaluation contract. It is deliberately unrepresentable in a real document, so it can never
// be confused with a value an operator wrote. A statement carrying it is assessed as UNKNOWN in that
// element, never as restricted and never as exposed.
const policyUnresolvedToken = "\x00unresolved\x00"

func policyHasUnresolved(vals []string) bool {
	for _, v := range vals {
		if v == policyUnresolvedToken {
			return true
		}
	}
	return false
}

// policyJSONFromExpr renders a `jsonencode({...})` argument as a policy document even when part of it does
// not evaluate, substituting policyUnresolvedToken for the leaves it could not establish. Reading the rest
// of the statement is what separates "an organization condition whose value this scan cannot confirm" from
// "no condition at all".
func policyJSONFromExpr(expr hclsyntax.Expression, ctx *hcl.EvalContext) ([]byte, bool) {
	call, ok := expr.(*hclsyntax.FunctionCallExpr)
	if !ok || call.Name != "jsonencode" || len(call.Args) != 1 {
		return nil, false
	}
	v, ok := policyAnyFromExpr(call.Args[0], ctx)
	if !ok {
		return nil, false
	}
	raw, err := json.Marshal(v)
	return raw, err == nil
}

func policyAnyFromExpr(expr hclsyntax.Expression, ctx *hcl.EvalContext) (any, bool) {
	switch e := expr.(type) {
	case *hclsyntax.ObjectConsExpr:
		out := map[string]any{}
		for _, item := range e.Items {
			kv, d := item.KeyExpr.Value(ctx)
			if d.HasErrors() || !kv.IsWhollyKnown() || kv.IsNull() || kv.Type() != cty.String {
				return nil, false
			}
			val, ok := policyAnyFromExpr(item.ValueExpr, ctx)
			if !ok {
				return nil, false
			}
			out[kv.AsString()] = val
		}
		return out, true
	case *hclsyntax.TupleConsExpr:
		out := make([]any, 0, len(e.Exprs))
		for _, sub := range e.Exprs {
			v, ok := policyAnyFromExpr(sub, ctx)
			if !ok {
				return nil, false
			}
			out = append(out, v)
		}
		return out, true
	}
	v, d := expr.Value(ctx)
	if d.HasErrors() || !v.IsWhollyKnown() {
		return policyUnresolvedToken, true
	}
	return ctyToAny(v)
}

func ctyToAny(v cty.Value) (any, bool) {
	if v.IsNull() {
		return nil, true
	}
	t := v.Type()
	switch {
	case t == cty.String:
		return v.AsString(), true
	case t == cty.Bool:
		return v.True(), true
	case t == cty.Number:
		f, _ := v.AsBigFloat().Float64()
		return f, true
	case t.IsListType(), t.IsSetType(), t.IsTupleType():
		out := []any{}
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			sub, ok := ctyToAny(ev)
			if !ok {
				return nil, false
			}
			out = append(out, sub)
		}
		return out, true
	case t.IsObjectType(), t.IsMapType():
		out := map[string]any{}
		for it := v.ElementIterator(); it.Next(); {
			kv, ev := it.Element()
			sub, ok := ctyToAny(ev)
			if !ok {
				return nil, false
			}
			out[kv.AsString()] = sub
		}
		return out, true
	}
	return nil, false
}

// policyDocumentRefs returns the aws_iam_policy_document data sources an expression reads.
func policyDocumentRefs(expr hclsyntax.Expression) []string {
	var out []string
	for _, tr := range expr.Variables() {
		if len(tr) < 3 || tr.RootName() != "data" {
			continue
		}
		kind, ok := tr[1].(hcl.TraverseAttr)
		if !ok || kind.Name != "aws_iam_policy_document" {
			continue
		}
		name, ok := tr[2].(hcl.TraverseAttr)
		if !ok {
			continue
		}
		out = append(out, name.Name)
	}
	return out
}
