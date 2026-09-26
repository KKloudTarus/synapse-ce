package misconfig

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// An OpenAPI document is the contract a gateway enforces, so what it omits is what the gateway will not check.
// A spec with no security requirement publishes every operation unauthenticated; an operation that declares an
// empty one opts out of the authentication the rest of the API has; an apiKey scheme beside an http:// server
// puts the key on the wire in clear; and an array with no maxItems is an unbounded request body.
//
// Both dialects are read: OpenAPI 3 (servers, components.securitySchemes) and Swagger 2 (schemes,
// securityDefinitions). Only the fields these four rules need are modelled, so an unrecognised document
// contributes nothing rather than a guess.

// openAPIDoc is the slice of a specification these rules inspect.
type openAPIDoc struct {
	OpenAPI string `yaml:"openapi"`
	Swagger string `yaml:"swagger"`
	// Security is the document-wide requirement. An absent field and an empty list differ: absent means the
	// document never states one, empty means it states that none is required.
	Security *[]map[string][]string `yaml:"security"`
	Schemes  []string               `yaml:"schemes"` // Swagger 2
	Servers  []struct {
		URL string `yaml:"url"`
	} `yaml:"servers"` // OpenAPI 3
	SecurityDefinitions map[string]openAPIScheme `yaml:"securityDefinitions"` // Swagger 2
	Components          struct {
		SecuritySchemes map[string]openAPIScheme `yaml:"securitySchemes"`
	} `yaml:"components"`
	Paths map[string]map[string]yaml.Node `yaml:"paths"`
}

type openAPIScheme struct {
	Type string `yaml:"type"`
	In   string `yaml:"in"`
	Name string `yaml:"name"`
}

// openAPIOperation is one path item's operation, read only for its own security requirement.
type openAPIOperation struct {
	Security *[]map[string][]string `yaml:"security"`
}

// openAPIMethods are the HTTP methods a path item can carry. Anything else under a path (parameters, servers,
// a $ref) is not an operation and is skipped.
var openAPIMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

// looksOpenAPI is the content pre-filter: the document must declare its dialect version and carry paths. A
// YAML file that merely mentions the word contributes nothing.
func looksOpenAPI(data []byte) bool {
	t := string(data)
	hasVersion := strings.Contains(t, "openapi:") || strings.Contains(t, "swagger:") ||
		strings.Contains(t, `"openapi"`) || strings.Contains(t, `"swagger"`)
	return hasVersion && (strings.Contains(t, "paths:") || strings.Contains(t, `"paths"`))
}

// scanOpenAPI returns the findings for one OpenAPI or Swagger document.
func scanOpenAPI(rel string, data []byte) []ports.MisconfigRawFinding {
	if tooDeepYAML(data) {
		return nil
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil
	}
	var doc openAPIDoc
	if err := node.Decode(&doc); err != nil {
		return nil
	}
	if doc.OpenAPI == "" && doc.Swagger == "" {
		return nil
	}

	var out []ports.MisconfigRawFinding
	add := func(rule, title, desc, key, resource string, sev shared.Severity) {
		line := firstKeyLine(&node, key)
		if line == 0 {
			line = 1
		}
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: rule, Title: title, Severity: sev,
			Resource: resource, Description: desc,
		})
	}

	// A document that never states a security requirement leaves every operation that does not state its own
	// open, which is the default a gateway will enforce.
	if doc.Security == nil || len(*doc.Security) == 0 {
		add("openapi-no-global-security", "API declares no security requirement",
			"The document states no top-level security requirement, so every operation that does not declare its own is published unauthenticated. Declare a security requirement at the document level and narrow it per operation where a route is deliberately public.",
			"security", "document", shared.SeverityMedium)
	}

	// An apiKey carried in a header or query string is a bearer credential in clear text unless the transport
	// is TLS. A declared http:// server, or a Swagger 2 http scheme, says it is not.
	if cleartext, where := openAPICleartextTransport(&doc); cleartext {
		for name, scheme := range openAPISchemes(&doc) {
			if !strings.EqualFold(strings.TrimSpace(scheme.Type), "apiKey") {
				continue
			}
			add("openapi-apikey-over-cleartext", "API key sent over cleartext transport",
				"Security scheme "+clip(name)+" carries an API key in the "+clip(orDefault(scheme.In, "request"))+
					", and the document declares "+where+", so the key travels in clear and is readable by anything on the path. Serve the API over https only.",
				"servers", "securityScheme/"+clip(name), shared.SeverityHigh)
			break // one finding per document: the remediation is the transport, not each scheme
		}
	}

	// An operation with an EMPTY security list opts out of whatever the document requires. That is a
	// deliberate hole, and it is reported separately from a document that never required anything.
	for path, item := range doc.Paths {
		for method, raw := range item {
			if !openAPIMethods[strings.ToLower(strings.TrimSpace(method))] {
				continue
			}
			var op openAPIOperation
			if err := raw.Decode(&op); err != nil {
				continue
			}
			if op.Security != nil && len(*op.Security) == 0 {
				out = append(out, ports.MisconfigRawFinding{
					File: rel, Line: lineOrOne(&raw), RuleID: "openapi-operation-security-empty",
					Title:       "Operation opts out of authentication",
					Severity:    shared.SeverityHigh,
					Resource:    clip(strings.ToUpper(method) + " " + path),
					Description: "The operation declares an empty security list, which removes the document's security requirement for this route alone. Remove the override, or state in the specification why this route is public.",
				})
			}
		}
	}
	out = append(out, openAPIUnboundedRequestArrays(rel, &node)...)
	out = append(out, openAPIUnboundedResponseCollections(rel, &node)...)
	return out
}

// maxOpenAPISchemaDepth bounds the schema walk independently of the YAML depth guard.
const maxOpenAPISchemaDepth = 40

// maxOpenAPIRefSegments bounds a local $ref pointer. A real one is "#/components/schemas/Name": four
// segments. Anything longer is refused rather than walked.
const maxOpenAPIRefSegments = 6

// openAPIRefs resolves a local $ref against the document that wrote it. A remote or non-local pointer is
// never followed: what it contains is not in this document, so resolving it would be a guess.
type openAPIRefs struct{ root *yaml.Node }

func (r openAPIRefs) resolve(ref string) *yaml.Node {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	segments := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
	if len(segments) == 0 || len(segments) > maxOpenAPIRefSegments {
		return nil
	}
	node := r.root
	for _, segment := range segments {
		if segment == "" {
			return nil
		}
		node = childByKey(mappingOf(node), segment)
		if node == nil {
			return nil
		}
	}
	return node
}

// deref follows a chain of local $refs to the node they name, refusing to revisit one so a cyclic
// specification terminates.
func (r openAPIRefs) deref(node *yaml.Node, seen map[string]bool, depth int) *yaml.Node {
	for i := 0; node != nil && i < maxOpenAPIRefDepth; i++ {
		mapping := mappingOf(node)
		if mapping == nil {
			return node
		}
		ref := scalarByKey(mapping, "$ref")
		if ref == "" {
			return mapping
		}
		if seen[ref] || depth+i >= maxOpenAPISchemaDepth {
			return nil
		}
		seen[ref] = true
		node = r.resolve(ref)
	}
	return node
}

// maxOpenAPIRefDepth bounds one $ref chain.
const maxOpenAPIRefDepth = 12

// openAPIUnboundedRequestArrays flags an array in a REQUEST schema that states no maxItems.
//
// The size of a request array is chosen by the caller, so an unbounded one is an allocation the client
// controls: a body declaring ten million items is a valid document the service must materialise. A RESPONSE
// array is bounded by the service's own data and is deliberately not flagged, which is the difference between
// this and the unconditional check other scanners ship.
//
// A local $ref is followed wherever it points inside the document (components.schemas, components.parameters,
// components.requestBodies), because a request body naming a shared schema is the ordinary way a specification
// is written and the array is usually only in the shared definition.
func openAPIUnboundedRequestArrays(rel string, root *yaml.Node) []ports.MisconfigRawFinding {
	doc := mappingOf(root)
	if doc == nil {
		return nil
	}
	refs := openAPIRefs{root: doc}
	var out []ports.MisconfigRawFinding
	seenRef := map[string]bool{}

	var walk func(node *yaml.Node, where string, depth int)
	walk = func(node *yaml.Node, where string, depth int) {
		if node == nil || depth > maxOpenAPISchemaDepth || len(out) >= maxOpenAPIArrayFindings {
			return
		}
		switch node.Kind {
		case yaml.MappingNode:
			if ref := scalarByKey(node, "$ref"); ref != "" {
				if !seenRef[ref] {
					seenRef[ref] = true
					walk(refs.resolve(ref), where, depth+1)
				}
				return
			}
			if strings.EqualFold(scalarByKey(node, "type"), "array") && childByKey(node, "maxItems") == nil {
				out = append(out, ports.MisconfigRawFinding{
					File: rel, Line: lineOrOne(node), RuleID: "openapi-request-array-unbounded",
					Title:    "Request array has no maximum size",
					Severity: shared.SeverityLow, Resource: clip(where),
					Description: "The array in this request schema states no maxItems, so the caller chooses how many elements to send and the service must materialise all of them. Declare maxItems. A response array is bounded by the service's own data and is not flagged.",
				})
			}
			for i := 0; i+1 < len(node.Content); i += 2 {
				walk(node.Content[i+1], where, depth+1)
			}
		case yaml.SequenceNode:
			for _, item := range node.Content {
				walk(item, where, depth+1)
			}
		}
	}

	paths := mappingOf(childByKey(doc, "paths"))
	if paths == nil {
		return nil
	}
	for i := 0; i+1 < len(paths.Content); i += 2 {
		path := paths.Content[i].Value
		item := mappingOf(paths.Content[i+1])
		if item == nil {
			continue
		}
		for j := 0; j+1 < len(item.Content); j += 2 {
			method := strings.ToLower(strings.TrimSpace(item.Content[j].Value))
			if !openAPIMethods[method] {
				continue
			}
			op := mappingOf(item.Content[j+1])
			where := strings.ToUpper(method) + " " + path
			walk(childByKey(op, "requestBody"), where, 0)
			walk(childByKey(op, "parameters"), where, 0)
		}
	}
	return out
}

// openAPICollectionWrappers are the property names a specification uses for the collection inside an envelope
// response. A response body is either the array itself or an object with one of these holding it.
var openAPICollectionWrappers = []string{"data", "items", "content", "results", "records", "list", "rows", "elements"}

// openAPIPageSizeParams are parameter names that bound how MANY elements one response carries. A page NUMBER
// (`page`, `offset`, `cursor`) is deliberately absent: it selects which window is returned, not how large it
// is, so a maximum on it bounds nothing.
var openAPIPageSizeParams = map[string]bool{
	"limit": true, "size": true, "per_page": true, "perpage": true, "pagesize": true, "page_size": true,
	"page_limit": true, "pagelimit": true, "top": true, "count": true, "first": true, "max": true,
	"maxresults": true, "max_results": true, "max_size": true, "maxsize": true,
}

// openAPIUnboundedResponseCollections flags an operation that returns a collection whose size nothing bounds.
//
// A response array is bounded by the service's own data, which is why the request rule above does not look at
// it. What makes it a defect is the pair: the collection declares no maxItems AND the operation has no
// page-size parameter with a `maximum`, so nothing in the contract stops one call from returning the whole
// table. A paginated endpoint whose page size is capped is correct and is not reported, and neither is a
// nested array on an object the operation returns: only the collection the operation IS.
func openAPIUnboundedResponseCollections(rel string, root *yaml.Node) []ports.MisconfigRawFinding {
	doc := mappingOf(root)
	if doc == nil {
		return nil
	}
	paths := mappingOf(childByKey(doc, "paths"))
	if paths == nil {
		return nil
	}
	refs := openAPIRefs{root: doc}
	var out []ports.MisconfigRawFinding
	for i := 0; i+1 < len(paths.Content); i += 2 {
		path := paths.Content[i].Value
		item := mappingOf(paths.Content[i+1])
		if item == nil {
			continue
		}
		pathParams := childByKey(item, "parameters")
		for j := 0; j+1 < len(item.Content) && len(out) < maxOpenAPIArrayFindings; j += 2 {
			method := strings.ToLower(strings.TrimSpace(item.Content[j].Value))
			if !openAPIMethods[method] {
				continue
			}
			op := mappingOf(item.Content[j+1])
			if op == nil {
				continue
			}
			if openAPIHasBoundedPageSize(refs, pathParams) || openAPIHasBoundedPageSize(refs, childByKey(op, "parameters")) {
				continue
			}
			collection := openAPIResponseCollection(refs, op)
			if collection == nil {
				continue
			}
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: lineOrOne(collection), RuleID: "openapi-response-collection-unbounded",
				Title:    "Response collection has no size bound",
				Severity: shared.SeverityLow, Resource: clip(strings.ToUpper(method) + " " + path),
				Description: "The operation returns a collection that declares no maxItems, and it has no page-size parameter with a maximum, so nothing in the contract stops one call from returning every row the table holds. Declare a maximum on the page-size parameter, or maxItems on the collection.",
			})
		}
	}
	return out
}

// openAPIHasBoundedPageSize reports whether a parameter list carries a page-size parameter with a declared
// maximum. That maximum is what makes the response a page instead of the whole table.
func openAPIHasBoundedPageSize(refs openAPIRefs, params *yaml.Node) bool {
	if params == nil || params.Kind != yaml.SequenceNode {
		return false
	}
	for _, entry := range params.Content {
		param := refs.deref(entry, map[string]bool{}, 0)
		if param == nil {
			continue
		}
		name := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(scalarByKey(param, "name")), "-", "_"))
		if !openAPIPageSizeParams[name] {
			continue
		}
		// Swagger 2 states the bound on the parameter itself; OpenAPI 3 states it on the parameter's schema.
		if childByKey(param, "maximum") != nil {
			return true
		}
		if schema := refs.deref(childByKey(param, "schema"), map[string]bool{}, 0); schema != nil && childByKey(schema, "maximum") != nil {
			return true
		}
	}
	return false
}

// openAPIResponseCollection returns the unbounded array a 2xx response body delivers, or nil when the
// operation does not return a collection or the collection is bounded.
func openAPIResponseCollection(refs openAPIRefs, op *yaml.Node) *yaml.Node {
	responses := mappingOf(childByKey(op, "responses"))
	if responses == nil {
		return nil
	}
	for i := 0; i+1 < len(responses.Content); i += 2 {
		code := strings.TrimSpace(responses.Content[i].Value)
		if !strings.HasPrefix(code, "2") {
			continue
		}
		response := refs.deref(responses.Content[i+1], map[string]bool{}, 0)
		if response == nil {
			continue
		}
		// OpenAPI 3 nests the schema under content/<media type>; Swagger 2 states it on the response.
		schemas := []*yaml.Node{childByKey(response, "schema")}
		if content := mappingOf(childByKey(response, "content")); content != nil {
			for k := 0; k+1 < len(content.Content); k += 2 {
				schemas = append(schemas, childByKey(mappingOf(content.Content[k+1]), "schema"))
			}
		}
		for _, schema := range schemas {
			if array := openAPICollectionSchema(refs, schema, map[string]bool{}, 0); array != nil {
				return array
			}
		}
	}
	return nil
}

// openAPICollectionSchema returns the schema's own array, following local $refs and one envelope property.
func openAPICollectionSchema(refs openAPIRefs, schema *yaml.Node, seen map[string]bool, depth int) *yaml.Node {
	if schema == nil || depth > maxOpenAPIRefDepth {
		return nil
	}
	resolved := refs.deref(schema, seen, depth)
	if resolved == nil {
		return nil
	}
	if strings.EqualFold(scalarByKey(resolved, "type"), "array") {
		if childByKey(resolved, "maxItems") != nil {
			return nil
		}
		return resolved
	}
	properties := mappingOf(childByKey(resolved, "properties"))
	if properties == nil {
		return nil
	}
	for _, wrapper := range openAPICollectionWrappers {
		child := childByKey(properties, wrapper)
		if child == nil {
			continue
		}
		if array := openAPICollectionSchema(refs, child, seen, depth+1); array != nil {
			return array
		}
	}
	return nil
}

// maxOpenAPIArrayFindings bounds this one rule's output per document, so a large specification cannot spend
// the report on it. The largest real specification measured on a live estate declares 104 unbounded request
// arrays, so the guard sits above what a specification written by hand reaches.
const maxOpenAPIArrayFindings = 200

func mappingOf(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return mappingOf(node.Content[0])
	}
	if node.Kind == yaml.MappingNode {
		return node
	}
	return nil
}

func childByKey(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarByKey(node *yaml.Node, key string) string {
	child := childByKey(node, key)
	if child == nil || child.Kind != yaml.ScalarNode {
		return ""
	}
	return child.Value
}

// lineOrOne is a yaml node's line, falling back to the first line for a node the decoder gave no position.
func lineOrOne(node *yaml.Node) int {
	if node != nil && node.Line > 0 {
		return node.Line
	}
	return 1
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// openAPISchemes merges both dialects' security-scheme maps.
func openAPISchemes(doc *openAPIDoc) map[string]openAPIScheme {
	out := make(map[string]openAPIScheme, len(doc.SecurityDefinitions)+len(doc.Components.SecuritySchemes))
	for name, scheme := range doc.SecurityDefinitions {
		out[name] = scheme
	}
	for name, scheme := range doc.Components.SecuritySchemes {
		out[name] = scheme
	}
	return out
}

// openAPICleartextTransport reports whether the document says it is served without TLS, and how it said so. A
// server URL carrying a {variable} is not judged: what it expands to is not in the document.
func openAPICleartextTransport(doc *openAPIDoc) (bool, string) {
	for _, scheme := range doc.Schemes {
		if strings.EqualFold(strings.TrimSpace(scheme), "http") {
			return true, "an http scheme"
		}
	}
	for _, server := range doc.Servers {
		url := strings.TrimSpace(server.URL)
		if strings.Contains(url, "{") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(url), "http://") {
			return true, "an http:// server"
		}
	}
	return false, ""
}
