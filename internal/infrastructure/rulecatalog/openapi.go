package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// openAPIRules are the OpenAPI / Swagger specification checks. A specification is the contract a gateway
// enforces, so what it omits is what the gateway will not check: these four are the omissions that decide
// whether a route is authenticated, whether a credential crosses the wire in clear, and whether a caller
// chooses how much the service allocates.
func openAPIRules() []rule.Rule {
	const compliantSpec = "openapi: 3.0.0\n" +
		"info:\n  title: api\n  version: \"1.0\"\n" +
		"servers:\n  - url: https://api.example.com\n" +
		"security:\n  - bearerAuth: []\n" +
		"components:\n  securitySchemes:\n    bearerAuth:\n      type: http\n      scheme: bearer\n" +
		"paths:\n  /items:\n    get:\n      responses:\n        \"200\":\n          description: ok\n"

	return []rule.Rule{
		{
			Key: "openapi-no-global-security", Name: "API declares no security requirement", Language: "OpenAPI",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityMedium, Tags: []string{"openapi", "authentication"},
			CWE: []string{"CWE-306"}, OWASP: []string{"A01:2021"}, Detection: rule.DetectionAST,
			Description: "The document states no top-level `security` requirement.",
			Rationale: "An OpenAPI document is the contract a gateway enforces, so what it omits is what the gateway will not check. " +
				"With no document-level requirement every operation that does not declare its own is published unauthenticated, and a route " +
				"added later inherits that default without anyone deciding to.\n\nSource: https://spec.openapis.org/oas/v3.1.0",
			Remediation:      "Declare a `security` requirement at the document level and narrow it per operation where a route is deliberately public.",
			CompliantExample: compliantSpec,
			NoncompliantExample: "openapi: 3.0.0\ninfo:\n  title: api\n  version: \"1.0\"\n" +
				"paths:\n  /items:\n    get:\n      responses:\n        \"200\":\n          description: ok\n",
			RemediationEffort: 30,
		},
		{
			Key: "openapi-operation-security-empty", Name: "Operation opts out of authentication", Language: "OpenAPI",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityHigh, Tags: []string{"openapi", "authentication"},
			CWE: []string{"CWE-306"}, OWASP: []string{"A01:2021"}, Detection: rule.DetectionAST,
			Description: "An operation declares an empty `security` list, removing the document's requirement for that one route.",
			Rationale: "An empty list is not an omission, it is an explicit override: the route is published without the authentication every " +
				"other route has, and nothing at the document level restores it. A gateway generated from the specification honours the hole.\n\n" +
				"Source: https://spec.openapis.org/oas/v3.1.0",
			Remediation:      "Remove the override, or record in the specification why the route is public.",
			CompliantExample: compliantSpec,
			NoncompliantExample: "openapi: 3.0.0\ninfo:\n  title: api\n  version: \"1.0\"\n" +
				"security:\n  - bearerAuth: []\n" +
				"components:\n  securitySchemes:\n    bearerAuth:\n      type: http\n      scheme: bearer\n" +
				"paths:\n  /items:\n    get:\n      security: []\n      responses:\n        \"200\":\n          description: ok\n",
			RemediationEffort: 15,
		},
		{
			Key: "openapi-apikey-over-cleartext", Name: "API key sent over cleartext transport", Language: "OpenAPI",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityHigh, Tags: []string{"openapi", "transport"},
			CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021"}, Detection: rule.DetectionAST,
			Description: "An `apiKey` security scheme is declared while the document also declares an `http://` server or an http scheme.",
			Rationale: "An API key in a header or query string is a bearer credential: whoever reads it can use it. Over http it is readable " +
				"by every hop on the path, and a query-string key is additionally recorded in proxy and server logs. The document itself is " +
				"what says the transport is cleartext.\n\nSource: https://cwe.mitre.org/data/definitions/319.html",
			Remediation:         "Serve the API over https only and remove the http server entry.",
			CompliantExample:    "openapi: 3.0.0\ninfo:\n  title: api\n  version: \"1.0\"\nservers:\n  - url: https://api.example.com\ncomponents:\n  securitySchemes:\n    apiKeyAuth:\n      type: apiKey\n      in: header\n      name: X-API-Key\npaths:\n  /items:\n    get:\n      responses:\n        \"200\":\n          description: ok\n",
			NoncompliantExample: "openapi: 3.0.0\ninfo:\n  title: api\n  version: \"1.0\"\nservers:\n  - url: http://api.example.com\ncomponents:\n  securitySchemes:\n    apiKeyAuth:\n      type: apiKey\n      in: header\n      name: X-API-Key\npaths:\n  /items:\n    get:\n      responses:\n        \"200\":\n          description: ok\n",
			RemediationEffort:   15,
		},
		{
			Key: "openapi-request-array-unbounded", Name: "Request array has no maximum size", Language: "OpenAPI",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityLow, Tags: []string{"openapi", "availability"},
			CWE: []string{"CWE-770"}, OWASP: []string{"A04:2021"}, Detection: rule.DetectionAST,
			Description: "An array in a request schema states no `maxItems`.",
			Rationale: "The size of a request array is chosen by the caller, so an unbounded one is an allocation the client controls: a body " +
				"declaring ten million elements is a valid document the service must materialise before any business rule sees it. A RESPONSE " +
				"array is bounded by the service's own data, so it is judged by its own rule (openapi-response-collection-unbounded) against a " +
				"different condition rather than flagged here.\n\nSource: https://cwe.mitre.org/data/definitions/770.html",
			Remediation:         "Declare `maxItems` on every array a caller can send.",
			CompliantExample:    "openapi: 3.0.0\ninfo:\n  title: api\n  version: \"1.0\"\npaths:\n  /items:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema:\n              type: array\n              maxItems: 100\n              items:\n                type: string\n      responses:\n        \"200\":\n          description: ok\n",
			NoncompliantExample: "openapi: 3.0.0\ninfo:\n  title: api\n  version: \"1.0\"\npaths:\n  /items:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema:\n              type: array\n              items:\n                type: string\n      responses:\n        \"200\":\n          description: ok\n",
			RemediationEffort:   15,
		},
		{
			Key: "openapi-response-collection-unbounded", Name: "Response collection has no size bound", Language: "OpenAPI",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityLow, Tags: []string{"openapi", "availability"},
			CWE: []string{"CWE-770"}, OWASP: []string{"A04:2021"}, Detection: rule.DetectionAST,
			Description: "An operation returns a collection with no `maxItems` and has no page-size parameter declaring a `maximum`.",
			Rationale: "A response array is bounded by the service's own data, so on its own it is not a defect. The pair is: nothing in the " +
				"contract caps the collection and nothing caps the page, so one call can be answered with every row the table holds. A page " +
				"NUMBER parameter does not bound this, because it selects which window is returned rather than how large the window is.\n\n" +
				"Source: https://cwe.mitre.org/data/definitions/770.html",
			Remediation:         "Declare a `maximum` on the page-size parameter, or `maxItems` on the collection the operation returns.",
			CompliantExample:    "openapi: 3.0.0\ninfo:\n  title: api\n  version: \"1.0\"\npaths:\n  /items:\n    get:\n      parameters:\n        - name: size\n          in: query\n          schema:\n            type: integer\n            maximum: 200\n      responses:\n        \"200\":\n          description: ok\n          content:\n            application/json:\n              schema:\n                type: array\n                items:\n                  type: string\n",
			NoncompliantExample: "openapi: 3.0.0\ninfo:\n  title: api\n  version: \"1.0\"\npaths:\n  /items:\n    get:\n      parameters:\n        - name: page\n          in: query\n          schema:\n            type: integer\n      responses:\n        \"200\":\n          description: ok\n          content:\n            application/json:\n              schema:\n                type: array\n                items:\n                  type: string\n",
			RemediationEffort:   30,
		},
	}
}
