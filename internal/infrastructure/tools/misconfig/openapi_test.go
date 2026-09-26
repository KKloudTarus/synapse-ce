package misconfig

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// A specification with no document-level security requirement publishes every operation that states none of
// its own. The cleartext rule fires on the same document because the declared server is http://.
func TestOpenAPINoSecurityAndCleartextAPIKey(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: orders
  version: "1.0"
servers:
  - url: http://orders.internal/api
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      in: query
      name: token
paths:
  /orders:
    get:
      responses:
        "200":
          description: ok
`
	got := ruleIDs(scan(t, map[string]string{"api/openapi.yaml": spec}))
	for _, want := range []string{"openapi-no-global-security", "openapi-apikey-over-cleartext"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %s to fire, got %v", want, keys(got))
		}
	}
	if f := got["openapi-apikey-over-cleartext"]; !contains(f.Description, "query") {
		t.Errorf("the description should name where the key travels, got %q", f.Description)
	}
}

// An operation that declares an EMPTY security list opts out of the requirement the rest of the API has.
// That is a different defect from a document which never stated one, and only the operation rule fires.
func TestOpenAPIOperationOptsOutOfAuthentication(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: orders
  version: "1.0"
servers:
  - url: https://orders.example.com
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
paths:
  /orders:
    get:
      responses:
        "200":
          description: ok
  /health:
    get:
      security: []
      responses:
        "200":
          description: ok
`
	got := ruleIDs(scan(t, map[string]string{"api/openapi.yaml": spec}))
	f, ok := got["openapi-operation-security-empty"]
	if !ok {
		t.Fatalf("expected the opt-out rule to fire, got %v", keys(got))
	}
	if f.Resource != "GET /health" {
		t.Errorf("the finding must name the route that opted out, got %q", f.Resource)
	}
	if _, ok := got["openapi-no-global-security"]; ok {
		t.Error("a document that states a requirement must not be reported as stating none")
	}
	if _, ok := got["openapi-apikey-over-cleartext"]; ok {
		t.Error("a bearer scheme over https is not an API key in clear text")
	}
}

// The request side is what the caller controls, so that is the only side flagged. A response array is bounded
// by the service's own data, and flagging it is the false positive other scanners ship.
func TestOpenAPIOnlyRequestArraysAreFlagged(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: orders
  version: "1.0"
servers:
  - url: https://orders.example.com
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
  schemas:
    OrderBatch:
      type: object
      properties:
        lines:
          type: array
          items:
            type: string
paths:
  /orders:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/OrderBatch"
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: array
                items:
                  type: string
  /bounded:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: array
              maxItems: 500
              items:
                type: string
      responses:
        "200":
          description: ok
`
	findings := scan(t, map[string]string{"api/openapi.yaml": spec})
	var arrays []ports.MisconfigRawFinding
	for _, f := range findings {
		if f.RuleID == "openapi-request-array-unbounded" {
			arrays = append(arrays, f)
		}
	}
	if len(arrays) != 1 {
		t.Fatalf("exactly the one unbounded request array must be reported, got %d: %v", len(arrays), arrays)
	}
	if arrays[0].Resource != "POST /orders" {
		t.Errorf("the finding must name the operation, got %q", arrays[0].Resource)
	}
}

// A list endpoint whose page size has no maximum can be asked for the whole table in one call, and a page
// NUMBER bounds nothing: it chooses which window is returned, not how large the window is. A sibling endpoint
// whose page size declares a maximum is correct and stays silent.
func TestOpenAPIResponseCollectionNeedsABound(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: customers
  version: "1.0"
servers:
  - url: https://customers.example.com
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
  parameters:
    PageSize:
      name: pageSize
      in: query
      schema:
        type: integer
        minimum: 1
    CappedSize:
      name: pageSize
      in: query
      schema:
        type: integer
        maximum: 200
  schemas:
    CustomerListResponse:
      type: object
      properties:
        data:
          type: array
          items:
            type: string
paths:
  /customers:
    get:
      parameters:
        - $ref: "#/components/parameters/PageSize"
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CustomerListResponse"
  /capped:
    get:
      parameters:
        - $ref: "#/components/parameters/CappedSize"
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CustomerListResponse"
  /page-number-only:
    get:
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            maximum: 1000
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CustomerListResponse"
`
	var got []ports.MisconfigRawFinding
	for _, f := range scan(t, map[string]string{"api/openapi.yaml": spec}) {
		if f.RuleID == "openapi-response-collection-unbounded" {
			got = append(got, f)
		}
	}
	resources := map[string]bool{}
	for _, f := range got {
		resources[f.Resource] = true
	}
	if !resources["GET /customers"] {
		t.Errorf("an uncapped page size must be reported, got %v", resources)
	}
	if !resources["GET /page-number-only"] {
		t.Errorf("a maximum on a page NUMBER bounds no collection, got %v", resources)
	}
	if resources["GET /capped"] {
		t.Error("a page size with a maximum bounds the collection and must stay silent")
	}
	if len(got) != 2 {
		t.Errorf("one finding per operation, got %d: %v", len(got), resources)
	}
}

// A nested array on an object an operation returns is a field, not the collection the operation is, and its
// size follows from the one record. Only the collection itself is judged.
func TestOpenAPINestedResponseArrayIsNotACollection(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: customers
  version: "1.0"
servers:
  - url: https://customers.example.com
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
paths:
  /customers/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: string
                  tags:
                    type: array
                    items:
                      type: string
`
	for _, f := range scan(t, map[string]string{"api/openapi.yaml": spec}) {
		if f.RuleID == "openapi-response-collection-unbounded" {
			t.Errorf("a nested field array must not be reported as an unbounded collection: %v", f.Resource)
		}
	}
}

// A request body reaching its array through components.parameters, not components.schemas, is the same defect.
// Following only one section of the document is what made another scanner miss it.
func TestOpenAPIRequestArrayThroughAParameterRef(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: orders
  version: "1.0"
servers:
  - url: https://orders.example.com
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
  parameters:
    Ids:
      name: ids
      in: query
      schema:
        type: array
        items:
          type: string
paths:
  /orders:
    get:
      parameters:
        - $ref: "#/components/parameters/Ids"
      responses:
        "200":
          description: ok
`
	got := ruleIDs(scan(t, map[string]string{"api/openapi.yaml": spec}))
	if _, ok := got["openapi-request-array-unbounded"]; !ok {
		t.Errorf("an array reached through a parameter $ref must be reported, got %v", keys(got))
	}
}

// A Swagger 2 document is the same contract in the older dialect, and it is read the same way: securityDefinitions
// instead of components.securitySchemes, and schemes instead of servers.
func TestOpenAPIReadsSwagger2(t *testing.T) {
	spec := `swagger: "2.0"
info:
  title: legacy
  version: "1.0"
host: legacy.internal
schemes:
  - http
securityDefinitions:
  apiKey:
    type: apiKey
    in: header
    name: X-Token
paths:
  /legacy:
    get:
      responses:
        "200":
          description: ok
`
	got := ruleIDs(scan(t, map[string]string{"swagger.yaml": spec}))
	for _, want := range []string{"openapi-no-global-security", "openapi-apikey-over-cleartext"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %s on a Swagger 2 document, got %v", want, keys(got))
		}
	}
}

// A server URL carrying a {variable} says nothing about the transport: what it expands to is not in the
// document, so it is not judged. Reporting it would be a guess presented as a finding.
func TestOpenAPITemplatedServerIsNotJudged(t *testing.T) {
	spec := `openapi: 3.0.0
info:
  title: orders
  version: "1.0"
servers:
  - url: "{scheme}://orders.example.com"
security:
  - apiKeyAuth: []
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-Token
paths:
  /orders:
    get:
      responses:
        "200":
          description: ok
`
	got := ruleIDs(scan(t, map[string]string{"api/openapi.yaml": spec}))
	if _, ok := got["openapi-apikey-over-cleartext"]; ok {
		t.Error("a templated server URL must not be read as cleartext transport")
	}
}

// A YAML file that merely mentions the word is not a specification, and neither is a Kubernetes CRD whose
// schema field is openAPIV3Schema. Neither contributes a finding.
func TestOpenAPIPreFilterIgnoresNonSpecs(t *testing.T) {
	notes := "title: openapi notes\nbody: paths are documented elsewhere\n"
	crd := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
`
	for _, f := range scan(t, map[string]string{"docs/notes.yaml": notes, "deploy/crd.yaml": crd}) {
		if strings.HasPrefix(f.RuleID, "openapi-") {
			t.Errorf("%s fired on %s, which is not an OpenAPI document", f.RuleID, f.File)
		}
	}
}
