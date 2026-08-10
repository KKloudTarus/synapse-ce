package api_test

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSourcePublishOpenAPIContract(t *testing.T) {
	b, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI paths missing")
	}
	route, ok := paths["/api/v1/projects/{key}/analyses/{id}/source"].(map[string]any)
	if !ok {
		t.Fatal("sanctioned source publish path missing from OpenAPI")
	}
	post, ok := route["post"].(map[string]any)
	if !ok {
		t.Fatal("sanctioned source publish POST missing from OpenAPI")
	}
	if got := post["operationId"]; got != "publishProjectAnalysisSource" {
		t.Fatalf("operationId=%v, want publishProjectAnalysisSource", got)
	}
	params, _ := post["parameters"].([]any)
	foundToolVersion := false
	for _, raw := range params {
		p, _ := raw.(map[string]any)
		if p["name"] == "X-Synapse-Tool-Version" && p["in"] == "header" && p["required"] == true {
			foundToolVersion = true
		}
	}
	if !foundToolVersion {
		t.Fatal("required X-Synapse-Tool-Version header missing from OpenAPI")
	}
	requestBody, _ := post["requestBody"].(map[string]any)
	content, _ := requestBody["content"].(map[string]any)
	if _, ok := content["application/x-tar"]; !ok {
		t.Fatal("application/x-tar request contract missing")
	}
	responses, _ := post["responses"].(map[string]any)
	for _, status := range []string{"201", "400", "401", "403", "404", "409", "413", "415", "500", "503"} {
		if _, ok := responses[status]; !ok {
			t.Fatalf("response %s missing from source publish OpenAPI contract", status)
		}
	}
	response201 := responses["201"].(map[string]any)
	responseContent := response201["content"].(map[string]any)["application/json"].(map[string]any)
	schema := responseContent["schema"].(map[string]any)
	digest := schema["properties"].(map[string]any)["digest"].(map[string]any)
	if digest["pattern"] != "^sha256:[0-9a-f]{64}$" {
		t.Fatalf("manifest digest pattern=%v", digest["pattern"])
	}
}
