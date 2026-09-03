package api_test

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// walkYAML traverses the YAML node tree.
func walkYAML(node *yaml.Node, visit func(node *yaml.Node)) {
	if node == nil {
		return
	}
	visit(node)
	for _, child := range node.Content {
		walkYAML(child, visit)
	}
}

// walkMappings traverses and looks for MappingNodes.
func walkMappings(node *yaml.Node, visit func(mapping *yaml.Node)) {
	if node == nil {
		return
	}
	if node.Kind == yaml.MappingNode {
		visit(node)
	}
	for _, child := range node.Content {
		walkMappings(child, visit)
	}
}

func TestOpenAPI_StrictValidation(t *testing.T) {
	b, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("failed to read openapi.yaml: %v", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		t.Fatalf("failed to parse yaml: %v", err)
	}

	if len(root.Content) == 0 {
		t.Fatal("empty yaml document")
	}
	doc := root.Content[0]

	t.Run("duplicate schema keys", func(t *testing.T) {
		walkMappings(doc, func(mapping *yaml.Node) {
			seen := make(map[string]bool)
			for i := 0; i < len(mapping.Content); i += 2 {
				keyNode := mapping.Content[i]
				if keyNode.Kind == yaml.ScalarNode {
					if seen[keyNode.Value] {
						t.Errorf("duplicate key found: %q at line %d", keyNode.Value, keyNode.Line)
					}
					seen[keyNode.Value] = true
				}
			}
		})
	})

	t.Run("duplicate operation IDs", func(t *testing.T) {
		opIDs := make(map[string]int)
		walkMappings(doc, func(mapping *yaml.Node) {
			for i := 0; i < len(mapping.Content); i += 2 {
				keyNode := mapping.Content[i]
				if keyNode.Value == "operationId" {
					valNode := mapping.Content[i+1]
					if valNode.Kind == yaml.ScalarNode {
						opID := valNode.Value
						if line, ok := opIDs[opID]; ok {
							t.Errorf("duplicate operationId %q found at line %d (previous at line %d)", opID, valNode.Line, line)
						}
						opIDs[opID] = valNode.Line
					}
				}
			}
		})
	})

	t.Run("unresolved local references", func(t *testing.T) {
		// Map out the components/schemas, components/responses, components/parameters
		// We'll just do a brute force check by trying to resolve each $ref.
		var mapDoc map[string]interface{}
		if err := yaml.Unmarshal(b, &mapDoc); err != nil {
			t.Fatalf("failed to parse into map: %v", err)
		}

		walkMappings(doc, func(mapping *yaml.Node) {
			for i := 0; i < len(mapping.Content); i += 2 {
				keyNode := mapping.Content[i]
				if keyNode.Value == "$ref" {
					valNode := mapping.Content[i+1]
					if valNode.Kind == yaml.ScalarNode {
						ref := valNode.Value
						if strings.HasPrefix(ref, "#/") {
							parts := strings.Split(ref[2:], "/")
							curr := mapDoc
							valid := true
							for _, p := range parts {
								if next, ok := curr[p].(map[string]interface{}); ok {
									curr = next
								} else if nextNode, ok2 := curr[p]; ok2 && nextNode != nil {
									// last element can be anything
									curr = nil
								} else {
									valid = false
									break
								}
							}
							if !valid {
								t.Errorf("unresolved local reference %q at line %d", ref, valNode.Line)
							}
						}
					}
				}
			}
		})
	})

	t.Run("required properties that do not exist", func(t *testing.T) {
		walkMappings(doc, func(mapping *yaml.Node) {
			// look for "required" and "properties" in the same mapping
			var requiredNodes []*yaml.Node
			var propertiesNode *yaml.Node

			for i := 0; i < len(mapping.Content); i += 2 {
				k := mapping.Content[i]
				v := mapping.Content[i+1]
				if k.Value == "required" && v.Kind == yaml.SequenceNode {
					requiredNodes = v.Content
				}
				if k.Value == "properties" && v.Kind == yaml.MappingNode {
					propertiesNode = v
				}
			}

			if len(requiredNodes) > 0 && propertiesNode != nil {
				// build map of properties
				props := make(map[string]bool)
				for i := 0; i < len(propertiesNode.Content); i += 2 {
					props[propertiesNode.Content[i].Value] = true
				}

				for _, r := range requiredNodes {
					if r.Kind == yaml.ScalarNode {
						if !props[r.Value] {
							t.Errorf("required property %q at line %d does not exist in 'properties'", r.Value, r.Line)
						}
					}
				}
			}
		})
	})

	t.Run("invalid examples", func(t *testing.T) {
		// Just parse it as a map and we can manually check MeasureGradeMetric examples if needed
		// But let's check for any example that uses `availability: unavailable` but does not set grade to null
		// or sets grade to string.
		walkMappings(doc, func(mapping *yaml.Node) {
			var avail, grade string
			hasAvail, hasGrade := false, false
			var gradeLine int

			for i := 0; i < len(mapping.Content); i += 2 {
				k := mapping.Content[i]
				v := mapping.Content[i+1]
				if k.Value == "availability" && v.Kind == yaml.ScalarNode {
					avail = v.Value
					hasAvail = true
				}
				if k.Value == "grade" {
					if v.Kind == yaml.ScalarNode && v.Tag != "!!null" {
						grade = v.Value
						hasGrade = true
					} else if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
						grade = "null"
						hasGrade = true
					}
					gradeLine = v.Line
				}
			}

			if hasAvail && hasGrade && avail == "unavailable" {
				if grade != "null" {
					t.Errorf("invalid example at line %d: availability is unavailable but grade is %q (should be null)", gradeLine, grade)
				}
			}
		})
	})

	t.Run("ratings and new-code coverage only applicable at project root", func(t *testing.T) {
		walkMappings(doc, func(mapping *yaml.Node) {
			var kind string
			var ratingsNode *yaml.Node
			var coverageNode *yaml.Node

			for i := 0; i < len(mapping.Content); i += 2 {
				k := mapping.Content[i]
				v := mapping.Content[i+1]
				if k.Value == "kind" && v.Kind == yaml.ScalarNode {
					kind = v.Value
				}
				if k.Value == "ratings" && v.Kind == yaml.MappingNode {
					ratingsNode = v
				}
				if k.Value == "coverage" && v.Kind == yaml.MappingNode {
					coverageNode = v
				}
			}

			if kind == "directory" || kind == "file" {
				if ratingsNode != nil {
					walkMappings(ratingsNode, func(r *yaml.Node) {
						var avail string
						for i := 0; i < len(r.Content); i += 2 {
							if r.Content[i].Value == "availability" {
								avail = r.Content[i+1].Value
							}
						}
						// If this is a MeasureGradeMetric mapping (it has availability)
						if avail != "" && avail != "not_applicable" {
							t.Errorf("invalid example at line %d: ratings for kind %q must be not_applicable, got %q", r.Line, kind, avail)
						}
					})
				}

				if coverageNode != nil {
					for i := 0; i < len(coverageNode.Content); i += 2 {
						k := coverageNode.Content[i]
						v := coverageNode.Content[i+1]
						if k.Value == "new_code_coverage" && v.Kind == yaml.MappingNode {
							var avail string
							for j := 0; j < len(v.Content); j += 2 {
								if v.Content[j].Value == "availability" {
									avail = v.Content[j+1].Value
								}
							}
							if avail != "" && avail != "not_applicable" {
								t.Errorf("invalid example at line %d: new_code_coverage for kind %q must be not_applicable, got %q", v.Line, kind, avail)
							}
						}
					}
				}
			}
		})
	})
}

func TestAttackPathOpenAPIContract(t *testing.T) {
	b, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	enum := func(schema, property string) []string {
		definition := schemas[schema].(map[string]any)
		properties, _ := definition["properties"].(map[string]any)
		if properties == nil {
			for _, part := range definition["allOf"].([]any) {
				if properties, _ = part.(map[string]any)["properties"].(map[string]any); properties != nil {
					break
				}
			}
		}
		values := properties[property].(map[string]any)["enum"].([]any)
		got := make([]string, len(values))
		for i, value := range values {
			got[i] = value.(string)
		}
		return got
	}
	assertEnum := func(schema, property string, want []string) {
		t.Helper()
		if got := enum(schema, property); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s.%s enum = %v, want %v", schema, property, got, want)
		}
	}

	assertEnum("AttackPathAsset", "Kind", []string{"host", "workload", "image", "cloud_account", "storage", "exposure", "identity", "namespace", "cluster", "repository"})
	assertEnum("Finding", "Kind", []string{"sca", "recon", "exploitation", "manual", "sast", "secret", "misconfig", "cloud_posture", "dast", "threat", "hypothesis", "quality", "reliability"})
	assertEnum("AttackPathFindingInput", "reachability", []string{"", "reachable", "not_reachable", "unknown"})
	assertEnum("AttackPathFindingInput", "tier", []string{"", "tier-0", "tier-1", "tier-1.5", "tier-2"})

	bounds := schemas["AttackPathBounds"].(map[string]any)
	properties := bounds["properties"].(map[string]any)
	required := bounds["required"].([]any)
	for _, field := range []string{"targetPathsHit", "findingPathsHit"} {
		property, ok := properties[field].(map[string]any)
		if !ok || property["type"] != "boolean" {
			t.Errorf("AttackPathBounds.%s must be a boolean", field)
		}
		found := false
		for _, value := range required {
			found = found || value == field
		}
		if !found {
			t.Errorf("AttackPathBounds.%s must be required", field)
		}
	}
}
