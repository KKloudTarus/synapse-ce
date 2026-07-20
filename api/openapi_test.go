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
}
