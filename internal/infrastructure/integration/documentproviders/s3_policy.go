package documentproviders

import (
	"encoding/json"
	"io"
	"strings"
)

const (
	s3PolicyMaxBytes = 20 << 10
	s3PolicyMaxDepth = 16
)

type s3PolicyDocument struct {
	Version   json.RawMessage     `json:"Version"`
	Statement []s3PolicyStatement `json:"Statement"`
}

type s3PolicyStatement struct {
	Sid       json.RawMessage `json:"Sid"`
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    json.RawMessage `json:"Action"`
	Resource  json.RawMessage `json:"Resource"`
	Condition json.RawMessage `json:"Condition"`
}

// verifyS3ReaderPolicy proves the narrow policy shape required for a document
// publication prefix. It deliberately understands only policy syntax that can
// grant object reads; unfamiliar syntax is not safe to ignore.
func verifyS3ReaderPolicy(raw, bucket, prefix, principal string) error {
	document, ok := decodeS3PolicyDocument(raw)
	if !ok || !s3PolicyInputsValid(bucket, prefix, principal) || len(document.Statement) == 0 || !s3PolicyVersionValid(document.Version) {
		return s3PolicyUnverifiable()
	}

	readers := 0
	conditionedStatement := false
	for _, statement := range document.Statement {
		if !s3PolicyStatementValid(statement) {
			return s3PolicyUnverifiable()
		}
		principals, ok := s3PolicyPrincipals(statement.Principal)
		if !ok {
			return s3PolicyUnverifiable()
		}
		actions, ok := s3PolicyStringList(statement.Action)
		if !ok || !s3PolicyActionsSupported(actions) {
			return s3PolicyUnverifiable()
		}
		resources, ok := s3PolicyStringList(statement.Resource)
		if !ok || !s3PolicyResourcesSupported(resources) {
			return s3PolicyUnverifiable()
		}
		conditioned := len(statement.Condition) != 0
		if conditioned && !s3PolicyConditionValid(statement.Condition) {
			return s3PolicyUnverifiable()
		}
		conditionedStatement = conditionedStatement || conditioned

		if statement.Effect != "Allow" || !s3PolicyGrantsObjectRead(actions) || !s3PolicyOverlapsAnyObject(resources, bucket, prefix) {
			continue
		}
		if s3PolicyPublic(principals) {
			return restrictionLostError(200, "public_bucket_policy")
		}
		if !s3PolicyOnlyPrincipal(principals, principal) {
			return restrictionLostError(200, "unexpected_reader_principal")
		}
		if conditioned || !s3PolicyCoversWholePrefix(resources, bucket, prefix) {
			continue
		}
		readers++
	}
	if conditionedStatement || readers != 1 {
		return s3PolicyUnverifiable()
	}
	return nil
}

func s3PolicyUnverifiable() error { return docError(200, "reader_policy_unverifiable", false) }

func s3PolicyInputsValid(bucket, prefix, principal string) bool {
	return s3BucketPattern.MatchString(bucket) && s3PrefixPattern.MatchString(prefix) &&
		!strings.Contains(prefix, "//") && !strings.Contains(prefix, "..") &&
		s3PrincipalPattern.MatchString(principal) && !strings.Contains(principal, "*")
}

func decodeS3PolicyDocument(raw string) (s3PolicyDocument, bool) {
	if len(raw) == 0 || len(raw) > s3PolicyMaxBytes || !s3PolicyJSONValid(raw) {
		return s3PolicyDocument{}, false
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document s3PolicyDocument
	if decoder.Decode(&document) != nil {
		return s3PolicyDocument{}, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return s3PolicyDocument{}, false
	}
	return document, true
}

// s3PolicyJSONValid rejects duplicate keys and substitution variables before
// typed decoding. A bounded token walk avoids retaining a generic JSON tree.
func s3PolicyJSONValid(raw string) bool {
	decoder := json.NewDecoder(strings.NewReader(raw))
	if !s3PolicyScanValue(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func s3PolicyScanValue(decoder *json.Decoder, depth int) bool {
	if depth > s3PolicyMaxDepth {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	switch value := token.(type) {
	case string:
		return !strings.Contains(value, "${")
	case json.Delim:
		switch value {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return false
				}
				name, ok := key.(string)
				if !ok || strings.Contains(name, "${") {
					return false
				}
				if _, exists := keys[name]; exists {
					return false
				}
				keys[name] = struct{}{}
				if !s3PolicyScanValue(decoder, depth+1) {
					return false
				}
			}
			closing, err := decoder.Token()
			return err == nil && closing == json.Delim('}')
		case '[':
			for decoder.More() {
				if !s3PolicyScanValue(decoder, depth+1) {
					return false
				}
			}
			closing, err := decoder.Token()
			return err == nil && closing == json.Delim(']')
		}
	}
	return true
}

func s3PolicyVersionValid(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var version string
	return json.Unmarshal(raw, &version) == nil && version == "2012-10-17"
}

func s3PolicyStatementValid(statement s3PolicyStatement) bool {
	if statement.Effect != "Allow" && statement.Effect != "Deny" || len(statement.Principal) == 0 ||
		len(statement.Action) == 0 || len(statement.Resource) == 0 {
		return false
	}
	if len(statement.Sid) != 0 {
		var sid string
		if json.Unmarshal(statement.Sid, &sid) != nil || sid == "" {
			return false
		}
	}
	return true
}

func s3PolicyPrincipals(raw json.RawMessage) ([]string, bool) {
	var shorthand string
	if json.Unmarshal(raw, &shorthand) == nil {
		if shorthand != "*" {
			return nil, false
		}
		return []string{shorthand}, true
	}
	var namespaces map[string]json.RawMessage
	if json.Unmarshal(raw, &namespaces) != nil || len(namespaces) != 1 {
		return nil, false
	}
	aws, ok := namespaces["AWS"]
	if !ok {
		return nil, false
	}
	return s3PolicyStringList(aws)
}

func s3PolicyStringList(raw json.RawMessage) ([]string, bool) {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return s3PolicyNonEmptyStrings([]string{single})
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil || len(values) == 0 {
		return nil, false
	}
	return s3PolicyNonEmptyStrings(values)
}

func s3PolicyNonEmptyStrings(values []string) ([]string, bool) {
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) {
			return nil, false
		}
	}
	return values, true
}

func s3PolicyConditionValid(raw json.RawMessage) bool {
	var condition map[string]json.RawMessage
	return json.Unmarshal(raw, &condition) == nil && len(condition) > 0
}

func s3PolicyActionsSupported(actions []string) bool {
	for _, action := range actions {
		value := strings.ToLower(action)
		if value == "*" || value == "s3:*" || value == "s3:getobject" || value == "s3:getobjectversion" {
			continue
		}
		if strings.Count(value, "*") == 1 && strings.HasSuffix(value, "*") {
			prefix := strings.TrimSuffix(value, "*")
			if strings.HasPrefix(prefix, "s3:get") &&
				(strings.HasPrefix("s3:getobject", prefix) || strings.HasPrefix("s3:getobjectversion", prefix)) {
				continue
			}
		}
		return false
	}
	return true
}

func s3PolicyGrantsObjectRead(actions []string) bool {
	for _, action := range actions {
		value := strings.ToLower(action)
		if value == "*" || value == "s3:*" || value == "s3:getobject" || value == "s3:getobjectversion" {
			return true
		}
		if strings.HasSuffix(value, "*") {
			prefix := strings.TrimSuffix(value, "*")
			if strings.HasPrefix(prefix, "s3:get") &&
				(strings.HasPrefix("s3:getobject", prefix) || strings.HasPrefix("s3:getobjectversion", prefix)) {
				return true
			}
		}
	}
	return false
}

func s3PolicyResourcesSupported(resources []string) bool {
	for _, resource := range resources {
		if !s3PolicyResourceValid(resource) {
			return false
		}
	}
	return true
}

func s3PolicyResourceValid(resource string) bool {
	if resource == "*" {
		return true
	}
	if strings.Contains(resource, "?") || strings.Contains(resource, "${") || strings.Count(resource, "*") > 1 {
		return false
	}
	if strings.Contains(resource, "*") && !strings.HasSuffix(resource, "*") {
		return false
	}
	literal := strings.TrimSuffix(resource, "*")
	const arnPrefix = "arn:aws:s3:::"
	if !strings.HasPrefix(literal, arnPrefix) {
		return false
	}
	rest := strings.TrimPrefix(literal, arnPrefix)
	bucket, key, hasKey := strings.Cut(rest, "/")
	if !s3BucketPattern.MatchString(bucket) {
		return false
	}
	if !hasKey {
		return !strings.Contains(resource, "*")
	}
	if key == "" && !strings.HasSuffix(resource, "*") {
		return false
	}
	return !strings.ContainsAny(key, "*?")
}

func s3PolicyPublic(principals []string) bool {
	for _, principal := range principals {
		if principal == "*" {
			return true
		}
	}
	return false
}

func s3PolicyOnlyPrincipal(principals []string, want string) bool {
	return len(principals) == 1 && principals[0] == want
}

func s3PolicyOverlapsAnyObject(resources []string, bucket, prefix string) bool {
	owned := "arn:aws:s3:::" + bucket + "/" + prefix + "/"
	for _, resource := range resources {
		if resource == "*" {
			return true
		}
		if !strings.HasPrefix(resource, "arn:aws:s3:::"+bucket+"/") {
			continue
		}
		literal := strings.TrimSuffix(resource, "*")
		if strings.HasSuffix(resource, "*") {
			if strings.HasPrefix(literal, owned) || strings.HasPrefix(owned, literal) {
				return true
			}
			continue
		}
		if strings.HasPrefix(literal, owned) {
			return true
		}
	}
	return false
}

func s3PolicyCoversWholePrefix(resources []string, bucket, prefix string) bool {
	owned := "arn:aws:s3:::" + bucket + "/" + prefix + "/"
	for _, resource := range resources {
		if resource == "*" {
			return true
		}
		if !strings.HasPrefix(resource, "arn:aws:s3:::"+bucket+"/") || !strings.HasSuffix(resource, "*") {
			continue
		}
		if strings.HasPrefix(owned, strings.TrimSuffix(resource, "*")) {
			return true
		}
	}
	return false
}
