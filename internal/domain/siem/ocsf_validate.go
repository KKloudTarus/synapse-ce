package siem

import (
	"fmt"
	"math"
	"strings"
)

// ValidateOCSF checks the fields this exporter is allowed to emit for the
// pinned OCSF finding classes. This adds mapper-specific semantic constraints
// to the complete vendored JSON Schema validation in infrastructure/siem/ocsf.
func ValidateOCSF(doc map[string]any) error {
	classUID, ok := number(doc["class_uid"])
	if !ok || (classUID != 2002 && classUID != 2004 && classUID != 2005) {
		return fmt.Errorf("class_uid %v is not a pinned finding class", doc["class_uid"])
	}
	category, ok := number(doc["category_uid"])
	if !ok || category != 2 {
		return fmt.Errorf("category_uid must be 2")
	}
	activity, ok := number(doc["activity_id"])
	if !ok || activity < 1 || activity > 3 {
		return fmt.Errorf("activity_id %v is outside create/update/close", doc["activity_id"])
	}
	typeUID, ok := number(doc["type_uid"])
	if !ok || typeUID != classUID*100+activity {
		return fmt.Errorf("type_uid does not match class and activity")
	}
	severity, ok := number(doc["severity_id"])
	if !ok || severity < 0 || severity > 6 {
		return fmt.Errorf("severity_id %v is outside the pinned enum", doc["severity_id"])
	}
	if _, ok := number(doc["time"]); !ok {
		return fmt.Errorf("time is required")
	}
	meta, _ := doc["metadata"].(map[string]any)
	if meta["version"] != OCSFSchemaVersion {
		return fmt.Errorf("metadata.version is not %s", OCSFSchemaVersion)
	}
	product, _ := meta["product"].(map[string]any)
	if product["name"] != "Synapse" || product["vendor_name"] != "Synapse" {
		return fmt.Errorf("metadata.product is not the pinned producer")
	}
	if classUID != 2005 {
		if profiles, exists := meta["profiles"]; exists {
			list, ok := profiles.([]any)
			if !ok || len(list) != 0 {
				return fmt.Errorf("finding exporter does not emit optional profiles")
			}
		}
	}
	switch classUID {
	case 2005:
		list, ok := doc["finding_info_list"].([]any)
		if !ok || len(list) == 0 {
			return fmt.Errorf("incident finding requires finding_info_list")
		}
		for _, item := range list {
			info, _ := item.(map[string]any)
			if !nonempty(info["uid"]) {
				return fmt.Errorf("incident finding requires finding_info_list.uid")
			}
		}
		profiles, ok := meta["profiles"].([]any)
		if !ok || len(profiles) != 1 || profiles[0] != "incident" {
			return fmt.Errorf("incident finding requires the incident profile")
		}
		status, ok := number(doc["status_id"])
		if !ok || status < 1 || status > 5 {
			return fmt.Errorf("incident status_id is required")
		}
		if _, ok := doc["assignee"].(map[string]any); !ok {
			if _, ok := doc["assignee_group"].(map[string]any); !ok {
				return fmt.Errorf("incident finding requires an assignee or group")
			}
		}
	case 2004:
		info, ok := doc["finding_info"].(map[string]any)
		if !ok || !nonempty(info["uid"]) {
			return fmt.Errorf("detection finding requires finding_info.uid")
		}
	case 2002:
		info, ok := doc["finding_info"].(map[string]any)
		if !ok || !nonempty(info["uid"]) {
			return fmt.Errorf("vulnerability finding requires finding_info.uid")
		}
		vulns, ok := doc["vulnerabilities"].([]any)
		if !ok || len(vulns) == 0 {
			return fmt.Errorf("vulnerability finding requires vulnerabilities")
		}
	}
	return nil
}

func number(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed || typed < -float64(1<<53) || typed > float64(1<<53) {
			return 0, false
		}
		return int(typed), true
	default:
		return 0, false
	}
}

func nonempty(value any) bool { text, ok := value.(string); return ok && strings.TrimSpace(text) != "" }
