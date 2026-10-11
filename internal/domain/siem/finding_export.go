package siem

import "strings"

func exportFindingAudit(tenant, id string, fact AuditFact, class DataClass, known []string, publicBase string) Exported {
	reason := "unsupported_finding_action"
	_, ok := findingActivity(fact)
	if strings.TrimSpace(fact.FindingID) == "" {
		reason = "missing_finding_id"
	} else if ok {
		if class == ClassDetail && cveID(fact.AdvisoryID) {
			body, err := vulnerabilityFinding(fact, class, known)
			if err == nil {
				return finish(id, class, FormatVulnerabilityFinding, body)
			}
		}
		body, err := detectionFinding(fact, class, known, publicBase)
		if err == nil {
			return finish(id, class, FormatDetectionFinding, body)
		}
	} else if fact.Action == "finding.status" || fact.Action == "finding.retest" {
		reason = "missing_or_unknown_finding_status"
	}
	return auditFallback(tenant, id, fact, class, known, publicBase, reason)
}

// Finding workflow verbs are explicit; no current finding state is consulted.
// Promotions can replace an existing projection, so they are updates.
func findingActivity(fact AuditFact) (int, bool) {
	switch fact.Action {
	case "finding.created":
		return 1, true
	case "finding.assigned", "finding.writeup_applied", "finding.threat_promoted", "finding.sast_promoted", "finding.dast_promoted":
		return 2, true
	case "finding.status", "finding.retest":
		switch fact.FindingStatus {
		case "open", "triage", "confirmed":
			return 2, true
		case "false_positive", "remediated":
			return 3, true
		default:
			return 0, false
		}
	default:
		if strings.HasPrefix(fact.Action, "finding.") {
			return 0, false
		}
		return auditActivity(fact.Action)
	}
}

func auditFallback(tenant, id string, fact AuditFact, class DataClass, known []string, publicBase, reason string) Exported {
	doc := auditEnvelopeDoc(tenant, fact, class, known, publicBase)
	doc["fallback_reason"] = reason
	result := finish(id, class, FormatAuditEnvelope, mustJSON(doc))
	if result.Disposition == ItemPending {
		result.Reason = reason
	}
	return result
}
