package siem

import "strings"

// AuditWithMetadata copies only mapping facts from the immutable audit metadata.
// It never loads a finding projection or mutates the input row or metadata.
func AuditWithMetadata(row AuditFact, metadata map[string]string) AuditFact {
	row.Severity = metadata["severity"]
	row.EngagementID = metadata["engagement_id"]
	row.AdvisoryID = metadata["advisory_id"]
	row.FindingID = metadata["finding_id"]
	row.AssetID = metadata["asset_id"]
	row.Host = metadata["host"]
	row.Title = metadata["title"]
	row.FindingStatus = ""
	if strings.HasPrefix(row.Action, "finding.") {
		if row.EngagementID == "" {
			row.EngagementID = metadata["engagement"]
		}
		if row.FindingID == "" {
			row.FindingID = row.Target
		}
		row.FindingStatus = metadata["status"]
	}
	return row
}
