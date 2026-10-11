package siem

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
)

// Exported is one record ready for a driver, or a terminal disposition that
// is stored and does not leave the process.
type Exported struct {
	RecordID    string
	Disposition ItemDisposition
	Format      string
	DataClass   DataClass
	Reason      string
	Body        []byte
	Digest      string
}

const (
	FormatAuditEnvelope        = "synapse.audit"
	FormatIncidentEnvelope     = "synapse.incident"
	FormatIncidentFinding      = "ocsf.incident_finding"
	FormatDetectionFinding     = "ocsf.detection_finding"
	FormatVulnerabilityFinding = "ocsf.vulnerability_finding"
)

// ScrubText applies known-secret replacement and the shared privacy pattern
// scrubber. The patterns are not copied here.
func ScrubText(value string, known []string) string {
	for _, secret := range known {
		if len(secret) < 4 {
			continue
		}
		value = strings.ReplaceAll(value, secret, privacy.RedactionPlaceholder)
	}
	scrubbed, _ := privacy.DefaultPolicy().Classify(privacy.CategoryNetworkComm, value)
	return scrubbed
}

// ExportAudit builds the outbound record for one verified audit row.
func ExportAudit(tenant string, fact AuditFact, class DataClass, known []string, publicBase string) Exported {
	id := RecordID(tenant, string(SourceAudit), strconv.FormatInt(fact.ID, 10))
	if class == ClassNone {
		return terminal(id, ItemSuppressed, class, "policy_none")
	}
	switch {
	case strings.HasPrefix(fact.Action, "finding."):
		return exportFindingAudit(tenant, id, fact, class, known, publicBase)
	case strings.HasPrefix(fact.Action, "vulnerability."):
		if class != ClassDetail {
			return auditFallback(tenant, id, fact, class, known, publicBase, "data_class")
		}
		if !cveID(fact.AdvisoryID) {
			return auditFallback(tenant, id, fact, class, known, publicBase, "missing_cve")
		}
		body, err := vulnerabilityFinding(fact, class, known)
		if err != nil {
			return auditFallback(tenant, id, fact, class, known, publicBase, "unsupported_activity")
		}
		return finish(id, class, FormatVulnerabilityFinding, body)
	case strings.HasPrefix(fact.Action, "detection."):
		body, err := detectionFinding(fact, class, known, publicBase)
		if err != nil {
			return auditFallback(tenant, id, fact, class, known, publicBase, "unsupported_activity")
		}
		return finish(id, class, FormatDetectionFinding, body)
	default:
		return finish(id, class, FormatAuditEnvelope, auditEnvelope(tenant, fact, class, known, publicBase))
	}
}

// ExportIncident builds the outbound record for one captured incident event.
// Status and activity come from that event. A later projection of the
// incident is not substituted for a historical event.
func ExportIncident(tenant string, fact IncidentFact, class DataClass, known []string, publicBase string) Exported {
	identity := fact.IncidentID + ":" + strconv.Itoa(fact.EventSeq)
	id := RecordID(tenant, string(fact.Phase), identity)
	if class == ClassNone {
		return terminal(id, ItemSuppressed, class, "policy_none")
	}
	if body, ok := incidentFinding(fact, class, known, publicBase); ok {
		return finish(id, class, FormatIncidentFinding, body)
	}
	reason := "missing_incident_fields"
	if classRank(class) < 2 {
		reason = "data_class"
	}
	doc := incidentEnvelopeDoc(tenant, fact, class, known, publicBase)
	doc["fallback_reason"] = reason
	exported := finish(id, class, FormatIncidentEnvelope, mustJSON(doc))
	if exported.Disposition == ItemPending {
		exported.Reason = reason
	}
	return exported
}

const (
	stringCreated = "created"
	stringStatus  = "status_changed"
)

func terminal(id string, disposition ItemDisposition, class DataClass, reason string) Exported {
	return Exported{RecordID: id, Disposition: disposition, DataClass: class, Reason: SafeDiagnostic(reason)}
}

func finish(id string, class DataClass, format string, body []byte) Exported {
	if len(body) == 0 || len(body) > MaxRecordBytes {
		return terminal(id, ItemQuarantined, class, "record_bytes")
	}
	sum := sha256.Sum256(body)
	return Exported{
		RecordID: id, Disposition: ItemPending, Format: format, DataClass: class,
		Body: body, Digest: hex.EncodeToString(sum[:]),
	}
}

func auditEnvelope(tenant string, fact AuditFact, class DataClass, known []string, publicBase string) []byte {
	return mustJSON(auditEnvelopeDoc(tenant, fact, class, known, publicBase))
}

func auditEnvelopeDoc(tenant string, fact AuditFact, class DataClass, known []string, publicBase string) map[string]any {
	doc := map[string]any{
		"schema":     EnvelopeVersion,
		"data_class": string(class),
		"tenant_id":  tenant,
		"action":     fact.Action,
		"severity":   severityOrUnknown(fact.Severity),
		"time":       fact.AtUnixMicro / 1000,
		"source": map[string]any{
			"kind":         string(SourceAudit),
			"id":           fact.ID,
			"hash_version": fact.HashVersion,
			"source_hash":  fact.Hash,
		},
	}
	if classRank(class) >= 2 {
		doc["actor"] = ScrubText(fact.Actor, known)
		doc["target_host"] = ScrubText(fact.Host, known)
		if fact.Title != "" {
			doc["title"] = ScrubText(fact.Title, known)
		}
		if fact.EngagementID != "" {
			doc["engagement_id"] = ScrubText(fact.EngagementID, known)
		}
	}
	if class == ClassDetail {
		putID(doc, "advisory_id", ScrubText(fact.AdvisoryID, known))
		putID(doc, "finding_id", ScrubText(fact.FindingID, known))
		putID(doc, "asset_id", ScrubText(fact.AssetID, known))
	}
	if fact.FindingID != "" {
		if origin, err := ParseOrigin(publicBase); err == nil {
			doc["link"] = origin.String() + "/findings/" + url.PathEscape(ScrubText(fact.FindingID, known))
		}
	}
	return doc
}

func incidentEnvelopeDoc(tenant string, fact IncidentFact, class DataClass, known []string, publicBase string) map[string]any {
	doc := map[string]any{
		"schema":      IncidentEnvelope,
		"data_class":  string(class),
		"tenant_id":   tenant,
		"kind":        fact.Kind,
		"severity":    severityOrUnknown(fact.Severity),
		"time":        fact.AtUnixMicro / 1000,
		"incident_id": ScrubText(fact.IncidentID, known),
		"event_seq":   fact.EventSeq,
		"source": map[string]any{
			"kind":       string(fact.Phase),
			"stream_seq": fact.StreamSeq,
		},
	}
	if classRank(class) >= 2 {
		doc["actor"] = ScrubText(fact.Actor, known)
		if fact.Title != "" {
			doc["title"] = ScrubText(fact.Title, known)
		}
		if fact.EngagementID != "" {
			doc["engagement_id"] = ScrubText(fact.EngagementID, known)
		}
	}
	if class == ClassDetail {
		if fact.Comment != "" {
			doc["comment"] = ScrubText(fact.Comment, known)
		}
		putID(doc, "asset_id", ScrubText(fact.AssetID, known))
		putID(doc, "detection_id", ScrubText(fact.DetectionID, known))
		if fact.ToStatus != "" {
			doc["to_status"] = ScrubText(fact.ToStatus, known)
		}
	}
	if link := incidentLink(publicBase, ScrubText(fact.IncidentID, known)); link != "" {
		doc["link"] = link
	}
	return doc
}

func incidentFinding(fact IncidentFact, class DataClass, known []string, publicBase string) ([]byte, bool) {
	activity, status, ok := incidentActivity(fact)
	if !ok || fact.IncidentID == "" {
		return nil, false
	}
	// The class constraint needs a real assignee or group. Signal must not
	// carry an owner name, so an incident finding starts at summary.
	if classRank(class) < 2 || strings.TrimSpace(fact.Owner) == "" && fact.Kind != stringCreated {
		return nil, false
	}
	assigneeName := strings.TrimSpace(fact.Owner)
	if assigneeName == "" {
		return nil, false
	}
	info := map[string]any{"uid": ScrubText(fact.IncidentID, known) + ":" + strconv.Itoa(fact.EventSeq)}
	if fact.Title != "" {
		info["title"] = ScrubText(fact.Title, known)
	}
	doc := baseFinding(2005, activity, fact.AtUnixMicro, fact.Severity)
	doc["status_id"] = status
	doc["finding_info_list"] = []any{info}
	doc["assignee"] = map[string]any{"name": ScrubText(assigneeName, known)}
	doc["metadata"].(map[string]any)["profiles"] = []any{"incident"}
	doc["unmapped"] = incidentUnmapped(fact, known)
	if link := incidentLink(publicBase, ScrubText(fact.IncidentID, known)); link != "" {
		doc["src_url"] = link
	}
	if class == ClassDetail && fact.Comment != "" {
		doc["comment"] = ScrubText(fact.Comment, known)
	}
	return mustJSON(doc), true
}

func detectionFinding(fact AuditFact, class DataClass, known []string, publicBase string) ([]byte, error) {
	activity, ok := findingActivity(fact)
	if !ok {
		return nil, errMissing
	}
	uid := fact.FindingID
	if uid == "" {
		uid = "audit:" + strconv.FormatInt(fact.ID, 10)
	}
	info := map[string]any{"uid": ScrubText(uid, known)}
	if classRank(class) >= 2 && fact.Title != "" {
		info["title"] = ScrubText(fact.Title, known)
	}
	doc := baseFinding(2004, activity, fact.AtUnixMicro, fact.Severity)
	doc["finding_info"] = info
	doc["unmapped"] = auditUnmapped(fact)
	if link := strings.TrimSpace(publicBase); link != "" && fact.FindingID != "" {
		if parsed, err := ParseOrigin(link); err == nil {
			info["src_url"] = parsed.String() + "/findings/" + url.PathEscape(ScrubText(fact.FindingID, known))
		}
	}
	return mustJSON(doc), nil
}

func cveID(value string) bool {
	value = strings.ToUpper(strings.TrimSpace(value))
	if !strings.HasPrefix(value, "CVE-") {
		return false
	}
	rest := strings.TrimPrefix(value, "CVE-")
	year, seq, ok := strings.Cut(rest, "-")
	if !ok || len(year) != 4 || seq == "" {
		return false
	}
	for _, part := range []string{year, seq} {
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func vulnerabilityFinding(fact AuditFact, class DataClass, known []string) ([]byte, error) {
	activity, ok := findingActivity(fact)
	if !ok {
		return nil, errMissing
	}
	uid := fact.FindingID
	if uid == "" {
		uid = "audit:" + strconv.FormatInt(fact.ID, 10)
	}
	info := map[string]any{"uid": ScrubText(uid, known)}
	if fact.Title != "" {
		info["title"] = ScrubText(fact.Title, known)
	}
	doc := baseFinding(2002, activity, fact.AtUnixMicro, fact.Severity)
	doc["finding_info"] = info
	doc["vulnerabilities"] = []any{map[string]any{"cve": map[string]any{"uid": ScrubText(fact.AdvisoryID, known)}}}
	doc["unmapped"] = auditUnmapped(fact)
	return mustJSON(doc), nil
}

func baseFinding(classUID, activity int, atUnixMicro int64, severity string) map[string]any {
	return map[string]any{
		"activity_id":  activity,
		"category_uid": 2,
		"class_uid":    classUID,
		"severity_id":  severityID(severity),
		"time":         atUnixMicro / 1000,
		"type_uid":     classUID*100 + activity,
		"metadata": map[string]any{
			"version": OCSFSchemaVersion,
			"product": map[string]any{"name": "Synapse", "vendor_name": "Synapse"},
		},
	}
}

func auditUnmapped(fact AuditFact) map[string]any {
	return map[string]any{
		"synapse_source_position": map[string]any{
			"source":       string(SourceAudit),
			"id":           fact.ID,
			"hash_version": fact.HashVersion,
		},
		"synapse_source_hash": fact.Hash,
	}
}

func incidentUnmapped(fact IncidentFact, known []string) map[string]any {
	return map[string]any{
		"synapse_source_position": map[string]any{
			"source":      string(fact.Phase),
			"stream_seq":  fact.StreamSeq,
			"incident_id": ScrubText(fact.IncidentID, known),
			"event_seq":   fact.EventSeq,
		},
	}
}

func incidentActivity(fact IncidentFact) (activity, status int, ok bool) {
	switch fact.Kind {
	case stringCreated:
		return 1, 1, true
	case stringStatus:
		switch fact.ToStatus {
		case "new":
			return 2, 1, true
		case "open", "triaged", "investigating", "contained", "remediated", "reopened":
			return 2, 2, true
		case "resolved":
			return 2, 4, true
		case "closed":
			return 3, 5, true
		default:
			return 0, 0, false
		}
	default:
		return 0, 0, false
	}
}

func auditActivity(action string) (int, bool) {
	switch {
	case strings.HasSuffix(action, ".created"):
		return 1, true
	case strings.HasSuffix(action, ".updated"):
		return 2, true
	case strings.HasSuffix(action, ".closed"):
		return 3, true
	default:
		return 0, false
	}
}

func severityID(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "informational", "info":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	case "fatal":
		return 6
	default:
		return 0
	}
}

func severityOrUnknown(severity string) string {
	if severityID(severity) == 0 {
		return "unknown"
	}
	return strings.ToLower(strings.TrimSpace(severity))
}

func classRank(class DataClass) int {
	rank, ok := class.Rank()
	if !ok {
		return 0
	}
	return rank
}

func putID(doc map[string]any, key, value string) {
	if value != "" {
		doc[key] = value
	}
}

func incidentLink(publicBase, incidentID string) string {
	publicBase = strings.TrimSpace(publicBase)
	if publicBase == "" || incidentID == "" {
		return ""
	}
	origin, err := ParseOrigin(publicBase)
	if err != nil {
		return ""
	}
	return origin.String() + "/fleet/incidents/" + url.PathEscape(incidentID)
}

func mustJSON(doc map[string]any) []byte {
	body, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	return body
}

var errMissing = errString("missing")

type errString string

func (e errString) Error() string { return string(e) }
