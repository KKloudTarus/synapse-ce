package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/businessassetuc"
)

type dashboardFinding struct {
	ID        shared.ID
	Severity  shared.Severity
	Status    finding.Status
	Class     string
	CreatedAt time.Time
}

type dashboardTrendPoint struct {
	Date   string         `json:"date"`
	Counts map[string]int `json:"counts"`
}

type securityOperationsSummary struct {
	RangeDays                int                   `json:"range_days"`
	GeneratedAt              time.Time             `json:"generated_at"`
	AssetPosture             map[string]int        `json:"asset_posture"`
	AssetsByCriticality      map[string]int        `json:"assets_by_criticality"`
	ActiveFindingsBySeverity map[string]int        `json:"active_findings_by_severity"`
	FindingsOverTime         []dashboardTrendPoint `json:"findings_over_time"`
	FindingsWithoutTimestamp int                   `json:"findings_without_timestamp"`
	ExternalFindingsIncluded bool                  `json:"external_findings_included"`
}

func (rt *Router) dashboardSecurityOperations(w http.ResponseWriter, r *http.Request) {
	days, ok := dashboardRangeDays(r.URL.Query().Get("range"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "range must be 7d, 30d, or 90d"})
		return
	}

	tenantID := requestTenant(r)
	ctx := shared.WithTenant(r.Context(), tenantID)
	assets, err := rt.businessAssets.List(ctx, tenantID, businessassetuc.Filter{})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	postures := make(map[shared.ID]string, len(assets))
	for _, item := range assets {
		posture, postureErr := rt.businessAssets.Posture(ctx, tenantID, item.ID)
		if postureErr != nil {
			writeError(w, rt.log, postureErr)
			return
		}
		postures[item.ID] = posture.Rating
	}

	engagements, err := rt.eng.List(ctx, tenantID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	rows := make([]dashboardFinding, 0)
	seen := map[shared.ID]bool{}
	// ponytail: this read model fans out over tenant engagements; replace it with repository-level
	// aggregate queries when dashboard volume makes the bounded server-side fan-out measurable.
	for _, engagement := range engagements {
		canonical, findingErr := rt.findings.List(ctx, engagement.ID)
		if findingErr != nil {
			writeError(w, rt.log, findingErr)
			return
		}
		for _, item := range finding.Publishable(canonical) {
			if seen[item.ID] {
				continue
			}
			seen[item.ID] = true
			rows = append(rows, dashboardFinding{ID: item.ID, Severity: item.Severity, Status: item.Status, Class: item.Class, CreatedAt: item.Audit.CreatedAt})
		}
		if rt.importedFindings == nil {
			continue
		}
		external, findingErr := rt.importedFindings.ListByEngagement(ctx, tenantID, engagement.ID)
		if findingErr != nil {
			writeError(w, rt.log, findingErr)
			return
		}
		for _, item := range external {
			if (!item.FindingID.IsZero() && seen[item.FindingID]) || seen[item.ID] {
				continue
			}
			seen[item.ID] = true
			rows = append(rows, dashboardFinding{ID: item.ID, Severity: item.Severity, Status: finding.StatusOpen, Class: finding.ClassThirdParty, CreatedAt: item.Audit.CreatedAt})
		}
	}

	writeJSON(w, http.StatusOK, buildSecurityOperationsSummary(assets, postures, rows, days, time.Now().UTC(), rt.importedFindings != nil))
}

func dashboardRangeDays(value string) (int, bool) {
	switch strings.TrimSpace(value) {
	case "", "30d":
		return 30, true
	case "7d":
		return 7, true
	case "90d":
		return 90, true
	default:
		return 0, false
	}
}

func buildSecurityOperationsSummary(assets []*asset.BusinessAsset, postures map[shared.ID]string, findings []dashboardFinding, days int, now time.Time, externalIncluded bool) securityOperationsSummary {
	postureCounts := counts("critical", "high_risk", "attention", "unknown", "good")
	criticalityCounts := counts("critical", "high", "medium", "low")
	severityCounts := counts("critical", "high", "medium", "low", "info", "unknown")
	for _, item := range assets {
		posture := postures[item.ID]
		if _, known := postureCounts[posture]; !known {
			posture = "unknown"
		}
		postureCounts[posture]++
		criticality := string(item.Criticality)
		if _, known := criticalityCounts[criticality]; known {
			criticalityCounts[criticality]++
		}
	}

	end := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -(days - 1))
	trend := make([]dashboardTrendPoint, days)
	trendByDate := make(map[string]map[string]int, days)
	for index := 0; index < days; index++ {
		date := start.AddDate(0, 0, index).Format("2006-01-02")
		trend[index] = dashboardTrendPoint{Date: date, Counts: counts("critical", "high", "medium", "low", "info", "unknown")}
		trendByDate[date] = trend[index].Counts
	}

	withoutTimestamp := 0
	for _, item := range findings {
		if item.Class == finding.ClassFirstPartyHistoric {
			continue
		}
		severity := string(item.Severity)
		if _, known := severityCounts[severity]; !known {
			severity = "unknown"
		}
		if activeFindingStatus(item.Status) {
			severityCounts[severity]++
		}
		if item.CreatedAt.IsZero() {
			withoutTimestamp++
			continue
		}
		date := item.CreatedAt.UTC().Format("2006-01-02")
		if bucket := trendByDate[date]; bucket != nil {
			bucket[severity]++
		}
	}

	return securityOperationsSummary{
		RangeDays: days, GeneratedAt: now.UTC(), AssetPosture: postureCounts,
		AssetsByCriticality: criticalityCounts, ActiveFindingsBySeverity: severityCounts,
		FindingsOverTime: trend, FindingsWithoutTimestamp: withoutTimestamp,
		ExternalFindingsIncluded: externalIncluded,
	}
}

func activeFindingStatus(status finding.Status) bool {
	return status == finding.StatusOpen || status == finding.StatusTriage || status == finding.StatusConfirmed
}

func counts(keys ...string) map[string]int {
	out := make(map[string]int, len(keys))
	for _, key := range keys {
		out[key] = 0
	}
	return out
}
