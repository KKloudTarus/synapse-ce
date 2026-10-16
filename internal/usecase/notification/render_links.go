package notification

import (
	"fmt"
	"net/url"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/consolelink"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SetConsoleLinkBuilder enables typed, server-built console links in rendered chat and email
// messages. A deployment without a public console origin leaves it unset and sends no links.
func (s *Service) SetConsoleLinkBuilder(builder consolelink.Builder) {
	s.links = &builder
}

func (s *Service) renderLinks(event domain.Event) []ports.RenderedLink {
	if s.links == nil {
		return nil
	}
	if event.SourceKind == "template_fixture" || event.SourceKind == "template_test" {
		if href, ok := s.links.Path("/settings/alerting"); ok {
			return []ports.RenderedLink{{Label: "Open notifications", URL: href}}
		}
		return nil
	}
	var (
		link  consolelink.Link
		label string
		err   error
	)
	switch event.Type {
	case domain.EventDigest:
		var links []ports.RenderedLink
		shown := 0
		limit := domain.MaxDigestItems
		if len(event.Context) > 0 {
			if context, err := domain.DecodeTemplateContext(event.Context); err == nil {
				limit = min(limit, len(context.Lists["items"]))
			}
		}
		ordered := append([]domain.DigestItem(nil), event.DigestItems...)
		sort.Slice(ordered, func(i, j int) bool {
			if ordered[i].Event.OccurredAt.Equal(ordered[j].Event.OccurredAt) {
				return ordered[i].Event.ID < ordered[j].Event.ID
			}
			return ordered[i].Event.OccurredAt.Before(ordered[j].Event.OccurredAt)
		})
		for _, item := range ordered {
			if _, known := domain.LookupEvent(item.Event.Type); !known || item.Event.Type == domain.EventDigest {
				continue
			}
			if _, allowed := domain.EffectiveDataClass(domain.DataClassDetail, item.Override); !allowed {
				continue
			}
			shown++
			if shown > limit {
				break
			}
			for _, link := range s.renderLinks(item.Event) {
				link.Label = fmt.Sprintf("%d · %s", shown, link.Label)
				links = append(links, link)
			}
		}
		if len(links) == 0 {
			if href, ok := s.links.Path("/settings/alerting"); ok {
				links = append(links, ports.RenderedLink{Label: "Open notifications", URL: href})
			}
		}
		return links

	case domain.EventApprovalRequested, domain.EventApprovalDecided, domain.EventApprovalTimedOut:
		kind := decodeEventData(event.Data).text("kind")
		path := ""
		switch kind {
		case "response":
			path = "/blueteam/response"
		case "agent":
			if _, err := s.links.Engagement(event.EngagementID); err == nil {
				path = "/engagements/" + url.PathEscape(event.EngagementID.String()) + "/agent"
			}
		}
		if href, ok := s.links.Path(path); ok {
			return []ports.RenderedLink{{Label: "Open approvals", URL: href}}
		}
		return nil
	case domain.EventResponseFinished:
		if href, ok := s.links.Path("/blueteam/response"); ok {
			return []ports.RenderedLink{{Label: "Open response", URL: href}}
		}
		return nil

	case domain.EventScanCompleted, domain.EventScanFailed:
		if !event.EngagementID.IsZero() && event.SubjectID != "" {
			link, err = s.links.Scan(event.EngagementID, shared.ID(event.SubjectID))
			label = "Open scan"
		}
	case domain.EventFindingCommented, domain.EventFindingMentioned, domain.EventSLAApproaching, domain.EventOwnershipChanged, domain.EventFindingCreated, domain.EventFindingStatusChanged, domain.EventFindingRetestCompleted, domain.EventSLABreached, domain.EventRiskAcceptanceCreated, domain.EventRiskAcceptanceExpiring, domain.EventRiskAcceptanceExpired:
		if !event.EngagementID.IsZero() && event.SubjectID != "" {
			link, err = s.links.Finding(event.EngagementID, shared.ID(event.SubjectID))
			label = "Open finding"
		}
	case domain.EventDASTRunFinished, domain.EventReconRunFinished, domain.EventCSPMRunFinished:
		if !event.EngagementID.IsZero() {
			link, err = s.links.Engagement(event.EngagementID)
			label = "Open engagement"
		}
	case domain.EventIncidentCreated, domain.EventIncidentUpdated:
		if event.SubjectID != "" {
			link, err = s.links.Incident(shared.ID(event.SubjectID))
			label = "Open incident"
		}
	case domain.EventEngagementCreated, domain.EventEngagementStatusChanged, domain.EventEngagementWindowStarting, domain.EventEngagementWindowEnding, domain.EventEvidenceChainBroken, domain.EventVulnerabilityAction:
		if !event.EngagementID.IsZero() {
			link, err = s.links.Engagement(event.EngagementID)
			label = "Open engagement"
		}
	}
	if err != nil || link.Href() == "" {
		return nil
	}
	return []ports.RenderedLink{{Label: label, URL: link.Href()}}
}

func webhookLinks(links []ports.RenderedLink) []domain.WebhookLink {
	if len(links) == 0 {
		return nil
	}
	out := make([]domain.WebhookLink, len(links))
	for i, link := range links {
		out[i] = domain.WebhookLink{Label: link.Label, URL: link.URL}
	}
	return out
}
