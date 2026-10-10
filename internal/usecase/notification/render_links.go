package notification

import (
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
	var (
		link  consolelink.Link
		label string
		err   error
	)
	switch event.Type {
	case domain.EventScanCompleted:
		if !event.EngagementID.IsZero() && event.SubjectID != "" {
			link, err = s.links.Scan(event.EngagementID, shared.ID(event.SubjectID))
			label = "Open scan"
		}
	case domain.EventSLAApproaching, domain.EventOwnershipChanged:
		if !event.EngagementID.IsZero() && event.SubjectID != "" {
			link, err = s.links.Finding(event.EngagementID, shared.ID(event.SubjectID))
			label = "Open finding"
		}
	case domain.EventIncidentCreated:
		if event.SubjectID != "" {
			link, err = s.links.Incident(shared.ID(event.SubjectID))
			label = "Open incident"
		}
	case domain.EventVulnerabilityAction:
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
