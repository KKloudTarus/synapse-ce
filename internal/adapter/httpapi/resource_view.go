package httpapi

import (
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
)

// This file holds the serialized shape of the two aggregates the API used to hand back as raw
// domain structs. Engagements and projects answered with Go field names (ID, TenantID,
// SourceBinding) while scans, analyses, and every newer resource answered in snake_case, so a
// client had to special-case per resource. These views are the transport contract: the domain
// types keep no JSON tags, and a rename inside the domain cannot silently change the wire format.

// scopeView is the serialized engagement scope. It reuses the request DTO for targets, so the shape
// a caller sends and the shape it reads back are the same.
type scopeView struct {
	InScope    []scopeTargetDTO `json:"in_scope"`
	OutOfScope []scopeTargetDTO `json:"out_of_scope"`
}

// blackoutView is a serialized rules-of-engagement blackout window.
type blackoutView struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// roeView is the serialized rules of engagement the execution gate enforces.
type roeView struct {
	AllowedToolClasses []string       `json:"allowed_tool_classes"`
	Blackouts          []blackoutView `json:"blackouts"`
}

// engagementView is the serialized shape of an engagement.
type engagementView struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	ProjectID       string    `json:"project_id,omitempty"`
	BusinessAssetID string    `json:"business_asset_id,omitempty"`
	Name            string    `json:"name"`
	Client          string    `json:"client"`
	Status          string    `json:"status"`
	Scope           scopeView `json:"scope"`
	RoE             roeView   `json:"roe"`
	// AuthorizedFrom and AuthorizedTo bound legal testing. A null bound is open on that side.
	AuthorizedFrom   *time.Time `json:"authorized_from"`
	AuthorizedTo     *time.Time `json:"authorized_to"`
	Timezone         string     `json:"timezone,omitempty"`
	LiveReconEnabled bool       `json:"live_recon_enabled"`
	// OffensiveRoE is the rules of engagement the offensive governance policy requires before adversary
	// emulation or exploitation chains may run. Distinct from RoE above (allowed tool classes + blackouts).
	OffensiveRoE offensiveRoEView `json:"offensive_roe"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
	// List enrichment (listEngagements): open finding counts and the latest scan job, so the table
	// shows what a row's scan found without a request per row. Absent on single-resource responses
	// and when the stores are not wired.
	FindingsCount  *engagementFindingsView `json:"findings_count,omitempty"`
	LastScanDate   *time.Time              `json:"last_scan_date,omitempty"`
	LastScanStatus string                  `json:"last_scan_status,omitempty"`
}

// engagementFindingsView counts an engagement's open findings of every kind by severity.
type engagementFindingsView struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func toTargetViews(targets []engdom.Target) []scopeTargetDTO {
	out := make([]scopeTargetDTO, 0, len(targets))
	for _, target := range targets {
		out = append(out, scopeTargetDTO{Kind: string(target.Kind), Value: target.Value})
	}
	return out
}

func toRoEView(roe engdom.RoE) roeView {
	classes := make([]string, 0, len(roe.AllowedToolClasses))
	for _, class := range roe.AllowedToolClasses {
		classes = append(classes, string(class))
	}
	blackouts := make([]blackoutView, 0, len(roe.Blackouts))
	for _, blackout := range roe.Blackouts {
		blackouts = append(blackouts, blackoutView{From: blackout.From, To: blackout.To})
	}
	return roeView{AllowedToolClasses: classes, Blackouts: blackouts}
}

// offensiveRoEView is the serialized offensive rules of engagement.
type offensiveRoEView struct {
	CustomerContact   string `json:"customer_contact"`
	EmergencyContact  string `json:"emergency_contact"`
	RiskCeiling       string `json:"risk_ceiling"`
	ExclusionsChecked bool   `json:"exclusions_checked"`
}

func toEngagementView(e *engdom.Engagement) engagementView {
	if e == nil {
		return engagementView{}
	}
	return engagementView{
		ID:              e.ID.String(),
		TenantID:        e.TenantID.String(),
		ProjectID:       e.ProjectID.String(),
		BusinessAssetID: e.BusinessAssetID.String(),
		Name:            e.Name,
		Client:          e.Client,
		Status:          string(e.Status),
		Scope: scopeView{
			InScope:    toTargetViews(e.Scope.InScope),
			OutOfScope: toTargetViews(e.Scope.OutOfScope),
		},
		RoE:              toRoEView(e.RoE),
		AuthorizedFrom:   e.AuthorizedFrom,
		AuthorizedTo:     e.AuthorizedTo,
		Timezone:         e.Timezone,
		LiveReconEnabled: e.LiveReconEnabled,
		OffensiveRoE: offensiveRoEView{
			CustomerContact:   e.CustomerContact,
			EmergencyContact:  e.EmergencyContact,
			RiskCeiling:       e.RiskCeiling,
			ExclusionsChecked: e.ExclusionsChecked,
		},
		CreatedAt: e.Audit.CreatedAt,
		UpdatedAt: e.Audit.UpdatedAt,
	}
}

func toEngagementViews(list []*engdom.Engagement) []engagementView {
	out := make([]engagementView, 0, len(list))
	for _, e := range list {
		out = append(out, toEngagementView(e))
	}
	return out
}

// projectView is the serialized shape of a code-quality project. SourceBinding already carries its
// own snake_case tags, so it is embedded as it is.
type projectView struct {
	ID                   string                `json:"id"`
	TenantID             string                `json:"tenant_id"`
	Name                 string                `json:"name"`
	Key                  string                `json:"key"`
	SourceBinding        project.SourceBinding `json:"source_binding"`
	DefaultProfileByLang map[string]string     `json:"default_profile_by_lang"`
	GateID               string                `json:"gate_id,omitempty"`
	CreatedAt            time.Time             `json:"created_at"`
	UpdatedAt            time.Time             `json:"updated_at"`
}

func toProjectView(p *project.Project) projectView {
	if p == nil {
		return projectView{}
	}
	return projectView{
		ID:                   p.ID.String(),
		TenantID:             p.TenantID.String(),
		Name:                 p.Name,
		Key:                  p.Key,
		SourceBinding:        p.SourceBinding,
		DefaultProfileByLang: p.DefaultProfileByLang,
		GateID:               p.GateID,
		CreatedAt:            p.Audit.CreatedAt,
		UpdatedAt:            p.Audit.UpdatedAt,
	}
}
