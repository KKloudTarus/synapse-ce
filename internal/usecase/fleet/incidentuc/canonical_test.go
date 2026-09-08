package incidentuc

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestCanonicalGetAndAliasAppend(t *testing.T) {
	svc, ctx := newSvc(t)
	create := func(id, detection shared.ID) {
		t.Helper()
		_, err := svc.Append(ctx, id, 0, []incident.IncidentEvent{{IncidentID: id, Kind: incident.EventCreated, At: base, Actor: "correlator", AssetID: asset, Title: string(id), Severity: shared.SeverityLow, DetectionID: detection}})
		if err != nil {
			t.Fatal(err)
		}
	}
	create("root", "d-root")
	create("middle", "d-middle")
	create("old", "d-old")
	merge := func(source, target shared.ID) {
		t.Helper()
		events, err := svc.store.LoadEvents(ctx, source)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.store.AppendEvents(ctx, source, len(events), []incident.IncidentEvent{{IncidentID: source, Kind: incident.EventMerged, At: base.Add(1), Actor: "correlator", CorrelationKey: "bridge-" + string(source), MergedInto: target}}); err != nil {
			t.Fatal(err)
		}
	}
	merge("old", "middle")
	merge("middle", "root")
	got, err := svc.Get(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "root" || len(got.Members) != 3 || len(got.DetectionIDs) != 3 {
		t.Fatalf("canonical get = %+v", got)
	}
	events, err := svc.store.LoadEvents(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Append(ctx, "old", len(events), []incident.IncidentEvent{{IncidentID: "old", Kind: incident.EventAnalystCommented, At: base.Add(2), Actor: "analyst", Comment: "canonical write"}}); err != nil {
		t.Fatal(err)
	}
	rootEvents, err := svc.store.LoadEvents(ctx, "root")
	if err != nil || len(rootEvents) != len(events)+1 || rootEvents[len(rootEvents)-1].IncidentID != "root" {
		t.Fatalf("alias append did not write root: %+v %v", rootEvents, err)
	}
	oldEvents, _ := svc.store.LoadEvents(ctx, "old")
	if len(oldEvents) != 2 {
		t.Fatalf("alias log mutated: %+v", oldEvents)
	}
}

func TestCanonicalListDeduplicatesBeforeLimit(t *testing.T) {
	svc, ctx := newSvc(t)
	for _, id := range []shared.ID{"a", "b", "c"} {
		if _, err := svc.Append(ctx, id, 0, []incident.IncidentEvent{{IncidentID: id, Kind: incident.EventCreated, At: base, Actor: "correlator", AssetID: asset, Title: string(id), Severity: shared.SeverityLow}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.store.AppendEvents(ctx, "a", 1, []incident.IncidentEvent{{IncidentID: "a", Kind: incident.EventMerged, At: base.Add(1), Actor: "correlator", CorrelationKey: "bridge-a", MergedInto: "b"}}); err != nil {
		t.Fatal(err)
	}
	items, err := svc.ListByAsset(ctx, asset, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != "b" || items[1].ID != "c" {
		t.Fatalf("root list = %+v", items)
	}
}
