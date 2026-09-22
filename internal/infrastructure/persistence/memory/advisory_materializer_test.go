package memory

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityintel"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
)

func TestAdvisoryRevisionSyncRunProvenanceIsTenantScoped(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctxA := shared.WithTenant(context.Background(), "tenant-a")
	record := observationRecord("osv", "CVE-1", "CVE-2026-5140", "summary")
	record.SyncRunID = "run-a"
	if _, err := store.Materialize(ctxA, []advisory.ObservationRecord{record}); err != nil {
		t.Fatal(err)
	}
	revisions, err := store.ListVulnerabilityAdvisoryRevisions(ctxA, vulnerabilityintel.AdvisoryRevisionQuery{AdvisoryID: "CVE-2026-5140", Limit: 10})
	if err != nil || len(revisions.Items) != 1 || len(revisions.Items[0].SyncRunIDs) != 1 || revisions.Items[0].SyncRunIDs[0] != "run-a" {
		t.Fatalf("revisions=%+v err=%v", revisions, err)
	}
	links, err := store.ListVulnerabilitySyncRunRevisions(ctxA, []shared.ID{"run-a"}, 10)
	if err != nil || len(links["run-a"].Items) != 1 || links["run-a"].Items[0].AdvisoryID != "CVE-2026-5140" {
		t.Fatalf("links=%+v err=%v", links, err)
	}
	links, err = store.ListVulnerabilitySyncRunRevisions(shared.WithTenant(context.Background(), "tenant-b"), []shared.ID{"run-a"}, 10)
	if err != nil || len(links["run-a"].Items) != 0 {
		t.Fatalf("cross-tenant links=%+v err=%v", links, err)
	}
}

func TestAdvisoryMaterializerRejectsSyncRunWithoutTenant(t *testing.T) {
	store := NewAdvisoryMaterializer()
	record := observationRecord("osv", "CVE-1", "CVE-2026-5141", "summary")
	record.SyncRunID = "run-a"
	if _, err := store.Materialize(context.Background(), []advisory.ObservationRecord{record}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant error=%v", err)
	}
	if _, err := store.GetCanonical(context.Background(), "CVE-2026-5141"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rejected materialization wrote canonical: %v", err)
	}
}

func observationRecord(source, record, id, summary string) advisory.ObservationRecord {
	return advisory.ObservationRecord{Observation: advisory.Observation{
		SourceType: source,
		SourceID:   source,
		RecordID:   record,
		Status:     advisory.StatusActive,
		Advisory:   advisory.Advisory{ID: id, Summary: summary},
	}}
}

func TestAdvisoryMaterializerIsIdempotentAndKeepsHistory(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := context.Background()
	record := observationRecord("osv", "CVE-1", "CVE-2026-0001", "old")
	first, err := store.Materialize(ctx, []advisory.ObservationRecord{record})
	if err != nil || !first.CreatedRevision || first.Revision != 1 {
		t.Fatalf("first materialization=%+v err=%v", first, err)
	}
	replay, err := store.Materialize(ctx, []advisory.ObservationRecord{record})
	if err != nil || replay.CreatedRevision || replay.Revision != 1 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	changed := observationRecord("osv", "CVE-1", "CVE-2026-0001", "new")
	second, err := store.Materialize(ctx, []advisory.ObservationRecord{changed})
	if err != nil || !second.CreatedRevision || second.Revision != 2 || len(second.ChangedFields) != 1 || second.ChangedFields[0] != advisory.ChangedSummary {
		t.Fatalf("changed materialization=%+v err=%v", second, err)
	}
	back, err := store.Materialize(ctx, []advisory.ObservationRecord{record})
	if err != nil || !back.CreatedRevision || back.Revision != 3 {
		t.Fatalf("reverted materialization=%+v err=%v", back, err)
	}
}

func TestAdvisoryMaterializerReplacesSLESOpenRangeAcrossVendorLifecycle(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "tools", "ownadvisory", "testdata", "oval-sle15sp6-affected.xml"))
	if err != nil {
		t.Fatal(err)
	}
	fixture = bytes.ReplaceAll(fixture, []byte("\r\n"), []byte("\n"))
	parseOne := func(t *testing.T, doc []byte) advisory.Advisory {
		t.Helper()
		advs, err := ownadvisory.ParseOVAL(doc)
		if err != nil {
			t.Fatalf("ParseOVAL: %v", err)
		}
		if len(advs) != 1 || advs[0].ID != "CVE-2026-53910" {
			t.Fatalf("want one current CVE-2026-53910 observation, got %+v", advs)
		}
		return advs[0]
	}
	materialize := func(t *testing.T, store *AdvisoryMaterializer, adv advisory.Advisory) advisory.MaterializationResult {
		t.Helper()
		result, err := store.Materialize(context.Background(), []advisory.ObservationRecord{{Observation: advisory.Observation{
			SourceType: "oval", SourceID: "suse-sles-15-sp6", RecordID: adv.ID, Status: advisory.StatusActive, Advisory: adv,
		}}})
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		return result
	}

	store := NewAdvisoryMaterializer()
	open := parseOne(t, fixture)
	first := materialize(t, store, open)
	if !first.CreatedRevision || first.Revision != 1 {
		t.Fatalf("open materialization = %+v", first)
	}
	canonical, err := store.GetCanonical(context.Background(), "CVE-2026-53910")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := canonical.Advisory.Match("SUSE:15.6", "diffutils", "3.6-4.3.1", ""); !ok {
		t.Fatal("open vendor state must match the installed package")
	}

	packageRemovedXML := bytes.Replace(fixture,
		[]byte("          <criterion test_ref=\"oval:org.opensuse.security:tst:diffutils-affected\" comment=\"diffutils is affected\"/>\n"),
		nil,
		1,
	)
	packageRemoved := parseOne(t, packageRemovedXML)
	removed := materialize(t, store, packageRemoved)
	if !removed.CreatedRevision || removed.Revision != 2 {
		t.Fatalf("package-removed materialization = %+v", removed)
	}
	canonical, err = store.GetCanonical(context.Background(), "CVE-2026-53910")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := canonical.Advisory.Match("SUSE:15.6", "diffutils", "3.6-4.3.1", ""); ok {
		t.Fatal("a package removed from the current CVE projection must not retain stale applicability")
	}
	if ok, _ := canonical.Advisory.Match("SUSE:15.6", "diffutils-lang", "3.6-4.3.1", ""); !ok {
		t.Fatal("the remaining current package branch must stay affected")
	}

	fixedXML := bytes.ReplaceAll(fixture,
		[]byte(`<linux:evr datatype="evr_string" operation="greater than">0:0-0</linux:evr>`),
		[]byte(`<linux:evr datatype="evr_string" operation="less than">0:3.6-4.3.2</linux:evr>`),
	)
	fixedXML = bytes.ReplaceAll(fixedXML, []byte(`comment="diffutils is affected"`), []byte(`comment="diffutils-3.6-4.3.2 is installed"`))
	fixedXML = bytes.ReplaceAll(fixedXML, []byte(`comment="diffutils-lang is affected"`), []byte(`comment="diffutils-lang-3.6-4.3.2 is installed"`))
	fixedXML = bytes.ReplaceAll(fixedXML, []byte(`comment="diffutils is >0"`), []byte(`comment="diffutils is &lt;0:3.6-4.3.2"`))
	fixedXML = bytes.ReplaceAll(fixedXML, []byte(`comment="diffutils-lang is >0"`), []byte(`comment="diffutils-lang is &lt;0:3.6-4.3.2"`))
	fixed := parseOne(t, fixedXML)
	second := materialize(t, store, fixed)
	if !second.CreatedRevision || second.Revision != 3 {
		t.Fatalf("fixed materialization = %+v", second)
	}
	canonical, err = store.GetCanonical(context.Background(), "CVE-2026-53910")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := canonical.Advisory.Match("SUSE:15.6", "diffutils", "3.6-4.3.2", ""); ok {
		t.Fatal("a package at the vendor fixed boundary must not retain stale open applicability")
	}

	notAffectedXML := bytes.ReplaceAll(fixture,
		[]byte(`<linux:evr datatype="evr_string" operation="greater than">0:0-0</linux:evr>`),
		[]byte(`<linux:version datatype="version" operation="equals">0</linux:version>`),
	)
	notAffectedXML = bytes.ReplaceAll(notAffectedXML, []byte(" is affected"), []byte(" is not affected"))
	notAffectedXML = bytes.ReplaceAll(notAffectedXML, []byte(" is >0"), []byte(" is ==0"))
	notAffected := parseOne(t, notAffectedXML)
	if len(notAffected.Affected) != 0 {
		t.Fatalf("vendor not-affected observation must be empty, got %+v", notAffected.Affected)
	}
	third := materialize(t, store, notAffected)
	if !third.CreatedRevision || third.Revision != 4 {
		t.Fatalf("not-affected materialization = %+v", third)
	}
	canonical, err = store.GetCanonical(context.Background(), "CVE-2026-53910")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := canonical.Advisory.Match("SUSE:15.6", "diffutils", "3.6-4.3.1", ""); ok {
		t.Fatal("authoritative not-affected replacement must remove stale applicability")
	}
}

func TestAdvisoryMaterializerRejectsAliasConflictWithoutPartialWrite(t *testing.T) {
	store := NewAdvisoryMaterializer()
	ctx := context.Background()
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{
		observationRecord("nvd", "one", "CVE-2026-0001", "one"),
	}); err != nil {
		t.Fatal(err)
	}
	conflict := observationRecord("vendor", "two", "VENDOR-2", "two")
	conflict.Observation.Advisory.ID = "CVE-2026-0002"
	conflict.Observation.Advisory.Aliases = []string{"GHSA-SHARED"}
	first := observationRecord("vendor", "one-alias", "CVE-2026-0001", "one alias")
	first.Observation.Advisory.Aliases = []string{"GHSA-SHARED"}
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{first}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Materialize(ctx, []advisory.ObservationRecord{conflict}); !errors.Is(err, advisory.ErrAliasConflict) {
		t.Fatalf("conflict error=%v", err)
	}
	if _, err := store.GetCanonical(ctx, "VENDOR-2"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("failed transaction exposed conflicting canonical: %v", err)
	}
	if _, err := store.GetCanonical(ctx, "CVE-2026-0001"); err != nil {
		t.Fatalf("existing canonical lost after conflict: %v", err)
	}
}

// D1.3: the in-memory store projects the same risk (KEV/EPSS) and status (Withdrawn) fields as Postgres, so
// a blank-DSN/in-memory scan has parity — an offline scan orders by exploitation risk and skips retractions.
func TestAdvisoryMaterializerProjectsRiskAndStatus(t *testing.T) {
	store := NewAdvisoryMaterializer()
	kev := true
	epss := 0.77
	rec := advisory.ObservationRecord{Observation: advisory.Observation{
		SourceType: "osv", SourceID: "osv", RecordID: "r1", Status: advisory.StatusActive,
		KEV: &kev, EPSS: &epss,
		Advisory: advisory.Advisory{ID: "CVE-2026-RISK", Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "left-pad", Versions: []string{"1.0.0"}}}},
	}}
	if _, err := store.Materialize(context.Background(), []advisory.ObservationRecord{rec}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	got, err := store.ByPackage(context.Background(), "npm", "left-pad")
	if err != nil || len(got) != 1 {
		t.Fatalf("ByPackage = %+v err=%v", got, err)
	}
	if !got[0].KEV || got[0].EPSS != 0.77 {
		t.Errorf("in-memory projection must carry KEV/EPSS, got KEV=%v EPSS=%v", got[0].KEV, got[0].EPSS)
	}

	// A withdrawn advisory projects Withdrawn=true (parity with postgres, so the matcher skips it).
	wrec := advisory.ObservationRecord{Observation: advisory.Observation{
		SourceType: "osv", SourceID: "osv", RecordID: "r2", Status: advisory.StatusWithdrawn,
		Advisory: advisory.Advisory{ID: "CVE-2026-GONE", Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "gone-pkg", Versions: []string{"1.0.0"}}}},
	}}
	if _, err := store.Materialize(context.Background(), []advisory.ObservationRecord{wrec}); err != nil {
		t.Fatalf("materialize withdrawn: %v", err)
	}
	w, _ := store.ByPackage(context.Background(), "npm", "gone-pkg")
	if len(w) != 1 || !w[0].Withdrawn {
		t.Errorf("withdrawn advisory must project Withdrawn=true, got %+v", w)
	}
}
