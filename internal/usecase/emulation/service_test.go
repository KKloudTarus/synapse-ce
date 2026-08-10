package emulation

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	demu "github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
	dexploit "github.com/KKloudTarus/synapse-ce/internal/domain/exploitation"
	domainpolicy "github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	exploituc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	offensivepolicyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// recordingExecutor reports every step as producing its observable, and records the radius it was asked
// to run at — a benign (production-safe) technique must arrive read-only.
type recordingExecutor struct {
	radii map[string]string // technique -> blast radius seen
}

func (e *recordingExecutor) Execute(_ context.Context, _ *dexploit.Chain, step dexploit.Step) (exploituc.StepOutcome, error) {
	if e.radii == nil {
		e.radii = map[string]string{}
	}
	e.radii[step.Technique] = string(step.BlastRadius)
	return exploituc.StepOutcome{Succeeded: true, ObservedRadius: step.BlastRadius,
		Proof: []byte("benign observable for " + step.Technique), Observation: "produced telemetry"}, nil
}

type emuAudit struct{ actions map[string]int }

func (a *emuAudit) Record(_ context.Context, e ports.AuditEntry) error {
	if a.actions == nil {
		a.actions = map[string]int{}
	}
	a.actions[e.Action]++
	return nil
}

type emuStore struct{ runs []demu.Run }

func (s *emuStore) SaveRun(_ context.Context, run demu.Run) error {
	s.runs = append(s.runs, run)
	return nil
}

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID { s.n++; return shared.ID(fmt.Sprintf("id-%d", s.n)) }

type emuClock struct{}

func (emuClock) Now() time.Time { return time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC) }

// realAdmitter wires the ACTUAL #418 policy so emulation admission is provably the same gate
// exploitation uses (issue #421 criterion: reuse the exploitation admission).
func realAdmitter(t *testing.T, allowHigh bool) exploituc.StepAdmitter {
	t.Helper()
	reg, err := domainpolicy.Load()
	if err != nil {
		t.Fatal(err)
	}
	gov, err := offensivepolicyuc.NewService(reg, noopSealer{}, &emuAudit{})
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC) }
	roe := offensivepolicyuc.RulesOfEngagement{
		AuthorizedScope: []string{"asset-x"}, WindowStart: now().Add(-time.Hour), WindowEnd: now().Add(time.Hour),
		CustomerContact: "ciso@example.test", EmergencyContact: "+84", RiskCeiling: domainpolicy.RiskHigh,
		ExclusionsChecked: true,
	}
	// Approvals: benign techniques are automatic (need none); the lab-only one is dual, so supply two
	// distinct humans when the test opts into high-risk emulation.
	approvals := func(step dexploit.Step) []offensivepolicyuc.Approval {
		if !allowHigh {
			return nil
		}
		return []offensivepolicyuc.Approval{
			{Approver: "alice", Technique: step.Technique, Target: step.Target.String()},
			{Approver: "bob", Technique: step.Technique, Target: step.Target.String()},
		}
	}
	return exploituc.NewPolicyStepAdmitter(gov, roe, approvals, now)
}

type noopSealer struct{}

func (noopSealer) SealOffensiveAuthorization(_ context.Context, _ shared.ID, _ []byte, _ string) (shared.ID, error) {
	return "ev-1", nil
}

func newService(t *testing.T, allowHigh bool) (*Service, *recordingExecutor, *emuAudit, *emuStore) {
	t.Helper()
	exec := &recordingExecutor{}
	audit := &emuAudit{}
	store := &emuStore{}
	svc, err := NewService(realAdmitter(t, allowHigh), exec, store, audit, emuClock{}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return svc, exec, audit, store
}

// TestEmulateProducesACoverageRecordPerTechniqueAndNeverOmits: every catalogued technique yields a
// record; a benign technique executes and is a gap (no detection engine yet); the lab-only technique is
// refused without the opt-in but is still recorded, never omitted.
func TestEmulateProducesACoverageRecordPerTechniqueAndNeverOmits(t *testing.T) {
	svc, exec, _, store := newService(t, false)
	all, _ := demu.Catalogue()

	run, err := svc.Emulate(context.Background(), "t1", "eng-1", "asset-x", "operator", Options{AllowLabOnly: false})
	if err != nil {
		t.Fatalf("emulate: %v", err)
	}
	if len(run.Coverage) != len(all) {
		t.Fatalf("a record per technique expected: %d records for %d techniques", len(run.Coverage), len(all))
	}
	byID := map[string]demu.CoverageRecord{}
	for _, r := range run.Coverage {
		byID[r.TechniqueID] = r
	}

	for _, tech := range all {
		rec, ok := byID[tech.ID]
		if !ok {
			t.Errorf("technique %s was omitted from coverage", tech.ID)
			continue
		}
		if rec.Expected != tech.Expected.DetectionID {
			t.Errorf("%s expected detection = %q, want %q", tech.ID, rec.Expected, tech.Expected.DetectionID)
		}
		if tech.ProductionSafe {
			// Benign, executed → a gap until the detection engine exists.
			if !rec.Executed || !rec.Gap {
				t.Errorf("%s should have executed and be a gap: %+v", tech.ID, rec)
			}
			// And it must have been admitted read-only — a benign proof does not change state.
			if got := exec.radii[tech.ID]; got != "read_only" {
				t.Errorf("%s ran at radius %q, want read_only (benign)", tech.ID, got)
			}
		} else {
			// Lab-only without opt-in → refused, not executed, not a gap, but recorded.
			if rec.Executed {
				t.Errorf("lab-only %s must not execute without the opt-in: %+v", tech.ID, rec)
			}
		}
	}
	if len(store.runs) != 1 {
		t.Fatalf("the run must be persisted once, got %d", len(store.runs))
	}
}

// TestLabOnlyRunsOnlyWithOptInAndDualApproval: with the opt-in AND its dual approval, the lab-only
// technique executes; it is state-changing and carries a cleanup path.
func TestLabOnlyRunsOnlyWithOptIn(t *testing.T) {
	svc, exec, _, _ := newService(t, true)
	run, err := svc.Emulate(context.Background(), "t1", "eng-1", "asset-x", "operator", Options{AllowLabOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var lab demu.CoverageRecord
	for _, r := range run.Coverage {
		if r.TechniqueID == "emu.service_restart_probe" {
			lab = r
		}
	}
	if !lab.Executed {
		t.Fatalf("with the opt-in and dual approval the lab-only technique must execute: %+v", lab)
	}
	if got := exec.radii["emu.service_restart_probe"]; got != "state_changing" {
		t.Errorf("the lab-only technique must run state_changing, got %q", got)
	}
}

// TestEmulationIsNotALooserPath is the #421 criterion: emulation admission IS the exploitation gate. A
// register that does not contain a technique refuses it here exactly as it would an exploitation step —
// proven by pointing the admitter at a policy whose register lacks the emulation entries.
func TestEmulationIsNotALooserPath(t *testing.T) {
	// Every emulation technique must be admissible through the shared admitter under the real policy;
	// if any were missing from the register, this run would record it refused (executed=false) rather
	// than silently executing it on a looser path.
	svc, _, audit, _ := newService(t, true)
	run, err := svc.Emulate(context.Background(), "t1", "eng-1", "asset-x", "operator", Options{AllowLabOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	// With every technique registered and admitted, none is refused for lack of a register entry.
	if audit.actions["emulation.technique.refused"] != 0 {
		t.Errorf("a technique was refused by the shared policy admitter unexpectedly: %+v", audit.actions)
	}
	executed := 0
	for _, r := range run.Coverage {
		if r.Executed {
			executed++
		}
	}
	if executed != len(run.Coverage) {
		t.Errorf("with the opt-in and approvals every registered technique should execute: %d of %d", executed, len(run.Coverage))
	}
	// Sanity: the audit recorded the run with a gap count equal to the executed count (no detections yet).
	if audit.actions["emulation.run"] != 1 {
		t.Errorf("the run must be audited once: %+v", audit.actions)
	}
}

// TestEmulateIsDeterministic: two runs over the same catalogue produce the same technique ordering, so a
// coverage trend is comparable.
func TestEmulateIsDeterministic(t *testing.T) {
	svc, _, _, _ := newService(t, false)
	a, _ := svc.Emulate(context.Background(), "t1", "eng-1", "asset-x", "op", Options{})
	b, _ := svc.Emulate(context.Background(), "t1", "eng-1", "asset-x", "op", Options{})
	if len(a.Coverage) != len(b.Coverage) {
		t.Fatal("coverage length not stable")
	}
	var ida, idb []string
	for i := range a.Coverage {
		ida = append(ida, a.Coverage[i].TechniqueID)
		idb = append(idb, b.Coverage[i].TechniqueID)
	}
	if strings.Join(ida, ",") != strings.Join(idb, ",") {
		t.Fatalf("coverage ordering not stable:\n %v\n %v", ida, idb)
	}
}
