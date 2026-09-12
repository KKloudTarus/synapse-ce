package sastbench

import (
	"strings"
	"testing"
)

func TestScorePerCategory(t *testing.T) {
	cases := []Case{
		{Name: "T1", Category: "cmdi", Real: true},  // detected -> TP
		{Name: "T2", Category: "cmdi", Real: true},  // not detected -> FN
		{Name: "T3", Category: "cmdi", Real: false}, // detected -> FP (sanitized-safe flagged)
		{Name: "T4", Category: "cmdi", Real: false}, // not detected -> TN
		{Name: "T5", Category: "sqli", Real: true},  // detected -> TP
		{Name: "X1", Category: "xss", Real: true},   // unscored category -> ignored
	}
	detected := map[string]map[string]bool{
		"T1": {"CWE-78": true},
		"T3": {"CWE-78": true},
		"T5": {"CWE-89": true},
		"X1": {"CWE-79": true},
	}
	scores := Score(detected, cases)
	byCat := map[string]CategoryScore{}
	for _, s := range scores {
		byCat[s.Category] = s
	}
	cmdi := byCat["cmdi"]
	if cmdi.TP != 1 || cmdi.FN != 1 || cmdi.FP != 1 || cmdi.TN != 1 || cmdi.Total != 4 {
		t.Fatalf("cmdi matrix wrong: %+v", cmdi)
	}
	if cmdi.Precision != 0.5 || cmdi.Recall != 0.5 {
		t.Errorf("cmdi precision/recall = %.2f/%.2f, want 0.50/0.50", cmdi.Precision, cmdi.Recall)
	}
	if byCat["sqli"].TP != 1 || byCat["sqli"].Recall != 1 {
		t.Errorf("sqli = %+v, want TP=1 recall=1", byCat["sqli"])
	}
	// xss is unscored: it must not appear
	if _, ok := byCat["xss"]; ok {
		t.Error("an unscored category must not be scored")
	}
	// all three modeled categories are always present (even with zero cases), so a gap reads as not-covered
	if len(scores) != 3 {
		t.Fatalf("want the 3 modeled categories, got %d", len(scores))
	}
}

// The ratchet flags a category whose recall dropped below its floor, and passes when all meet it.
func TestCheckRatchet(t *testing.T) {
	floors := DefaultFloors()
	if floors.Recall["cmdi"] <= 0 {
		t.Fatal("default floors did not load")
	}
	// a scorecard at/above the floors passes
	ok := []CategoryScore{
		{Category: "cmdi", Recall: floors.Recall["cmdi"]},
		{Category: "sqli", Recall: floors.Recall["sqli"] + 0.05},
		{Category: "pathtraver", Recall: floors.Recall["pathtraver"] + 0.01},
	}
	if b := CheckRatchet(ok, floors); len(b) != 0 {
		t.Fatalf("scorecard at/above floors must pass, got breaches %v", b)
	}
	// a regression below a floor is flagged
	bad := []CategoryScore{{Category: "sqli", Recall: floors.Recall["sqli"] - 0.01}}
	if b := CheckRatchet(bad, floors); len(b) != 1 {
		t.Fatalf("a below-floor recall must breach the ratchet, got %v", b)
	}
	// degeneracy tripwire: an all-flagging regression drives recall to 1 (passing the recall floor) while
	// precision collapses; the tripwire must catch it.
	degen := []CategoryScore{{Category: "cmdi", Recall: 1.0, TP: 5, FP: 100, Precision: 5.0 / 105.0}}
	b := CheckRatchet(degen, floors)
	if len(b) != 1 || !strings.Contains(b[0], "degeneracy tripwire") {
		t.Fatalf("collapsed precision at full recall must trip the degeneracy guard, got %v", b)
	}
}
