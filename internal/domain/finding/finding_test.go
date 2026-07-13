package finding

import "testing"

func TestStatusValid(t *testing.T) {
	for _, s := range []Status{StatusOpen, StatusTriage, StatusConfirmed, StatusFalsePos, StatusRemediated} {
		if !s.Valid() {
			t.Errorf("Status %q should be valid", s)
		}
	}
	for _, s := range []Status{"", "bogus", "OPEN", "fixed", "false-positive"} {
		if s.Valid() {
			t.Errorf("Status %q should be invalid", s)
		}
	}
}

func TestKindValid(t *testing.T) {
	for _, k := range []Kind{KindSCA, KindRecon, KindExploitation, KindManual, KindSAST, KindSecret, KindMisconfig, KindDAST, KindThreat} {
		if !k.Valid() {
			t.Errorf("Kind %q should be valid", k)
		}
	}
	for _, k := range []Kind{"", "SCA", "vuln", "ai"} {
		if k.Valid() {
			t.Errorf("Kind %q should be invalid", k)
		}
	}
}

func TestPublishable(t *testing.T) {
	in := []Finding{
		{ID: "sca", Kind: KindSCA, EvidenceScore: 0},                                       // not gated → kept
		{ID: "manual", Kind: KindManual},                                                   // not gated → kept
		{ID: "recon", Kind: KindRecon},                                                     // not gated → kept
		{ID: "exp-unproven", Kind: KindExploitation, EvidenceScore: EvidenceThreshold - 1}, // below bar → dropped
		{ID: "exp-proven", Kind: KindExploitation, EvidenceScore: EvidenceThreshold},       // at bar → kept
	}
	got := map[string]bool{}
	for _, f := range Publishable(in) {
		got[f.ID.String()] = true
	}
	if !got["sca"] || !got["manual"] || !got["recon"] || !got["exp-proven"] {
		t.Errorf("Publishable must keep non-gated + proven exploitation findings: %v", got)
	}
	if got["exp-unproven"] {
		t.Error("Publishable must drop an unproven exploitation finding")
	}
	if len(got) != 4 {
		t.Errorf("want 4 publishable findings, got %d", len(got))
	}
	// Input must not be mutated.
	if len(in) != 5 {
		t.Errorf("Publishable must not mutate its input, len now %d", len(in))
	}
}

func TestCanPromote(t *testing.T) {
	// Evidence-gating is PROVENANCE-keyed: a finding with an agent proposer (or Kind=exploitation as a belt)
	// must clear the bar; an ungated finding (scanner SCA/recon, human manual – no proposer) always promotes.
	cases := []struct {
		name       string
		kind       Kind
		proposedBy string
		score      int
		want       bool
	}{
		{"sca always promotes regardless of score", KindSCA, "", 0, true},
		{"recon always promotes", KindRecon, "", 0, true},
		{"manual always promotes", KindManual, "", 10, true},
		{"exploitation below bar blocked", KindExploitation, "agent:x", EvidenceThreshold - 1, false},
		{"exploitation at bar promotes", KindExploitation, "agent:x", EvidenceThreshold, true},
		{"exploitation well above bar promotes", KindExploitation, "agent:x", 100, true},
		// Provenance gates regardless of kind: an AI-proposed finding of ANY kind is gated.
		{"AI-proposed sca below bar blocked", KindSCA, "agent:x", 0, false},
		{"AI-proposed sca at bar promotes", KindSCA, "agent:x", EvidenceThreshold, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := Finding{Kind: c.kind, ProposedBy: c.proposedBy, EvidenceScore: c.score}
			if got := f.CanPromote(); got != c.want {
				t.Errorf("Kind %q proposedBy %q score %d: CanPromote = %v, want %v", c.kind, c.proposedBy, c.score, got, c.want)
			}
			wantGate := c.kind == KindExploitation || c.proposedBy != ""
			if gate := f.RequiresEvidenceGate(); gate != wantGate {
				t.Errorf("Kind %q proposedBy %q: RequiresEvidenceGate = %v, want %v", c.kind, c.proposedBy, gate, wantGate)
			}
		})
	}
}

func TestMeetsEvidenceBar(t *testing.T) {
	cases := []struct {
		score int
		want  bool
	}{
		{0, false},
		{EvidenceThreshold - 1, false},
		{EvidenceThreshold, true},
		{100, true},
	}
	for _, c := range cases {
		f := Finding{EvidenceScore: c.score}
		if got := f.MeetsEvidenceBar(); got != c.want {
			t.Errorf("EvidenceScore %d: MeetsEvidenceBar = %v, want %v (threshold %d)", c.score, got, c.want, EvidenceThreshold)
		}
	}
}

func TestIsRuleBased(t *testing.T) {
	for _, k := range []Kind{KindSAST, KindSecret, KindMisconfig, KindQuality, KindReliability} {
		if !k.IsRuleBased() {
			t.Errorf("Kind %q should be rule-based", k)
		}
	}
	for _, k := range []Kind{"", KindSCA, KindRecon, KindExploitation, KindManual, KindDAST, KindThreat, KindHypothesis, "unknown"} {
		if k.IsRuleBased() {
			t.Errorf("Kind %q should not be rule-based", k)
		}
	}
}

func TestValidateRuleKey(t *testing.T) {
	cases := []struct {
		name    string
		kind    Kind
		ruleKey string
		wantErr error
	}{
		{"valid sast", KindSAST, "go:sql-injection", nil},
		{"valid secret", KindSecret, "aws-key", nil},
		{"valid misconfig", KindMisconfig, "tf.s3.public", nil},
		{"valid quality", KindQuality, "quality-duplicated-block", nil},
		{"valid reliability", KindReliability, "reliability-empty-catch", nil},
		{"empty rule-based", KindSAST, "", ErrRuleKeyRequired},
		{"empty non-rule", KindSCA, "", nil},
		{"empty kind (treated as sca)", "", "", nil},
		{"non-empty sca", KindSCA, "some-key", ErrRuleKeyForbidden},
		{"non-empty unknown", "unknown", "key", ErrRuleKeyForbidden},
		{"leading space", KindSAST, " key", ErrRuleKeyInvalid},
		{"trailing space", KindSAST, "key ", ErrRuleKeyInvalid},
		{"tab", KindSAST, "my\tkey", ErrRuleKeyInvalid},
		{"newline", KindSAST, "my\nkey", ErrRuleKeyInvalid},
		{"unicode space", KindSAST, "my\u2000key", ErrRuleKeyInvalid},
		{"control", KindSAST, "my\x00key", ErrRuleKeyInvalid},
		{"hyphen", KindSAST, "my-key", nil},
		{"underscore", KindSAST, "my_key", nil},
		{"slash", KindSAST, "my/key", nil},
		{"dot", KindSAST, "my.key", nil},
		{"colon future", KindSAST, "go:sql-injection", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := Finding{Kind: c.kind, RuleKey: c.ruleKey}
			if err := f.ValidateRuleKey(); err != c.wantErr {
				t.Errorf("Kind %q RuleKey %q: got %v, want %v", c.kind, c.ruleKey, err, c.wantErr)
			}
		})
	}
}
