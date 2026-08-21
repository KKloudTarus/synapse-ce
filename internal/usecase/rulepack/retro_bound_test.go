package rulepack

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCollectRetroEvidenceRejectsAmbiguousLimitHit(t *testing.T) {
	p := gatePack(t)
	now := time.Unix(20, 0).UTC()
	event := detection.Event{Class: detection.ClassProcess, At: now, Host: "h1", Process: &detection.ProcessEvent{Comm: "tool", Args: []string{"--danger"}}}
	hunter := &fakeHunter{result: ports.HuntResult{Events: []detection.Event{event, event}, Complete: true}}
	_, err := CollectRetroEvidence(context.Background(), p, hunter, []RetroCase{{
		RuleID: "det.test",
		Query:  ports.HuntQuery{HostID: "h1", Class: detection.ClassProcess, Since: now.Add(-time.Minute), Until: now.Add(time.Minute), Limit: 2},
	}})
	if err == nil {
		t.Fatal("retro evidence that hits the row limit must fail closed")
	}
}

func TestCollectRetroEvidenceRequiresExplicitBoundedLimit(t *testing.T) {
	p := gatePack(t)
	now := time.Unix(20, 0).UTC()
	hunter := &fakeHunter{result: ports.HuntResult{Complete: true}}
	for _, limit := range []int{0, maxRetroHuntEvents + 1} {
		_, err := CollectRetroEvidence(context.Background(), p, hunter, []RetroCase{{
			RuleID: "det.test",
			Query:  ports.HuntQuery{HostID: "h1", Class: detection.ClassProcess, Since: now.Add(-time.Minute), Until: now.Add(time.Minute), Limit: limit},
		}})
		if err == nil {
			t.Fatalf("retro limit %d must be rejected", limit)
		}
	}
}
