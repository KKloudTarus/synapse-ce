package scanrun

import (
	"strings"
	"testing"
	"time"
)

func TestCanonicalTargetGoldenVectors(t *testing.T) {
	commit := strings.Repeat("a", 40)
	digest := "sha256:" + strings.Repeat("b", 64)
	tests := []struct {
		name  string
		left  TargetInput
		right TargetInput
		equal bool
	}{
		{"repository", TargetInput{TargetRepository, "HTTPS://User@GitHub.COM:443/Org/Repo.git/", commit, 1}, TargetInput{TargetRepository, "https://github.com/Org/Repo", commit, 1}, true},
		{"repository path case", TargetInput{TargetRepository, "https://github.com/Org/Repo", commit, 1}, TargetInput{TargetRepository, "https://github.com/org/repo", commit, 1}, false},
		{"image", TargetInput{TargetImage, "Docker.IO/Library/NGINX:latest", digest, 1}, TargetInput{TargetImage, "docker.io/library/nginx@" + digest, "", 1}, true},
		{"image digest", TargetInput{TargetImage, "nginx:latest", digest, 1}, TargetInput{TargetImage, "nginx:latest", "sha256:" + strings.Repeat("c", 64), 1}, false},
		{"host unicode", TargetInput{TargetHost, "BÜCHER.example.", "", 1}, TargetInput{TargetHost, "xn--bcher-kva.example", "", 1}, true},
		{"host ipv6", TargetInput{TargetHost, "[2001:0db8::1]", "", 1}, TargetInput{TargetHost, "2001:db8::1", "", 1}, true},
		{"url", TargetInput{TargetURL, "HTTPS://User:Pass@BÜCHER.example:443/a/../b?z=2&token=secret&a=1#frag", "", 1}, TargetInput{TargetURL, "https://xn--bcher-kva.example/b?a=1&z=2", "", 1}, true},
		{"cloud display independent", TargetInput{TargetCloud, "AWS://123456789012/arn:aws:s3:::ProdBucket", "", 1}, TargetInput{TargetCloud, "aws://123456789012/arn:aws:s3:::ProdBucket", "", 1}, true},
		{"cloud metadata independent", TargetInput{TargetCloud, "aws://123/resource/A?display_name=Production#region-alias", "", 1}, TargetInput{TargetCloud, "aws://123/resource/A", "", 1}, true},
		{"cloud resource case", TargetInput{TargetCloud, "aws://123/resource/A", "", 1}, TargetInput{TargetCloud, "aws://123/resource/a", "", 1}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left, leftErr := CanonicalTarget(test.left)
			right, rightErr := CanonicalTarget(test.right)
			if leftErr != nil || rightErr != nil {
				t.Fatalf("canonicalize: left=%v right=%v", leftErr, rightErr)
			}
			if got := left == right; got != test.equal {
				t.Fatalf("equality=%v want=%v\nleft=%+v\nright=%+v", got, test.equal, left, right)
			}
		})
	}
}

func TestCanonicalTargetRejectsMutableAndAmbiguousIdentity(t *testing.T) {
	image, err := CanonicalTarget(TargetInput{Kind: TargetImage, Raw: "nginx:latest", SchemaVersion: 1})
	if err != nil || image.EvaluatedRevision != "" {
		t.Fatalf("mutable image identity = %+v, %v", image, err)
	}
	if _, err := CanonicalTarget(TargetInput{Kind: TargetRepository, Raw: "https://github.com/org/repo", EvaluatedRevision: "main", SchemaVersion: 1}); err == nil {
		t.Fatal("mutable repository ref accepted")
	}
}

func TestSealLanesIsDeterministicAndCoverageHonest(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	finished := now.Add(time.Minute)
	target, err := CanonicalTarget(TargetInput{Kind: TargetRepository, Raw: "https://github.com/org/repo", EvaluatedRevision: strings.Repeat("a", 40), SchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	lane := Lane{
		Key: "sca", Producer: "synapse", TerminalStatus: StatusSucceeded, Target: target,
		AuthoritativeFindingKinds: []string{"secret", "sca", "sca"}, StartedAt: now, FinishedAt: &finished,
		ResultRef: "scan-result/run-1", EvidenceRef: "evidence-1", ResultSHA256: strings.Repeat("b", 64), ManifestSchemaVersion: 1,
		Versions: []Version{{Kind: VersionTool, Name: "synapse", Version: "v1"}},
		Stages:   []Stage{{Key: "scan", Status: StageSucceeded}},
	}
	first, err := SealLanes([]Lane{lane}, finished)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SealLanes([]Lane{lane}, finished)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].ManifestHash != second[0].ManifestHash || len(first[0].AuthoritativeFindingKinds) != 2 {
		t.Fatalf("non-deterministic seal: first=%+v second=%+v", first[0], second[0])
	}

	lane.Target.EvaluatedRevision = ""
	if _, err := SealLanes([]Lane{lane}, finished); err == nil {
		t.Fatal("successful source lane without immutable revision accepted")
	}
	lane.TerminalStatus = StatusPartial
	if _, err := SealLanes([]Lane{lane}, finished); err != nil {
		t.Fatalf("honest partial lane rejected: %v", err)
	}
	lane.TerminalStatus = StatusSucceeded
	lane.Target.EvaluatedRevision = "main"
	if _, err := SealLanes([]Lane{lane}, finished); err == nil {
		t.Fatal("successful lane accepted a mutable repository ref")
	}
	lane.Target.EvaluatedRevision = strings.Repeat("a", 40)
	sealed, err := SealLanes([]Lane{lane}, finished)
	if err != nil {
		t.Fatal(err)
	}
	sealed[0].Producer = "tampered"
	if err := ValidateSealedLane(sealed[0]); err == nil {
		t.Fatal("tampered sealed lane hash accepted")
	}
}
