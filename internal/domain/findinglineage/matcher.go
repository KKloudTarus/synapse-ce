package findinglineage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type MatcherDescriptor struct {
	ProducerKind                string
	FindingKind                 string
	Method                      MatchMethod
	MethodVersion               int
	CanonicalizationVersion     int
	FingerprintSchemaVersion    int
	TargetIdentitySchemaVersion int
}

func (descriptor MatcherDescriptor) Validate() error {
	if err := validateShort("matcher producer kind", descriptor.ProducerKind); err != nil {
		return err
	}
	if err := validateShort("matcher finding kind", descriptor.FindingKind); err != nil {
		return err
	}
	if !descriptor.Method.Valid() || descriptor.MethodVersion <= 0 || descriptor.CanonicalizationVersion != CanonicalizationVersionV1 || descriptor.FingerprintSchemaVersion <= 0 || descriptor.TargetIdentitySchemaVersion <= 0 {
		return fmt.Errorf("%w: matcher descriptor versions are invalid", shared.ErrValidation)
	}
	return nil
}

type MatcherRequest struct {
	Fingerprint         CanonicalFingerprint
	SourceReferenceHash string
}

type MatcherResult struct {
	Method     MatchMethod
	Version    int
	Reasons    []string
	Candidates []CandidateRef
}

func (result MatcherResult) Validate(descriptor MatcherDescriptor) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if result.Method != descriptor.Method || result.Version != descriptor.MethodVersion {
		return fmt.Errorf("%w: matcher result metadata does not match descriptor", shared.ErrValidation)
	}
	if len(result.Reasons) == 0 || len(result.Reasons) > maxReasonPayload {
		return fmt.Errorf("%w: matcher reasons are required and bounded", shared.ErrValidation)
	}
	for _, reason := range result.Reasons {
		if err := validateShort("matcher reason", reason); err != nil {
			return err
		}
	}
	if len(result.Candidates) > maxCandidateRefs {
		return fmt.Errorf("%w: matcher returned too many candidates", shared.ErrValidation)
	}
	for _, candidate := range result.Candidates {
		if err := candidate.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type Matcher interface {
	Descriptor() MatcherDescriptor
	Match(context.Context, MatcherRequest) (MatcherResult, error)
}

type ConformanceVector struct {
	Name                string
	Input               FingerprintCanonicalInputV1
	ExpectedFingerprint string
	ExpectedError       error
}

func VerifyConformance(descriptor MatcherDescriptor, vectors []ConformanceVector) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if len(vectors) == 0 {
		return fmt.Errorf("%w: conformance vectors are required", shared.ErrValidation)
	}
	for _, vector := range vectors {
		if strings.TrimSpace(vector.Name) == "" {
			return fmt.Errorf("%w: conformance vector name is required", shared.ErrValidation)
		}
		if vector.Input.ProducerKind != descriptor.ProducerKind || vector.Input.CanonicalizationVersion != descriptor.CanonicalizationVersion || vector.Input.TargetIdentitySchemaVersion != descriptor.TargetIdentitySchemaVersion {
			return fmt.Errorf("%w: conformance vector %q omits required matcher metadata", shared.ErrValidation, vector.Name)
		}
		fingerprint, err := CanonicalizeFingerprintV1(vector.Input)
		if vector.ExpectedError != nil {
			if !errors.Is(err, vector.ExpectedError) {
				return fmt.Errorf("conformance vector %q error = %v, expected %v", vector.Name, err, vector.ExpectedError)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("conformance vector %q: %w", vector.Name, err)
		}
		if !validDigest(vector.ExpectedFingerprint) || fingerprint.Fingerprint != vector.ExpectedFingerprint {
			return fmt.Errorf("%w: conformance vector %q fingerprint mismatch", shared.ErrValidation, vector.Name)
		}
	}
	return nil
}
