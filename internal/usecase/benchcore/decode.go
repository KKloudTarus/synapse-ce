package benchcore

import (
	"fmt"
	"io"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// DecodeManifest strictly decodes and validates a closure manifest.
func DecodeManifest(r io.Reader) (ClosureManifest, error) {
	var m ClosureManifest
	if err := benchmark.StrictDecode(r, &m); err != nil {
		return ClosureManifest{}, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if err := m.Validate(); err != nil {
		return ClosureManifest{}, err
	}
	return m, nil
}

// DecodeReceipt strictly decodes a run-start receipt.
func DecodeReceipt(r io.Reader) (RunStartReceipt, error) {
	var out RunStartReceipt
	if err := benchmark.StrictDecode(r, &out); err != nil {
		return RunStartReceipt{}, fmt.Errorf("%w: %v", ErrInvalidReceipt, err)
	}
	return out, nil
}

// DecodeScorecard strictly decodes a scorecard.
func DecodeScorecard(r io.Reader) (Scorecard, error) {
	var out Scorecard
	if err := benchmark.StrictDecode(r, &out); err != nil {
		return Scorecard{}, fmt.Errorf("%w: %v", ErrInvalidScorecard, err)
	}
	return out, nil
}

// DecodeObservations strictly decodes an array of observations and validates each.
func DecodeObservations(r io.Reader) ([]Observation, error) {
	var out []Observation
	if err := benchmark.StrictDecode(r, &out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidObservation, err)
	}
	for _, o := range out {
		if err := o.Validate(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
