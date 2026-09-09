package main

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestResponseRuntimeIsExplicitAndRequiresProcessCoverage(t *testing.T) {
	runtime, err := newEndpointResponseRuntime(config{})
	if err != nil || runtime != nil {
		t.Fatalf("disabled response runtime=%v err=%v", runtime, err)
	}
	_, err = newEndpointResponseRuntime(config{responseEnabled: true, detectClasses: "network"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("response runtime without process coverage error=%v", err)
	}
}

func TestResponseExecutionFlagParsingDefaultsClosed(t *testing.T) {
	for _, value := range []string{"", "false", "0", "no", "off", "unexpected"} {
		if envEnabled(value) {
			t.Fatalf("envEnabled(%q)=true", value)
		}
	}
	for _, value := range []string{"true", "1", "yes", "ON"} {
		if !envEnabled(value) {
			t.Fatalf("envEnabled(%q)=false", value)
		}
	}
}
