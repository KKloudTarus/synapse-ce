package rulepack

import (
	fleettelemetry "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetry"
	purplecoverageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/purplecoverage"
)

var _ TelemetryHunter = (*fleettelemetry.Service)(nil)
var _ PurpleReader = (*purplecoverageuc.Service)(nil)
