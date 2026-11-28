// Package workerroles names the queue job kinds each worker role claims (#1559). The control role
// owns every data-only kind; the execution role owns every kind that runs a tool. The two sets are
// disjoint and together cover every kind a producer can enqueue, which kinds_test.go pins against
// the kind constants in the use cases, so a new kind cannot be enqueued without an owner.
package workerroles

import (
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityreconcile"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	cspmuc "github.com/KKloudTarus/synapse-ce/internal/usecase/cspm"
	dastrunuc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/inbox"
	integrationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/integrations"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	ownershipuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ownership"
	reconuc "github.com/KKloudTarus/synapse-ce/internal/usecase/recon"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/usercontacts"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/vulnerabilitymonitor"
)

// ControlKinds are the data-only kinds: they read and write the database and talk to integration
// providers, and never run a tool.
func ControlKinds() []string {
	return sorted(
		integrationuc.JobKind,
		comparisonuc.JobKind,
		cycleuc.AssessmentClosureReportJobKind,
		ownershipuc.RouteJobKind,
		notificationuc.JobKind,
		usercontacts.JobKind,
		inbox.JobKind,
		inbox.SlackJobKind,
		inbox.TeamsJobKind,
		vulnerabilitymonitor.JobKind,
		vulnerabilityreconcile.JobKind,
	)
}

// ExecutionKinds are the kinds whose handlers run a tool in the sandbox under an egress grant.
func ExecutionKinds() []string {
	return sorted(
		scauc.ScanJobKind,
		reconuc.JobKind,
		dastrunuc.JobKind,
		cspmuc.JobKind,
		orchestrator.JobKind,
	)
}

// IsControl reports whether kind belongs to the control role.
func IsControl(kind string) bool { return contains(ControlKinds(), kind) }

// IsExecution reports whether kind belongs to the execution role.
func IsExecution(kind string) bool { return contains(ExecutionKinds(), kind) }

func sorted(kinds ...string) []string {
	out := append([]string(nil), kinds...)
	sort.Strings(out)
	return out
}

func contains(kinds []string, kind string) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}
