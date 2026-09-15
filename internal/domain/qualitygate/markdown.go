package qualitygate

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
)

// RenderMarkdown renders a deterministic, credential-free quality-gate summary suitable for a PR/MR
// comment. The scope is display text supplied by the caller (for example "new code vs main").
func RenderMarkdown(scope string, rep rating.Report, dupDensity float64, coverage string, result Result) string {
	status := "✅ **Quality gate passed**"
	if !result.Passed {
		status = "❌ **Quality gate failed**"
	}

	var out strings.Builder
	fmt.Fprintf(&out, "## Synapse quality gate\n\n%s _(%s)_\n\n", status, scope)
	fmt.Fprintf(&out, "| Rating | Grade |\n|---|---|\n| Security | %s |\n| Reliability | %s |\n| Maintainability | %s |\n", rep.Security, rep.Reliability, rep.Maintainability)
	fmt.Fprintf(&out, "\nDuplication %.1f%% · Coverage %s\n\n", dupDensity, coverage)
	out.WriteString("| Condition | Actual | |\n|---|---|---|\n")
	for _, cr := range result.Results {
		mark := "✅"
		if !cr.Passed {
			mark = "❌"
		}
		fmt.Fprintf(&out, "| `%s` | %s | %s |\n", cr.Condition, renderConditionActual(cr), mark)
	}
	return out.String()
}

func renderConditionActual(cr ConditionResult) string {
	if cr.Unmeasured {
		return "no data"
	}
	return fmt.Sprintf("actual %g", cr.Actual)
}
