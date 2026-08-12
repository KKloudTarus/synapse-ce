package sca

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func sastFindingDedupKey(sr ports.SASTRawFinding) string {
	return "sast:" + sr.RuleID + ":" + sr.File + ":" + strconv.Itoa(sr.Line)
}

func aiTriageEvidenceForCandidates(candidates []finding.Finding, raws []ports.SASTRawFinding) map[string][]ports.AITriageEvidenceToken {
	rawByKey := make(map[string]ports.SASTRawFinding, len(raws))
	for _, raw := range raws {
		rawByKey[sastFindingDedupKey(raw)] = raw
	}
	out := make(map[string][]ports.AITriageEvidenceToken, len(candidates))
	for _, item := range candidates {
		tokens := make([]ports.AITriageEvidenceToken, 0, 20)
		add := func(id string, kind ports.AITriageEvidenceKind, value string) {
			value = cleanAITriageEvidenceValue(value)
			if value == "" {
				return
			}
			tokens = append(tokens, ports.AITriageEvidenceToken{ID: id, Kind: kind, Value: value})
		}
		add("ev:finding_identity", ports.AITriageEvidenceKindFindingIdentity, finding.Identity(item))
		add("ev:rule", ports.AITriageEvidenceKindRule, item.RuleKey)
		add("ev:cwe", ports.AITriageEvidenceKindCWE, item.CWE)
		add("ev:scope", ports.AITriageEvidenceKindScope, item.Scope)
		if item.SourceLocation != nil && item.SourceLocation.Validate() == nil {
			add("ev:source_location", ports.AITriageEvidenceKindSourceLocation, fmt.Sprintf("%s:%d", item.SourceLocation.File, item.SourceLocation.StartLine))
		}
		if r := strings.TrimSpace(item.Reachability); r != "" && !strings.EqualFold(r, "unknown") {
			add("ev:reachability", ports.AITriageEvidenceKindReachability, r)
		}
		if raw, ok := rawByKey[item.DedupKey]; ok {
			add("ev:source", ports.AITriageEvidenceKindSource, raw.Source)
			add("ev:source_evidence", ports.AITriageEvidenceKindSourceEvidence, raw.SourceEvidence)
			add("ev:sink", ports.AITriageEvidenceKindSink, raw.Sink)
			add("ev:sink_evidence", ports.AITriageEvidenceKindSinkEvidence, raw.SinkEvidence)
			add("ev:data_flow", ports.AITriageEvidenceKindDataFlow, raw.DataFlow)
			add("ev:data_flow_evidence", ports.AITriageEvidenceKindDataFlowEvidence, raw.DataFlowEvidence)
			add("ev:data_flow_confidence", ports.AITriageEvidenceKindDataFlowConfidence, raw.DataFlowConfidence)
			lowerFlow := strings.ToLower(raw.DataFlowEvidence)
			if raw.DataFlowConfidence == "interprocedural" || raw.DataFlowConfidence == "cross-file" {
				add("ev:call_graph", ports.AITriageEvidenceKindCallGraph, raw.DataFlowEvidence)
				if strings.Contains(lowerFlow, "path=") {
					add("ev:taint_path", ports.AITriageEvidenceKindTaintPath, raw.DataFlowEvidence)
				}
			}
			if raw.DataFlowConfidence == "sanitized" || strings.Contains(lowerFlow, "sanitizer") || strings.HasPrefix(lowerFlow, "sanitized:") {
				add("ev:sanitizer", ports.AITriageEvidenceKindSanitizer, raw.DataFlowEvidence)
			}
			add("ev:framework_route", ports.AITriageEvidenceKindFramework, raw.Route)
			add("ev:framework_entrypoint", ports.AITriageEvidenceKindFramework, raw.EntryPoint)
			add("ev:framework_middleware", ports.AITriageEvidenceKindFramework, raw.RouteMiddleware)
			add("ev:auth_scope", ports.AITriageEvidenceKindAuthScope, raw.AuthScope)
			add("ev:control_evidence", ports.AITriageEvidenceKindControlEvidence, raw.ControlEvidence)
			add("ev:counter_evidence", ports.AITriageEvidenceKindCounterEvidence, raw.CounterEvidence)
			if raw.ValidationMethod != "" || raw.ValidationDisposition != "" {
				add("ev:validation", ports.AITriageEvidenceKindValidation, strings.Trim(strings.TrimSpace(raw.ValidationMethod+" / "+raw.ValidationDisposition), " /"))
			}
		}
		out[item.DedupKey] = tokens
	}
	return out
}

func cleanAITriageEvidenceValue(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	runes := []rune(value)
	if len(runes) > ports.MaxAITriageEvidenceValueRunes {
		value = string(runes[:ports.MaxAITriageEvidenceValueRunes])
	}
	return value
}
