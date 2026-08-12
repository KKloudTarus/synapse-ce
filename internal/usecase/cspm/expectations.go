package cspm

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxExpectationFiles = 1000
	maxExpectationBytes = 20 << 20
)

var (
	tfResourceOpen = regexp.MustCompile(`^resource\s+"([^"]+)"\s+"[^"]+"\s*\{`)
	tfLiteral      = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_]+)\s*=\s*"([^"]+)"\s*$`)
	tfBoolLiteral  = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_]+)\s*=\s*(true|false)\s*$`)
	tfPublicMember = regexp.MustCompile(`(?m)^\s*member\s*=\s*"(allUsers|allAuthenticatedUsers)"\s*$`)
)

// ExpectationSource reads bounded retained IaC source and emits normalized drift expectations.
type ExpectationSource struct {
	engagements ports.EngagementRepository
	analyses    ports.ProjectAnalysisStore
	artifacts   ports.ProjectSourceArtifactStore
}

var _ ports.CloudExpectationSource = (*ExpectationSource)(nil)

func NewExpectationSource(engagements ports.EngagementRepository, analyses ports.ProjectAnalysisStore, artifacts ports.ProjectSourceArtifactStore) (*ExpectationSource, error) {
	if engagements == nil || analyses == nil || artifacts == nil {
		return nil, fmt.Errorf("%w: CSPM expectation source requires engagements, analyses, and artifacts", shared.ErrValidation)
	}
	return &ExpectationSource{engagements: engagements, analyses: analyses, artifacts: artifacts}, nil
}

func (s *ExpectationSource) Expectations(ctx context.Context, tenantID, engagementID shared.ID) ([]cloudposture.Expectation, []cloudposture.CoverageIssue, error) {
	engagement, err := s.engagements.GetByIDInTenant(ctx, tenantID, engagementID)
	if err != nil {
		return nil, nil, err
	}
	if engagement.ProjectID.IsZero() {
		return nil, nil, nil
	}
	analysis, _, err := s.analyses.LatestWithResult(ctx, tenantID, engagement.ProjectID)
	if err != nil {
		return nil, []cloudposture.CoverageIssue{{Category: "drift", Code: "source_unavailable"}}, nil
	}
	var out []cloudposture.Expectation
	var gaps []cloudposture.CoverageIssue
	var total int64
	tfFiles := 0
	for _, file := range analysis.SourceManifest.Files {
		if !file.Available || file.Generated || !strings.HasSuffix(strings.ToLower(file.Path), ".tf") {
			continue
		}
		if tfFiles == maxExpectationFiles || total+file.Bytes > maxExpectationBytes {
			gaps = append(gaps, cloudposture.CoverageIssue{Category: "drift", Code: "source_truncated"})
			break
		}
		tfFiles++
		content, _, loadErr := s.artifacts.Load(ctx, tenantID, engagement.ProjectID, analysis.ID, file.Path)
		if loadErr != nil {
			gaps = append(gaps, cloudposture.CoverageIssue{Category: "drift", Scope: file.Path, Code: "source_unavailable"})
			continue
		}
		total += int64(len(content))
		expectations, parseGaps := terraformExpectations(file.Path, string(content))
		for index := range expectations {
			expectations[index].AnalysisID = shared.ID(analysis.ID)
			expectations[index].ArtifactDigest = analysis.SourceManifest.ArtifactDigest()
		}
		out = append(out, expectations...)
		gaps = append(gaps, parseGaps...)
	}
	if analysis.SourceManifest.Truncated {
		gaps = append(gaps, cloudposture.CoverageIssue{Category: "drift", Code: "source_truncated"})
	}
	return out, gaps, nil
}

func terraformExpectations(path, content string) ([]cloudposture.Expectation, []cloudposture.CoverageIssue) {
	type frame struct {
		typ   string
		depth int
		body  strings.Builder
	}
	var stack []*frame
	var out []cloudposture.Expectation
	var gaps []cloudposture.CoverageIssue
	depth := 0
	for _, raw := range strings.Split(content, "\n") {
		line := stripTerraformComment(raw)
		trimmed := strings.TrimSpace(line)
		if match := tfResourceOpen.FindStringSubmatch(trimmed); match != nil {
			stack = append(stack, &frame{typ: match[1], depth: depth})
		}
		if len(stack) > 0 {
			stack[len(stack)-1].body.WriteString(trimmed)
			stack[len(stack)-1].body.WriteByte('\n')
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth < 0 {
			depth = 0
		}
		for len(stack) > 0 && depth <= stack[len(stack)-1].depth {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			expectations, blockGaps := terraformBlockExpectations(path, current.typ, current.body.String())
			out = append(out, expectations...)
			gaps = append(gaps, blockGaps...)
		}
	}
	if len(stack) != 0 {
		gaps = append(gaps, cloudposture.CoverageIssue{Category: "drift", Scope: path, Code: "iac_parse_refused", Detail: "unterminated Terraform resource block"})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		if a.ResourceID != b.ResourceID {
			return a.ResourceID < b.ResourceID
		}
		return a.Control < b.Control
	})
	return out, gaps
}

func terraformBlockExpectations(path, resourceType, body string) ([]cloudposture.Expectation, []cloudposture.CoverageIssue) {
	literals := map[string]string{}
	for _, match := range tfLiteral.FindAllStringSubmatch(body, -1) {
		literals[match[1]] = match[2]
	}
	bools := map[string]bool{}
	for _, match := range tfBoolLiteral.FindAllStringSubmatch(body, -1) {
		bools[match[1]] = match[2] == "true"
	}
	gap := func(detail string) ([]cloudposture.Expectation, []cloudposture.CoverageIssue) {
		return nil, []cloudposture.CoverageIssue{{Category: "drift", Scope: path, Code: "iac_scope_unresolved", Detail: detail}}
	}
	expectation := func(provider cloudposture.Provider, scopeKey, resourceID, control string, state cloudposture.State) cloudposture.Expectation {
		return cloudposture.Expectation{Provider: provider, ScopeKey: scopeKey, ResourceID: resourceID, Control: control, State: state, Source: path}
	}
	switch resourceType {
	case "aws_s3_bucket":
		name := literals["bucket"]
		if name == "" {
			return gap("AWS S3 bucket name is dynamic")
		}
		var out []cloudposture.Expectation
		if acl := literals["acl"]; acl != "" {
			state := cloudposture.StateDisabled
			if strings.HasPrefix(acl, "public-") {
				state = cloudposture.StateEnabled
			}
			out = append(out, expectation(cloudposture.ProviderAWS, "", "arn:aws:s3:::"+name, "public", state))
		}
		if strings.Contains(body, "server_side_encryption_configuration") {
			out = append(out, expectation(cloudposture.ProviderAWS, "", "arn:aws:s3:::"+name, "encrypted", cloudposture.StateEnabled))
		}
		return out, nil
	case "azurerm_storage_account":
		name, subscription, group := literals["name"], literals["subscription_id"], literals["resource_group_name"]
		if name == "" || subscription == "" || group == "" {
			return gap("Azure storage identity requires literal name, subscription_id, and resource_group_name")
		}
		subscription = strings.Trim(subscription, "/")
		scope := "azure:subscriptions/" + subscription
		id := "/subscriptions/" + subscription + "/resourceGroups/" + group + "/providers/Microsoft.Storage/storageAccounts/" + name
		if allowed, ok := bools["allow_nested_items_to_be_public"]; ok {
			state := cloudposture.StateDisabled
			if allowed {
				state = cloudposture.StateUnknown
			}
			return []cloudposture.Expectation{expectation(cloudposture.ProviderAzure, scope, id, "public", state)}, nil
		}
	case "azurerm_storage_container":
		name, account, subscription, group := literals["name"], literals["storage_account_name"], literals["subscription_id"], literals["resource_group_name"]
		if name == "" || account == "" || subscription == "" || group == "" {
			return gap("Azure container identity requires literal name, storage_account_name, subscription_id, and resource_group_name")
		}
		state := cloudposture.StateDisabled
		if access := literals["container_access_type"]; access == "blob" || access == "container" {
			state = cloudposture.StateEnabled
		}
		subscription = strings.Trim(subscription, "/")
		scope := "azure:subscriptions/" + subscription
		id := "/subscriptions/" + subscription + "/resourceGroups/" + group + "/providers/Microsoft.Storage/storageAccounts/" + account + "/blobServices/default/containers/" + name
		return []cloudposture.Expectation{expectation(cloudposture.ProviderAzure, scope, id, "public", state)}, nil
	case "google_storage_bucket":
		name, project := literals["name"], literals["project"]
		if name == "" || project == "" {
			return gap("GCP bucket identity requires literal name and project")
		}
		scope := "gcp:projects/" + project
		id := "projects/" + project + "/buckets/" + name
		if prevention := literals["public_access_prevention"]; prevention == "enforced" {
			return []cloudposture.Expectation{expectation(cloudposture.ProviderGCP, scope, id, "public", cloudposture.StateDisabled)}, nil
		}
	case "google_storage_bucket_iam_member":
		bucket, project := literals["bucket"], literals["project"]
		if bucket == "" || project == "" {
			return gap("GCP bucket IAM identity requires literal bucket and project")
		}
		if tfPublicMember.MatchString(body) {
			return []cloudposture.Expectation{expectation(cloudposture.ProviderGCP, "gcp:projects/"+project, "projects/"+project+"/buckets/"+bucket, "public", cloudposture.StateEnabled)}, nil
		}
	}
	return nil, nil
}

func stripTerraformComment(line string) string {
	quoted := false
	for index := 0; index < len(line); index++ {
		switch line[index] {
		case '"':
			if index == 0 || line[index-1] != '\\' {
				quoted = !quoted
			}
		case '#':
			if !quoted {
				return line[:index]
			}
		case '/':
			if !quoted && index+1 < len(line) && line[index+1] == '/' {
				return line[:index]
			}
		}
	}
	return line
}
