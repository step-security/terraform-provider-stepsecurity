package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomWorkflowPathProblem(t *testing.T) {
	tests := []struct {
		path      string
		wantValid bool
	}{
		{"ci/workflows", true},
		{"templates", true},
		{".github/other", true},
		{"./ci/workflows", false},
		{"ci/workflows/", false},
		{"ci//workflows", false},
		{" ci/workflows", false},
		{"", false},
		{"   ", false},
		{".", false},
		{"/etc", false},
		{"..", false},
		{"../other-repo", false},
		{"ci/../../outside", false},
		{".github/workflows", false},
	}
	for _, tt := range tests {
		problem := customWorkflowPathProblem(tt.path)
		assert.Equal(t, tt.wantValid, problem == "", "customWorkflowPathProblem(%q) = %q", tt.path, problem)
	}
	// The message says how to write a path that only needs cleaning.
	assert.Contains(t, customWorkflowPathProblem("./ci/workflows/"), `must be written as "ci/workflows"`)
}

// runPolicyDrivenPRCustomWorkflowPathsValidateConfig drives the real ValidateConfig
// with only custom_workflow_paths populated.
func runPolicyDrivenPRCustomWorkflowPathsValidateConfig(t *testing.T, paths []string) *fwresource.ValidateConfigResponse {
	t.Helper()

	ctx := context.Background()
	r := &policyDrivenPRResource{}

	schemaResp := &fwresource.SchemaResponse{}
	r.Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError(), "schema errors: %v", schemaResp.Diagnostics)
	schema := schemaResp.Schema

	optionsType, ok := schema.Attributes["auto_remediation_options"].GetType().(types.ObjectType)
	require.True(t, ok, "auto_remediation_options should be an object")

	optionValues := make(map[string]attr.Value, len(optionsType.AttrTypes))
	for name, at := range optionsType.AttrTypes {
		optionValues[name] = nullValueFor(t, ctx, at)
	}
	elems := make([]attr.Value, 0, len(paths))
	for _, p := range paths {
		elems = append(elems, types.StringValue(p))
	}
	set, diags := types.SetValue(types.StringType, elems)
	require.False(t, diags.HasError(), "paths: %v", diags)
	optionValues["custom_workflow_paths"] = set

	options, diags := types.ObjectValue(optionsType.AttrTypes, optionValues)
	require.False(t, diags.HasError(), "options object: %v", diags)

	selectedRepos, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue("widgets")})
	require.False(t, diags.HasError(), "selected repos: %v", diags)

	model := policyDrivenPRModel{
		ID:                    types.StringNull(),
		Owner:                 types.StringValue("test-org"),
		AutoRemdiationOptions: options,
		SelectedRepos:         selectedRepos,
		SelectedReposFilter:   nullValueFor(t, ctx, schema.Attributes["selected_repos_filter"].GetType()).(types.Object),
		ExcludedRepos:         types.ListNull(types.StringType),
	}

	plan := tfsdk.Plan{Schema: schema}
	require.False(t, plan.Set(ctx, model).HasError())

	resp := &fwresource.ValidateConfigResponse{}
	r.ValidateConfig(ctx, fwresource.ValidateConfigRequest{
		Config: tfsdk.Config{Raw: plan.Raw, Schema: schema},
	}, resp)
	return resp
}

// TestPolicyDrivenPRResource_ValidateConfig_CustomWorkflowPaths: paths must be
// written in the cleaned form the API stores, and stay inside the repository.
func TestPolicyDrivenPRResource_ValidateConfig_CustomWorkflowPaths(t *testing.T) {
	tests := []struct {
		name      string
		paths     []string
		wantError bool
	}{
		{"clean paths", []string{"ci/workflows", "templates"}, false},
		{"leading ./", []string{"./ci/workflows"}, true},
		{"trailing /", []string{"ci/workflows/"}, true},
		{"outside the repository", []string{"ci/workflows", "../other-repo"}, true},
		{"absolute", []string{"/etc"}, true},
		{".github/workflows", []string{".github/workflows"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := runPolicyDrivenPRCustomWorkflowPathsValidateConfig(t, tt.paths)
			assert.Equal(t, tt.wantError, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
		})
	}
}
