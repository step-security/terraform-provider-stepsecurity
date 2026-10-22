package provider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Documents the empty-list contract for the prejob and requirement fields: the
// backend serializes empty slices as omitted JSON, so the response carries nil
// and the previous state's empty-vs-null signal must be preserved, otherwise
// apply fails with an inconsistent result (same contract as the harden-runner
// label sets).
func TestGithubRunPolicyResource_CreatePreservesEmptyPrejobAndRequirementSets(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 10, 19, 1, 2, 3, 0, time.UTC)

	emptySet := types.SetValueMust(types.StringType, []attr.Value{})
	rule := types.ObjectValueMust(runnerLabelRequirementObjectType.AttrTypes, map[string]attr.Value{
		"if_label_matches": types.StringValue("self-hosted"),
		"require_labels":   emptySet,
		"forbid_labels":    types.SetValueMust(types.StringType, []attr.Value{types.StringValue("docker-enabled:true")}),
	})

	plan := githubRunPolicyResourceModel{
		Owner:        types.StringValue("test-org"),
		Name:         types.StringValue("Prejob Empty Lists Policy"),
		PolicyID:     types.StringNull(),
		AllRepos:     types.BoolValue(true),
		AllOrgs:      types.BoolValue(false),
		Repositories: types.ListNull(types.StringType),
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("Prejob Empty Lists Policy"),
			EnableActionPolicy:             types.BoolValue(false),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolValue(false),
			HardenRunnerTargetLabels:       types.SetNull(types.StringType),
			HardenRunnerCustomActions:      types.SetNull(types.StringType),
			EnableRunsOnPolicy:             types.BoolValue(true),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolValue(false),
			EnableCompromisedActionsPolicy: types.BoolValue(false),
			IsDryRun:                       types.BoolValue(true),
			ExemptedUsers:                  types.SetNull(types.StringType),
			EnforceMethod:                  types.StringValue("prejob"),
			PrejobAllowedRunnerLabels:      emptySet,
			RunnerLabelRequirements:        types.ListValueMust(runnerLabelRequirementObjectType, []attr.Value{rule}),
		}),
		CreatedBy:     types.StringNull(),
		CreatedAt:     types.StringNull(),
		LastUpdatedBy: types.StringNull(),
		LastUpdatedAt: types.StringNull(),
	}

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("CreateRunPolicy", mock.Anything, "test-org", mock.MatchedBy(func(req stepsecurityapi.CreateRunPolicyRequest) bool {
			return req.PolicyConfig.EnforceMethod == "prejob" &&
				len(req.PolicyConfig.PrejobAllowedRunnerLabels) == 0 &&
				len(req.PolicyConfig.RunnerLabelRequirements) == 1 &&
				len(req.PolicyConfig.RunnerLabelRequirements[0].RequireLabels) == 0 &&
				len(req.PolicyConfig.RunnerLabelRequirements[0].ForbidLabels) == 1
		})).
		Return(&stepsecurityapi.RunPolicy{
			Owner:         "test-org",
			PolicyID:      "policy-prejob-empty",
			Name:          "Prejob Empty Lists Policy",
			CreatedBy:     "test-user",
			CreatedAt:     now,
			LastUpdatedBy: "test-user",
			LastUpdatedAt: now,
			AllRepos:      true,
			PolicyConfig: stepsecurityapi.RunPolicyConfig{
				Owner:              "test-org",
				Name:               "Prejob Empty Lists Policy",
				EnableRunsOnPolicy: true,
				IsDryRun:           true,
				EnforceMethod:      "prejob",
				// Backend omits empty slices (JSON omitempty): nil comes back
				// for the planned empty set and the rule's empty require list.
				PrejobAllowedRunnerLabels: nil,
				RunnerLabelRequirements: []stepsecurityapi.RunnerLabelRequirement{{
					IfLabelMatches: "self-hosted",
					RequireLabels:  nil,
					ForbidLabels:   []string{"docker-enabled:true"},
				}},
			},
		}, nil).
		Once()

	r := &githubRunPolicyResource{client: mockClient}
	req := fwresource.CreateRequest{Plan: testGithubRunPolicyPlan(t, plan)}
	resp := &fwresource.CreateResponse{State: tfsdk.State{Schema: testGithubRunPolicyResourceSchema(t)}}

	r.Create(ctx, req, resp)

	require.False(t, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
	mockClient.AssertExpectations(t)

	var state githubRunPolicyResourceModel
	require.False(t, resp.State.Get(ctx, &state).HasError())
	var policyConfig policyConfigModel
	require.False(t, state.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{}).HasError())

	assert.False(t, policyConfig.PrejobAllowedRunnerLabels.IsNull(), "planned empty prejob set must not drift to null")
	assert.Empty(t, setStrings(t, policyConfig.PrejobAllowedRunnerLabels))
	assert.True(t, policyConfig.PrejobDisallowedRunnerLabels.IsNull(), "omitted list stays null")

	var rules []runnerLabelRequirementModel
	require.False(t, policyConfig.RunnerLabelRequirements.ElementsAs(ctx, &rules, false).HasError())
	require.Len(t, rules, 1)
	assert.False(t, rules[0].RequireLabels.IsNull(), "planned empty require set must not drift to null")
	assert.Empty(t, setStrings(t, rules[0].RequireLabels))
	assert.Equal(t, []string{"docker-enabled:true"}, setStrings(t, rules[0].ForbidLabels))
}

// A planned empty runner_label_requirements list must also survive the
// omitted-JSON round trip.
func TestGithubRunPolicyResource_CreatePreservesEmptyRequirementsList(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 10, 19, 1, 2, 3, 0, time.UTC)

	plan := githubRunPolicyResourceModel{
		Owner:        types.StringValue("test-org"),
		Name:         types.StringValue("Empty Requirements Policy"),
		PolicyID:     types.StringNull(),
		AllRepos:     types.BoolValue(true),
		AllOrgs:      types.BoolValue(false),
		Repositories: types.ListNull(types.StringType),
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("Empty Requirements Policy"),
			EnableActionPolicy:             types.BoolValue(false),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolValue(false),
			HardenRunnerTargetLabels:       types.SetNull(types.StringType),
			HardenRunnerCustomActions:      types.SetNull(types.StringType),
			EnableRunsOnPolicy:             types.BoolValue(true),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolValue(false),
			EnableCompromisedActionsPolicy: types.BoolValue(false),
			IsDryRun:                       types.BoolValue(true),
			ExemptedUsers:                  types.SetNull(types.StringType),
			RunnerLabelRequirements:        types.ListValueMust(runnerLabelRequirementObjectType, []attr.Value{}),
		}),
		CreatedBy:     types.StringNull(),
		CreatedAt:     types.StringNull(),
		LastUpdatedBy: types.StringNull(),
		LastUpdatedAt: types.StringNull(),
	}

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("CreateRunPolicy", mock.Anything, "test-org", mock.MatchedBy(func(req stepsecurityapi.CreateRunPolicyRequest) bool {
			return len(req.PolicyConfig.RunnerLabelRequirements) == 0
		})).
		Return(&stepsecurityapi.RunPolicy{
			Owner:         "test-org",
			PolicyID:      "policy-empty-reqs",
			Name:          "Empty Requirements Policy",
			CreatedBy:     "test-user",
			CreatedAt:     now,
			LastUpdatedBy: "test-user",
			LastUpdatedAt: now,
			AllRepos:      true,
			PolicyConfig: stepsecurityapi.RunPolicyConfig{
				Owner:                   "test-org",
				Name:                    "Empty Requirements Policy",
				EnableRunsOnPolicy:      true,
				IsDryRun:                true,
				RunnerLabelRequirements: nil,
			},
		}, nil).
		Once()

	r := &githubRunPolicyResource{client: mockClient}
	req := fwresource.CreateRequest{Plan: testGithubRunPolicyPlan(t, plan)}
	resp := &fwresource.CreateResponse{State: tfsdk.State{Schema: testGithubRunPolicyResourceSchema(t)}}

	r.Create(ctx, req, resp)

	require.False(t, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
	mockClient.AssertExpectations(t)

	var state githubRunPolicyResourceModel
	require.False(t, resp.State.Get(ctx, &state).HasError())
	var policyConfig policyConfigModel
	require.False(t, state.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{}).HasError())

	assert.False(t, policyConfig.RunnerLabelRequirements.IsNull(), "planned empty requirements list must not drift to null")
	var rules []runnerLabelRequirementModel
	require.False(t, policyConfig.RunnerLabelRequirements.ElementsAs(ctx, &rules, false).HasError())
	assert.Empty(t, rules)
}
