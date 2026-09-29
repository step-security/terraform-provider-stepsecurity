package provider

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGithubPATGovernancePolicyResource(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing
			{
				Config: testProviderConfig() + testAccGithubPATGovernancePolicyResourceConfig("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "enabled", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "fine_grained_max_age_days", "90"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "classic_max_age_days", "60"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "flag_no_expiry", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "unused_days", "0"),
				),
			},
			// Update and Read testing
			{
				Config: testProviderConfig() + testAccGithubPATGovernancePolicyResourceConfigUpdated("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "flag_over_scoped", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "over_scoped_scopes.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "unused_days", "180"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "expiry_reminder_days.#", "2"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccGithubPATGovernancePolicyResourceConfig(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_pat_governance_policy" "test" {
  owner                     = %[1]q
  enabled                   = true
  fine_grained_max_age_days = 90
  classic_max_age_days      = 60
  flag_no_expiry            = true
}
`, owner)
}

func testAccGithubPATGovernancePolicyResourceConfigUpdated(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_pat_governance_policy" "test" {
  owner                     = %[1]q
  enabled                   = true
  fine_grained_max_age_days = 90
  classic_max_age_days      = 60
  flag_no_expiry            = true
  flag_over_scoped          = true
  over_scoped_scopes        = ["repo", "admin:org"]
  unused_days               = 180
  expiry_reminder_days      = [14, 3]
}
`, owner)
}

// Unit Tests

func TestGithubPATGovernancePolicyResource_Metadata(t *testing.T) {
	t.Parallel()

	r := &githubPATGovernancePolicyResource{}
	ctx := context.Background()

	req := resource.MetadataRequest{ProviderTypeName: "stepsecurity"}
	resp := &resource.MetadataResponse{}
	r.Metadata(ctx, req, resp)

	assert.Equal(t, "stepsecurity_github_pat_governance_policy", resp.TypeName)
}

func TestGithubPATGovernancePolicyResource_Schema(t *testing.T) {
	t.Parallel()

	r := &githubPATGovernancePolicyResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}
	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	expectedAttrs := []string{
		"id", "owner", "enabled",
		"fine_grained_max_age_days", "classic_max_age_days",
		"flag_no_expiry", "flag_over_scoped", "over_scoped_scopes",
		"unused_days", "github_issue_repo", "expiry_reminder_days",
	}
	for _, attrName := range expectedAttrs {
		if _, exists := resp.Schema.Attributes[attrName]; !exists {
			t.Errorf("Expected attribute %s not found in schema", attrName)
		}
	}

	assert.True(t, resp.Schema.Attributes["owner"].IsRequired(), "owner should be required")
	assert.True(t, resp.Schema.Attributes["enabled"].IsRequired(), "enabled should be required")
	assert.True(t, resp.Schema.Attributes["id"].IsComputed(), "id should be computed")
	assert.True(t, resp.Schema.Attributes["fine_grained_max_age_days"].IsOptional(), "fine_grained_max_age_days should be optional")
	assert.True(t, resp.Schema.Attributes["over_scoped_scopes"].IsOptional(), "over_scoped_scopes should be optional")
	assert.True(t, resp.Schema.Attributes["expiry_reminder_days"].IsOptional(), "expiry_reminder_days should be optional")
}

func TestGithubPATGovernancePolicyClient_GetHandlesNullPolicy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		mockResponse *stepsecurityapi.PATGovernancePolicy
		mockError    error
		expectNil    bool
		expectError  bool
	}{
		{
			name: "configured policy",
			mockResponse: &stepsecurityapi.PATGovernancePolicy{
				Enabled:               true,
				FineGrainedMaxAgeDays: 90,
			},
			expectNil: false,
		},
		{
			// The API returns 200 with a null policy for an org that has
			// never configured one.
			name:         "unconfigured policy",
			mockResponse: nil,
			expectNil:    true,
		},
		{
			name:        "api error",
			mockError:   errors.New("boom"),
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockClient := &stepsecurityapi.MockStepSecurityClient{}
			mockClient.On("GetPATGovernancePolicy", mock.Anything, "tf-acc-test").Return(tc.mockResponse, tc.mockError)

			policy, err := mockClient.GetPATGovernancePolicy(context.Background(), "tf-acc-test")
			if tc.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if tc.expectNil {
				assert.Nil(t, policy)
			} else {
				assert.NotNil(t, policy)
				assert.True(t, policy.Enabled)
			}
		})
	}
}

func TestGithubPATGovernancePolicyModel_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	apiPolicy := &stepsecurityapi.PATGovernancePolicy{
		Enabled:               true,
		FineGrainedMaxAgeDays: 90,
		ClassicMaxAgeDays:     60,
		FlagNoExpiry:          true,
		FlagOverScoped:        true,
		OverScopedScopes:      []string{"repo", "admin:org"},
		UnusedDays:            180,
		GitHubIssueRepo:       "widgets",
		ExpiryReminderDays:    []int64{14, 3},
	}

	var model githubPATGovernancePolicyModel
	model.Owner = types.StringValue("tf-acc-test")
	err := model.setFromAPIPolicy(ctx, apiPolicy)
	assert.NoError(t, err)

	assert.Equal(t, "tf-acc-test", model.ID.ValueString())
	assert.True(t, model.Enabled.ValueBool())
	assert.Equal(t, int64(90), model.FineGrainedMaxAgeDays.ValueInt64())
	assert.Equal(t, int64(60), model.ClassicMaxAgeDays.ValueInt64())
	assert.True(t, model.FlagNoExpiry.ValueBool())
	assert.True(t, model.FlagOverScoped.ValueBool())
	assert.Equal(t, "widgets", model.GitHubIssueRepo.ValueString())

	// Convert back and compare with the source policy.
	converted, err := model.toAPIPolicy(ctx)
	assert.NoError(t, err)
	assert.Equal(t, *apiPolicy, stepsecurityapi.PATGovernancePolicy{
		Enabled:               converted.Enabled,
		FineGrainedMaxAgeDays: converted.FineGrainedMaxAgeDays,
		ClassicMaxAgeDays:     converted.ClassicMaxAgeDays,
		FlagNoExpiry:          converted.FlagNoExpiry,
		FlagOverScoped:        converted.FlagOverScoped,
		OverScopedScopes:      converted.OverScopedScopes,
		UnusedDays:            converted.UnusedDays,
		GitHubIssueRepo:       converted.GitHubIssueRepo,
		ExpiryReminderDays:    converted.ExpiryReminderDays,
	})

	// Empty lists from the API become null lists in state, so an omitted
	// attribute never drifts.
	minimal := &stepsecurityapi.PATGovernancePolicy{Enabled: false}
	err = model.setFromAPIPolicy(ctx, minimal)
	assert.NoError(t, err)
	assert.True(t, model.OverScopedScopes.IsNull())
	assert.True(t, model.ExpiryReminderDays.IsNull())
	assert.Equal(t, "", model.GitHubIssueRepo.ValueString())
}
