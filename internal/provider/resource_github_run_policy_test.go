package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGithubRunPolicyResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccGithubRunPolicyResourceConfig("test-org", "Test Policy"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "owner", "test-org"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "name", "Test Policy"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "all_repos", "true"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_action_policy", "true"),
					resource.TestCheckResourceAttrSet("stepsecurity_github_run_policy.test", "policy_id"),
					resource.TestCheckResourceAttrSet("stepsecurity_github_run_policy.test", "id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "stepsecurity_github_run_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				Config: testAccGithubRunPolicyResourceConfigUpdated("test-org", "Updated Test Policy"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "name", "Updated Test Policy"),
					resource.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_secrets_policy", "true"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestGithubRunPolicyResource_Create(t *testing.T) {
	resource := &githubRunPolicyResource{}
	
	// Verify resource is properly initialized
	assert.NotNil(t, resource)
	assert.Nil(t, resource.client)
	
	// Test that we can set a client
	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	resource.client = mockClient
	assert.NotNil(t, resource.client)
}

func TestGithubRunPolicyResource_UpdateModelFromAPI(t *testing.T) {
	resource := &githubRunPolicyResource{}
	
	ctx := context.Background()
	model := &githubRunPolicyResourceModel{}
	
	apiResponse := &stepsecurityapi.RunPolicy{
		Owner:         "test-org",
		Customer:      "test-customer",
		PolicyID:      "test-policy-123",
		Name:          "Test Policy",
		CreatedBy:     "test-user",
		CreatedAt:     time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		LastUpdatedBy: "test-user",
		LastUpdatedAt: time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
		AllRepos:      true,
		AllOrgs:       false,
		Repositories:  []string{"repo1", "repo2"},
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:              "test-org",
			Name:               "Test Policy",
			EnableActionPolicy: true,
			AllowedActions: map[string]string{
				"actions/checkout": "allow",
			},
			EnableRunsOnPolicy: true,
			DisallowedRunnerLabels: map[string]struct{}{
				"self-hosted": {},
			},
		},
	}
	
	var diags diag.Diagnostics
	resource.updateModelFromAPI(ctx, model, apiResponse, &diags)
	
	assert.Equal(t, "test-org", model.Owner.ValueString())
	assert.Equal(t, "test-policy-123", model.PolicyID.ValueString())
	assert.Equal(t, "Test Policy", model.Name.ValueString())
	assert.True(t, model.AllRepos.ValueBool())
	assert.False(t, model.AllOrgs.ValueBool())
}

func testAccGithubRunPolicyResourceConfig(owner, name string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_run_policy" "test" {
  owner     = %[1]q
  name      = %[2]q
  all_repos = true
  
  policy_config = {
    owner                = %[1]q
    name                 = %[2]q
    enable_action_policy = true
    allowed_actions = {
      "actions/checkout" = "allow"
    }
  }
}
`, owner, name)
}

func testAccGithubRunPolicyResourceConfigUpdated(owner, name string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_run_policy" "test" {
  owner     = %[1]q
  name      = %[2]q
  all_repos = true
  
  policy_config = {
    owner                 = %[1]q
    name                  = %[2]q
    enable_action_policy  = true
    enable_secrets_policy = true
    allowed_actions = {
      "actions/checkout"             = "allow"
      "step-security/harden-runner" = "allow"
    }
  }
}
`, owner, name)
}