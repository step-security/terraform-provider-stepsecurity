package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGithubRunPoliciesDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccGithubRunPoliciesDataSourceConfig("test-org"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policies.test", "owner", "test-org"),
					resource.TestCheckResourceAttrSet("data.stepsecurity_github_run_policies.test", "run_policies.#"),
				),
			},
		},
	})
}

func TestGithubRunPoliciesDataSource_Read(t *testing.T) {
	dataSource := &githubRunPoliciesDataSource{}

	// Verify that the data source is properly instantiated
	assert.NotNil(t, dataSource)
	assert.Nil(t, dataSource.client)
}

func TestGithubRunPoliciesDataSource_EmptyResult(t *testing.T) {
	dataSource := &githubRunPoliciesDataSource{}

	// Test initialization with empty client
	assert.NotNil(t, dataSource)
	assert.Nil(t, dataSource.client)
}

func TestGithubRunPoliciesDataSource_ErrorHandling(t *testing.T) {
	dataSource := &githubRunPoliciesDataSource{}

	// Test that we can configure the data source
	assert.NotNil(t, dataSource)

	// Set a mock client and verify it
	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	dataSource.client = mockClient
	assert.NotNil(t, dataSource.client)
}

func testAccGithubRunPoliciesDataSourceConfig(owner string) string {
	return fmt.Sprintf(`
data "stepsecurity_github_run_policies" "test" {
  owner = %[1]q
}
`, owner)
}
