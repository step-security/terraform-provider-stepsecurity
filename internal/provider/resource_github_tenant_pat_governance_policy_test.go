package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestGithubTenantPATGovernancePolicyResource_Metadata(t *testing.T) {
	t.Parallel()

	resp := &resource.MetadataResponse{}
	(&githubTenantPATGovernancePolicyResource{}).Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "stepsecurity"}, resp)
	assert.Equal(t, "stepsecurity_github_tenant_pat_governance_policy", resp.TypeName)
}

// The tenant policy carries exactly the organization policy's settings, minus
// the organization's identity and its follow-tenant switch.
func TestGithubTenantPATGovernancePolicyResource_SchemaMirrorsTheOrganizationSettings(t *testing.T) {
	t.Parallel()

	resp := &resource.SchemaResponse{}
	(&githubTenantPATGovernancePolicyResource{}).Schema(context.Background(), resource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)

	orgResp := &resource.SchemaResponse{}
	(&githubPATGovernancePolicyResource{}).Schema(context.Background(), resource.SchemaRequest{}, orgResp)
	require.False(t, orgResp.Diagnostics.HasError())

	for name := range orgResp.Schema.Attributes {
		switch name {
		case "id", "owner", "use_tenant_policy":
			assert.NotContains(t, resp.Schema.Attributes, name, "%s is organization-only", name)
		default:
			assert.Contains(t, resp.Schema.Attributes, name)
		}
	}
	assert.Len(t, resp.Schema.Attributes, len(orgResp.Schema.Attributes)-3)
	assert.True(t, resp.Schema.Attributes["enabled"].IsRequired())
}

func TestGithubTenantPATGovernancePolicyModel_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	no := false
	apiPolicy := &stepsecurityapi.PATGovernancePolicy{
		Enabled:                                true,
		ClassicMaxAgeDays:                      60,
		FlagNoExpiry:                           true,
		ExpiryReminderCC:                       []string{"security@example.com"},
		ClassicNotifyOnRevocation:              &no,
		FineGrainedNoncompliantRevokeAfterDays: 45,
	}

	var model githubTenantPATGovernancePolicyModel
	require.NoError(t, model.setFromAPIPolicy(ctx, apiPolicy))
	assert.Equal(t, int64(60), model.ClassicMaxAgeDays.ValueInt64())
	assert.True(t, model.FineGrainedNotifyOnRevocation.IsNull())

	converted, err := model.toAPIPolicy(ctx)
	require.NoError(t, err)
	assert.Equal(t, *apiPolicy, converted)
	assert.Nil(t, converted.UseTenantPolicy, "a tenant policy has nothing above it to follow")
}
