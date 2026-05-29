package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	resourcehelper "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// TestSecureRegistryPolicyResource_Schema verifies the schema compiles and has expected attributes.
func TestSecureRegistryPolicyResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaReq := fwresource.SchemaRequest{}
	schemaResp := &fwresource.SchemaResponse{}

	NewSecureRegistryPolicyResource().Schema(ctx, schemaReq, schemaResp)

	assert.False(t, schemaResp.Diagnostics.HasError(), "Schema() returned errors: %v", schemaResp.Diagnostics)

	attrs := schemaResp.Schema.Attributes
	for _, required := range []string{"registry", "cooldown_control", "compromised_packages_control"} {
		assert.Contains(t, attrs, required, "expected attribute %q in schema", required)
	}
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_BothControls verifies the request
// builder includes both controls when both are present in the plan.
func TestSecureRegistryPolicyResource_buildUpsertRequest_BothControls(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	cooldownObj, cooldownDiag := buildTestCooldownObject(ctx, true, 7, []string{"react"})
	assert.False(t, cooldownDiag.HasError())

	compPkgObj, compDiag := buildTestCompromisedPackagesObject(true)
	assert.False(t, compDiag.HasError())

	plan := &secureRegistryPolicyResourceModel{
		CooldownControl:            cooldownObj,
		CompromisedPackagesControl: compPkgObj,
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, nil, &diags)

	assert.False(t, diags.HasError())
	assert.NotNil(t, req.CooldownPeriod)
	assert.True(t, req.CooldownPeriod.Enabled)
	assert.Equal(t, 7, req.CooldownPeriod.PeriodInDays)
	assert.Equal(t, []string{"react"}, req.CooldownPeriod.ExemptionList)
	assert.NotNil(t, req.CompromisedPackages)
	assert.True(t, req.CompromisedPackages.Enabled)
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedControl verifies that
// removing a control from plan (null) while state had it causes an explicit disable.
func TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedControl(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	// Previous state had cooldown enabled.
	prevCooldownObj, _ := buildTestCooldownObject(ctx, true, 7, nil)
	prevState := &secureRegistryPolicyResourceModel{
		CooldownControl:            prevCooldownObj,
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
	}

	// New plan: cooldown removed (null), compromised packages added.
	compPkgObj, _ := buildTestCompromisedPackagesObject(true)
	plan := &secureRegistryPolicyResourceModel{
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: compPkgObj,
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, prevState, &diags)

	assert.False(t, diags.HasError())
	// Cooldown should be explicitly disabled (not omitted).
	assert.NotNil(t, req.CooldownPeriod)
	assert.False(t, req.CooldownPeriod.Enabled)
	// Compromised packages from plan.
	assert.NotNil(t, req.CompromisedPackages)
	assert.True(t, req.CompromisedPackages.Enabled)
}

// TestSecureRegistryPolicyResource_applyAPIResponse_DisabledControlNotInRefStaysNull verifies
// that a disabled backend control does not get populated in state when the ref (current state)
// had null for that control.
func TestSecureRegistryPolicyResource_applyAPIResponse_DisabledControlNotInRefStaysNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CooldownPeriod: &stepsecurityapi.CooldownPeriodControl{
			Enabled:      false,
			PeriodInDays: 1,
		},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{
			Enabled: false,
		},
	}

	model := &secureRegistryPolicyResourceModel{
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.True(t, model.CooldownControl.IsNull(), "disabled cooldown should remain null when not tracked")
	assert.True(t, model.CompromisedPackagesControl.IsNull(), "disabled compromised packages should remain null when not tracked")
}

// TestSecureRegistryPolicyResource_applyAPIResponse_EnabledControlPopulatesState verifies
// that an enabled backend control is reflected in state.
func TestSecureRegistryPolicyResource_applyAPIResponse_EnabledControlPopulatesState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CooldownPeriod: &stepsecurityapi.CooldownPeriodControl{
			Enabled:       true,
			PeriodInDays:  14,
			ExemptionList: []string{"@babel/core"},
		},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{
			Enabled: true,
		},
	}

	model := &secureRegistryPolicyResourceModel{
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.False(t, model.CooldownControl.IsNull(), "enabled cooldown should be in state")
	assert.False(t, model.CompromisedPackagesControl.IsNull(), "enabled compromised packages should be in state")

	var cooldown cooldownControlModel
	diags = model.CooldownControl.As(ctx, &cooldown, basetypes.ObjectAsOptions{})
	assert.False(t, diags.HasError())
	assert.True(t, cooldown.Enabled.ValueBool())
	assert.Equal(t, int64(14), cooldown.PeriodInDays.ValueInt64())
}

// TestSecureRegistryPolicyResource_MockUpsert unit-tests Create flow with a mock client.
func TestSecureRegistryPolicyResource_MockUpsert(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mockClient := &stepsecurityapi.MockStepSecurityClient{}

	expectedResult := &stepsecurityapi.SecureRegistryControls{
		Customer:  "test-customer",
		Registry:  "npm",
		UpdatedBy: "test@example.com",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CooldownPeriod: &stepsecurityapi.CooldownPeriodControl{
			Enabled:      true,
			PeriodInDays: 7,
		},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{
			Enabled: true,
		},
	}

	mockClient.On("UpsertRegistryControls", ctx, "npm", mock.AnythingOfType("stepsecurityapi.UpsertSecureRegistryControlsRequest")).
		Return(expectedResult, nil)

	r := &secureRegistryPolicyResource{client: mockClient}

	cooldownObj, _ := buildTestCooldownObject(ctx, true, 7, nil)
	compPkgObj, _ := buildTestCompromisedPackagesObject(true)

	plan := &secureRegistryPolicyResourceModel{
		Registry:                   types.StringValue("npm"),
		CooldownControl:            cooldownObj,
		CompromisedPackagesControl: compPkgObj,
	}

	upsertReq := stepsecurityapi.UpsertSecureRegistryControlsRequest{
		CooldownPeriod:      &stepsecurityapi.CooldownPeriodControl{Enabled: true, PeriodInDays: 7},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{Enabled: true},
	}

	result, err := r.client.UpsertRegistryControls(ctx, "npm", upsertReq)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.CooldownPeriod.Enabled)
	assert.True(t, result.CompromisedPackages.Enabled)

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, plan, plan, result, &diags)
	assert.False(t, diags.HasError())
	assert.False(t, plan.CooldownControl.IsNull())
	assert.False(t, plan.CompromisedPackagesControl.IsNull())

	mockClient.AssertExpectations(t)
}

// TestAccSecureRegistryPolicyResource is an acceptance test that runs against the real API.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			// Create with both controls
			{
				Config: testAccSecureRegistryPolicyConfig(true, 7, true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "registry", "npm"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "cooldown_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "cooldown_control.period_in_days", "7"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "compromised_packages_control.enabled", "true"),
				),
			},
			// ImportState
			{
				ResourceName:      "stepsecurity_secure_registry_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update: change period_in_days
			{
				Config: testAccSecureRegistryPolicyConfig(true, 14, true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "cooldown_control.period_in_days", "14"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "compromised_packages_control.enabled", "true"),
				),
			},
			// Update: disable cooldown by removing the block
			{
				Config: testAccSecureRegistryPolicyOnlyCompromisedConfig(true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckNoResourceAttr("stepsecurity_secure_registry_policy.test", "cooldown_control"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "compromised_packages_control.enabled", "true"),
				),
			},
		},
	})
}

// --- helpers ---

func buildTestCooldownObject(ctx context.Context, enabled bool, periodInDays int64, exemptions []string) (types.Object, diag.Diagnostics) {
	var exemptionList types.Set
	var diags diag.Diagnostics
	if exemptions != nil {
		vals := make([]attr.Value, len(exemptions))
		for i, v := range exemptions {
			vals[i] = types.StringValue(v)
		}
		exemptionList, diags = types.SetValue(types.StringType, vals)
		if diags.HasError() {
			return types.ObjectNull(cooldownControlAttrTypes), diags
		}
	} else {
		exemptionList = types.SetNull(types.StringType)
	}
	return types.ObjectValue(cooldownControlAttrTypes, map[string]attr.Value{
		"enabled":        types.BoolValue(enabled),
		"period_in_days": types.Int64Value(periodInDays),
		"exemption_list": exemptionList,
	})
}

func buildTestCompromisedPackagesObject(enabled bool) (types.Object, diag.Diagnostics) {
	return types.ObjectValue(compromisedPackagesControlAttrTypes, map[string]attr.Value{
		"enabled": types.BoolValue(enabled),
	})
}

func testAccSecureRegistryPolicyConfig(cooldownEnabled bool, periodInDays int, compromisedEnabled bool) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "test" {
  registry = "npm"

  cooldown_control = {
    enabled        = %t
    period_in_days = %d
  }

  compromised_packages_control = {
    enabled = %t
  }
}
`, cooldownEnabled, periodInDays, compromisedEnabled)
}

func testAccSecureRegistryPolicyOnlyCompromisedConfig(compromisedEnabled bool) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "test" {
  registry = "npm"

  compromised_packages_control = {
    enabled = %t
  }
}
`, compromisedEnabled)
}
