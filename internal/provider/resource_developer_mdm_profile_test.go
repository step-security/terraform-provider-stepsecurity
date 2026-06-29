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
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func assignmentObject(t *testing.T, allDevices bool, deviceIDs types.Set) types.Object {
	t.Helper()
	obj, diags := types.ObjectValue(developerMDMAssignmentAttrTypes, map[string]attr.Value{
		"all_devices": types.BoolValue(allDevices),
		"device_ids":  deviceIDs,
	})
	require.False(t, diags.HasError())
	return obj
}

func TestDeveloperMDMProfileResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMProfileResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)

	assert.False(t, schemaResp.Diagnostics.HasError(), "Schema() errors: %v", schemaResp.Diagnostics)

	attrs := schemaResp.Schema.Attributes
	for _, name := range []string{"id", "profile_id", "name", "description", "policy_ids", "assignment", "created_by", "created_at", "updated_by", "updated_at"} {
		assert.Contains(t, attrs, name, "missing attribute %q", name)
	}
}

func TestDeveloperMDMProfile_BuildRequestUnassigned(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMProfileModel{
		Name:        types.StringValue("eng"),
		Description: types.StringValue("workstations"),
		PolicyIDs:   stringSet(t, "p1"),
		Assignment:  types.ObjectNull(developerMDMAssignmentAttrTypes),
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMProfileRequest(ctx, model, &diags)
	require.False(t, diags.HasError(), "build errors: %v", diags)

	assert.Equal(t, "eng", req.Name)
	assert.Equal(t, "workstations", req.Description)
	assert.Equal(t, []string{"p1"}, req.PolicyIDs)
	assert.False(t, req.Assignment.AllDevices)
	assert.Empty(t, req.Assignment.DeviceIDs)
}

func TestDeveloperMDMProfile_BuildRequestAllDevices(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMProfileModel{
		Name:       types.StringValue("eng"),
		PolicyIDs:  stringSet(t, "p1"),
		Assignment: assignmentObject(t, true, types.SetNull(types.StringType)),
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMProfileRequest(ctx, model, &diags)
	require.False(t, diags.HasError())

	assert.True(t, req.Assignment.AllDevices)
	assert.Empty(t, req.Assignment.DeviceIDs)
}

func TestDeveloperMDMProfile_BuildRequestDeviceIDs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMProfileModel{
		Name: types.StringValue("eng"),
		// Intentionally unsorted to verify deterministic ordering.
		PolicyIDs:  stringSet(t, "p2", "p1"),
		Assignment: assignmentObject(t, false, stringSet(t, "d2", "d1")),
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMProfileRequest(ctx, model, &diags)
	require.False(t, diags.HasError())

	assert.Equal(t, []string{"p1", "p2"}, req.PolicyIDs)
	assert.False(t, req.Assignment.AllDevices)
	assert.Equal(t, []string{"d1", "d2"}, req.Assignment.DeviceIDs)
}

func TestDeveloperMDMProfile_ValidateRejectsInvalidAssignment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	cases := []struct {
		name  string
		model developerMDMProfileModel
	}{
		{
			"empty policy set",
			developerMDMProfileModel{
				Name:       types.StringValue("p"),
				PolicyIDs:  stringSet(t),
				Assignment: types.ObjectNull(developerMDMAssignmentAttrTypes),
			},
		},
		{
			"empty policy id",
			developerMDMProfileModel{
				Name:       types.StringValue("p"),
				PolicyIDs:  stringSet(t, ""),
				Assignment: types.ObjectNull(developerMDMAssignmentAttrTypes),
			},
		},
		{
			"both assignment modes",
			developerMDMProfileModel{
				Name:       types.StringValue("p"),
				PolicyIDs:  stringSet(t, "p1"),
				Assignment: assignmentObject(t, true, stringSet(t, "d1")),
			},
		},
		{
			"empty device id",
			developerMDMProfileModel{
				Name:       types.StringValue("p"),
				PolicyIDs:  stringSet(t, "p1"),
				Assignment: assignmentObject(t, false, stringSet(t, "")),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diags := validateDeveloperMDMProfile(ctx, tc.model)
			assert.True(t, diags.HasError(), "expected validation error for %q", tc.name)
		})
	}
}

func TestDeveloperMDMProfile_ValidateAcceptsValidProfiles(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Unassigned, all-devices, and device-specific are all valid local configurations.
	valid := []developerMDMProfileModel{
		{Name: types.StringValue("p"), PolicyIDs: stringSet(t, "p1"), Assignment: types.ObjectNull(developerMDMAssignmentAttrTypes)},
		{Name: types.StringValue("p"), PolicyIDs: stringSet(t, "p1"), Assignment: assignmentObject(t, true, types.SetNull(types.StringType))},
		{Name: types.StringValue("p"), PolicyIDs: stringSet(t, "p1"), Assignment: assignmentObject(t, false, stringSet(t, "d1", "d2"))},
	}
	for i, model := range valid {
		assert.False(t, validateDeveloperMDMProfile(ctx, model).HasError(), "valid profile %d should not error", i)
	}
}

func TestDeveloperMDMProfile_ValidateOnePolicyPerCategory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("rejects duplicate category", func(t *testing.T) {
		mockClient := &stepsecurityapi.MockStepSecurityClient{}
		mockClient.On("GetDeveloperMDMPolicy", mock.Anything, "p1").Return(&stepsecurityapi.DeveloperMDMPolicy{PolicyID: "p1", Category: "ide_extension"}, nil)
		mockClient.On("GetDeveloperMDMPolicy", mock.Anything, "p2").Return(&stepsecurityapi.DeveloperMDMPolicy{PolicyID: "p2", Category: "ide_extension"}, nil)

		diags := validateDeveloperMDMProfilePolicyCategories(ctx, mockClient, []string{"p1", "p2"})
		assert.True(t, diags.HasError(), "expected duplicate ide_extension category to be rejected")
	})

	t.Run("accepts single policy", func(t *testing.T) {
		mockClient := &stepsecurityapi.MockStepSecurityClient{}
		mockClient.On("GetDeveloperMDMPolicy", mock.Anything, "p1").Return(&stepsecurityapi.DeveloperMDMPolicy{PolicyID: "p1", Category: "ide_extension"}, nil)

		diags := validateDeveloperMDMProfilePolicyCategories(ctx, mockClient, []string{"p1"})
		assert.False(t, diags.HasError(), "single policy should pass: %v", diags)
	})
}

func TestDeveloperMDMProfile_ApplyAPIToModel(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	profile := &stepsecurityapi.DeveloperMDMProfile{
		ProfileID:   "prof1",
		Name:        "eng",
		Description: "desc",
		PolicyIDs:   []string{"p1", "p2"},
		Assignment:  stepsecurityapi.DeveloperMDMAssignment{AllDevices: true},
		CreatedBy:   "user@x.io",
		CreatedAt:   "2026-06-29T00:00:00Z",
		UpdatedBy:   "user@x.io",
		UpdatedAt:   "2026-06-29T01:00:00Z",
	}

	model := &developerMDMProfileModel{}
	var diags diag.Diagnostics
	applyDeveloperMDMProfileToModel(ctx, profile, model, &diags)
	require.False(t, diags.HasError(), "apply errors: %v", diags)

	assert.Equal(t, "prof1", model.ID.ValueString())
	assert.Equal(t, "prof1", model.ProfileID.ValueString())
	assert.Equal(t, "eng", model.Name.ValueString())
	assert.Equal(t, "desc", model.Description.ValueString())
	assert.Equal(t, "user@x.io", model.CreatedBy.ValueString())
	assert.Equal(t, "2026-06-29T01:00:00Z", model.UpdatedAt.ValueString())

	// All backend policy IDs are preserved, even ones the provider does not have typed resources for.
	var policyIDs []string
	model.PolicyIDs.ElementsAs(ctx, &policyIDs, false)
	assert.ElementsMatch(t, []string{"p1", "p2"}, policyIDs)

	require.False(t, model.Assignment.IsNull(), "assignment should be populated")
	var assignment developerMDMProfileAssignmentModel
	model.Assignment.As(ctx, &assignment, basetypes.ObjectAsOptions{})
	assert.True(t, assignment.AllDevices.ValueBool())
}

// TestDeveloperMDMProfile_ApplyEmptyAssignmentPreservesShape guards Terraform's
// apply-consistency contract. An empty backend assignment must collapse to null only
// when the prior model omitted the block; an explicitly-configured empty assignment
// object must keep its (non-null) shape so a planned object is not replaced by null,
// and a server-side clear of a previously real assignment must surface as null.
func TestDeveloperMDMProfile_ApplyEmptyAssignmentPreservesShape(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	emptyBackend := &stepsecurityapi.DeveloperMDMProfile{ProfileID: "prof1", Name: "eng"}

	cases := []struct {
		name     string
		prior    types.Object
		wantNull bool
	}{
		{"omitted block stays null", types.ObjectNull(developerMDMAssignmentAttrTypes), true},
		{"explicit empty object preserved", assignmentObject(t, false, types.SetNull(types.StringType)), false},
		{"server cleared real assignment goes null", assignmentObject(t, true, types.SetNull(types.StringType)), true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			model := &developerMDMProfileModel{Assignment: tc.prior}
			var diags diag.Diagnostics
			applyDeveloperMDMProfileToModel(ctx, emptyBackend, model, &diags)
			require.False(t, diags.HasError(), "apply errors: %v", diags)
			assert.Equal(t, tc.wantNull, model.Assignment.IsNull(), "assignment null-ness mismatch")
		})
	}
}

// TestAccDeveloperMDMProfileResource runs against the real API.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
// It avoids all_devices=true so it cannot enforce policy on a real fleet.
func TestAccDeveloperMDMProfileResource(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			// Create an unassigned profile referencing a policy.
			{
				Config: testAccDeveloperMDMProfileConfig(""),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_profile.test", "name", "tf-acc profile"),
					resourcehelper.TestCheckResourceAttrSet("stepsecurity_developer_mdm_profile.test", "profile_id"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_profile.test", "policy_ids.#", "1"),
				),
			},
			// Import by profile_id.
			{
				ResourceName:      "stepsecurity_developer_mdm_profile.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update to an explicit fake device ID (never all_devices in acc tests).
			{
				Config: testAccDeveloperMDMProfileConfig("tf-acc-fake-device"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_profile.test", "assignment.device_ids.#", "1"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_profile.test", "assignment.device_ids.0", "tf-acc-fake-device"),
				),
			},
		},
	})
}

func testAccDeveloperMDMProfileConfig(deviceID string) string {
	assignment := ""
	if deviceID != "" {
		assignment = fmt.Sprintf(`
  assignment = {
    device_ids = [%q]
  }
`, deviceID)
	}
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_developer_mdm_ide_extension_policy" "test" {
  name = "tf-acc profile policy"
  mode = "allowlist"

  rules = [
    {
      publisher = "ms-python"
      name      = "python"
      stable    = true
    },
  ]
}

resource "stepsecurity_developer_mdm_profile" "test" {
  name       = "tf-acc profile"
  policy_ids = [stepsecurity_developer_mdm_ide_extension_policy.test.policy_id]
%s}
`, assignment)
}
