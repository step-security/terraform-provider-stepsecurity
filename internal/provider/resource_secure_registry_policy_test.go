package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	resourcehelper "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

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
	for _, required := range []string{"registry", "cooldown_control", "compromised_packages_control", "typosquatting_control", "custom_block_list_control", "npm_settings"} {
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

// TestSecureRegistryPolicyResource_buildUpsertRequest_CustomBlockListAndNpmSettings verifies the
// request builder includes both new controls when present in the plan.
func TestSecureRegistryPolicyResource_buildUpsertRequest_CustomBlockListAndNpmSettings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	blockListObj, blockListDiag := buildTestCustomBlockListObject(ctx, true, []string{"lodash@4*", "@scope/*"})
	assert.False(t, blockListDiag.HasError())

	npmSettingsObj, npmDiag := buildTestNpmSettingsObject(true)
	assert.False(t, npmDiag.HasError())

	plan := &secureRegistryPolicyResourceModel{
		Registry:               types.StringValue("npm"),
		CustomBlockListControl: blockListObj,
		NpmSettings:            npmSettingsObj,
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, nil, &diags)

	assert.False(t, diags.HasError())
	assert.NotNil(t, req.CustomBlockList)
	assert.True(t, req.CustomBlockList.Enabled)
	assert.ElementsMatch(t, []string{"lodash@4*", "@scope/*"}, req.CustomBlockList.Patterns)
	assert.NotNil(t, req.NpmSettings)
	assert.True(t, req.NpmSettings.RewriteTarballURLs)
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedCustomBlockListAndNpmSettings
// verifies that removing custom_block_list_control/npm_settings from plan (null) while state had
// them causes an explicit disable/reset.
func TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedCustomBlockListAndNpmSettings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	prevBlockListObj, _ := buildTestCustomBlockListObject(ctx, true, []string{"left-pad"})
	prevNpmSettingsObj, _ := buildTestNpmSettingsObject(true)
	prevState := &secureRegistryPolicyResourceModel{
		Registry:               types.StringValue("npm"),
		CustomBlockListControl: prevBlockListObj,
		NpmSettings:            prevNpmSettingsObj,
	}

	plan := &secureRegistryPolicyResourceModel{
		Registry:               types.StringValue("npm"),
		CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
		NpmSettings:            types.ObjectNull(npmSettingsAttrTypes),
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, prevState, &diags)

	assert.False(t, diags.HasError())
	assert.NotNil(t, req.CustomBlockList)
	assert.False(t, req.CustomBlockList.Enabled)
	assert.Equal(t, []string{}, req.CustomBlockList.Patterns)
	assert.NotNil(t, req.NpmSettings)
	assert.False(t, req.NpmSettings.RewriteTarballURLs)
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_Typosquatting verifies the request
// builder includes the typosquatting control when present in the plan.
func TestSecureRegistryPolicyResource_buildUpsertRequest_Typosquatting(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	typosquattingObj, typosquattingDiag := buildTestTyposquattingObject(ctx, true, []string{"reactt", "lodashh"})
	assert.False(t, typosquattingDiag.HasError())

	plan := &secureRegistryPolicyResourceModel{
		Registry:             types.StringValue("npm"),
		TyposquattingControl: typosquattingObj,
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, nil, &diags)

	assert.False(t, diags.HasError())
	assert.NotNil(t, req.Typosquatting)
	assert.True(t, req.Typosquatting.Enabled)
	assert.ElementsMatch(t, []string{"reactt", "lodashh"}, req.Typosquatting.Whitelist)
}

// TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedTyposquatting verifies that
// removing typosquatting_control from plan (null) while state had it causes an explicit disable.
func TestSecureRegistryPolicyResource_buildUpsertRequest_DisablesRemovedTyposquatting(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	prevTyposquattingObj, _ := buildTestTyposquattingObject(ctx, true, []string{"reactt"})
	prevState := &secureRegistryPolicyResourceModel{
		Registry:             types.StringValue("npm"),
		TyposquattingControl: prevTyposquattingObj,
	}

	plan := &secureRegistryPolicyResourceModel{
		Registry:             types.StringValue("npm"),
		TyposquattingControl: types.ObjectNull(typosquattingControlAttrTypes),
	}

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, prevState, &diags)

	assert.False(t, diags.HasError())
	assert.NotNil(t, req.Typosquatting)
	assert.False(t, req.Typosquatting.Enabled)
	assert.Equal(t, []string{}, req.Typosquatting.Whitelist)
}

// TestSecureRegistryPolicyResource_applyAPIResponse_TyposquattingDisabledNotInRefStaysNull verifies
// that a disabled typosquatting control does not get populated in state when not tracked.
func TestSecureRegistryPolicyResource_applyAPIResponse_TyposquattingDisabledNotInRefStaysNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		TyposquattingControl: types.ObjectNull(typosquattingControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		Typosquatting: &stepsecurityapi.TyposquattingControl{
			Enabled: false,
		},
	}

	model := &secureRegistryPolicyResourceModel{
		TyposquattingControl: types.ObjectNull(typosquattingControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.True(t, model.TyposquattingControl.IsNull(), "disabled typosquatting should remain null when not tracked")
}

// TestSecureRegistryPolicyResource_applyAPIResponse_TyposquattingEnabledPopulatesState verifies
// that an enabled typosquatting control is reflected in state.
func TestSecureRegistryPolicyResource_applyAPIResponse_TyposquattingEnabledPopulatesState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		TyposquattingControl: types.ObjectNull(typosquattingControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		Typosquatting: &stepsecurityapi.TyposquattingControl{
			Enabled:   true,
			Whitelist: []string{"reactt"},
		},
	}

	model := &secureRegistryPolicyResourceModel{
		TyposquattingControl: types.ObjectNull(typosquattingControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.False(t, model.TyposquattingControl.IsNull(), "enabled typosquatting should be in state")

	var typosquatting typosquattingControlModel
	diags = model.TyposquattingControl.As(ctx, &typosquatting, basetypes.ObjectAsOptions{})
	assert.False(t, diags.HasError())
	assert.True(t, typosquatting.Enabled.ValueBool())
}

// TestSecureRegistryPolicyResource_applyAPIResponse_CustomBlockListDisabledNotInRefStaysNull verifies
// that a disabled custom block list control does not get populated in state when not tracked.
func TestSecureRegistryPolicyResource_applyAPIResponse_CustomBlockListDisabledNotInRefStaysNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CustomBlockList: &stepsecurityapi.CustomBlockListControl{
			Enabled: false,
		},
	}

	model := &secureRegistryPolicyResourceModel{
		CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.True(t, model.CustomBlockListControl.IsNull(), "disabled custom block list should remain null when not tracked")
}

// TestSecureRegistryPolicyResource_applyAPIResponse_CustomBlockListEnabledPopulatesState verifies
// that an enabled custom block list control is reflected in state.
func TestSecureRegistryPolicyResource_applyAPIResponse_CustomBlockListEnabledPopulatesState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:  "npm",
		UpdatedBy: "api",
		UpdatedAt: "2024-01-01T00:00:00Z",
		CustomBlockList: &stepsecurityapi.CustomBlockListControl{
			Enabled:  true,
			Patterns: []string{"lodash@4*"},
		},
	}

	model := &secureRegistryPolicyResourceModel{
		CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.False(t, model.CustomBlockListControl.IsNull(), "enabled custom block list should be in state")

	var blockList customBlockListControlModel
	diags = model.CustomBlockListControl.As(ctx, &blockList, basetypes.ObjectAsOptions{})
	assert.False(t, diags.HasError())
	assert.True(t, blockList.Enabled.ValueBool())
}

// TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsDisabledNotInRefStaysNull verifies
// that npm_settings with RewriteTarballURLs=false does not get populated in state when the ref
// (current state) had null for it — mirrors the other controls' null-preservation rule.
func TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsDisabledNotInRefStaysNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:    "npm",
		UpdatedBy:   "api",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		NpmSettings: &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: false},
	}

	model := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.True(t, model.NpmSettings.IsNull(), "npm_settings with rewrite_tarball_urls=false should remain null when not tracked")
}

// TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsEnabledPopulatesState verifies
// that npm_settings with RewriteTarballURLs=true is reflected in state.
func TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsEnabledPopulatesState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:    "npm",
		UpdatedBy:   "api",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		NpmSettings: &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: true},
	}

	model := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	require.False(t, model.NpmSettings.IsNull(), "enabled npm_settings should be in state")

	var npmSettings npmSettingsModel
	diags = model.NpmSettings.As(ctx, &npmSettings, basetypes.ObjectAsOptions{})
	assert.False(t, diags.HasError())
	assert.True(t, npmSettings.RewriteTarballURLs.ValueBool())
}

// TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsDisabledButTrackedStaysInState verifies
// that npm_settings with RewriteTarballURLs=false stays populated when it was already tracked
// (e.g. user explicitly configured rewrite_tarball_urls = false).
func TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsDisabledButTrackedStaysInState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	trackedObj := mustBuildTestNpmSettingsObject(t, false)
	ref := &secureRegistryPolicyResourceModel{
		NpmSettings: trackedObj,
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:    "npm",
		UpdatedBy:   "api",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		NpmSettings: &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: false},
	}

	model := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.False(t, model.NpmSettings.IsNull(), "previously tracked npm_settings should remain in state even when false")
}

// TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsNullForNonNpm verifies npm_settings
// stays null when the backend never returns it (e.g. pypi).
func TestSecureRegistryPolicyResource_applyAPIResponse_NpmSettingsNullForNonNpm(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	ref := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	apiResponse := &stepsecurityapi.SecureRegistryControls{
		Registry:    "pypi",
		UpdatedBy:   "api",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		NpmSettings: nil,
	}

	model := &secureRegistryPolicyResourceModel{
		NpmSettings: types.ObjectNull(npmSettingsAttrTypes),
	}

	var diags diag.Diagnostics
	r.applyAPIResponseToModel(ctx, ref, model, apiResponse, &diags)

	assert.False(t, diags.HasError())
	assert.True(t, model.NpmSettings.IsNull())
}

// TestSecureRegistryPolicyResource_ValidateConfig_NpmSettings exercises the real ValidateConfig
// method, asserting registry-gated controls (npm_settings, typosquatting_control,
// custom_block_list_control on maven) are rejected for unsupported registries and allowed
// where supported.
func TestSecureRegistryPolicyResource_ValidateConfig_NpmSettings(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                   string
		registry               string
		npmSettings            types.Object
		typosquattingControl   types.Object
		customBlockListControl types.Object
		expectedError          bool
	}{
		{
			name:                   "npm_settings_allowed_for_npm",
			registry:               "npm",
			npmSettings:            mustBuildTestNpmSettingsObject(t, true),
			typosquattingControl:   types.ObjectNull(typosquattingControlAttrTypes),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          false,
		},
		{
			name:                   "npm_settings_rejected_for_pypi",
			registry:               "pypi",
			npmSettings:            mustBuildTestNpmSettingsObject(t, true),
			typosquattingControl:   types.ObjectNull(typosquattingControlAttrTypes),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          true,
		},
		{
			name:                   "npm_settings_absent_for_pypi",
			registry:               "pypi",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   types.ObjectNull(typosquattingControlAttrTypes),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          false,
		},
		{
			name:                   "typosquatting_control_allowed_for_npm",
			registry:               "npm",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          false,
		},
		{
			name:                   "typosquatting_control_allowed_for_pypi",
			registry:               "pypi",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          false,
		},
		{
			name:                   "typosquatting_control_allowed_for_maven",
			registry:               "maven",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          false,
		},
		{
			name:                   "typosquatting_control_rejected_for_nuget",
			registry:               "nuget",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          true,
		},
		{
			name:                   "typosquatting_control_rejected_for_go",
			registry:               "go",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          true,
		},
		{
			name:                   "typosquatting_control_rejected_for_ruby",
			registry:               "ruby",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          true,
		},
		{
			name:                   "typosquatting_control_rejected_for_cargo",
			registry:               "cargo",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   mustBuildTestTyposquattingObject(t, true),
			customBlockListControl: types.ObjectNull(customBlockListControlAttrTypes),
			expectedError:          true,
		},
		{
			name:                   "custom_block_list_control_rejected_for_maven",
			registry:               "maven",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   types.ObjectNull(typosquattingControlAttrTypes),
			customBlockListControl: mustBuildTestCustomBlockListObject(t, true, []string{"left-pad"}),
			expectedError:          true,
		},
		{
			name:                   "custom_block_list_control_allowed_for_nuget",
			registry:               "nuget",
			npmSettings:            types.ObjectNull(npmSettingsAttrTypes),
			typosquattingControl:   types.ObjectNull(typosquattingControlAttrTypes),
			customBlockListControl: mustBuildTestCustomBlockListObject(t, true, []string{"left-pad"}),
			expectedError:          false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			r := &secureRegistryPolicyResource{}

			model := secureRegistryPolicyResourceModel{
				Registry:                   types.StringValue(tc.registry),
				CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
				CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
				TyposquattingControl:       tc.typosquattingControl,
				CustomBlockListControl:     tc.customBlockListControl,
				NpmSettings:                tc.npmSettings,
				GoSettings:                 types.ObjectNull(goSettingsAttrTypes),
			}

			config := testSecureRegistryPolicyConfig(t, model)
			resp := &fwresource.ValidateConfigResponse{}

			r.ValidateConfig(ctx, fwresource.ValidateConfigRequest{Config: config}, resp)

			if tc.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "unexpected diagnostics: %v", resp.Diagnostics)
			}
		})
	}
}

// TestSecureRegistryPolicyResource_ValidateConfig_UnknownBlocksDeferValidation verifies that
// ValidateConfig does not raise a false-positive error when a gated block's value is Unknown
// (e.g. derived from a not-yet-computed reference) rather than concretely configured — Unknown
// is distinct from Null and must not be treated as "the user set this block".
func TestSecureRegistryPolicyResource_ValidateConfig_UnknownBlocksDeferValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		registry string
		model    func(m *secureRegistryPolicyResourceModel)
	}{
		{
			name:     "unknown_npm_settings_on_pypi",
			registry: "pypi",
			model: func(m *secureRegistryPolicyResourceModel) {
				m.NpmSettings = types.ObjectUnknown(npmSettingsAttrTypes)
			},
		},
		{
			name:     "unknown_typosquatting_control_on_nuget",
			registry: "nuget",
			model: func(m *secureRegistryPolicyResourceModel) {
				m.TyposquattingControl = types.ObjectUnknown(typosquattingControlAttrTypes)
			},
		},
		{
			name:     "unknown_custom_block_list_control_on_maven",
			registry: "maven",
			model: func(m *secureRegistryPolicyResourceModel) {
				m.CustomBlockListControl = types.ObjectUnknown(customBlockListControlAttrTypes)
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			r := &secureRegistryPolicyResource{}

			model := secureRegistryPolicyResourceModel{
				Registry:                   types.StringValue(tc.registry),
				CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
				CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
				TyposquattingControl:       types.ObjectNull(typosquattingControlAttrTypes),
				CustomBlockListControl:     types.ObjectNull(customBlockListControlAttrTypes),
				NpmSettings:                types.ObjectNull(npmSettingsAttrTypes),
				GoSettings:                 types.ObjectNull(goSettingsAttrTypes),
			}
			tc.model(&model)

			config := testSecureRegistryPolicyConfig(t, model)
			resp := &fwresource.ValidateConfigResponse{}

			r.ValidateConfig(ctx, fwresource.ValidateConfigRequest{Config: config}, resp)

			assert.False(t, resp.Diagnostics.HasError(), "unknown block should defer validation, got: %v", resp.Diagnostics)
		})
	}
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

// TestSecureRegistryPolicyResource_MockUpsert_Maven unit-tests Create flow for the maven
// registry, which only supports cooldown_control and compromised_packages_control.
func TestSecureRegistryPolicyResource_MockUpsert_Maven(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mockClient := &stepsecurityapi.MockStepSecurityClient{}

	expectedResult := &stepsecurityapi.SecureRegistryControls{
		Customer:  "test-customer",
		Registry:  "maven",
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

	mockClient.On("UpsertRegistryControls", ctx, "maven", mock.AnythingOfType("stepsecurityapi.UpsertSecureRegistryControlsRequest")).
		Return(expectedResult, nil)

	r := &secureRegistryPolicyResource{client: mockClient}

	cooldownObj, _ := buildTestCooldownObject(ctx, true, 7, nil)
	compPkgObj, _ := buildTestCompromisedPackagesObject(true)

	plan := &secureRegistryPolicyResourceModel{
		Registry:                   types.StringValue("maven"),
		CooldownControl:            cooldownObj,
		CompromisedPackagesControl: compPkgObj,
	}

	upsertReq := stepsecurityapi.UpsertSecureRegistryControlsRequest{
		CooldownPeriod:      &stepsecurityapi.CooldownPeriodControl{Enabled: true, PeriodInDays: 7},
		CompromisedPackages: &stepsecurityapi.CompromisedPackagesControl{Enabled: true},
	}

	result, err := r.client.UpsertRegistryControls(ctx, "maven", upsertReq)
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
			// Update: add custom_block_list_control and npm_settings
			{
				Config: testAccSecureRegistryPolicyNpmFullConfig(true, []string{"lodash@4*", "@scope/*"}, true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "custom_block_list_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "custom_block_list_control.patterns.#", "2"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "npm_settings.rewrite_tarball_urls", "true"),
				),
			},
			// Update: change patterns list and disable tarball rewriting
			{
				Config: testAccSecureRegistryPolicyNpmFullConfig(true, []string{"requests@*"}, false),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "custom_block_list_control.patterns.#", "1"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.test", "npm_settings.rewrite_tarball_urls", "false"),
				),
			},
			// Update: remove custom_block_list_control block
			{
				Config: testAccSecureRegistryPolicyOnlyCompromisedConfig(true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckNoResourceAttr("stepsecurity_secure_registry_policy.test", "custom_block_list_control"),
				),
			},
		},
	})
}

// TestAccSecureRegistryPolicyResource_PypiBlockList is an acceptance test covering
// custom_block_list_control on pypi (npm_settings is not applicable there).
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource_PypiBlockList(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyPypiBlockListConfig(true, []string{"requests@2.25.0", "insecure-package"}),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.pypi_test", "registry", "pypi"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.pypi_test", "custom_block_list_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.pypi_test", "custom_block_list_control.patterns.#", "2"),
				),
			},
			// npm_settings is not applicable to pypi — plan-time ValidateConfig error.
			{
				Config:      testAccSecureRegistryPolicyPypiWithNpmSettingsConfig(),
				ExpectError: regexp.MustCompile(`npm_settings is not applicable`),
			},
		},
	})
}

// TestAccSecureRegistryPolicyResource_Typosquatting is an acceptance test covering
// typosquatting_control on npm, including plan-time rejection on an unsupported registry.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource_Typosquatting(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyTyposquattingConfig(true, []string{"reactt", "lodashh"}),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_test", "registry", "npm"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_test", "typosquatting_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_test", "typosquatting_control.exemption_list.#", "2"),
				),
			},
			{
				ResourceName:      "stepsecurity_secure_registry_policy.typosquatting_test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// typosquatting_control is not applicable to nuget — plan-time ValidateConfig error.
			{
				Config:      testAccSecureRegistryPolicyNugetWithTyposquattingConfig(),
				ExpectError: regexp.MustCompile(`typosquatting_control is not applicable`),
			},
		},
	})
}

// TestAccSecureRegistryPolicyResource_TyposquattingPypiMaven is an acceptance test covering
// typosquatting_control on pypi and maven, including registry-specific exemption names.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource_TyposquattingPypiMaven(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyTyposquattingRegistryConfig("pypi", []string{"reqeusts"}),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_pypi", "registry", "pypi"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_pypi", "typosquatting_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_pypi", "typosquatting_control.exemption_list.#", "1"),
				),
			},
			{
				ResourceName:      "stepsecurity_secure_registry_policy.typosquatting_pypi",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyTyposquattingRegistryConfig("maven", []string{"com.example:guavaa"}),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_maven", "registry", "maven"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.typosquatting_maven", "typosquatting_control.enabled", "true"),
					resourcehelper.TestCheckTypeSetElemAttr("stepsecurity_secure_registry_policy.typosquatting_maven", "typosquatting_control.exemption_list.*", "com.example:guavaa"),
				),
			},
			{
				ResourceName:      "stepsecurity_secure_registry_policy.typosquatting_maven",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccSecureRegistryPolicyResource_AutoExemptSecurityFixes is an acceptance test covering
// cooldown_control.auto_exempt_security_fixes: a severity threshold, a switch to a CVSS
// threshold, and removal of the block.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource_AutoExemptSecurityFixes(t *testing.T) {
	const name = "stepsecurity_secure_registry_policy.auto_exempt_test"
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyAutoExemptConfig(`auto_exempt_security_fixes = {
      enabled      = true
      min_severity = "high"
    }`),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr(name, "cooldown_control.auto_exempt_security_fixes.enabled", "true"),
					resourcehelper.TestCheckResourceAttr(name, "cooldown_control.auto_exempt_security_fixes.min_severity", "high"),
					resourcehelper.TestCheckNoResourceAttr(name, "cooldown_control.auto_exempt_security_fixes.min_cvss_score"),
				),
			},
			{
				ResourceName:      name,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccSecureRegistryPolicyAutoExemptConfig(`auto_exempt_security_fixes = {
      enabled        = true
      min_cvss_score = 7.5
    }`),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr(name, "cooldown_control.auto_exempt_security_fixes.min_cvss_score", "7.5"),
					resourcehelper.TestCheckNoResourceAttr(name, "cooldown_control.auto_exempt_security_fixes.min_severity"),
				),
			},
			// Removing the block clears the setting.
			{
				Config: testAccSecureRegistryPolicyAutoExemptConfig(""),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr(name, "cooldown_control.enabled", "true"),
					resourcehelper.TestCheckNoResourceAttr(name, "cooldown_control.auto_exempt_security_fixes.enabled"),
				),
			},
			// Enabled without a threshold is rejected at plan time.
			{
				Config: testAccSecureRegistryPolicyAutoExemptConfig(`auto_exempt_security_fixes = {
      enabled = true
    }`),
				ExpectError: regexp.MustCompile(`Set min_cvss_score or min_severity`),
			},
		},
	})
}

// TestAccSecureRegistryPolicyResource_Maven is an acceptance test covering the maven registry,
// which supports cooldown_control/compromised_packages_control but not custom_block_list_control.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource_Maven(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyMavenConfig(true, 7, true),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.maven_test", "registry", "maven"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.maven_test", "cooldown_control.period_in_days", "7"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.maven_test", "compromised_packages_control.enabled", "true"),
				),
			},
			{
				ResourceName:      "stepsecurity_secure_registry_policy.maven_test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// custom_block_list_control is not applicable to maven — plan-time ValidateConfig error.
			{
				Config:      testAccSecureRegistryPolicyMavenWithBlockListConfig(),
				ExpectError: regexp.MustCompile(`custom_block_list_control is not applicable`),
			},
		},
	})
}

// TestAccSecureRegistryPolicyResource_Nuget is an acceptance test covering the nuget registry,
// which supports the same controls as npm minus typosquatting_control/npm_settings.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccSecureRegistryPolicyResource_Nuget(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccSecureRegistryPolicyNugetBlockListConfig(true, []string{"Newtonsoft.Json@1*"}),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.nuget_test", "registry", "nuget"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.nuget_test", "custom_block_list_control.enabled", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_secure_registry_policy.nuget_test", "custom_block_list_control.patterns.#", "1"),
				),
			},
			{
				ResourceName:      "stepsecurity_secure_registry_policy.nuget_test",
				ImportState:       true,
				ImportStateVerify: true,
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
	return buildTestCooldownObjectWithAutoExempt(enabled, periodInDays, exemptionList, types.ObjectNull(autoExemptSecurityFixesAttrTypes))
}

func buildTestCooldownObjectWithAutoExempt(enabled bool, periodInDays int64, exemptionList types.Set, autoExempt types.Object) (types.Object, diag.Diagnostics) {
	return types.ObjectValue(cooldownControlAttrTypes, map[string]attr.Value{
		"enabled":                    types.BoolValue(enabled),
		"period_in_days":             types.Int64Value(periodInDays),
		"exemption_list":             exemptionList,
		"auto_exempt_security_fixes": autoExempt,
	})
}

func mustBuildTestAutoExemptObject(t *testing.T, enabled types.Bool, score types.Float64, severity types.String) types.Object {
	t.Helper()
	obj, diags := types.ObjectValue(autoExemptSecurityFixesAttrTypes, map[string]attr.Value{
		"enabled":        enabled,
		"min_cvss_score": score,
		"min_severity":   severity,
	})
	require.False(t, diags.HasError())
	return obj
}

func mustBuildTestCooldownWithAutoExempt(t *testing.T, autoExempt types.Object) types.Object {
	t.Helper()
	obj, diags := buildTestCooldownObjectWithAutoExempt(true, 7, types.SetNull(types.StringType), autoExempt)
	require.False(t, diags.HasError())
	return obj
}

func buildTestCompromisedPackagesObject(enabled bool) (types.Object, diag.Diagnostics) {
	return types.ObjectValue(compromisedPackagesControlAttrTypes, map[string]attr.Value{
		"enabled": types.BoolValue(enabled),
	})
}

func buildTestTyposquattingObject(ctx context.Context, enabled bool, exemptions []string) (types.Object, diag.Diagnostics) {
	var exemptionList types.Set
	var diags diag.Diagnostics
	if exemptions != nil {
		vals := make([]attr.Value, len(exemptions))
		for i, v := range exemptions {
			vals[i] = types.StringValue(v)
		}
		exemptionList, diags = types.SetValue(types.StringType, vals)
		if diags.HasError() {
			return types.ObjectNull(typosquattingControlAttrTypes), diags
		}
	} else {
		exemptionList = types.SetNull(types.StringType)
	}
	return types.ObjectValue(typosquattingControlAttrTypes, map[string]attr.Value{
		"enabled":        types.BoolValue(enabled),
		"exemption_list": exemptionList,
	})
}

func buildTestCustomBlockListObject(ctx context.Context, enabled bool, patterns []string) (types.Object, diag.Diagnostics) {
	var patternsSet types.Set
	var diags diag.Diagnostics
	if patterns != nil {
		vals := make([]attr.Value, len(patterns))
		for i, v := range patterns {
			vals[i] = types.StringValue(v)
		}
		patternsSet, diags = types.SetValue(types.StringType, vals)
		if diags.HasError() {
			return types.ObjectNull(customBlockListControlAttrTypes), diags
		}
	} else {
		patternsSet = types.SetNull(types.StringType)
	}
	return types.ObjectValue(customBlockListControlAttrTypes, map[string]attr.Value{
		"enabled":               types.BoolValue(enabled),
		"patterns":              patternsSet,
		"block_pseudo_versions": types.SetNull(types.StringType),
		"block_yanked_versions": types.BoolValue(false),
	})
}

func buildTestNpmSettingsObject(rewriteTarballURLs bool) (types.Object, diag.Diagnostics) {
	return types.ObjectValue(npmSettingsAttrTypes, map[string]attr.Value{
		"rewrite_tarball_urls":            types.BoolValue(rewriteTarballURLs),
		"block_message_template":          types.StringNull(),
		"hidden_versions_notice_template": types.StringNull(),
	})
}

func buildTestNpmSettingsObjectWithTemplates(rewriteTarballURLs bool, block, notice types.String) (types.Object, diag.Diagnostics) {
	return types.ObjectValue(npmSettingsAttrTypes, map[string]attr.Value{
		"rewrite_tarball_urls":            types.BoolValue(rewriteTarballURLs),
		"block_message_template":          block,
		"hidden_versions_notice_template": notice,
	})
}

func mustBuildTestNpmSettingsObject(t *testing.T, rewriteTarballURLs bool) types.Object {
	t.Helper()
	obj, diags := buildTestNpmSettingsObject(rewriteTarballURLs)
	require.False(t, diags.HasError())
	return obj
}

func mustBuildTestTyposquattingObject(t *testing.T, enabled bool) types.Object {
	t.Helper()
	obj, diags := buildTestTyposquattingObject(context.Background(), enabled, nil)
	require.False(t, diags.HasError())
	return obj
}

func mustBuildTestCustomBlockListObject(t *testing.T, enabled bool, patterns []string) types.Object {
	t.Helper()
	obj, diags := buildTestCustomBlockListObject(context.Background(), enabled, patterns)
	require.False(t, diags.HasError())
	return obj
}

func testSecureRegistryPolicySchema(t *testing.T) resourceschema.Schema {
	t.Helper()

	r := &secureRegistryPolicyResource{}
	resp := &fwresource.SchemaResponse{}
	r.Schema(context.Background(), fwresource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError())

	return resp.Schema
}

func testSecureRegistryPolicyConfig(t *testing.T, model secureRegistryPolicyResourceModel) tfsdk.Config {
	t.Helper()

	schema := testSecureRegistryPolicySchema(t)
	plan := tfsdk.Plan{Schema: schema}
	diags := plan.Set(context.Background(), model)
	require.False(t, diags.HasError())

	return tfsdk.Config{Raw: plan.Raw, Schema: schema}
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

func quotedPatternsList(patterns []string) string {
	quoted := make([]string, len(patterns))
	for i, p := range patterns {
		quoted[i] = fmt.Sprintf("%q", p)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func testAccSecureRegistryPolicyNpmFullConfig(blockListEnabled bool, patterns []string, rewriteTarballURLs bool) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "test" {
  registry = "npm"

  compromised_packages_control = {
    enabled = true
  }

  custom_block_list_control = {
    enabled  = %t
    patterns = %s
  }

  npm_settings = {
    rewrite_tarball_urls = %t
  }
}
`, blockListEnabled, quotedPatternsList(patterns), rewriteTarballURLs)
}

func testAccSecureRegistryPolicyPypiBlockListConfig(blockListEnabled bool, patterns []string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "pypi_test" {
  registry = "pypi"

  custom_block_list_control = {
    enabled  = %t
    patterns = %s
  }
}
`, blockListEnabled, quotedPatternsList(patterns))
}

func testAccSecureRegistryPolicyPypiWithNpmSettingsConfig() string {
	return testProviderConfig() + `
resource "stepsecurity_secure_registry_policy" "pypi_test" {
  registry = "pypi"

  npm_settings = {
    rewrite_tarball_urls = true
  }
}
`
}

func testAccSecureRegistryPolicyTyposquattingConfig(enabled bool, exemptions []string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "typosquatting_test" {
  registry = "npm"

  typosquatting_control = {
    enabled        = %t
    exemption_list = %s
  }
}
`, enabled, quotedPatternsList(exemptions))
}

func testAccSecureRegistryPolicyNugetWithTyposquattingConfig() string {
	return testProviderConfig() + `
resource "stepsecurity_secure_registry_policy" "nuget_test" {
  registry = "nuget"

  typosquatting_control = {
    enabled = true
  }
}
`
}

func testAccSecureRegistryPolicyTyposquattingRegistryConfig(registry string, exemptions []string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "typosquatting_%[1]s" {
  registry = %[1]q

  typosquatting_control = {
    enabled        = true
    exemption_list = %[2]s
  }
}
`, registry, quotedPatternsList(exemptions))
}

// testAccSecureRegistryPolicyAutoExemptConfig renders a pypi cooldown policy. autoExempt is
// the full auto_exempt_security_fixes attribute, or "" to leave it out.
func testAccSecureRegistryPolicyAutoExemptConfig(autoExempt string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "auto_exempt_test" {
  registry = "pypi"

  cooldown_control = {
    enabled        = true
    period_in_days = 7
    %s
  }
}
`, autoExempt)
}

func testAccSecureRegistryPolicyMavenConfig(cooldownEnabled bool, periodInDays int, compromisedEnabled bool) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "maven_test" {
  registry = "maven"

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

func testAccSecureRegistryPolicyMavenWithBlockListConfig() string {
	return testProviderConfig() + `
resource "stepsecurity_secure_registry_policy" "maven_test" {
  registry = "maven"

  custom_block_list_control = {
    enabled  = true
    patterns = ["left-pad@*"]
  }
}
`
}

func testAccSecureRegistryPolicyNugetBlockListConfig(blockListEnabled bool, patterns []string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_secure_registry_policy" "nuget_test" {
  registry = "nuget"

  custom_block_list_control = {
    enabled  = %t
    patterns = %s
  }
}
`, blockListEnabled, quotedPatternsList(patterns))
}

func TestValidateMessageTemplate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		tmpl    string
		max     int
		allowed []string
		wantErr string
	}{
		{"plain text", "Contact #platform-security", 500, blockMessagePlaceholders, ""},
		{"all block placeholders", "{{package}} {{version}} {{control}} {{reason}} {{ecosystem}}", 500, blockMessagePlaceholders, ""},
		{"all notice placeholders", "{{package}} {{count}} {{versions}} {{cooldown_days}} {{details}} {{ecosystem}}", 300, noticePlaceholders, ""},
		{"whitespace inside braces", "{{ package }} blocked", 500, blockMessagePlaceholders, ""},
		{"unknown placeholder", "ask {{owner}}", 500, blockMessagePlaceholders, "unknown placeholder {{owner}}"},
		{"notice placeholder in block template", "{{count}}", 500, blockMessagePlaceholders, "unknown placeholder {{count}}"},
		{"block placeholder in notice template", "{{reason}}", 300, noticePlaceholders, "unknown placeholder {{reason}}"},
		{"unterminated open", "{{package", 500, blockMessagePlaceholders, "unterminated or malformed"},
		{"stray close", "package}}", 500, blockMessagePlaceholders, "unterminated or malformed"},
		{"trailing open braces", "{{package}} {{", 500, blockMessagePlaceholders, "unterminated or malformed"},
		{"newline", "line1\nline2", 500, blockMessagePlaceholders, "single line"},
		{"tab", "a\tb", 500, blockMessagePlaceholders, "single line"},
		{"del char", "a\x7fb", 500, blockMessagePlaceholders, "single line"},
		{"exactly max length", strings.Repeat("a", 500), 500, blockMessagePlaceholders, ""},
		{"over max length", strings.Repeat("a", 501), 500, blockMessagePlaceholders, "at most 500 characters"},
		{"length counts characters not bytes", strings.Repeat("é", 300), 300, noticePlaceholders, ""},
		{"notice over max", strings.Repeat("a", 301), 300, noticePlaceholders, "at most 300 characters"},
		{"empty clears", "", 500, blockMessagePlaceholders, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateMessageTemplate(tt.tmpl, tt.max, tt.allowed)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestMessageTemplateValidator_SkipsNullAndUnknown(t *testing.T) {
	t.Parallel()

	v := messageTemplate(maxBlockMessageTemplateLen, blockMessagePlaceholders)
	for _, val := range []types.String{types.StringNull(), types.StringUnknown()} {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{ConfigValue: val}, resp)
		assert.False(t, resp.Diagnostics.HasError())
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{ConfigValue: types.StringValue("{{bad}}")}, resp)
	assert.True(t, resp.Diagnostics.HasError())
}

func TestSecureRegistryPolicyResource_buildUpsertRequest_NpmTemplates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}
	str := func(s string) *string { return &s }

	tests := []struct {
		name       string
		plan       types.Object
		prev       *secureRegistryPolicyResourceModel
		wantBlock  *string
		wantNotice *string
	}{
		{
			name:       "both set are sent",
			plan:       mustObj(t, true, types.StringValue("b {{package}}"), types.StringValue("n {{count}}")),
			wantBlock:  str("b {{package}}"),
			wantNotice: str("n {{count}}"),
		},
		{
			name: "never set stays omitted",
			plan: mustObj(t, true, types.StringNull(), types.StringNull()),
		},
		{
			name:       "removed attributes are sent as empty string",
			plan:       mustObj(t, true, types.StringNull(), types.StringNull()),
			prev:       &secureRegistryPolicyResourceModel{NpmSettings: mustObj(t, true, types.StringValue("b"), types.StringValue("n"))},
			wantBlock:  str(""),
			wantNotice: str(""),
		},
		{
			name:       "only one removed",
			plan:       mustObj(t, false, types.StringValue("b2"), types.StringNull()),
			prev:       &secureRegistryPolicyResourceModel{NpmSettings: mustObj(t, true, types.StringValue("b"), types.StringValue("n"))},
			wantBlock:  str("b2"),
			wantNotice: str(""),
		},
		{
			name:       "whole npm_settings block removed clears templates",
			plan:       types.ObjectNull(npmSettingsAttrTypes),
			prev:       &secureRegistryPolicyResourceModel{NpmSettings: mustObj(t, true, types.StringValue("b"), types.StringValue("n"))},
			wantBlock:  str(""),
			wantNotice: str(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plan := &secureRegistryPolicyResourceModel{Registry: types.StringValue("npm"), NpmSettings: tt.plan}
			var diags diag.Diagnostics
			req := r.buildUpsertRequest(ctx, plan, tt.prev, &diags)
			require.False(t, diags.HasError())
			require.NotNil(t, req.NpmSettings)
			assert.Equal(t, tt.wantBlock, req.NpmSettings.BlockMessageTemplate)
			assert.Equal(t, tt.wantNotice, req.NpmSettings.HiddenVersionsNoticeTemplate)
		})
	}
}

func mustObj(t *testing.T, rewrite bool, block, notice types.String) types.Object {
	t.Helper()
	obj, diags := buildTestNpmSettingsObjectWithTemplates(rewrite, block, notice)
	require.False(t, diags.HasError())
	return obj
}

func TestSecureRegistryPolicyResource_applyAPIResponse_NpmTemplates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}
	str := func(s string) *string { return &s }

	tests := []struct {
		name       string
		ref        types.Object
		api        *stepsecurityapi.NpmSettingsControl
		wantNull   bool
		wantBlock  types.String
		wantNotice types.String
	}{
		{
			name:       "templates in API response populate state",
			ref:        types.ObjectNull(npmSettingsAttrTypes),
			api:        &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: false, BlockMessageTemplate: str("b"), HiddenVersionsNoticeTemplate: str("n")},
			wantBlock:  types.StringValue("b"),
			wantNotice: types.StringValue("n"),
		},
		{
			name:       "absent fields map to null with no drift when tracked",
			ref:        mustObj(t, true, types.StringNull(), types.StringNull()),
			api:        &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: true},
			wantBlock:  types.StringNull(),
			wantNotice: types.StringNull(),
		},
		{
			name:       "empty string maps to null",
			ref:        mustObj(t, true, types.StringNull(), types.StringNull()),
			api:        &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: true, BlockMessageTemplate: str(""), HiddenVersionsNoticeTemplate: str("")},
			wantBlock:  types.StringNull(),
			wantNotice: types.StringNull(),
		},
		{
			name:       "explicit empty string in ref is preserved",
			ref:        mustObj(t, true, types.StringValue(""), types.StringValue("")),
			api:        &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: true},
			wantBlock:  types.StringValue(""),
			wantNotice: types.StringValue(""),
		},
		{
			name:       "empty string in ref is replaced by a non-empty API value",
			ref:        mustObj(t, true, types.StringValue(""), types.StringNull()),
			api:        &stepsecurityapi.NpmSettingsControl{RewriteTarballURLs: true, BlockMessageTemplate: str("b")},
			wantBlock:  types.StringValue("b"),
			wantNotice: types.StringNull(),
		},
		{
			name:     "untracked, all defaults stays null",
			ref:      types.ObjectNull(npmSettingsAttrTypes),
			api:      &stepsecurityapi.NpmSettingsControl{},
			wantNull: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ref := &secureRegistryPolicyResourceModel{NpmSettings: tt.ref}
			model := &secureRegistryPolicyResourceModel{NpmSettings: types.ObjectNull(npmSettingsAttrTypes)}
			var diags diag.Diagnostics
			r.applyAPIResponseToModel(ctx, ref, model, &stepsecurityapi.SecureRegistryControls{Registry: "npm", NpmSettings: tt.api}, &diags)
			require.False(t, diags.HasError())
			if tt.wantNull {
				assert.True(t, model.NpmSettings.IsNull())
				return
			}
			require.False(t, model.NpmSettings.IsNull())
			attrs := model.NpmSettings.Attributes()
			assert.Equal(t, tt.wantBlock, attrs["block_message_template"])
			assert.Equal(t, tt.wantNotice, attrs["hidden_versions_notice_template"])
		})
	}
}

// newEcosystemModel builds a full config model with every control null, for ValidateConfig tests.
func newEcosystemModel(registry string) secureRegistryPolicyResourceModel {
	return secureRegistryPolicyResourceModel{
		Registry:                   types.StringValue(registry),
		CooldownControl:            types.ObjectNull(cooldownControlAttrTypes),
		CompromisedPackagesControl: types.ObjectNull(compromisedPackagesControlAttrTypes),
		TyposquattingControl:       types.ObjectNull(typosquattingControlAttrTypes),
		CustomBlockListControl:     types.ObjectNull(customBlockListControlAttrTypes),
		NpmSettings:                types.ObjectNull(npmSettingsAttrTypes),
		GoSettings:                 types.ObjectNull(goSettingsAttrTypes),
	}
}

func blockListWith(t *testing.T, pseudo []string, yanked bool) types.Object {
	t.Helper()
	pseudoSet := types.SetNull(types.StringType)
	if pseudo != nil {
		vals := make([]attr.Value, len(pseudo))
		for i, v := range pseudo {
			vals[i] = types.StringValue(v)
		}
		var d diag.Diagnostics
		pseudoSet, d = types.SetValue(types.StringType, vals)
		require.False(t, d.HasError())
	}
	obj, d := types.ObjectValue(customBlockListControlAttrTypes, map[string]attr.Value{
		"enabled":               types.BoolValue(true),
		"patterns":              types.SetNull(types.StringType),
		"block_pseudo_versions": pseudoSet,
		"block_yanked_versions": types.BoolValue(yanked),
	})
	require.False(t, d.HasError())
	return obj
}

func TestSecureRegistryPolicyResource_ValidateConfig_NewEcosystems(t *testing.T) {
	t.Parallel()

	goSettings := types.ObjectValueMust(goSettingsAttrTypes, map[string]attr.Value{"proxy_checksum_db": types.BoolValue(true)})

	tests := []struct {
		name      string
		registry  string
		mutate    func(t *testing.T, m *secureRegistryPolicyResourceModel)
		wantError bool
	}{
		{"go plain", "go", func(*testing.T, *secureRegistryPolicyResourceModel) {}, false},
		{"ruby plain", "ruby", func(*testing.T, *secureRegistryPolicyResourceModel) {}, false},
		{"cargo plain", "cargo", func(*testing.T, *secureRegistryPolicyResourceModel) {}, false},
		{"go_settings on go", "go", func(_ *testing.T, m *secureRegistryPolicyResourceModel) { m.GoSettings = goSettings }, false},
		{"go_settings on npm", "npm", func(_ *testing.T, m *secureRegistryPolicyResourceModel) { m.GoSettings = goSettings }, true},
		{"go_settings on cargo", "cargo", func(_ *testing.T, m *secureRegistryPolicyResourceModel) { m.GoSettings = goSettings }, true},
		{"go_settings unknown on npm defers", "npm", func(_ *testing.T, m *secureRegistryPolicyResourceModel) {
			m.GoSettings = types.ObjectUnknown(goSettingsAttrTypes)
		}, false},
		{"pseudo versions on go", "go", func(t *testing.T, m *secureRegistryPolicyResourceModel) {
			m.CustomBlockListControl = blockListWith(t, []string{"*"}, false)
		}, false},
		{"pseudo versions on npm", "npm", func(t *testing.T, m *secureRegistryPolicyResourceModel) {
			m.CustomBlockListControl = blockListWith(t, []string{"*"}, false)
		}, true},
		{"yanked on cargo", "cargo", func(t *testing.T, m *secureRegistryPolicyResourceModel) {
			m.CustomBlockListControl = blockListWith(t, nil, true)
		}, false},
		{"yanked on ruby", "ruby", func(t *testing.T, m *secureRegistryPolicyResourceModel) {
			m.CustomBlockListControl = blockListWith(t, nil, true)
		}, true},
		{"typosquatting on go", "go", func(t *testing.T, m *secureRegistryPolicyResourceModel) {
			m.TyposquattingControl = mustBuildTestTyposquattingObject(t, true)
		}, true},
		{"npm_settings on ruby", "ruby", func(t *testing.T, m *secureRegistryPolicyResourceModel) {
			m.NpmSettings = mustBuildTestNpmSettingsObject(t, true)
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := newEcosystemModel(tt.registry)
			tt.mutate(t, &m)
			resp := &fwresource.ValidateConfigResponse{}
			(&secureRegistryPolicyResource{}).ValidateConfig(context.Background(), fwresource.ValidateConfigRequest{Config: testSecureRegistryPolicyConfig(t, m)}, resp)
			assert.Equal(t, tt.wantError, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
		})
	}
}

func TestSecureRegistryPolicyResource_buildUpsertRequest_NewEcosystemControls(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}

	plan := &secureRegistryPolicyResourceModel{
		Registry:               types.StringValue("go"),
		CustomBlockListControl: blockListWith(t, []string{"github.com/example-org/*"}, false),
		GoSettings:             types.ObjectValueMust(goSettingsAttrTypes, map[string]attr.Value{"proxy_checksum_db": types.BoolValue(true)}),
	}
	var diags diag.Diagnostics
	req := r.buildUpsertRequest(ctx, plan, nil, &diags)
	require.False(t, diags.HasError())
	assert.Equal(t, []string{"github.com/example-org/*"}, req.CustomBlockList.BlockPseudoVersions)
	require.NotNil(t, req.GoSettings)
	assert.True(t, req.GoSettings.ProxyChecksumDB)

	cargoPlan := &secureRegistryPolicyResourceModel{Registry: types.StringValue("cargo"), CustomBlockListControl: blockListWith(t, nil, true)}
	req = r.buildUpsertRequest(ctx, cargoPlan, nil, &diags)
	require.False(t, diags.HasError())
	assert.True(t, req.CustomBlockList.BlockYankedVersions)
	assert.Nil(t, req.CustomBlockList.BlockPseudoVersions)

	// go_settings removed from config resets on the backend.
	prev := &secureRegistryPolicyResourceModel{GoSettings: plan.GoSettings}
	removed := &secureRegistryPolicyResourceModel{Registry: types.StringValue("go"), GoSettings: types.ObjectNull(goSettingsAttrTypes)}
	req = r.buildUpsertRequest(ctx, removed, prev, &diags)
	require.NotNil(t, req.GoSettings)
	assert.False(t, req.GoSettings.ProxyChecksumDB)
}

func TestSecureRegistryPolicyResource_applyAPIResponse_NewEcosystemControls(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &secureRegistryPolicyResource{}
	var diags diag.Diagnostics

	ref := &secureRegistryPolicyResourceModel{GoSettings: types.ObjectNull(goSettingsAttrTypes), CustomBlockListControl: types.ObjectNull(customBlockListControlAttrTypes)}
	model := &secureRegistryPolicyResourceModel{}
	r.applyAPIResponseToModel(ctx, ref, model, &stepsecurityapi.SecureRegistryControls{
		Registry:        "go",
		GoSettings:      &stepsecurityapi.GoSettingsControl{ProxyChecksumDB: true},
		CustomBlockList: &stepsecurityapi.CustomBlockListControl{Enabled: true, BlockPseudoVersions: []string{"*"}},
	}, &diags)
	require.False(t, diags.HasError())
	assert.Equal(t, types.BoolValue(true), model.GoSettings.Attributes()["proxy_checksum_db"])
	assert.False(t, model.CustomBlockListControl.Attributes()["block_pseudo_versions"].(types.Set).IsNull())

	// Defaults on an untracked block stay null and unset pseudo versions map to null (no drift).
	model = &secureRegistryPolicyResourceModel{}
	r.applyAPIResponseToModel(ctx, ref, model, &stepsecurityapi.SecureRegistryControls{
		Registry:        "go",
		GoSettings:      &stepsecurityapi.GoSettingsControl{},
		CustomBlockList: &stepsecurityapi.CustomBlockListControl{Enabled: true},
	}, &diags)
	assert.True(t, model.GoSettings.IsNull())
	assert.True(t, model.CustomBlockListControl.Attributes()["block_pseudo_versions"].(types.Set).IsNull())

	// Cargo yanked flag round-trips.
	model = &secureRegistryPolicyResourceModel{}
	r.applyAPIResponseToModel(ctx, ref, model, &stepsecurityapi.SecureRegistryControls{
		Registry:        "cargo",
		CustomBlockList: &stepsecurityapi.CustomBlockListControl{Enabled: true, BlockYankedVersions: true},
	}, &diags)
	assert.Equal(t, types.BoolValue(true), model.CustomBlockListControl.Attributes()["block_yanked_versions"])
}

// --- cooldown_control.auto_exempt_security_fixes ---

func TestSecureRegistryPolicyResource_buildUpsertRequest_AutoExemptSecurityFixes(t *testing.T) {
	t.Parallel()

	score := 7.5
	tests := []struct {
		name       string
		autoExempt func(t *testing.T) types.Object
		want       *stepsecurityapi.AutoExemptSecurityFixes
	}{
		{
			name: "severity_threshold",
			autoExempt: func(t *testing.T) types.Object {
				return mustBuildTestAutoExemptObject(t, types.BoolValue(true), types.Float64Null(), types.StringValue("high"))
			},
			want: &stepsecurityapi.AutoExemptSecurityFixes{Enabled: true, MinSeverity: "high"},
		},
		{
			name: "cvss_threshold",
			autoExempt: func(t *testing.T) types.Object {
				return mustBuildTestAutoExemptObject(t, types.BoolValue(true), types.Float64Value(7.5), types.StringNull())
			},
			want: &stepsecurityapi.AutoExemptSecurityFixes{Enabled: true, MinCVSSScore: &score},
		},
		{
			name: "disabled_without_threshold",
			autoExempt: func(t *testing.T) types.Object {
				return mustBuildTestAutoExemptObject(t, types.BoolValue(false), types.Float64Null(), types.StringNull())
			},
			want: &stepsecurityapi.AutoExemptSecurityFixes{Enabled: false},
		},
		{
			name:       "omitted",
			autoExempt: func(*testing.T) types.Object { return types.ObjectNull(autoExemptSecurityFixesAttrTypes) },
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &secureRegistryPolicyResource{}
			plan := newEcosystemModel("pypi")
			plan.CooldownControl = mustBuildTestCooldownWithAutoExempt(t, tt.autoExempt(t))

			var diags diag.Diagnostics
			req := r.buildUpsertRequest(context.Background(), &plan, nil, &diags)
			require.False(t, diags.HasError(), "%v", diags)
			require.NotNil(t, req.CooldownPeriod)
			assert.Equal(t, tt.want, req.CooldownPeriod.AutoExemptSecurityFixes)
		})
	}
}

// Removing cooldown_control sends a disabled cooldown without the auto-exemption, which the
// backend's whole-object replace turns into "cleared".
func TestSecureRegistryPolicyResource_buildUpsertRequest_RemovedCooldownDropsAutoExempt(t *testing.T) {
	t.Parallel()
	r := &secureRegistryPolicyResource{}

	prev := newEcosystemModel("npm")
	prev.CooldownControl = mustBuildTestCooldownWithAutoExempt(t,
		mustBuildTestAutoExemptObject(t, types.BoolValue(true), types.Float64Null(), types.StringValue("critical")))
	plan := newEcosystemModel("npm")

	var diags diag.Diagnostics
	req := r.buildUpsertRequest(context.Background(), &plan, &prev, &diags)
	require.False(t, diags.HasError())
	require.NotNil(t, req.CooldownPeriod)
	assert.False(t, req.CooldownPeriod.Enabled)
	assert.Nil(t, req.CooldownPeriod.AutoExemptSecurityFixes)
}

func TestSecureRegistryPolicyResource_applyAPIResponse_AutoExemptSecurityFixes(t *testing.T) {
	t.Parallel()

	score := 9.0
	tests := []struct {
		name         string
		api          *stepsecurityapi.AutoExemptSecurityFixes
		wantNull     bool
		wantEnabled  bool
		wantScore    types.Float64
		wantSeverity types.String
	}{
		{name: "absent", api: nil, wantNull: true},
		{
			name:         "severity",
			api:          &stepsecurityapi.AutoExemptSecurityFixes{Enabled: true, MinSeverity: "moderate"},
			wantEnabled:  true,
			wantScore:    types.Float64Null(),
			wantSeverity: types.StringValue("moderate"),
		},
		{
			name:         "score",
			api:          &stepsecurityapi.AutoExemptSecurityFixes{Enabled: true, MinCVSSScore: &score},
			wantEnabled:  true,
			wantScore:    types.Float64Value(9.0),
			wantSeverity: types.StringNull(),
		},
		{
			name:         "disabled_without_threshold",
			api:          &stepsecurityapi.AutoExemptSecurityFixes{Enabled: false},
			wantEnabled:  false,
			wantScore:    types.Float64Null(),
			wantSeverity: types.StringNull(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &secureRegistryPolicyResource{}
			ref := newEcosystemModel("pypi")
			ref.CooldownControl = mustBuildTestCooldownWithAutoExempt(t, types.ObjectNull(autoExemptSecurityFixesAttrTypes))
			model := newEcosystemModel("pypi")

			var diags diag.Diagnostics
			r.applyAPIResponseToModel(context.Background(), &ref, &model, &stepsecurityapi.SecureRegistryControls{
				Registry:       "pypi",
				CooldownPeriod: &stepsecurityapi.CooldownPeriodControl{Enabled: true, PeriodInDays: 7, AutoExemptSecurityFixes: tt.api},
			}, &diags)
			require.False(t, diags.HasError(), "%v", diags)

			autoExempt := model.CooldownControl.Attributes()["auto_exempt_security_fixes"].(types.Object)
			if tt.wantNull {
				assert.True(t, autoExempt.IsNull())
				return
			}
			var got autoExemptSecurityFixesModel
			require.False(t, autoExempt.As(context.Background(), &got, basetypes.ObjectAsOptions{}).HasError())
			assert.Equal(t, tt.wantEnabled, got.Enabled.ValueBool())
			assert.True(t, tt.wantScore.Equal(got.MinCVSSScore), "score: want %v got %v", tt.wantScore, got.MinCVSSScore)
			assert.True(t, tt.wantSeverity.Equal(got.MinSeverity), "severity: want %v got %v", tt.wantSeverity, got.MinSeverity)
		})
	}
}

// A configured CVSS score is reused from ref when the API echoes the same number, so the
// planned value (e.g. 0.1) round-trips without float64 conversion drift.
func TestSecureRegistryPolicyResource_applyAPIResponse_AutoExemptScoreRoundTrips(t *testing.T) {
	t.Parallel()
	for _, v := range []float64{0.1, 7.5, 10.0} {
		r := &secureRegistryPolicyResource{}
		refScore := types.Float64Value(v)
		ref := newEcosystemModel("npm")
		ref.CooldownControl = mustBuildTestCooldownWithAutoExempt(t,
			mustBuildTestAutoExemptObject(t, types.BoolValue(true), refScore, types.StringNull()))
		model := newEcosystemModel("npm")

		apiScore := v
		var diags diag.Diagnostics
		r.applyAPIResponseToModel(context.Background(), &ref, &model, &stepsecurityapi.SecureRegistryControls{
			Registry: "npm",
			CooldownPeriod: &stepsecurityapi.CooldownPeriodControl{Enabled: true, PeriodInDays: 7,
				AutoExemptSecurityFixes: &stepsecurityapi.AutoExemptSecurityFixes{Enabled: true, MinCVSSScore: &apiScore}},
		}, &diags)
		require.False(t, diags.HasError())

		got := model.CooldownControl.Attributes()["auto_exempt_security_fixes"].(types.Object).Attributes()["min_cvss_score"]
		assert.True(t, refScore.Equal(got), "score %v: want %v got %v", v, refScore, got)
	}
}

func TestSecureRegistryPolicyResource_ValidateConfig_AutoExemptThreshold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		enabled   types.Bool
		score     types.Float64
		severity  types.String
		wantError bool
	}{
		{name: "enabled_with_severity", enabled: types.BoolValue(true), score: types.Float64Null(), severity: types.StringValue("high")},
		{name: "enabled_with_score", enabled: types.BoolValue(true), score: types.Float64Value(5), severity: types.StringNull()},
		{name: "enabled_without_threshold", enabled: types.BoolValue(true), score: types.Float64Null(), severity: types.StringNull(), wantError: true},
		{name: "disabled_without_threshold", enabled: types.BoolValue(false), score: types.Float64Null(), severity: types.StringNull()},
		{name: "unknown_enabled_defers", enabled: types.BoolUnknown(), score: types.Float64Null(), severity: types.StringNull()},
		{name: "unknown_threshold_defers", enabled: types.BoolValue(true), score: types.Float64Unknown(), severity: types.StringNull()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &secureRegistryPolicyResource{}
			model := newEcosystemModel("maven")
			model.CooldownControl = mustBuildTestCooldownWithAutoExempt(t,
				mustBuildTestAutoExemptObject(t, tt.enabled, tt.score, tt.severity))

			resp := &fwresource.ValidateConfigResponse{}
			r.ValidateConfig(context.Background(), fwresource.ValidateConfigRequest{Config: testSecureRegistryPolicyConfig(t, model)}, resp)
			assert.Equal(t, tt.wantError, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
		})
	}
}

// TestSecureRegistryPolicyResource_AutoExemptSchemaValidators runs the attribute validators
// declared on min_cvss_score and min_severity against a real config.
func TestSecureRegistryPolicyResource_AutoExemptSchemaValidators(t *testing.T) {
	t.Parallel()

	schema := testSecureRegistryPolicySchema(t)
	autoExemptAttrs := schema.Attributes["cooldown_control"].(resourceschema.SingleNestedAttribute).
		Attributes["auto_exempt_security_fixes"].(resourceschema.SingleNestedAttribute).Attributes
	scoreValidators := autoExemptAttrs["min_cvss_score"].(resourceschema.Float64Attribute).Validators
	severityValidators := autoExemptAttrs["min_severity"].(resourceschema.StringAttribute).Validators
	base := path.Root("cooldown_control").AtName("auto_exempt_security_fixes")
	baseExpr := path.MatchRoot("cooldown_control").AtName("auto_exempt_security_fixes")

	tests := []struct {
		name      string
		score     types.Float64
		severity  types.String
		wantError bool
	}{
		{name: "score_only", score: types.Float64Value(0.1), severity: types.StringNull()},
		{name: "severity_only", score: types.Float64Null(), severity: types.StringValue("low")},
		{name: "both_set", score: types.Float64Value(7), severity: types.StringValue("high"), wantError: true},
		{name: "score_below_range", score: types.Float64Value(0), severity: types.StringNull(), wantError: true},
		{name: "score_above_range", score: types.Float64Value(10.1), severity: types.StringNull(), wantError: true},
		{name: "unknown_severity_label", score: types.Float64Null(), severity: types.StringValue("medium"), wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			model := newEcosystemModel("npm")
			model.CooldownControl = mustBuildTestCooldownWithAutoExempt(t,
				mustBuildTestAutoExemptObject(t, types.BoolValue(true), tt.score, tt.severity))
			config := testSecureRegistryPolicyConfig(t, model)

			var diags diag.Diagnostics
			for _, v := range scoreValidators {
				resp := &validator.Float64Response{}
				v.ValidateFloat64(context.Background(), validator.Float64Request{
					Path: base.AtName("min_cvss_score"), PathExpression: baseExpr.AtName("min_cvss_score"),
					Config: config, ConfigValue: tt.score,
				}, resp)
				diags.Append(resp.Diagnostics...)
			}
			for _, v := range severityValidators {
				resp := &validator.StringResponse{}
				v.ValidateString(context.Background(), validator.StringRequest{
					Path: base.AtName("min_severity"), PathExpression: baseExpr.AtName("min_severity"),
					Config: config, ConfigValue: tt.severity,
				}, resp)
				diags.Append(resp.Diagnostics...)
			}
			assert.Equal(t, tt.wantError, diags.HasError(), "%v", diags)
		})
	}
}
