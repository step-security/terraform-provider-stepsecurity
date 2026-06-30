package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	resourcehelper "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func stringSet(t *testing.T, values ...string) types.Set {
	t.Helper()
	vals := make([]attr.Value, len(values))
	for i, v := range values {
		vals[i] = types.StringValue(v)
	}
	set, diags := types.SetValue(types.StringType, vals)
	require.False(t, diags.HasError())
	return set
}

func TestDeveloperMDMIDEExtensionPolicyResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMIDEExtensionPolicyResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)

	assert.False(t, schemaResp.Diagnostics.HasError(), "Schema() errors: %v", schemaResp.Diagnostics)

	attrs := schemaResp.Schema.Attributes
	for _, name := range []string{"id", "policy_id", "name", "description", "target", "mode", "rules", "created_by", "created_at", "updated_by", "updated_at"} {
		assert.Contains(t, attrs, name, "missing attribute %q", name)
	}
}

func TestDeveloperMDMIDEExtensionPolicy_BuildRequestAllowlistStable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMIDEExtensionPolicyModel{
		Name:        types.StringValue("eng"),
		Description: types.StringValue("approved extensions"),
		Target:      types.StringValue(stepsecurityapi.DeveloperMDMTargetVSCode),
		Mode:        types.StringValue("allowlist"),
		Rules: []developerMDMIDEExtensionRuleModel{
			{
				Publisher: types.StringValue("ms-python"),
				Name:      types.StringValue("python"),
				Versions:  types.SetNull(types.StringType),
				Stable:    types.BoolValue(true),
			},
		},
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, model, &diags)
	require.False(t, diags.HasError(), "build errors: %v", diags)

	assert.Equal(t, stepsecurityapi.DeveloperMDMCategoryIDEExtension, req.Category)
	assert.Equal(t, stepsecurityapi.DeveloperMDMTargetVSCode, req.Target)
	assert.Equal(t, 1, req.SpecVersion)
	assert.Equal(t, "allowlist", req.Mode)
	assert.Equal(t, "approved extensions", req.Description)

	var spec stepsecurityapi.DeveloperMDMIDEExtensionSpec
	require.NoError(t, json.Unmarshal(req.Spec, &spec))
	require.Len(t, spec.Rules, 1)
	assert.Equal(t, "ms-python", spec.Rules[0].Publisher)
	assert.True(t, spec.Rules[0].Stable)
	assert.Empty(t, spec.Rules[0].Versions)
}

func TestDeveloperMDMIDEExtensionPolicy_BuildRequestAllowlistVersions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMIDEExtensionPolicyModel{
		Name:   types.StringValue("eng"),
		Target: types.StringValue(stepsecurityapi.DeveloperMDMTargetVSCode),
		Mode:   types.StringValue("allowlist"),
		Rules: []developerMDMIDEExtensionRuleModel{
			{
				Publisher: types.StringValue("redhat"),
				Name:      types.StringValue("vscode-yaml"),
				// Intentionally unsorted to verify deterministic ordering.
				Versions: stringSet(t, "2.0.0", "1.15.0", "1.10.0"),
				Stable:   types.BoolValue(false),
			},
		},
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, model, &diags)
	require.False(t, diags.HasError())

	var spec stepsecurityapi.DeveloperMDMIDEExtensionSpec
	require.NoError(t, json.Unmarshal(req.Spec, &spec))
	require.Len(t, spec.Rules, 1)
	assert.Equal(t, []string{"1.10.0", "1.15.0", "2.0.0"}, spec.Rules[0].Versions)
	assert.False(t, spec.Rules[0].Stable)
}

func TestDeveloperMDMIDEExtensionPolicy_BuildRequestBlocklist(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := developerMDMIDEExtensionPolicyModel{
		Name:   types.StringValue("block"),
		Target: types.StringValue(stepsecurityapi.DeveloperMDMTargetVSCode),
		Mode:   types.StringValue("blocklist"),
		Rules: []developerMDMIDEExtensionRuleModel{
			{
				Publisher: types.StringValue("evil"),
				Name:      types.StringValue("malware"),
				Versions:  types.SetNull(types.StringType),
				Stable:    types.BoolValue(false),
			},
		},
	}

	var diags diag.Diagnostics
	req := buildDeveloperMDMIDEExtensionPolicyRequest(ctx, model, &diags)
	require.False(t, diags.HasError())
	assert.Equal(t, "blocklist", req.Mode)

	// Blocklist rules carry no versions or stable; omitempty drops them from JSON.
	assert.NotContains(t, string(req.Spec), "versions")
	assert.NotContains(t, string(req.Spec), "stable")

	var spec stepsecurityapi.DeveloperMDMIDEExtensionSpec
	require.NoError(t, json.Unmarshal(req.Spec, &spec))
	require.Len(t, spec.Rules, 1)
	assert.Equal(t, "evil", spec.Rules[0].Publisher)
	assert.False(t, spec.Rules[0].Stable)
	assert.Empty(t, spec.Rules[0].Versions)
}

func TestDeveloperMDMIDEExtensionPolicy_ValidateRejectsInvalidRules(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	rule := func(mut func(*developerMDMIDEExtensionRuleModel)) developerMDMIDEExtensionRuleModel {
		r := developerMDMIDEExtensionRuleModel{
			Publisher: types.StringValue("ms-python"),
			Name:      types.StringValue("python"),
			Versions:  types.SetNull(types.StringType),
			Stable:    types.BoolValue(false),
		}
		mut(&r)
		return r
	}

	cases := []struct {
		name string
		mode string
		rule developerMDMIDEExtensionRuleModel
	}{
		{"publisher with dot", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Publisher = types.StringValue("ms.python") })},
		{"publisher wildcard", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Publisher = types.StringValue("*") })},
		{"publisher with space", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Publisher = types.StringValue("ms python") })},
		{"name wildcard", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Name = types.StringValue("py*thon") })},
		{"blocklist with versions", "blocklist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Versions = stringSet(t, "1.0.0") })},
		{"versions without name", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) {
			r.Name = types.StringNull()
			r.Versions = stringSet(t, "1.0.0")
		})},
		{"bad version", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Versions = stringSet(t, "1.0") })},
		{"literal stable version", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Versions = stringSet(t, "stable") })},
		{"stable plus versions", "allowlist", rule(func(r *developerMDMIDEExtensionRuleModel) {
			r.Stable = types.BoolValue(true)
			r.Versions = stringSet(t, "1.0.0")
		})},
		{"stable on blocklist", "blocklist", rule(func(r *developerMDMIDEExtensionRuleModel) { r.Stable = types.BoolValue(true) })},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			model := developerMDMIDEExtensionPolicyModel{
				Name:  types.StringValue("p"),
				Mode:  types.StringValue(tc.mode),
				Rules: []developerMDMIDEExtensionRuleModel{tc.rule},
			}
			diags := validateDeveloperMDMIDEExtensionPolicy(ctx, model)
			assert.True(t, diags.HasError(), "expected validation error for %q", tc.name)
		})
	}
}

func TestDeveloperMDMIDEExtensionPolicy_ValidateAcceptsValidRules(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Cross-rule conflict: same key cannot mix stable and explicit versions.
	conflict := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: []developerMDMIDEExtensionRuleModel{
			{Publisher: types.StringValue("redhat"), Name: types.StringValue("yaml"), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(true)},
			{Publisher: types.StringValue("redhat"), Name: types.StringValue("yaml"), Versions: stringSet(t, "1.0.0"), Stable: types.BoolValue(false)},
		},
	}
	assert.True(t, validateDeveloperMDMIDEExtensionPolicy(ctx, conflict).HasError(), "expected same-key stable/versions conflict")

	// Empty rules are backend-valid for both modes.
	for _, mode := range []string{"allowlist", "blocklist"} {
		empty := developerMDMIDEExtensionPolicyModel{
			Name:  types.StringValue("p"),
			Mode:  types.StringValue(mode),
			Rules: []developerMDMIDEExtensionRuleModel{},
		}
		assert.False(t, validateDeveloperMDMIDEExtensionPolicy(ctx, empty).HasError(), "empty rules should be valid for %s", mode)
	}

	// Whole-publisher allow, stable allow, exact-version allow.
	valid := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: []developerMDMIDEExtensionRuleModel{
			{Publisher: types.StringValue("github"), Name: types.StringNull(), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(false)},
			{Publisher: types.StringValue("ms-python"), Name: types.StringValue("python"), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(true)},
			{Publisher: types.StringValue("redhat"), Name: types.StringValue("vscode-yaml"), Versions: stringSet(t, "1.15.0", "1.15.0@linux-x64"), Stable: types.BoolValue(false)},
		},
	}
	assert.False(t, validateDeveloperMDMIDEExtensionPolicy(ctx, valid).HasError(), "valid policy should not error: %v", validateDeveloperMDMIDEExtensionPolicy(ctx, valid))
}

func TestDeveloperMDMIDEExtensionPolicy_ApplyAPIToModel(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policy := &stepsecurityapi.DeveloperMDMPolicy{
		PolicyID:    "p1",
		Name:        "eng",
		Description: "desc",
		Category:    "ide_extension",
		Target:      "vscode",
		Mode:        "allowlist",
		SpecVersion: 1,
		Spec:        json.RawMessage(`{"rules":[{"publisher":"ms-python","name":"python","stable":true},{"publisher":"redhat","name":"vscode-yaml","versions":["1.15.0"]}]}`),
		CreatedBy:   "user@x.io",
		CreatedAt:   "2026-06-29T00:00:00Z",
		UpdatedBy:   "user@x.io",
		UpdatedAt:   "2026-06-29T01:00:00Z",
	}

	model := &developerMDMIDEExtensionPolicyModel{}
	var diags diag.Diagnostics
	applyDeveloperMDMPolicyToModel(ctx, policy, model, &diags)
	require.False(t, diags.HasError(), "apply errors: %v", diags)

	assert.Equal(t, "p1", model.ID.ValueString())
	assert.Equal(t, "p1", model.PolicyID.ValueString())
	assert.Equal(t, "eng", model.Name.ValueString())
	assert.Equal(t, "vscode", model.Target.ValueString())
	assert.Equal(t, "desc", model.Description.ValueString())
	assert.Equal(t, "allowlist", model.Mode.ValueString())
	assert.Equal(t, "user@x.io", model.CreatedBy.ValueString())
	assert.Equal(t, "2026-06-29T01:00:00Z", model.UpdatedAt.ValueString())

	require.Len(t, model.Rules, 2)
	assert.Equal(t, "ms-python", model.Rules[0].Publisher.ValueString())
	assert.True(t, model.Rules[0].Stable.ValueBool())
	assert.True(t, model.Rules[0].Versions.IsNull())
	assert.Equal(t, "redhat", model.Rules[1].Publisher.ValueString())

	var versions []string
	model.Rules[1].Versions.ElementsAs(ctx, &versions, false)
	assert.Equal(t, []string{"1.15.0"}, versions)
}

func TestDeveloperMDMIDEExtensionPolicy_NonIDECategoryReadDiagnostic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policy := &stepsecurityapi.DeveloperMDMPolicy{
		PolicyID: "p1",
		Name:     "other",
		Category: "some_other_category",
		Mode:     "allowlist",
	}

	model := &developerMDMIDEExtensionPolicyModel{}
	var diags diag.Diagnostics
	applyDeveloperMDMPolicyToModel(ctx, policy, model, &diags)
	assert.True(t, diags.HasError(), "expected diagnostic for non-ide_extension category")
}

// TestAccDeveloperMDMIDEExtensionPolicyResource runs against the real API.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccDeveloperMDMIDEExtensionPolicyResource(t *testing.T) {
	const name = "tf-acc IDE extension policy"
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			// Create.
			{
				Config: testAccDeveloperMDMIDEExtensionPolicyConfig(name, "approved extensions", "true"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "name", name),
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "mode", "allowlist"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "description", "approved extensions"),
					resourcehelper.TestCheckResourceAttrSet("stepsecurity_developer_mdm_ide_extension_policy.test", "policy_id"),
					resourcehelper.TestCheckResourceAttrSet("stepsecurity_developer_mdm_ide_extension_policy.test", "id"),
				),
			},
			// Import by policy_id.
			{
				ResourceName:      "stepsecurity_developer_mdm_ide_extension_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update description and a rule field.
			{
				Config: testAccDeveloperMDMIDEExtensionPolicyConfig(name, "updated description", "false"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "description", "updated description"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "rules.0.stable", "false"),
				),
			},
		},
	})
}

func testAccDeveloperMDMIDEExtensionPolicyConfig(name, description, stable string) string {
	return testProviderConfig() + fmt.Sprintf(`
resource "stepsecurity_developer_mdm_ide_extension_policy" "test" {
  name        = %q
  description = %q
  mode        = "allowlist"

  rules = [
    {
      publisher = "ms-python"
      name      = "python"
      stable    = %s
    },
  ]
}
`, name, description, stable)
}
