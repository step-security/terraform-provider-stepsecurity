package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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
				Comment:   types.StringValue("approved per SEC-1234"),
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
	assert.Equal(t, "approved per SEC-1234", spec.Rules[0].Comment)
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

	// versions with an unknown name defers rather than erroring: the name may
	// resolve to a valid value at apply time, and create/update re-validates
	// once it is known. (An explicitly null name still errors; see
	// TestDeveloperMDMIDEExtensionPolicy_ValidateRejectsInvalidRules.)
	unknownName := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: []developerMDMIDEExtensionRuleModel{
			{Publisher: types.StringValue("redhat"), Name: types.StringUnknown(), Versions: stringSet(t, "1.15.0"), Stable: types.BoolValue(false)},
		},
	}
	assert.False(t, validateDeveloperMDMIDEExtensionPolicy(ctx, unknownName).HasError(), "versions with an unknown name should defer, not error")

	// An unknown-name versions rule must not falsely collide in the cross-rule
	// conflict map with a whole-publisher stable rule for the same publisher: the
	// compiled key is not known until the name resolves, so tracking defers rather
	// than treating the zero-value "" name as the same extension.
	unknownNameNoCollision := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: []developerMDMIDEExtensionRuleModel{
			{Publisher: types.StringValue("github"), Name: types.StringNull(), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(true)},
			{Publisher: types.StringValue("github"), Name: types.StringUnknown(), Versions: stringSet(t, "1.0.0"), Stable: types.BoolValue(false)},
		},
	}
	assert.False(t, validateDeveloperMDMIDEExtensionPolicy(ctx, unknownNameNoCollision).HasError(), "unknown-name versions rule must not collide with a whole-publisher stable rule")

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

// TestDeveloperMDMIDEExtensionPolicy_ConflictDiagnosticIsHumanReadable proves the
// cross-rule conflict message shows a readable `publisher.name` identifier and
// never leaks the internal NUL-delimited map key.
func TestDeveloperMDMIDEExtensionPolicy_ConflictDiagnosticIsHumanReadable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conflict := developerMDMIDEExtensionPolicyModel{
		Name: types.StringValue("p"),
		Mode: types.StringValue("allowlist"),
		Rules: []developerMDMIDEExtensionRuleModel{
			{Publisher: types.StringValue("redhat"), Name: types.StringValue("yaml"), Versions: types.SetNull(types.StringType), Stable: types.BoolValue(true)},
			{Publisher: types.StringValue("redhat"), Name: types.StringValue("yaml"), Versions: stringSet(t, "1.0.0"), Stable: types.BoolValue(false)},
		},
	}

	diags := validateDeveloperMDMIDEExtensionPolicy(ctx, conflict)
	require.True(t, diags.HasError(), "expected same-key stable/versions conflict")

	var detail string
	for _, d := range diags.Errors() {
		if strings.Contains(d.Summary(), "Conflicting rules") {
			detail = d.Detail()
		}
	}
	require.NotEmpty(t, detail, "expected a conflicting-rules diagnostic")
	assert.Contains(t, detail, "redhat.yaml", "message should use a human-readable publisher.name identifier")
	assert.NotContains(t, detail, "\x00", "message must not leak the internal NUL-delimited key")
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
		Spec:        json.RawMessage(`{"rules":[{"publisher":"ms-python","name":"python","stable":true,"comment":"approved per SEC-1234"},{"publisher":"redhat","name":"vscode-yaml","versions":["1.15.0"]}]}`),
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
	assert.Equal(t, "approved per SEC-1234", model.Rules[0].Comment.ValueString())
	assert.Equal(t, "redhat", model.Rules[1].Publisher.ValueString())
	// Rule 1 carries no comment in the API response, so it reads back as null.
	assert.True(t, model.Rules[1].Comment.IsNull())

	var versions []string
	model.Rules[1].Versions.ElementsAs(ctx, &versions, false)
	assert.Equal(t, []string{"1.15.0"}, versions)
}

// TestDeveloperMDMIDEExtensionPolicy_CommentLengthValidator exercises the schema
// validator wired to the rule `comment` attribute. The imperative
// validateDeveloperMDMIDEExtensionPolicy helper does not run schema-level
// validators, so the bounds are verified by pulling the validator off the schema
// and running it directly. Empty is rejected (an unset comment is expressed by
// omitting the attribute, not by ""; this avoids an apply inconsistency from the
// omitempty round-trip). The multibyte case confirms the cap counts runes, not
// bytes (i.e. a UTF8-length validator, not a byte-length one).
func TestDeveloperMDMIDEExtensionPolicy_CommentLengthValidator(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMIDEExtensionPolicyResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError())

	rules, ok := schemaResp.Schema.Attributes["rules"].(schema.ListNestedAttribute)
	require.True(t, ok, "rules should be a ListNestedAttribute")
	comment, ok := rules.NestedObject.Attributes["comment"].(schema.StringAttribute)
	require.True(t, ok, "comment should be a StringAttribute")
	require.NotEmpty(t, comment.Validators, "comment should have a length validator")

	validate := func(value string) diag.Diagnostics {
		var all diag.Diagnostics
		for _, v := range comment.Validators {
			resp := &validator.StringResponse{}
			v.ValidateString(ctx, validator.StringRequest{
				Path:        path.Root("rules").AtListIndex(0).AtName("comment"),
				ConfigValue: types.StringValue(value),
			}, resp)
			all.Append(resp.Diagnostics...)
		}
		return all
	}

	assert.True(t, validate("").HasError(), "empty comment should be rejected (omit the attribute instead)")
	assert.False(t, validate(strings.Repeat("a", 512)).HasError(), "512 runes should be accepted")
	assert.True(t, validate(strings.Repeat("a", 513)).HasError(), "513 runes should be rejected")
	assert.False(t, validate(strings.Repeat("世", 512)).HasError(), "512 multibyte runes should be accepted (rune-counted)")
}

// TestDeveloperMDMIDEExtensionPolicy_RuleNameRejectsEmpty exercises the schema
// validator on the rule `name` attribute. An unset name (target the whole
// publisher) is expressed by omitting the attribute, not by ""; an empty string
// would be dropped by omitempty and read back as null, causing an apply
// inconsistency, so it is rejected at plan time.
func TestDeveloperMDMIDEExtensionPolicy_RuleNameRejectsEmpty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	NewDeveloperMDMIDEExtensionPolicyResource().Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError())

	rules, ok := schemaResp.Schema.Attributes["rules"].(schema.ListNestedAttribute)
	require.True(t, ok, "rules should be a ListNestedAttribute")
	nameAttr, ok := rules.NestedObject.Attributes["name"].(schema.StringAttribute)
	require.True(t, ok, "name should be a StringAttribute")
	require.NotEmpty(t, nameAttr.Validators, "name should have a length validator")

	validate := func(value string) diag.Diagnostics {
		var all diag.Diagnostics
		for _, v := range nameAttr.Validators {
			resp := &validator.StringResponse{}
			v.ValidateString(ctx, validator.StringRequest{
				Path:        path.Root("rules").AtListIndex(0).AtName("name"),
				ConfigValue: types.StringValue(value),
			}, resp)
			all.Append(resp.Diagnostics...)
		}
		return all
	}

	assert.True(t, validate("").HasError(), "empty name should be rejected (omit the attribute to target the whole publisher)")
	assert.False(t, validate("python").HasError(), "a non-empty name should be accepted")
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
					resourcehelper.TestCheckResourceAttr("stepsecurity_developer_mdm_ide_extension_policy.test", "rules.0.comment", "approved for engineering"),
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
      comment   = "approved for engineering"
    },
  ]
}
`, name, description, stable)
}
