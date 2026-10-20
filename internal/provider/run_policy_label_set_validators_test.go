package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func runSetValidator(t *testing.T, value types.Set) bool {
	t.Helper()
	resp := &validator.SetResponse{}
	caseInsensitiveUnique().ValidateSet(context.Background(), validator.SetRequest{
		Path:        path.Root("test"),
		ConfigValue: value,
	}, resp)
	return resp.Diagnostics.HasError()
}

func TestCaseInsensitiveUniqueValidator(t *testing.T) {
	t.Parallel()

	stringsSet := func(values ...string) types.Set {
		elems := make([]attr.Value, len(values))
		for i, v := range values {
			elems[i] = types.StringValue(v)
		}
		return types.SetValueMust(types.StringType, elems)
	}

	assert.True(t, runSetValidator(t, stringsSet("GPU", "gpu")), "case-variant duplicates must be rejected")
	assert.False(t, runSetValidator(t, stringsSet("gpu", "large")))
	assert.False(t, runSetValidator(t, types.SetNull(types.StringType)))
	assert.False(t, runSetValidator(t, types.SetUnknown(types.StringType)))
}

func TestRunnerLabelRequirementRuleValidator(t *testing.T) {
	t.Parallel()

	rule := func(require, forbid types.Set) types.Object {
		return types.ObjectValueMust(runnerLabelRequirementObjectType.AttrTypes, map[string]attr.Value{
			"if_label_matches": types.StringValue("codebuild-*"),
			"require_labels":   require,
			"forbid_labels":    forbid,
		})
	}
	run := func(value types.Object) bool {
		resp := &validator.ObjectResponse{}
		runnerLabelRequirementRule().ValidateObject(context.Background(), validator.ObjectRequest{
			Path:        path.Root("test"),
			ConfigValue: value,
		}, resp)
		return resp.Diagnostics.HasError()
	}

	empty := types.SetValueMust(types.StringType, []attr.Value{})
	one := types.SetValueMust(types.StringType, []attr.Value{types.StringValue("buildspec-override:true")})

	assert.True(t, run(rule(types.SetNull(types.StringType), types.SetNull(types.StringType))), "neither direction set must be rejected")
	assert.True(t, run(rule(empty, empty)), "both empty must be rejected")
	assert.False(t, run(rule(one, types.SetNull(types.StringType))))
	assert.False(t, run(rule(types.SetNull(types.StringType), one)))
	assert.False(t, run(rule(types.SetUnknown(types.StringType), types.SetNull(types.StringType))), "unknown values defer to apply")
	assert.False(t, run(types.ObjectNull(runnerLabelRequirementObjectType.AttrTypes)))
}
