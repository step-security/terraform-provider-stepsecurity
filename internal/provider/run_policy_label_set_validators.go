package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// caseInsensitiveUniqueValidator rejects label sets containing values that
// differ only by case. The backend deduplicates labels case-insensitively
// (first occurrence wins), so such a set would plan N elements and read back
// fewer, failing the apply with an inconsistent-result error.
type caseInsensitiveUniqueValidator struct{}

func (v caseInsensitiveUniqueValidator) Description(_ context.Context) string {
	return "values must be unique case-insensitively"
}

func (v caseInsensitiveUniqueValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v caseInsensitiveUniqueValidator) ValidateSet(ctx context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	seen := make(map[string]string)
	for _, element := range req.ConfigValue.Elements() {
		stringElement, ok := element.(types.String)
		if !ok || stringElement.IsNull() || stringElement.IsUnknown() {
			continue
		}
		value := stringElement.ValueString()
		key := strings.ToLower(value)
		if first, dup := seen[key]; dup {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Duplicate Label After Case Folding",
				fmt.Sprintf("%q and %q differ only by case; the server deduplicates labels case-insensitively, which would change the set after apply.", first, value),
			)
			return
		}
		seen[key] = value
	}
}

// caseInsensitiveUnique returns the shared case-folding uniqueness validator.
func caseInsensitiveUnique() validator.Set {
	return caseInsensitiveUniqueValidator{}
}

// runnerLabelRequirementRuleValidator enforces the rule-level contract the
// server applies: every rule needs at least one required or forbidden label
// (the both-set case is covered by ConflictsWith on the two sets).
type runnerLabelRequirementRuleValidator struct{}

func (v runnerLabelRequirementRuleValidator) Description(_ context.Context) string {
	return "a rule needs at least one required or forbidden label"
}

func (v runnerLabelRequirementRuleValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v runnerLabelRequirementRuleValidator) ValidateObject(ctx context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	attributes := req.ConfigValue.Attributes()
	knownNonEmpty := func(name string) (bool, bool) {
		set, ok := attributes[name].(types.Set)
		if !ok || set.IsUnknown() {
			return false, false
		}
		return !set.IsNull() && len(set.Elements()) > 0, true
	}
	requireNonEmpty, requireKnown := knownNonEmpty("require_labels")
	forbidNonEmpty, forbidKnown := knownNonEmpty("forbid_labels")
	if !requireKnown || !forbidKnown {
		return
	}
	if !requireNonEmpty && !forbidNonEmpty {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Empty Runner Label Requirement",
			"a rule needs at least one entry in require_labels or forbid_labels.",
		)
	}
}

// runnerLabelRequirementRule returns the rule-level object validator.
func runnerLabelRequirementRule() validator.Object {
	return runnerLabelRequirementRuleValidator{}
}
