package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type excludedRunnerLabelValidator struct{}

// excludedRunnerLabel returns a string validator for a harden_runner_excluded_labels
// entry. It rejects at plan time what the API would reject (a lone "*") or rewrite
// (blank entries and surrounding whitespace, which the API trims and drops and
// would otherwise show up as drift).
func excludedRunnerLabel() validator.String {
	return excludedRunnerLabelValidator{}
}

func (v excludedRunnerLabelValidator) Description(_ context.Context) string {
	return `a non-empty runner label without leading or trailing whitespace, other than a lone "*"`
}

func (v excludedRunnerLabelValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v excludedRunnerLabelValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	label := req.ConfigValue.ValueString()
	switch {
	case strings.TrimSpace(label) == "":
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid excluded runner label",
			"Excluded runner labels must not be empty.")
	case strings.TrimSpace(label) != label:
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid excluded runner label",
			"Excluded runner label "+`"`+label+`"`+" has leading or trailing whitespace. Remove it; the API trims labels, so the stored value would not match the configuration.")
	case label == "*":
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid excluded runner label",
			`"*" excludes every job, leaving enable_harden_runner_policy enabled but enforcing nothing. Remove the entry to target all jobs, or narrow it to the runner labels you want to skip (e.g. "custom-runner-*").`)
	}
}
