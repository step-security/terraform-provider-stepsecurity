package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// The GitHub Action Cooldown control takes cool_down_period like the package cooldown
// controls, and its exemptions as actions_to_exempt_in_cooldown_check, which the API stores
// under exempted_actions.

const actionCooldownCheck = "github_action_recent_release_guard"

func actionCooldownFixture(settings string) string {
	if settings != "" {
		settings = "\n    settings = " + settings
	}
	return githubChecksFixture(fmt.Sprintf(`
  controls = [{
    control = "GitHub Action Cooldown"
    enable  = true
    type    = "required"%s
  }]
  required_checks = { repos = ["*"] }
`, settings))
}

// expectStoredActionCooldown checks the stored settings are exactly the cooldown period and,
// when actions is non-nil, the exempted actions.
func expectStoredActionCooldown(backend *fakeGithubChecksBackend, period int, actions []string) func(*terraform.State) error {
	return func(*terraform.State) error {
		settings := backend.check(actionCooldownCheck).Settings
		want := map[string]any{"cooldown_period_in_days": period}
		if actions != nil {
			want[exemptedActionsSetting] = actions
		}
		if fmt.Sprint(settings) != fmt.Sprint(want) {
			return fmt.Errorf("stored settings = %v, want %v", settings, want)
		}
		return nil
	}
}

func TestAvailableControlsIncludesActionCooldown(t *testing.T) {
	if got := stepsecurityapi.AvailableControls[actionCooldownControl]; got != actionCooldownCheck {
		t.Fatalf("AvailableControls[%q] = %q, want %q", actionCooldownControl, got, actionCooldownCheck)
	}
	if got := stepsecurityapi.GetControlName(actionCooldownCheck); got != actionCooldownControl {
		t.Fatalf("GetControlName(%q) = %q, want %q", actionCooldownCheck, got, actionCooldownControl)
	}
	if !isCooldownControl(actionCooldownControl) {
		t.Fatal("the GitHub Action Cooldown control takes cooldown settings")
	}
}

// TestAccGithubChecksActionCooldownSettings walks the settings through set, changed, removed
// and an empty exemption list, checking what reaches the backend and that every step plans
// clean afterwards.
func TestAccGithubChecksActionCooldownSettings(t *testing.T) {
	backend := newFakeGithubChecksBackend()
	empty := tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}

	steps := []tfresource.TestStep{}
	for _, s := range []struct {
		settings string
		check    func(*terraform.State) error
	}{
		{`{ cool_down_period = 7, actions_to_exempt_in_cooldown_check = ["example-org/*", "example-org/example-action@v1"] }`,
			expectStoredActionCooldown(backend, 7, []string{"example-org/*", "example-org/example-action@v1"})},
		{`{ cool_down_period = 3, actions_to_exempt_in_cooldown_check = ["example-org/example-action"] }`,
			expectStoredActionCooldown(backend, 3, []string{"example-org/example-action"})},
		// Removing the block keeps the default period and clears the exemptions.
		{``, expectStoredActionCooldown(backend, 2, nil)},
		// An empty list is not sent, and plans clean against the API's missing key.
		{`{ cool_down_period = 5, actions_to_exempt_in_cooldown_check = [] }`, expectStoredActionCooldown(backend, 5, nil)},
	} {
		config := actionCooldownFixture(s.settings)
		steps = append(steps,
			tfresource.TestStep{Config: config, Check: s.check},
			tfresource.TestStep{Config: config, ConfigPlanChecks: empty},
		)
	}
	testAccGithubChecks(t, backend, false, steps...)
}

// TestAccGithubChecksActionCooldownImport imports an org whose GitHub Action Cooldown has
// exemptions stored.
func TestAccGithubChecksActionCooldownImport(t *testing.T) {
	backend := newFakeGithubChecksBackend()
	backend.stored.Checks[actionCooldownCheck] = stepsecurityapi.CheckConfig{
		Enabled: true,
		Type:    "required",
		Settings: map[string]any{
			"cooldown_period_in_days": float64(4),
			exemptedActionsSetting:    []any{"example-org/*"},
		},
	}
	enabled := true
	backend.stored.EnableRequiredChecksForAllNewRepos = &enabled

	config := actionCooldownFixture(`{ cool_down_period = 4, actions_to_exempt_in_cooldown_check = ["example-org/*"] }`)
	testAccGithubChecks(t, backend, false,
		tfresource.TestStep{
			Config:             config,
			ResourceName:       githubChecksAddress,
			ImportState:        true,
			ImportStateId:      "step-terraform-tests",
			ImportStatePersist: true,
		},
		tfresource.TestStep{Config: config, PlanOnly: true},
	)
}

// TestAccGithubChecksActionCooldownSettingsValidation rejects settings on the wrong control
// at plan time.
func TestAccGithubChecksActionCooldownSettingsValidation(t *testing.T) {
	testCases := map[string]struct {
		control  string
		settings string
		want     string
	}{
		"packages_on_action_cooldown": {
			control:  "GitHub Action Cooldown",
			settings: `{ packages_to_exempt_in_cooldown_check = ["lodash"] }`,
			want:     `can't provide packages_to_exempt_in_cooldown_check`,
		},
		"actions_on_package_cooldown": {
			control:  "NPM Package Cooldown",
			settings: `{ actions_to_exempt_in_cooldown_check = ["example-org/*"] }`,
			want:     `can't provide actions_to_exempt_in_cooldown_check`,
		},
		"actions_on_pwn_request": {
			control:  "PWN Request",
			settings: `{ actions_to_exempt_in_cooldown_check = ["example-org/*"] }`,
			want:     `can't provide cooldown settings`,
		},
		"actions_on_other_control": {
			control:  "Script Injection",
			settings: `{ actions_to_exempt_in_cooldown_check = ["example-org/*"] }`,
			want:     `can't provide settings`,
		},
		"period_out_of_range": {
			control:  "GitHub Action Cooldown",
			settings: `{ cool_down_period = 45 }`,
			want:     `cool_down_period should be between 1 and 30`,
		},
		"ignore_for_non_public_repos_on_action_cooldown": {
			control:  "GitHub Action Cooldown",
			settings: `{ ignore_for_non_public_repos = true }`,
			want:     `can't provide ignore_for_non_public_repos`,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			body := fmt.Sprintf(`
  controls = [{
    control  = %q
    enable   = true
    type     = "required"
    settings = %s
  }]
`, tc.control, tc.settings)
			testAccGithubChecks(t, newFakeGithubChecksBackend(), false,
				tfresource.TestStep{
					Config:      githubChecksFixture(body),
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(regexp.QuoteMeta(tc.want)),
				},
			)
		})
	}
}

func TestGithubChecksResource_ConvertToCreateRequest_ActionCooldownSettings(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		settings types.Object
		want     map[string]any
	}{
		{"period_and_actions", createActionCooldownSettingsObject(ptr(int64(7)), []string{"example-org/*"}),
			map[string]any{"cooldown_period_in_days": int64(7), exemptedActionsSetting: []string{"example-org/*"}}},
		{"empty_actions_not_sent", createActionCooldownSettingsObject(ptr(int64(3)), []string{}),
			map[string]any{"cooldown_period_in_days": int64(3)}},
		{"no_block_sends_default_period", createNullSettingsObject(),
			map[string]any{"cooldown_period_in_days": int64(2)}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			req, err := r.convertToCreateRequest(context.Background(), githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{{
					Control:  types.StringValue(actionCooldownControl),
					Enable:   types.BoolValue(true),
					Type:     types.StringValue("required"),
					Settings: tc.settings,
				}}),
				RequiredChecks: types.ObjectNull(checksConfigAttrTypes()),
				OptionalChecks: types.ObjectNull(checksConfigAttrTypes()),
				BaselineCheck:  types.ObjectNull(checksConfigAttrTypes()),
			})
			if err != nil {
				t.Fatalf("convertToCreateRequest: %v", err)
			}
			got := req.Checks[actionCooldownCheck].Settings
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("settings = %#v, want %#v", got, tc.want)
			}
			if _, ok := got["exempted_packages"]; ok {
				t.Error("the GitHub Action Cooldown control must not send exempted_packages")
			}
		})
	}
}

func TestGithubChecksResource_ConvertToState_ActionCooldownSettings(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		settings map[string]any
		want     types.Object
	}{
		{"period_and_actions", map[string]any{"cooldown_period_in_days": float64(7), exemptedActionsSetting: []any{"example-org/*"}},
			createActionCooldownSettingsObject(ptr(int64(7)), []string{"example-org/*"})},
		{"period_only", map[string]any{"cooldown_period_in_days": float64(5)},
			createActionCooldownSettingsObject(ptr(int64(5)), nil)},
		// exempted_packages belongs to the package cooldown controls and is not read here
		{"packages_key_ignored", map[string]any{"cooldown_period_in_days": float64(5), "exempted_packages": []any{"lodash"}},
			createActionCooldownSettingsObject(ptr(int64(5)), nil)},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			state := r.convertToState(context.Background(), testOwner, stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{Checks: map[string]stepsecurityapi.CheckConfig{
					actionCooldownCheck: {Enabled: true, Type: "required", Settings: tc.settings},
				}},
			})
			controls := controlsListToSlice(state.Controls)
			if len(controls) != 1 {
				t.Fatalf("got %d controls, want 1", len(controls))
			}
			if !controls[0].Settings.Equal(tc.want) {
				t.Errorf("settings = %v, want %v", controls[0].Settings, tc.want)
			}
		})
	}
}

func TestGithubChecksResource_ValidateConfig_ActionCooldownSettings(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		control string
		setting types.Object
		wantErr string
	}{
		{"action_cooldown_with_actions", actionCooldownControl, createActionCooldownSettingsObject(ptr(int64(5)), []string{"example-org/*"}), ""},
		{"action_cooldown_with_packages", actionCooldownControl, createSettingsObject(ptr(int64(5)), []string{"lodash"}), "can't provide packages_to_exempt_in_cooldown_check"},
		{"package_cooldown_with_actions", "NuGet Package Cooldown", createActionCooldownSettingsObject(ptr(int64(5)), []string{"example-org/*"}), "can't provide actions_to_exempt_in_cooldown_check"},
		{"pwn_request_with_actions", pwnRequestControl, createActionCooldownSettingsObject(nil, []string{"example-org/*"}), "can't provide cooldown settings"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			r := &githubChecksResource{}
			resp := &resource.ValidateConfigResponse{}
			r.ValidateConfig(ctx, mustValidateConfigRequest(t, ctx, r, githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{{
					Control:  types.StringValue(tc.control),
					Enable:   types.BoolValue(true),
					Type:     types.StringValue("required"),
					Settings: tc.setting,
				}}),
			}), resp)

			if tc.wantErr == "" {
				if resp.Diagnostics.HasError() {
					t.Errorf("unexpected error: %v", resp.Diagnostics)
				}
				return
			}
			if !regexp.MustCompile(regexp.QuoteMeta(tc.wantErr)).MatchString(fmt.Sprint(resp.Diagnostics)) {
				t.Errorf("diagnostics = %v, want an error containing %q", resp.Diagnostics, tc.wantErr)
			}
		})
	}
}
