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

// ignore_for_non_public_repos is the PWN Request control's only setting. The API stores it in
// the check's settings under its original key, pass_on_private_repos, and the check reads it
// to pass findings in non-public (private and internal) repositories with a low-priority note
// instead of failing.

const pwnRequestCheck = "pwn_request_check"

func pwnRequestFixture(settings string) string {
	if settings != "" {
		settings = "\n    settings = " + settings
	}
	return githubChecksFixture(fmt.Sprintf(`
  controls = [{
    control = "PWN Request"
    enable  = true
    type    = "required"%s
  }]
  required_checks = { repos = ["*"] }
`, settings))
}

// storedPassOnPrivateRepos returns the stored setting, and whether the check has any
// settings stored at all.
func storedPassOnPrivateRepos(backend *fakeGithubChecksBackend) (any, bool) {
	settings := backend.check(pwnRequestCheck).Settings
	if settings == nil {
		return nil, false
	}
	return settings[passOnPrivateReposSetting], true
}

func expectStoredPassOnPrivateRepos(backend *fakeGithubChecksBackend, want bool) func(*terraform.State) error {
	return func(*terraform.State) error {
		got, ok := storedPassOnPrivateRepos(backend)
		if !ok || got != want {
			return fmt.Errorf("stored settings = %v, want %s = %t", backend.check(pwnRequestCheck).Settings, passOnPrivateReposSetting, want)
		}
		if len(backend.check(pwnRequestCheck).Settings) != 1 {
			return fmt.Errorf("stored settings = %v, want only %s", backend.check(pwnRequestCheck).Settings, passOnPrivateReposSetting)
		}
		return nil
	}
}

func expectNoStoredSettings(backend *fakeGithubChecksBackend) func(*terraform.State) error {
	return func(*terraform.State) error {
		if settings := backend.check(pwnRequestCheck).Settings; settings != nil {
			return fmt.Errorf("stored settings = %v, want none", settings)
		}
		return nil
	}
}

// TestAccGithubChecksPwnRequestIgnoreForNonPublicRepos walks the setting through on, off,
// removed and an empty settings block, checking what reaches the backend and that every
// step plans clean afterwards.
func TestAccGithubChecksPwnRequestIgnoreForNonPublicRepos(t *testing.T) {
	backend := newFakeGithubChecksBackend()
	empty := tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}

	steps := []tfresource.TestStep{}
	for _, s := range []struct {
		settings string
		check    func(*terraform.State) error
	}{
		{`{ ignore_for_non_public_repos = true }`, expectStoredPassOnPrivateRepos(backend, true)},
		{`{ ignore_for_non_public_repos = false }`, expectStoredPassOnPrivateRepos(backend, false)},
		// Removing the block clears the stored value: the API replaces a check's config whole.
		{``, expectNoStoredSettings(backend)},
		{`{ ignore_for_non_public_repos = true }`, expectStoredPassOnPrivateRepos(backend, true)},
		// An empty block means "not set", the same as leaving it out.
		{`{}`, expectNoStoredSettings(backend)},
	} {
		config := pwnRequestFixture(s.settings)
		steps = append(steps,
			tfresource.TestStep{Config: config, Check: s.check},
			tfresource.TestStep{Config: config, ConfigPlanChecks: empty},
		)
	}
	testAccGithubChecks(t, backend, false, steps...)
}

// TestAccGithubChecksPwnRequestImport imports an org whose PWN Request has the setting on.
func TestAccGithubChecksPwnRequestImport(t *testing.T) {
	backend := newFakeGithubChecksBackend()
	backend.stored.Checks[pwnRequestCheck] = stepsecurityapi.CheckConfig{
		Enabled:  true,
		Type:     "required",
		Settings: map[string]any{passOnPrivateReposSetting: true},
	}
	enabled := true
	backend.stored.EnableRequiredChecksForAllNewRepos = &enabled

	config := pwnRequestFixture(`{ ignore_for_non_public_repos = true }`)
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

// TestAccGithubChecksPwnRequestOutOfBandSettingIsDrift: turning the setting on outside
// Terraform shows in the plan, and one apply clears it again.
func TestAccGithubChecksPwnRequestOutOfBandSettingIsDrift(t *testing.T) {
	backend := newFakeGithubChecksBackend()
	config := pwnRequestFixture("")
	testAccGithubChecks(t, backend, false,
		tfresource.TestStep{Config: config},
		tfresource.TestStep{
			PreConfig: func() {
				backend.mu.Lock()
				check := backend.stored.Checks[pwnRequestCheck]
				check.Settings = map[string]any{passOnPrivateReposSetting: true}
				backend.stored.Checks[pwnRequestCheck] = check
				backend.mu.Unlock()
			},
			Config:             config,
			PlanOnly:           true,
			ExpectNonEmptyPlan: true,
		},
		tfresource.TestStep{Config: config, Check: expectNoStoredSettings(backend)},
		tfresource.TestStep{Config: config, PlanOnly: true},
	)
}

// TestAccGithubChecksPwnRequestSettingsValidation rejects settings on the wrong control at
// plan time.
func TestAccGithubChecksPwnRequestSettingsValidation(t *testing.T) {
	testCases := map[string]struct {
		body string
		want string
	}{
		"cooldown_period_on_pwn_request": {
			body: `
  controls = [{
    control  = "PWN Request"
    enable   = true
    type     = "required"
    settings = { ignore_for_non_public_repos = true, cool_down_period = 3 }
  }]
`,
			want: `can't provide cooldown settings`,
		},
		"ignore_for_non_public_repos_on_cooldown_control": {
			body: `
  controls = [{
    control  = "NPM Package Cooldown"
    enable   = true
    type     = "required"
    settings = { ignore_for_non_public_repos = true }
  }]
`,
			want: `can't provide ignore_for_non_public_repos`,
		},
		"ignore_for_non_public_repos_on_other_control": {
			body: `
  controls = [{
    control  = "NPM Package Compromised Updates"
    enable   = true
    type     = "required"
    settings = { ignore_for_non_public_repos = true }
  }]
`,
			want: `can't provide settings`,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			testAccGithubChecks(t, newFakeGithubChecksBackend(), false,
				tfresource.TestStep{
					Config:      githubChecksFixture(tc.body),
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(regexp.QuoteMeta(tc.want)),
				},
			)
		})
	}
}

func TestGithubChecksResource_ConvertToCreateRequest_PwnRequestSettings(t *testing.T) {
	t.Parallel()

	pass, fail := true, false
	testCases := []struct {
		name     string
		settings types.Object
		want     map[string]any
	}{
		{"setting_on", createPwnSettingsObject(&pass), map[string]any{passOnPrivateReposSetting: true}},
		{"setting_off_is_sent", createPwnSettingsObject(&fail), map[string]any{passOnPrivateReposSetting: false}},
		{"empty_block_sends_nothing", createPwnSettingsObject(nil), nil},
		{"no_block_sends_nothing", createNullSettingsObject(), nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			req, err := r.convertToCreateRequest(context.Background(), githubChecksModel{
				Owner: types.StringValue(testOwner),
				Controls: mustControlsList([]control{{
					Control:  types.StringValue(pwnRequestControl),
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
			got := req.Checks[pwnRequestCheck].Settings
			if fmt.Sprint(got) != fmt.Sprint(tc.want) || (got == nil) != (tc.want == nil) {
				t.Errorf("settings = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestGithubChecksResource_ConvertToState_PwnRequestSettings(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		settings map[string]any
		want     types.Object
	}{
		{"bool_true", map[string]any{passOnPrivateReposSetting: true}, createPwnSettingsObject(ptr(true))},
		{"bool_false", map[string]any{passOnPrivateReposSetting: false}, createPwnSettingsObject(ptr(false))},
		{"string_true", map[string]any{passOnPrivateReposSetting: "true"}, createPwnSettingsObject(ptr(true))},
		{"not_stored", nil, createNullSettingsObject()},
		{"other_keys_only", map[string]any{"cooldown_period_in_days": 2}, createNullSettingsObject()},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubChecksResource{}
			state := r.convertToState(context.Background(), testOwner, stepsecurityapi.GitHubPRChecksConfig{
				ChecksConfig: stepsecurityapi.ChecksConfig{Checks: map[string]stepsecurityapi.CheckConfig{
					pwnRequestCheck: {Enabled: true, Type: "required", Settings: tc.settings},
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

func TestGithubChecksResource_ValidateConfig_PwnRequestSettings(t *testing.T) {
	t.Parallel()

	pass := true
	testCases := []struct {
		name    string
		control string
		setting types.Object
		wantErr string
	}{
		{"pwn_request_with_setting", pwnRequestControl, createPwnSettingsObject(&pass), ""},
		{"pwn_request_with_empty_block", pwnRequestControl, createPwnSettingsObject(nil), ""},
		{"pwn_request_with_cooldown", pwnRequestControl, createSettingsObject(ptr(int64(3)), nil), "can't provide cooldown settings"},
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

func ptr[T any](v T) *T { return &v }
