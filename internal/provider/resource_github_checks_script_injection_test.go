package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// ignore_for_non_public_repos on the Script Injection control works the same way as on
// PWN Request: the API stores it as pass_on_private_repos in the check's own settings,
// and the check passes findings in non-public repositories with a low-priority note.

const scriptInjectionCheck = "script_injection_check"

func scriptInjectionFixture(settings string) string {
	if settings != "" {
		settings = "\n    settings = " + settings
	}
	return githubChecksFixture(fmt.Sprintf(`
  controls = [{
    control = "Script Injection"
    enable  = true
    type    = "required"%s
  }]
  required_checks = { repos = ["*"] }
`, settings))
}

// expectStoredSetting checks the named check's stored settings hold only the setting, with
// the given value. A nil want means no settings are stored.
func expectStoredSetting(backend *fakeGithubChecksBackend, check string, want *bool) func(*terraform.State) error {
	return func(*terraform.State) error {
		settings := backend.check(check).Settings
		if want == nil {
			if settings != nil {
				return fmt.Errorf("%s stored settings = %v, want none", check, settings)
			}
			return nil
		}
		if got, ok := settings[passOnPrivateReposSetting]; !ok || got != *want || len(settings) != 1 {
			return fmt.Errorf("%s stored settings = %v, want only %s = %t", check, settings, passOnPrivateReposSetting, *want)
		}
		return nil
	}
}

// TestAccGithubChecksScriptInjectionIgnoreForNonPublicRepos walks the setting through on,
// off, removed and an empty settings block, checking what reaches the backend and that
// every step plans clean afterwards.
func TestAccGithubChecksScriptInjectionIgnoreForNonPublicRepos(t *testing.T) {
	backend := newFakeGithubChecksBackend()
	empty := tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}
	on, off := true, false

	steps := []tfresource.TestStep{}
	for _, s := range []struct {
		settings string
		want     *bool
	}{
		{`{ ignore_for_non_public_repos = true }`, &on},
		{`{ ignore_for_non_public_repos = false }`, &off},
		// Removing the block clears the stored value: the API replaces a check's config whole.
		{``, nil},
		{`{ ignore_for_non_public_repos = true }`, &on},
		// An empty block means "not set", the same as leaving it out.
		{`{}`, nil},
	} {
		config := scriptInjectionFixture(s.settings)
		steps = append(steps,
			tfresource.TestStep{Config: config, Check: expectStoredSetting(backend, scriptInjectionCheck, s.want)},
			tfresource.TestStep{Config: config, ConfigPlanChecks: empty},
		)
	}
	testAccGithubChecks(t, backend, false, steps...)
}

// TestAccGithubChecksScriptInjectionImport imports an org whose Script Injection has the
// setting on.
func TestAccGithubChecksScriptInjectionImport(t *testing.T) {
	backend := newFakeGithubChecksBackend()
	backend.stored.Checks[scriptInjectionCheck] = stepsecurityapi.CheckConfig{
		Enabled:  true,
		Type:     "required",
		Settings: map[string]any{passOnPrivateReposSetting: true},
	}
	enabled := true
	backend.stored.EnableRequiredChecksForAllNewRepos = &enabled

	config := scriptInjectionFixture(`{ ignore_for_non_public_repos = true }`)
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

// TestAccGithubChecksNonPublicReposSettingIsPerControl: the setting on PWN Request and on
// Script Injection are stored separately, so turning one on leaves the other as it is.
func TestAccGithubChecksNonPublicReposSettingIsPerControl(t *testing.T) {
	backend := newFakeGithubChecksBackend()
	on := true
	config := githubChecksFixture(`
  controls = [
    {
      control  = "PWN Request"
      enable   = true
      type     = "required"
      settings = { ignore_for_non_public_repos = true }
    },
    {
      control = "Script Injection"
      enable  = true
      type    = "required"
    },
  ]
  required_checks = { repos = ["*"] }
`)
	testAccGithubChecks(t, backend, false,
		tfresource.TestStep{
			Config: config,
			Check: func(s *terraform.State) error {
				if err := expectStoredSetting(backend, pwnRequestCheck, &on)(s); err != nil {
					return err
				}
				return expectStoredSetting(backend, scriptInjectionCheck, nil)(s)
			},
		},
		tfresource.TestStep{Config: config, PlanOnly: true},
	)
}

// TestAccGithubChecksScriptInjectionSettingsValidation rejects cooldown fields on Script
// Injection at plan time, as on PWN Request.
func TestAccGithubChecksScriptInjectionSettingsValidation(t *testing.T) {
	testAccGithubChecks(t, newFakeGithubChecksBackend(), false,
		tfresource.TestStep{
			Config: githubChecksFixture(`
  controls = [{
    control  = "Script Injection"
    enable   = true
    type     = "required"
    settings = { ignore_for_non_public_repos = true, cool_down_period = 3 }
  }]
`),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(regexp.QuoteMeta("can't provide cooldown settings")),
		},
	)
}

func TestGithubChecksResource_ScriptInjectionSettingsRoundTrip(t *testing.T) {
	t.Parallel()

	pass := true
	r := &githubChecksResource{}
	req, err := r.convertToCreateRequest(context.Background(), githubChecksModel{
		Owner: types.StringValue(testOwner),
		Controls: mustControlsList([]control{{
			Control:  types.StringValue(scriptInjectionControl),
			Enable:   types.BoolValue(true),
			Type:     types.StringValue("required"),
			Settings: createPwnSettingsObject(&pass),
		}}),
		RequiredChecks: types.ObjectNull(checksConfigAttrTypes()),
		OptionalChecks: types.ObjectNull(checksConfigAttrTypes()),
		BaselineCheck:  types.ObjectNull(checksConfigAttrTypes()),
	})
	if err != nil {
		t.Fatalf("convertToCreateRequest: %v", err)
	}
	if got := req.Checks[scriptInjectionCheck].Settings[passOnPrivateReposSetting]; got != true {
		t.Errorf("sent settings = %v, want %s = true", req.Checks[scriptInjectionCheck].Settings, passOnPrivateReposSetting)
	}

	state := r.convertToState(context.Background(), testOwner, *req)
	controls := controlsListToSlice(state.Controls)
	if len(controls) != 1 || !controls[0].Settings.Equal(createPwnSettingsObject(&pass)) {
		t.Errorf("state settings = %v, want ignore_for_non_public_repos = true", controls)
	}
}
