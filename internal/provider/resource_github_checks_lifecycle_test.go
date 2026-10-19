package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// fakeGithubChecksBackend stands in for GET/PUT /v1/github/{owner}/checks/config. It copies
// the API's merge rules: a PUT overwrites only the checks and repos it sends and never
// deletes any, the enable_*_for_all_new_repos flags
// change only when sent, and GET returns everything stored, disabled checks included.
type fakeGithubChecksBackend struct {
	mu     sync.Mutex
	stored stepsecurityapi.GitHubPRChecksConfig
}

func newFakeGithubChecksBackend() *fakeGithubChecksBackend {
	return &fakeGithubChecksBackend{stored: stepsecurityapi.GitHubPRChecksConfig{
		ChecksConfig: stepsecurityapi.ChecksConfig{Checks: map[string]stepsecurityapi.CheckConfig{}},
		Repos:        map[string]stepsecurityapi.CheckOptions{},
	}}
}

func (b *fakeGithubChecksBackend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !strings.HasSuffix(req.URL.Path, "/checks/config") {
		http.Error(w, "unexpected path: "+req.URL.Path, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	b.mu.Lock()
	defer b.mu.Unlock()

	switch req.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(b.stored)
	case http.MethodPut:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		var incoming stepsecurityapi.GitHubPRChecksConfig
		if err := json.Unmarshal(body, &incoming); err != nil {
			http.Error(w, "unparseable body", http.StatusBadRequest)
			return
		}
		for name, check := range incoming.Checks {
			b.stored.Checks[name] = check
		}
		if incoming.EnableBaselineCheckForAllNewRepos != nil {
			b.stored.EnableBaselineCheckForAllNewRepos = incoming.EnableBaselineCheckForAllNewRepos
		}
		if incoming.EnableRequiredChecksForAllNewRepos != nil {
			b.stored.EnableRequiredChecksForAllNewRepos = incoming.EnableRequiredChecksForAllNewRepos
		}
		if incoming.EnableOptionalChecksForAllNewRepos != nil {
			b.stored.EnableOptionalChecksForAllNewRepos = incoming.EnableOptionalChecksForAllNewRepos
		}
		b.stored.CustomDescription = incoming.CustomDescription
		for repo, opts := range incoming.Repos {
			b.stored.Repos[repo] = opts
		}
		fmt.Fprint(w, `{"message":"Checks config updated successfully"}`)
	default:
		http.Error(w, "unexpected method "+req.Method, http.StatusMethodNotAllowed)
	}
}

func (b *fakeGithubChecksBackend) check(name string) stepsecurityapi.CheckConfig {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stored.Checks[name]
}

func (b *fakeGithubChecksBackend) repo(name string) stepsecurityapi.CheckOptions {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stored.Repos[name]
}

func testAccGithubChecks(t *testing.T, backend *fakeGithubChecksBackend, providerPerStep bool, steps ...resource.TestStep) {
	t.Helper()

	tfPath := os.Getenv("TF_ACC_TERRAFORM_PATH")
	if tfPath == "" {
		found, err := exec.LookPath("terraform")
		if err != nil {
			t.Skip("terraform CLI not found in PATH; set TF_ACC_TERRAFORM_PATH to run this test")
		}
		tfPath = found
	}

	server := httptest.NewServer(backend)
	t.Cleanup(server.Close)

	t.Setenv("TF_ACC", "1")
	t.Setenv("TF_ACC_TERRAFORM_PATH", tfPath)
	t.Setenv("STEP_SECURITY_API_BASE_URL", server.URL)
	t.Setenv("STEP_SECURITY_API_KEY", "test-key")
	t.Setenv("STEP_SECURITY_CUSTOMER", "tf-acc-test")

	tc := resource.TestCase{Steps: steps}
	if !providerPerStep {
		tc.ProtoV6ProviderFactories = testAccProtoV6ProviderFactories
	}
	resource.Test(t, tc)
}

// The last release before the state-shape fix. Upgrade tests write state with it first.
var githubChecksPreviousRelease = map[string]resource.ExternalProvider{
	"stepsecurity": {Source: "registry.terraform.io/step-security/stepsecurity", VersionConstraint: "0.0.46"},
}

func githubChecksFixture(body string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_checks" "test" {
  owner = "step-terraform-tests"
%s
}
`, body)
}

const githubChecksAddress = "stepsecurity_github_checks.test"

// TestAccGithubChecksBlockShapeFollowsConfig covers the "Provider produced inconsistent
// result" errors: each check block keeps the shape it has in config, whether or not a
// control of its type exists.
func TestAccGithubChecksBlockShapeFollowsConfig(t *testing.T) {
	testCases := map[string]string{
		"optional_control_block_omitted": `
  controls = [{ control = "Script Injection", enable = true, type = "optional" }]
`,
		"required_control_block_omitted": `
  controls = [{ control = "Script Injection", enable = true, type = "required" }]
`,
		"no_control_of_type_repos_empty": `
  controls        = [{ control = "Script Injection", enable = true, type = "optional" }]
  required_checks = { repos = [] }
  baseline_check  = { repos = [] }
`,
		"omit_repos_empty": `
  controls        = [{ control = "Script Injection", enable = true, type = "required" }]
  required_checks = { repos = ["*"], omit_repos = [] }
`,
	}

	for name, body := range testCases {
		t.Run(name, func(t *testing.T) {
			testAccGithubChecks(t, newFakeGithubChecksBackend(), false,
				resource.TestStep{Config: githubChecksFixture(body)},
				resource.TestStep{
					Config:           githubChecksFixture(body),
					ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
				},
			)
		})
	}
}

// TestAccGithubChecksEmptyExemptPackages keeps an empty exempt list, which the API never
// stores, from coming back as null.
func TestAccGithubChecksEmptyExemptPackages(t *testing.T) {
	config := githubChecksFixture(`
  controls = [{
    control  = "NPM Package Cooldown"
    enable   = true
    type     = "required"
    settings = { cool_down_period = 3, packages_to_exempt_in_cooldown_check = [] }
  }]
  required_checks = { repos = ["*"] }
`)
	testAccGithubChecks(t, newFakeGithubChecksBackend(), false,
		resource.TestStep{Config: config},
		resource.TestStep{Config: config, PlanOnly: true},
	)
}

// TestAccGithubChecksRemovalsReachTheBackend: the PUT never deletes, so a control or repo
// removed from config has to be sent switched off.
func TestAccGithubChecksRemovalsReachTheBackend(t *testing.T) {
	backend := newFakeGithubChecksBackend()
	testAccGithubChecks(t, backend, false,
		resource.TestStep{Config: githubChecksFixture(`
  controls = [
    { control = "Script Injection", enable = true, type = "required" },
    { control = "NPM Package Cooldown", enable = true, type = "required" },
  ]
  required_checks = { repos = ["repo-1", "repo-2"] }
`)},
		resource.TestStep{
			Config: githubChecksFixture(`
  controls        = [{ control = "Script Injection", enable = true, type = "required" }]
  required_checks = { repos = ["repo-1"] }
`),
			Check: func(*terraform.State) error {
				if backend.check("npm_package_recent_release_guard").Enabled {
					return fmt.Errorf("removed control is still enabled in the backend")
				}
				if backend.repo("repo-2").RunRequiredChecks {
					return fmt.Errorf("removed repo still runs required checks in the backend")
				}
				return nil
			},
		},
		resource.TestStep{
			Config: githubChecksFixture(`
  controls        = [{ control = "Script Injection", enable = true, type = "required" }]
  required_checks = { repos = ["repo-1"] }
`),
			PlanOnly: true,
		},
	)
}

// TestAccGithubChecksOutOfBandControlIsDrift: a control enabled outside Terraform shows up
// in the plan and one apply disables it.
func TestAccGithubChecksOutOfBandControlIsDrift(t *testing.T) {
	backend := newFakeGithubChecksBackend()
	config := githubChecksFixture(`
  controls        = [{ control = "Script Injection", enable = true, type = "required" }]
  required_checks = { repos = ["*"] }
`)
	testAccGithubChecks(t, backend, false,
		resource.TestStep{Config: config},
		resource.TestStep{
			PreConfig: func() {
				backend.mu.Lock()
				backend.stored.Checks["pwn_request_check"] = stepsecurityapi.CheckConfig{Enabled: true, Type: "optional"}
				backend.mu.Unlock()
			},
			Config:             config,
			PlanOnly:           true,
			ExpectNonEmptyPlan: true,
		},
		resource.TestStep{
			Config: config,
			Check: func(*terraform.State) error {
				if backend.check("pwn_request_check").Enabled {
					return fmt.Errorf("out-of-band control is still enabled after apply")
				}
				return nil
			},
		},
		resource.TestStep{Config: config, PlanOnly: true},
	)
}

// TestAccGithubChecksNoSettingsPlanNoise: an unrelated change doesn't plan settings as
// "(known after apply)".
func TestAccGithubChecksNoSettingsPlanNoise(t *testing.T) {
	body := `
  controls = [
    { control = "Script Injection", enable = true, type = "required" },
    { control = "NPM Package Cooldown", enable = true, type = "required" },
  ]
  required_checks = { repos = ["*"] }
`
	testAccGithubChecks(t, newFakeGithubChecksBackend(), false,
		resource.TestStep{Config: githubChecksFixture(body)},
		resource.TestStep{
			Config: githubChecksFixture(body + `  custom_description = "changed"` + "\n"),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectKnownValue(githubChecksAddress, tfjsonpath.New("controls").AtSliceIndex(0).AtMapKey("settings"), knownvalue.Null()),
				plancheck.ExpectKnownValue(githubChecksAddress, tfjsonpath.New("controls").AtSliceIndex(1).AtMapKey("settings").AtMapKey("cool_down_period"), knownvalue.Int64Exact(2)),
			}},
		},
	)
}

// TestAccGithubChecksUpgradeFromPreviousRelease: state written by the previous release keeps
// working. Configs that release could apply give an empty plan after the upgrade.
func TestAccGithubChecksUpgradeFromPreviousRelease(t *testing.T) {
	testCases := map[string]string{
		"blocks_with_repos": `
  custom_description = "desc"
  controls = [
    { control = "Script Injection", enable = true, type = "required" },
    { control = "PWN Request", enable = true, type = "optional" },
    { control = "NPM Package Cooldown", enable = true, type = "required", settings = { cool_down_period = 5, packages_to_exempt_in_cooldown_check = ["lodash"] } },
    { control = "PyPI Package Cooldown", enable = false, type = "optional" },
  ]
  required_checks = { repos = ["repo-b", "repo-a"] }
  optional_checks = { repos = ["*"], omit_repos = ["repo-c"] }
  baseline_check  = { repos = ["repo-a"] }
`,
		"blocks_with_empty_repos": `
  controls = [
    { control = "Script Injection", enable = true, type = "required" },
    { control = "PWN Request", enable = true, type = "optional" },
  ]
  required_checks = { repos = [] }
  optional_checks = { repos = [] }
`,
	}

	for name, body := range testCases {
		t.Run(name, func(t *testing.T) {
			testAccGithubChecks(t, newFakeGithubChecksBackend(), true,
				resource.TestStep{ExternalProviders: githubChecksPreviousRelease, Config: githubChecksFixture(body)},
				resource.TestStep{
					ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
					Config:                   githubChecksFixture(body),
					ConfigPlanChecks:         resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
				},
			)
		})
	}
}

// TestAccGithubChecksUpgradeFromFailedApply: a config the previous release failed to apply
// (an optional control without optional_checks) converges after one apply with this one.
func TestAccGithubChecksUpgradeFromFailedApply(t *testing.T) {
	config := githubChecksFixture(`
  controls        = [{ control = "Script Injection", enable = true, type = "optional" }]
  required_checks = { repos = [] }
`)
	testAccGithubChecks(t, newFakeGithubChecksBackend(), true,
		resource.TestStep{
			ExternalProviders: githubChecksPreviousRelease,
			Config:            config,
			ExpectError:       regexp.MustCompile(`inconsistent result after apply`),
		},
		resource.TestStep{ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, Config: config},
		resource.TestStep{ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, Config: config, PlanOnly: true},
	)
}
