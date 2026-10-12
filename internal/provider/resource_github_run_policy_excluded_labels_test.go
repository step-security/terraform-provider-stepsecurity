package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// fakeRunPolicyBackend stands in for the run policy API. Like agent-api, PUT replaces
// the whole stored policy, so a field the request omits is cleared. Excluded labels go
// through the same normalization as validateAndNormalizeRunPolicyConfig: entries are
// trimmed, blanks dropped, and a lone "*" is rejected with a 400.
type fakeRunPolicyBackend struct {
	mu     sync.Mutex
	stored map[string]stepsecurityapi.RunPolicy
	nextID int
}

func newFakeRunPolicyBackend() *fakeRunPolicyBackend {
	return &fakeRunPolicyBackend{stored: map[string]stepsecurityapi.RunPolicy{}}
}

func (b *fakeRunPolicyBackend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Paths: /v1/github/{owner}/actions/run-policies[/{policy_id}]
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[4] != "run-policies" {
		http.Error(w, "unexpected path: "+req.URL.Path, http.StatusNotFound)
		return
	}
	owner := parts[2]
	policyID := ""
	if len(parts) == 6 {
		policyID = parts[5]
	}

	w.Header().Set("Content-Type", "application/json")

	b.mu.Lock()
	defer b.mu.Unlock()

	switch req.Method {
	case http.MethodGet:
		policy, ok := b.stored[policyID]
		if !ok {
			http.Error(w, "policy does not exist", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(policy)

	case http.MethodPost, http.MethodPut:
		var incoming stepsecurityapi.UpdateRunPolicyRequest
		if err := json.NewDecoder(req.Body).Decode(&incoming); err != nil {
			http.Error(w, "unparseable body", http.StatusBadRequest)
			return
		}
		excluded, err := normalizeFakeExcludedLabels(incoming.PolicyConfig.HardenRunnerExcludedLabels)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(err.Error())
			return
		}
		incoming.PolicyConfig.HardenRunnerExcludedLabels = excluded

		if req.Method == http.MethodPost {
			b.nextID++
			policyID = fmt.Sprintf("policy-%d", b.nextID)
		} else if _, ok := b.stored[policyID]; !ok {
			http.Error(w, "policy does not exist", http.StatusBadRequest)
			return
		}

		incoming.PolicyConfig.Owner = owner
		incoming.PolicyConfig.Name = incoming.Name
		policy := stepsecurityapi.RunPolicy{
			Owner:        owner,
			PolicyID:     policyID,
			Name:         incoming.Name,
			PolicyConfig: incoming.PolicyConfig,
			AllRepos:     incoming.AllRepos,
			AllOrgs:      incoming.AllOrgs,
			Repositories: incoming.Repositories,
		}
		b.stored[policyID] = policy
		_ = json.NewEncoder(w).Encode(policy)

	case http.MethodDelete:
		delete(b.stored, policyID)
		fmt.Fprint(w, `{}`)

	default:
		http.Error(w, "unexpected method "+req.Method, http.StatusMethodNotAllowed)
	}
}

func normalizeFakeExcludedLabels(labels []string) ([]string, error) {
	var trimmed []string
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" {
			continue
		}
		if label == "*" {
			return nil, fmt.Errorf("invalid harden_runner_excluded_labels: %q excludes every job", label)
		}
		trimmed = append(trimmed, label)
	}
	return trimmed, nil
}

// setExcludedLabels mimics an edit made outside Terraform, e.g. in the console.
func (b *fakeRunPolicyBackend) setExcludedLabels(labels []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, policy := range b.stored {
		policy.PolicyConfig.HardenRunnerExcludedLabels = labels
		b.stored[id] = policy
	}
}

func (b *fakeRunPolicyBackend) excludedLabels() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, policy := range b.stored {
		labels := append([]string(nil), policy.PolicyConfig.HardenRunnerExcludedLabels...)
		sort.Strings(labels)
		return labels
	}
	return nil
}

func testAccGithubRunPolicyAgainstFake(t *testing.T, backend *fakeRunPolicyBackend, steps ...resource.TestStep) {
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

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// githubRunPolicyExcludedLabelsFixture renders a Harden Runner policy with the given
// extra policy_config lines, so the omitted case is otherwise the same configuration.
func githubRunPolicyExcludedLabelsFixture(isDryRun bool, extra string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_run_policy" "test" {
  owner     = "step-terraform-tests"
  name      = "excluded-labels"
  all_repos = true

  policy_config = {
    owner                       = "step-terraform-tests"
    name                        = "excluded-labels"
    enable_harden_runner_policy = true
    is_dry_run                  = %t
%s
  }
}
`, isDryRun, extra)
}

func expectExcludedLabels(backend *fakeRunPolicyBackend, want ...string) func() error {
	return func() error {
		got := backend.excludedLabels()
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			return fmt.Errorf("backend harden_runner_excluded_labels = %q, want %q", got, want)
		}
		return nil
	}
}

func checkBackend(fn func() error) resource.TestCheckFunc {
	return func(_ *terraform.State) error { return fn() }
}

// TestAccGithubRunPolicyExcludedLabelsLifecycle covers setting, changing and clearing
// harden_runner_excluded_labels, and checks each step against the backend and for a
// settled plan.
func TestAccGithubRunPolicyExcludedLabelsLifecycle(t *testing.T) {
	backend := newFakeRunPolicyBackend()
	const addr = "stepsecurity_github_run_policy.test"

	testAccGithubRunPolicyAgainstFake(t, backend,
		resource.TestStep{
			Config: githubRunPolicyExcludedLabelsFixture(false, `    harden_runner_excluded_labels = ["self-hosted-gpu", "custom-runner-*"]`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckTypeSetElemAttr(addr, "policy_config.harden_runner_excluded_labels.*", "self-hosted-gpu"),
				resource.TestCheckTypeSetElemAttr(addr, "policy_config.harden_runner_excluded_labels.*", "custom-runner-*"),
				checkBackend(expectExcludedLabels(backend, "self-hosted-gpu", "custom-runner-*")),
			),
		},
		resource.TestStep{
			Config: githubRunPolicyExcludedLabelsFixture(false, `    harden_runner_excluded_labels = ["arm-*"]`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(addr, "policy_config.harden_runner_excluded_labels.#", "1"),
				checkBackend(expectExcludedLabels(backend, "arm-*")),
			),
		},
		// Omitting the attribute leaves the backend value alone, even when another
		// field changes and the full-replace PUT goes out.
		resource.TestStep{
			Config: githubRunPolicyExcludedLabelsFixture(true, ""),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckTypeSetElemAttr(addr, "policy_config.harden_runner_excluded_labels.*", "arm-*"),
				checkBackend(expectExcludedLabels(backend, "arm-*")),
			),
		},
		// [] clears the exclusions and stays [] in state even though the API omits it.
		resource.TestStep{
			Config: githubRunPolicyExcludedLabelsFixture(true, `    harden_runner_excluded_labels = []`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(addr, "policy_config.harden_runner_excluded_labels.#", "0"),
				checkBackend(expectExcludedLabels(backend)),
			),
		},
		resource.TestStep{
			Config: githubRunPolicyExcludedLabelsFixture(true, `    harden_runner_excluded_labels = []`),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		},
	)
}

// TestAccGithubRunPolicyExcludedLabelsSetOutsideTerraform is the configuration of a user
// who never set the attribute, which is also what state written by an earlier provider
// version looks like. Labels added in the console must show up in state without a diff,
// and must survive an unrelated apply rather than being wiped by the full-replace PUT.
func TestAccGithubRunPolicyExcludedLabelsSetOutsideTerraform(t *testing.T) {
	backend := newFakeRunPolicyBackend()
	const addr = "stepsecurity_github_run_policy.test"

	testAccGithubRunPolicyAgainstFake(t, backend,
		resource.TestStep{
			Config: githubRunPolicyExcludedLabelsFixture(false, ""),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckNoResourceAttr(addr, "policy_config.harden_runner_excluded_labels"),
				checkBackend(expectExcludedLabels(backend)),
			),
		},
		resource.TestStep{
			PreConfig: func() { backend.setExcludedLabels([]string{"gpu-*"}) },
			Config:    githubRunPolicyExcludedLabelsFixture(false, ""),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
			Check: resource.TestCheckTypeSetElemAttr(addr, "policy_config.harden_runner_excluded_labels.*", "gpu-*"),
		},
		resource.TestStep{
			Config: githubRunPolicyExcludedLabelsFixture(true, ""),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(addr, "policy_config.is_dry_run", "true"),
				resource.TestCheckTypeSetElemAttr(addr, "policy_config.harden_runner_excluded_labels.*", "gpu-*"),
				checkBackend(expectExcludedLabels(backend, "gpu-*")),
			),
		},
	)
}

// TestAccGithubRunPolicyExcludedLabelsRejectedAtPlan checks that values the API would
// reject or rewrite fail at plan time instead.
func TestAccGithubRunPolicyExcludedLabelsRejectedAtPlan(t *testing.T) {
	for name, tc := range map[string]struct {
		labels string
		want   string
	}{
		"lone wildcard":       {`["*"]`, `excludes every job`},
		"wildcard with peers": {`["gpu", "*"]`, `excludes every job`},
		"empty string":        {`[""]`, `must not be empty`},
		"blank":               {`["  "]`, `must not be empty`},
		"surrounding spaces":  {`[" gpu "]`, `leading or trailing whitespace`},
	} {
		t.Run(name, func(t *testing.T) {
			testAccGithubRunPolicyAgainstFake(t, newFakeRunPolicyBackend(),
				resource.TestStep{
					Config:   githubRunPolicyExcludedLabelsFixture(false, "    harden_runner_excluded_labels = "+tc.labels),
					PlanOnly: true,
					// Terraform wraps long diagnostics, so any run of whitespace may be a line break.
					ExpectError: regexp.MustCompile(`(?s)Invalid excluded runner label.*policy_config\.harden_runner_excluded_labels.*` +
						strings.ReplaceAll(tc.want, " ", `\s+`)),
				},
			)
		})
	}
}
