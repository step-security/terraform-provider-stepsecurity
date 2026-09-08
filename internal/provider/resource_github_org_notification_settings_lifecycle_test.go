package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// fakeGithubNotificationSettingsBackend stands in for the org notification
// settings API. The real handler builds a DynamoDB update expression that sets
// only the fields a request sends non-empty, so an omitted field keeps its
// stored value — which is what makes an omitted threat_intel block mean "leave
// the organization's setting alone". This fake reproduces exactly that rule.
type fakeGithubNotificationSettingsBackend struct {
	mu     sync.Mutex
	stored map[string]any
	writes int
}

func newFakeGithubNotificationSettingsBackend(seed map[string]any) *fakeGithubNotificationSettingsBackend {
	stored := map[string]any{}
	for key, value := range seed {
		stored[key] = value
	}
	return &fakeGithubNotificationSettingsBackend{stored: stored}
}

func (b *fakeGithubNotificationSettingsBackend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Path: /v1/github/{owner}/actions/runs/notification-settings
	if !strings.HasSuffix(req.URL.Path, "/actions/runs/notification-settings") {
		http.Error(w, "unexpected path: "+req.URL.Path, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	b.mu.Lock()
	defer b.mu.Unlock()

	switch req.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(b.stored)

	case http.MethodPost:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		var incoming map[string]any
		if err := json.Unmarshal(body, &incoming); err != nil {
			http.Error(w, "unparseable body", http.StatusBadRequest)
			return
		}

		b.writes++
		for key, value := range incoming {
			if text, ok := value.(string); ok && text == "" {
				continue
			}
			b.stored[key] = value
		}

		fmt.Fprint(w, `{}`)

	default:
		http.Error(w, "unexpected method "+req.Method, http.StatusMethodNotAllowed)
	}
}

func (b *fakeGithubNotificationSettingsBackend) storedString(key string) string {
	b.mu.Lock()
	defer b.mu.Unlock()

	text, _ := b.stored[key].(string)
	return text
}

func testAccGithubOrgNotificationSettings(t *testing.T, backend *fakeGithubNotificationSettingsBackend, steps ...resource.TestStep) {
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

// githubOrgNotificationSettingsFixture renders the resource with an optional
// threat_intel block, so the omitted case exercises the same configuration
// otherwise.
func githubOrgNotificationSettingsFixture(threatIntel string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_org_notification_settings" "test" {
  owner = "step-terraform-tests"

  notification_channels = {
    email = "security@example.com"
  }

  notification_events = {
    domain_blocked          = true
    new_endpoint_discovered = true
  }
%s
}
`, threatIntel)
}

// TestAccGithubOrgNotificationSettingsThreatIntel writes a granularity and checks
// both what reaches the API and that the plan settles.
func TestAccGithubOrgNotificationSettingsThreatIntel(t *testing.T) {
	backend := newFakeGithubNotificationSettingsBackend(nil)

	testAccGithubOrgNotificationSettings(t, backend, resource.TestStep{
		Config: githubOrgNotificationSettingsFixture(`
  threat_intel = {
    enabled = true
    level   = "name"
  }
`),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "threat_intel.enabled", "true"),
			resource.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "threat_intel.level", "name"),
			func(*terraform.State) error {
				if got := backend.storedString("orgThreatIntelLevel"); got != "name" {
					return fmt.Errorf("orgThreatIntelLevel = %q, want %q", got, "name")
				}
				// The per-source flags predate the level and are mirrored from the
				// same on/off, so backend paths that still read them agree.
				for _, key := range []string{
					"notifyForCompromisedNPMInPR",
					"notifyForCompromisedPyPIInPR",
					"notifyForCompromisedActionInWorkflow",
				} {
					if got := backend.storedString(key); got != "true" {
						return fmt.Errorf("%s = %q, want %q", key, got, "true")
					}
				}
				return nil
			},
		),
	})
}

// TestAccGithubOrgNotificationSettingsThreatIntelDisabled pins the opt-out
// behaviour: disabling has to write the explicit "off", because an empty level
// reads back as notifying about everything. The configured level also has to
// survive, since a disabled org has no stored granularity.
func TestAccGithubOrgNotificationSettingsThreatIntelDisabled(t *testing.T) {
	backend := newFakeGithubNotificationSettingsBackend(nil)

	testAccGithubOrgNotificationSettings(t, backend, resource.TestStep{
		Config: githubOrgNotificationSettingsFixture(`
  threat_intel = {
    enabled = false
    level   = "version"
  }
`),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "threat_intel.enabled", "false"),
			resource.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "threat_intel.level", "version"),
			func(*terraform.State) error {
				if got := backend.storedString("orgThreatIntelLevel"); got != "off" {
					return fmt.Errorf("orgThreatIntelLevel = %q, want %q", got, "off")
				}
				if got := backend.storedString("notifyForCompromisedNPMInPR"); got != "false" {
					return fmt.Errorf("notifyForCompromisedNPMInPR = %q, want %q", got, "false")
				}
				return nil
			},
		),
	})
}

// TestAccGithubOrgNotificationSettingsThreatIntelOmittedAdopts covers the
// existing configurations that predate this attribute: omitting the block must
// leave the organization's setting untouched and adopt it into state, not
// overwrite it.
func TestAccGithubOrgNotificationSettingsThreatIntelOmittedAdopts(t *testing.T) {
	backend := newFakeGithubNotificationSettingsBackend(map[string]any{
		"orgThreatIntelLevel":         "version",
		"notifyForCompromisedNPMInPR": "true",
	})

	testAccGithubOrgNotificationSettings(t, backend, resource.TestStep{
		Config: githubOrgNotificationSettingsFixture(""),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "threat_intel.enabled", "true"),
			resource.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "threat_intel.level", "version"),
			func(*terraform.State) error {
				if got := backend.storedString("orgThreatIntelLevel"); got != "version" {
					return fmt.Errorf("orgThreatIntelLevel = %q, want it left at %q", got, "version")
				}
				return nil
			},
		),
	})
}

// TestAccGithubOrgNotificationSettingsThreatIntelOmittedDefaultsOptOut checks the
// same omitted case against an organization that never configured threat intel:
// the backend notifies about everything, and state has to say so.
func TestAccGithubOrgNotificationSettingsThreatIntelOmittedDefaultsOptOut(t *testing.T) {
	backend := newFakeGithubNotificationSettingsBackend(nil)

	testAccGithubOrgNotificationSettings(t, backend, resource.TestStep{
		Config: githubOrgNotificationSettingsFixture(""),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "threat_intel.enabled", "true"),
			resource.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "threat_intel.level", "all"),
			func(*terraform.State) error {
				if got := backend.storedString("orgThreatIntelLevel"); got != "" {
					return fmt.Errorf("orgThreatIntelLevel = %q, want it left unset", got)
				}
				return nil
			},
		),
	})
}

// TestAccGithubOrgNotificationSettingsThreatIntelUpdate changes the granularity
// and then turns it off.
func TestAccGithubOrgNotificationSettingsThreatIntelUpdate(t *testing.T) {
	backend := newFakeGithubNotificationSettingsBackend(nil)

	testAccGithubOrgNotificationSettings(t, backend,
		resource.TestStep{
			Config: githubOrgNotificationSettingsFixture(`
  threat_intel = {
    enabled = true
    level   = "all"
  }
`),
		},
		resource.TestStep{
			Config: githubOrgNotificationSettingsFixture(`
  threat_intel = {
    enabled = true
    level   = "version"
  }
`),
			Check: resource.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "threat_intel.level", "version"),
		},
		resource.TestStep{
			Config: githubOrgNotificationSettingsFixture(`
  threat_intel = {
    enabled = false
  }
`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("stepsecurity_github_org_notification_settings.test", "threat_intel.enabled", "false"),
				func(*terraform.State) error {
					if got := backend.storedString("orgThreatIntelLevel"); got != "off" {
						return fmt.Errorf("orgThreatIntelLevel = %q, want %q", got, "off")
					}
					return nil
				},
			),
		},
	)
}
