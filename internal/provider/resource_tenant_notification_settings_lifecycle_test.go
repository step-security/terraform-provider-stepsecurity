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

// fakeTenantNotificationsBackend stands in for the tenant notification settings
// API, reproducing the three behaviours of the real handler that the resource has
// to work around:
//
//   - the shared channels are assigned from the request on every write, whatever
//     the source, so an omitted channel is a cleared channel;
//   - slack_notification_method and slack_channel_id are only assigned when
//     non-empty, so they can be set but never cleared;
//   - source=tenant owns the threat intel and Developer MDM options and nothing
//     else, so the ADO options must survive a write.
//
// A non-empty plan after a clean apply against this backend is a provider-side
// round-trip defect.
type fakeTenantNotificationsBackend struct {
	mu     sync.Mutex
	stored fakeTenantNotificationRecord
	writes int
}

type fakeTenantNotificationRecord struct {
	Customer                string          `json:"customer"`
	Email                   string          `json:"email"`
	SlackWebhookURL         string          `json:"slack_webhook_url"`
	TeamsWebhookURL         string          `json:"teams_webhook_url"`
	SlackNotificationMethod string          `json:"slack_notification_method"`
	SlackChannelID          string          `json:"slack_channel_id"`
	ThreatIntel             json.RawMessage `json:"threat_intel_notification_options,omitempty"`
	DeveloperMDM            json.RawMessage `json:"developer_mdm_notification_options,omitempty"`
	ADO                     json.RawMessage `json:"ado_notification_options,omitempty"`
}

func (b *fakeTenantNotificationsBackend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Path: /v1/application/customers/{customer}/notifications
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[4] != "notifications" {
		http.Error(w, "unexpected path: "+req.URL.Path, http.StatusNotFound)
		return
	}
	customer := parts[3]

	w.Header().Set("Content-Type", "application/json")

	b.mu.Lock()
	defer b.mu.Unlock()

	switch req.Method {
	case http.MethodGet:
		// The real handler answers 200 with a zero record for a tenant that has
		// never saved settings; it never 404s.
		_ = json.NewEncoder(w).Encode(b.stored)

	case http.MethodPut:
		source := req.URL.Query().Get("source")
		switch source {
		case "ado", "gitlab", "threat_intel", "tenant":
		default:
			http.Error(w, `{"message":"a 'source' query parameter with value is required"}`, http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		var incoming fakeTenantNotificationRecord
		if err := json.Unmarshal(body, &incoming); err != nil {
			http.Error(w, "unparseable body", http.StatusBadRequest)
			return
		}

		b.writes++
		b.stored.Customer = customer
		b.stored.Email = incoming.Email
		b.stored.SlackWebhookURL = incoming.SlackWebhookURL
		b.stored.TeamsWebhookURL = incoming.TeamsWebhookURL
		if incoming.SlackNotificationMethod != "" {
			b.stored.SlackNotificationMethod = incoming.SlackNotificationMethod
		}
		if incoming.SlackChannelID != "" {
			b.stored.SlackChannelID = incoming.SlackChannelID
		}
		if source == "tenant" || source == "threat_intel" {
			b.stored.ThreatIntel = incoming.ThreatIntel
		}
		if source == "tenant" {
			b.stored.DeveloperMDM = incoming.DeveloperMDM
		}

		fmt.Fprint(w, `{"message":"Notification settings updated successfully"}`)

	default:
		http.Error(w, "unexpected method "+req.Method, http.StatusMethodNotAllowed)
	}
}

func testAccTenantNotificationSettings(t *testing.T, backend *fakeTenantNotificationsBackend, steps ...resource.TestStep) {
	t.Helper()

	// Resolve a Terraform CLI before enabling acceptance mode and pin it, so the
	// harness never falls back to downloading one. These tests are otherwise
	// hermetic — the backend is an httptest server — and skipping when no CLI is
	// installed keeps `go test ./...` offline.
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

const tenantNotificationSettingsFullFixture = `
resource "stepsecurity_tenant_notification_settings" "test" {
  notification_channels = {
    email             = "security@example.com"
    slack_webhook_url = "https://hooks.slack.com/services/T/B/X"
  }

  threat_intel = {
    enabled = true
    level   = "version"
  }

  developer_mdm = {
    new_ides           = true
    new_ide_extensions = true
    suspicious_files   = true
  }
}
`

// TestAccTenantNotificationSettingsPlanIsEmptyAfterApply is the round-trip
// check: everything the provider writes has to come back in a form the
// configuration can produce.
func TestAccTenantNotificationSettingsPlanIsEmptyAfterApply(t *testing.T) {
	testAccTenantNotificationSettings(t, &fakeTenantNotificationsBackend{}, resource.TestStep{
		Config: tenantNotificationSettingsFullFixture,
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "notification_channels.email", "security@example.com"),
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "notification_channels.teams_webhook_url", ""),
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "threat_intel.enabled", "true"),
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "threat_intel.level", "version"),
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "developer_mdm.new_ides", "true"),
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "developer_mdm.config_changes", "false"),
		),
	})
}

// TestAccTenantNotificationSettingsUpdate changes the threat intel level and the
// subscribed events, then leaves the plan empty again.
func TestAccTenantNotificationSettingsUpdate(t *testing.T) {
	testAccTenantNotificationSettings(t, &fakeTenantNotificationsBackend{},
		resource.TestStep{Config: tenantNotificationSettingsFullFixture},
		resource.TestStep{
			Config: `
resource "stepsecurity_tenant_notification_settings" "test" {
  notification_channels = {
    email = "soc@example.com"
  }

  threat_intel = {
    enabled = true
    level   = "all"
  }

  developer_mdm = {
    config_changes = true
  }
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "notification_channels.email", "soc@example.com"),
				// Dropping the webhook from the configuration clears it, because
				// the API assigns the channels from every write.
				resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "notification_channels.slack_webhook_url", ""),
				resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "threat_intel.level", "all"),
				resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "developer_mdm.new_ides", "false"),
				resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "developer_mdm.config_changes", "true"),
			),
		},
	)
}

// TestAccTenantNotificationSettingsDisabledLevelIsStable pins the one attribute
// the API does not persist. With no subscription there is no level to read back,
// so a configured level has to survive the refresh rather than snap to the
// schema default.
func TestAccTenantNotificationSettingsDisabledLevelIsStable(t *testing.T) {
	testAccTenantNotificationSettings(t, &fakeTenantNotificationsBackend{}, resource.TestStep{
		Config: `
resource "stepsecurity_tenant_notification_settings" "test" {
  notification_channels = {
    email = "security@example.com"
  }

  threat_intel = {
    enabled = false
    level   = "all"
  }

  developer_mdm = {
    suspicious_files = true
  }
}
`,
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "threat_intel.enabled", "false"),
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "threat_intel.level", "all"),
		),
	})
}

// TestAccTenantNotificationSettingsPreservesSlackMethod covers the attributes the
// API can set but not clear: omitting them has to leave the tenant's existing
// values alone and adopt them into state, not fight them on every plan.
func TestAccTenantNotificationSettingsPreservesSlackMethod(t *testing.T) {
	backend := &fakeTenantNotificationsBackend{
		stored: fakeTenantNotificationRecord{
			SlackNotificationMethod: "oauth",
			SlackChannelID:          "C0123456789",
		},
	}

	testAccTenantNotificationSettings(t, backend, resource.TestStep{
		Config: `
resource "stepsecurity_tenant_notification_settings" "test" {
  notification_channels = {
    email = "security@example.com"
  }

  threat_intel = {
    enabled = true
  }

  developer_mdm = {
    new_mcp_servers = true
  }
}
`,
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "notification_channels.slack_notification_method", "oauth"),
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "notification_channels.slack_channel_id", "C0123456789"),
			// level defaults to the most conservative setting when omitted.
			resource.TestCheckResourceAttr("stepsecurity_tenant_notification_settings.test", "threat_intel.level", "version"),
		),
	})
}

// TestAccTenantNotificationSettingsPreservesOtherSources checks that a write does
// not disturb the Azure DevOps options, which belong to their own source and are
// not managed here.
func TestAccTenantNotificationSettingsPreservesOtherSources(t *testing.T) {
	backend := &fakeTenantNotificationsBackend{
		stored: fakeTenantNotificationRecord{
			ADO: json.RawMessage(`{"new_endpoint_discovered":true,"file_overwrites":true}`),
		},
	}

	testAccTenantNotificationSettings(t, backend, resource.TestStep{
		Config: tenantNotificationSettingsFullFixture,
		Check: func(*terraform.State) error {
			backend.mu.Lock()
			defer backend.mu.Unlock()

			if backend.writes == 0 {
				return fmt.Errorf("expected the provider to write the tenant settings")
			}
			var ado struct {
				NewEndpointDiscovered bool `json:"new_endpoint_discovered"`
				FileOverwrites        bool `json:"file_overwrites"`
			}
			if err := json.Unmarshal(backend.stored.ADO, &ado); err != nil {
				return fmt.Errorf("ado options were not preserved: %w", err)
			}
			if !ado.NewEndpointDiscovered || !ado.FileOverwrites {
				return fmt.Errorf("ado options were overwritten: %+v", ado)
			}
			return nil
		},
	})
}

// TestAccTenantNotificationSettingsImport imports the tenant's existing record.
//
// ImportStateVerify is not used because it matches instances on an `id`
// attribute, and this resource has none: there is one record per tenant and the
// tenant comes from the provider, so there is nothing for an id to identify.
func TestAccTenantNotificationSettingsImport(t *testing.T) {
	backend := &fakeTenantNotificationsBackend{
		stored: fakeTenantNotificationRecord{
			Customer:                "tf-acc-test",
			Email:                   "security@example.com",
			SlackWebhookURL:         "https://hooks.slack.com/services/T/B/X",
			SlackNotificationMethod: "webhook",
			ThreatIntel:             json.RawMessage(`{"notify_on_version_match":true}`),
			DeveloperMDM:            json.RawMessage(`{"new_ides":{"enabled":true},"suspicious_files":{"enabled":true}}`),
		},
	}

	testAccTenantNotificationSettings(t, backend,
		resource.TestStep{Config: tenantNotificationSettingsFullFixture},
		resource.TestStep{
			ResourceName:  "stepsecurity_tenant_notification_settings.test",
			ImportState:   true,
			ImportStateId: "tf-acc-test",
			ImportStateCheck: func(states []*terraform.InstanceState) error {
				if len(states) != 1 {
					return fmt.Errorf("expected 1 imported instance, got %d", len(states))
				}
				for attribute, expected := range map[string]string{
					"notification_channels.email":                     "security@example.com",
					"notification_channels.slack_webhook_url":         "https://hooks.slack.com/services/T/B/X",
					"notification_channels.slack_notification_method": "webhook",
					"threat_intel.enabled":                            "true",
					"threat_intel.level":                              "version",
					"developer_mdm.new_ides":                          "true",
					"developer_mdm.suspicious_files":                  "true",
					"developer_mdm.config_changes":                    "false",
				} {
					if got := states[0].Attributes[attribute]; got != expected {
						return fmt.Errorf("imported %s = %q, want %q", attribute, got, expected)
					}
				}
				return nil
			},
		},
	)
}

// TestAccTenantNotificationSettingsDestroy checks that destroying the resource
// unsubscribes the tenant. The channels go with it: the API assigns them from
// every write, so there is no way to drop the subscriptions and keep them.
func TestAccTenantNotificationSettingsDestroy(t *testing.T) {
	backend := &fakeTenantNotificationsBackend{}

	testAccTenantNotificationSettings(t, backend, resource.TestStep{
		Config:  tenantNotificationSettingsFullFixture,
		Destroy: false,
	})

	// resource.Test destroys at the end of the case, so by here the delete has run.
	backend.mu.Lock()
	defer backend.mu.Unlock()

	if backend.stored.Email != "" || backend.stored.SlackWebhookURL != "" {
		t.Errorf("expected channels to be cleared, got %+v", backend.stored)
	}

	var threatIntel struct {
		NotifyOnPackageNameMatch bool `json:"notify_on_package_name_match"`
		NotifyOnVersionMatch     bool `json:"notify_on_version_match"`
		NotifyForAllIncidents    bool `json:"notify_for_all_incidents"`
	}
	if err := json.Unmarshal(backend.stored.ThreatIntel, &threatIntel); err != nil {
		t.Fatalf("unparseable stored threat intel options: %v", err)
	}
	if threatIntel.NotifyOnPackageNameMatch || threatIntel.NotifyOnVersionMatch || threatIntel.NotifyForAllIncidents {
		t.Errorf("expected the tenant to be unsubscribed from threat intel, got %+v", threatIntel)
	}

	developerMDM := map[string]struct {
		Enabled bool `json:"enabled"`
	}{}
	if err := json.Unmarshal(backend.stored.DeveloperMDM, &developerMDM); err != nil {
		t.Fatalf("unparseable stored developer MDM options: %v", err)
	}
	for event, subscription := range developerMDM {
		if subscription.Enabled {
			t.Errorf("expected %s to be unsubscribed", event)
		}
	}
}
