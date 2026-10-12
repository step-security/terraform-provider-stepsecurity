package provider

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const orgProfilesResource = "stepsecurity_github_org_notification_settings.test"

// githubOrgNotificationProfilesFixture renders the org resource with the given
// notification_profiles value, or without the attribute when it is "".
func githubOrgNotificationProfilesFixture(profiles string) string {
	attribute := ""
	if profiles != "" {
		attribute = "\n  notification_profiles = " + profiles
	}
	return fmt.Sprintf(`
resource "stepsecurity_github_org_notification_settings" "test" {
  owner = "step-terraform-tests"

  notification_channels = {
    email = "security@example.com"
  }

  notification_events = {
    domain_blocked = true
  }
%s
}
`, attribute)
}

const orgTwoProfiles = `[
    {
      name   = "Network"
      type   = "slack_webhook"
      target = "https://hooks.slack.com/services/T/B/network"
      events = ["domain_blocked", "new_endpoint_discovered"]
    },
    {
      name               = "Policy"
      type               = "email"
      target             = "policy@example.com"
      events             = ["run_blocked_by_policy", "pat_abuse_detected"]
      threat_intel_level = "version"
    },
  ]`

const orgOneProfile = `[
    {
      name   = "Network"
      type   = "slack_webhook"
      target = "https://hooks.slack.com/services/T/B/network"
      events = ["domain_blocked"]
    },
  ]`

func (b *fakeGithubNotificationSettingsBackend) storedProfiles() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()

	raw, _ := b.stored["notificationChannels"].([]any)
	profiles := make([]map[string]any, 0, len(raw))
	for _, p := range raw {
		if profile, ok := p.(map[string]any); ok {
			profiles = append(profiles, profile)
		}
	}
	return profiles
}

func profileEvents(profile map[string]any) []string {
	raw, _ := profile["events"].([]any)
	events := make([]string, 0, len(raw))
	for _, e := range raw {
		if text, ok := e.(string); ok {
			events = append(events, text)
		}
	}
	return events
}

// TestAccGithubOrgNotificationProfiles creates two profiles, updates them down
// to one, clears them, and checks what reaches the API at each step. Each step
// also checks the plan settles, so state and API agree.
func TestAccGithubOrgNotificationProfiles(t *testing.T) {
	backend := newFakeGithubNotificationSettingsBackend(nil)
	var networkID string

	testAccGithubOrgNotificationSettings(t, backend,
		resource.TestStep{
			Config: githubOrgNotificationProfilesFixture(orgTwoProfiles),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(orgProfilesResource, "notification_profiles.#", "2"),
				resource.TestCheckResourceAttrSet(orgProfilesResource, "notification_profiles.0.id"),
				resource.TestCheckResourceAttr(orgProfilesResource, "notification_profiles.0.threat_intel_level", "off"),
				resource.TestCheckResourceAttr(orgProfilesResource, "notification_profiles.1.threat_intel_level", "version"),
				resource.TestCheckTypeSetElemAttr(orgProfilesResource, "notification_profiles.1.events.*", "pat_abuse_detected"),
				func(s *terraform.State) error {
					networkID = s.RootModule().Resources[orgProfilesResource].Primary.Attributes["notification_profiles.0.id"]

					profiles := backend.storedProfiles()
					if len(profiles) != 2 {
						return fmt.Errorf("API holds %d profiles, want 2", len(profiles))
					}
					// Events reach the API as settings field names.
					if got := strings.Join(profileEvents(profiles[0]), ","); got != "notifyWhenDomainBlocked,notifyWhenEndpointDiscovered" &&
						got != "notifyWhenEndpointDiscovered,notifyWhenDomainBlocked" {
						return fmt.Errorf("first profile events = %q", got)
					}
					if got := profiles[1]["orgThreatIntelLevel"]; got != "version" {
						return fmt.Errorf("second profile level = %v, want version", got)
					}
					return nil
				},
			),
		},
		resource.TestStep{
			Config: githubOrgNotificationProfilesFixture(orgOneProfile),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(orgProfilesResource, "notification_profiles.#", "1"),
				func(s *terraform.State) error {
					// The kept profile keeps its id, so the API sees an update rather
					// than a new profile.
					if got := s.RootModule().Resources[orgProfilesResource].Primary.Attributes["notification_profiles.0.id"]; got != networkID {
						return fmt.Errorf("profile id changed from %q to %q", networkID, got)
					}
					profiles := backend.storedProfiles()
					if len(profiles) != 1 || strings.Join(profileEvents(profiles[0]), ",") != "notifyWhenDomainBlocked" {
						return fmt.Errorf("API profiles = %v, want one profile with notifyWhenDomainBlocked", profiles)
					}
					return nil
				},
			),
		},
		resource.TestStep{
			Config: githubOrgNotificationProfilesFixture("[]"),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(orgProfilesResource, "notification_profiles.#", "0"),
				func(*terraform.State) error {
					if profiles := backend.storedProfiles(); len(profiles) != 0 {
						return fmt.Errorf("an empty list left %d profiles in the API", len(profiles))
					}
					return nil
				},
			),
		},
	)
}

// TestAccGithubOrgNotificationProfilesOmittedAdopts leaves profiles configured
// in the console alone: an omitted list is never written, and is read into
// state.
func TestAccGithubOrgNotificationProfilesOmittedAdopts(t *testing.T) {
	backend := newFakeGithubNotificationSettingsBackend(map[string]any{
		"notificationChannels": []any{
			map[string]any{
				"id":                  "console-profile",
				"name":                "Secrets",
				"type":                "email",
				"target":              "secrets@example.com",
				"events":              []any{"notifyForSecretsDetection"},
				"orgThreatIntelLevel": "off",
			},
		},
	})

	testAccGithubOrgNotificationSettings(t, backend, resource.TestStep{
		Config: githubOrgNotificationProfilesFixture(""),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(orgProfilesResource, "notification_profiles.#", "1"),
			resource.TestCheckResourceAttr(orgProfilesResource, "notification_profiles.0.id", "console-profile"),
			resource.TestCheckTypeSetElemAttr(orgProfilesResource, "notification_profiles.0.events.*", "secrets_detected"),
			func(*terraform.State) error {
				if backend.profileWrites != 0 {
					return fmt.Errorf("an omitted list was written %d time(s)", backend.profileWrites)
				}
				return nil
			},
		),
	})
}

// TestAccGithubOrgNotificationProfilesDestroy removes the profiles on destroy,
// along with the rest of the settings.
func TestAccGithubOrgNotificationProfilesDestroy(t *testing.T) {
	backend := newFakeGithubNotificationSettingsBackend(nil)

	testAccGithubOrgNotificationSettings(t, backend,
		resource.TestStep{Config: githubOrgNotificationProfilesFixture(orgTwoProfiles)},
		resource.TestStep{Config: githubOrgNotificationProfilesFixture(orgTwoProfiles), Destroy: true},
	)

	if profiles := backend.storedProfiles(); len(profiles) != 0 {
		t.Fatalf("destroy left %d profiles in the API", len(profiles))
	}
}

const tenantProfilesResource = "stepsecurity_tenant_notification_settings.test"

func tenantNotificationProfilesFixture(profiles string) string {
	attribute := ""
	if profiles != "" {
		attribute = "\n  notification_profiles = " + profiles
	}
	return fmt.Sprintf(`
resource "stepsecurity_tenant_notification_settings" "test" {
  notification_channels = {
    email = "security@example.com"
  }

  threat_intel = {
    enabled = true
    level   = "version"
  }

  developer_mdm = {
    new_ides = true
  }
%s
}
`, attribute)
}

// TestAccTenantNotificationProfiles creates a profile, checks the API shape and
// that the plan settles, then clears it.
func TestAccTenantNotificationProfiles(t *testing.T) {
	backend := &fakeTenantNotificationsBackend{}

	testAccTenantNotificationSettings(t, backend,
		resource.TestStep{
			Config: tenantNotificationProfilesFixture(`[
    {
      name                 = "Devices"
      type                 = "teams"
      target               = "https://example.webhook.office.com/devices"
      threat_intel_level   = "all"
      developer_mdm_events = ["new_mcp_servers", "suspicious_files"]
    },
  ]`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(tenantProfilesResource, "notification_profiles.#", "1"),
				resource.TestCheckResourceAttrSet(tenantProfilesResource, "notification_profiles.0.id"),
				resource.TestCheckResourceAttr(tenantProfilesResource, "notification_profiles.0.threat_intel_level", "all"),
				resource.TestCheckTypeSetElemAttr(tenantProfilesResource, "notification_profiles.0.developer_mdm_events.*", "new_mcp_servers"),
				func(*terraform.State) error {
					if len(backend.stored.NotificationChannels) != 1 {
						return fmt.Errorf("API holds %d profiles, want 1", len(backend.stored.NotificationChannels))
					}
					profile, _ := json.Marshal(backend.stored.NotificationChannels[0])
					for _, want := range []string{`"notify_for_all_incidents":true`, `"new_mcp_servers":{"enabled":true}`, `"suspicious_files":{"enabled":true}`, `"new_ides":{"enabled":false}`} {
						if !strings.Contains(string(profile), want) {
							return fmt.Errorf("API profile %s is missing %s", profile, want)
						}
					}
					return nil
				},
			),
		},
		resource.TestStep{
			Config: tenantNotificationProfilesFixture("[]"),
			Check: func(*terraform.State) error {
				if len(backend.stored.NotificationChannels) != 0 {
					return fmt.Errorf("an empty list left %d profiles in the API", len(backend.stored.NotificationChannels))
				}
				return nil
			},
		},
	)
}

// TestAccTenantNotificationProfilesOmittedAdopts leaves console profiles alone
// and reads them into state.
func TestAccTenantNotificationProfilesOmittedAdopts(t *testing.T) {
	backend := &fakeTenantNotificationsBackend{
		stored: fakeTenantNotificationRecord{
			NotificationChannels: []map[string]any{{
				"id":     "console-profile",
				"name":   "Threat intel",
				"type":   "email",
				"target": "intel@example.com",
				"threat_intel_notification_options": map[string]any{
					"notify_on_package_name_match": true,
				},
				"developer_mdm_notification_options": map[string]any{},
			}},
		},
	}

	testAccTenantNotificationSettings(t, backend, resource.TestStep{
		Config: tenantNotificationProfilesFixture(""),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(tenantProfilesResource, "notification_profiles.#", "1"),
			resource.TestCheckResourceAttr(tenantProfilesResource, "notification_profiles.0.id", "console-profile"),
			resource.TestCheckResourceAttr(tenantProfilesResource, "notification_profiles.0.threat_intel_level", "name"),
			resource.TestCheckResourceAttr(tenantProfilesResource, "notification_profiles.0.developer_mdm_events.#", "0"),
			func(*terraform.State) error {
				if backend.profileWrites != 0 {
					return fmt.Errorf("an omitted list was written %d time(s)", backend.profileWrites)
				}
				return nil
			},
		),
	})
}
