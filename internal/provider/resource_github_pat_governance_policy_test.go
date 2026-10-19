package provider

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGithubPATGovernancePolicyResource(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing
			{
				Config: testProviderConfig() + testAccGithubPATGovernancePolicyResourceConfig("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "enabled", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "fine_grained_max_age_days", "90"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "classic_max_age_days", "60"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "flag_no_expiry", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "unused_days", "0"),
				),
			},
			// Update and Read testing
			{
				Config: testProviderConfig() + testAccGithubPATGovernancePolicyResourceConfigUpdated("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "flag_over_scoped", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "over_scoped_scopes.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "unused_days", "180"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "expiry_reminder_days.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "classic_unused_days", "0"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "classic_expiry_reminder_days.0", "0"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "notify_on_revocation", "true"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "classic_notify_on_revocation", "false"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "fine_grained_noncompliant_revoke_after_days", "3650"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "revocation_notification_template.subject", "Your token was revoked"),
					res.TestCheckResourceAttr("stepsecurity_github_pat_governance_policy.test", "expiry_reminder_templates.fine_grained.14.subject", "Two weeks left on your token"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccGithubPATGovernancePolicyResourceConfig(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_pat_governance_policy" "test" {
  owner                     = %[1]q
  enabled                   = true
  fine_grained_max_age_days = 90
  classic_max_age_days      = 60
  flag_no_expiry            = true
}
`, owner)
}

func testAccGithubPATGovernancePolicyResourceConfigUpdated(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_pat_governance_policy" "test" {
  owner                     = %[1]q
  enabled                   = true
  fine_grained_max_age_days = 90
  classic_max_age_days      = 60
  flag_no_expiry            = true
  flag_over_scoped          = true
  over_scoped_scopes        = ["repo", "admin:org"]
  unused_days               = 180
  expiry_reminder_days      = [14, 3]

  classic_unused_days                         = 0
  classic_expiry_reminder_days                = [0]
  expiry_reminder_cc                          = ["security@example.com"]
  notify_on_revocation                        = true
  classic_notify_on_revocation                = false
  fine_grained_noncompliant_revoke_after_days = 3650
  revocation_notification_template = {
    subject = "Your token was revoked"
    body    = "<p>It no longer met the organization's token policy.</p>"
  }
  expiry_reminder_templates = {
    fine_grained = {
      "14" = {
        subject = "Two weeks left on your token"
        body    = "<p>Please rotate it.</p>"
      }
    }
  }
}
`, owner)
}

// Unit Tests

func TestGithubPATGovernancePolicyResource_Metadata(t *testing.T) {
	t.Parallel()

	r := &githubPATGovernancePolicyResource{}
	ctx := context.Background()

	req := resource.MetadataRequest{ProviderTypeName: "stepsecurity"}
	resp := &resource.MetadataResponse{}
	r.Metadata(ctx, req, resp)

	assert.Equal(t, "stepsecurity_github_pat_governance_policy", resp.TypeName)
}

func TestGithubPATGovernancePolicyResource_Schema(t *testing.T) {
	t.Parallel()

	r := &githubPATGovernancePolicyResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}
	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	expectedAttrs := []string{
		"id", "owner", "enabled",
		"fine_grained_max_age_days", "classic_max_age_days",
		"flag_no_expiry", "flag_over_scoped", "over_scoped_scopes",
		"unused_days", "fine_grained_unused_days", "classic_unused_days",
		"github_issue_repo",
		"expiry_reminder_days", "fine_grained_expiry_reminder_days", "classic_expiry_reminder_days",
		"expiry_reminder_templates", "expiry_reminder_cc", "expiry_reminder_to_owner",
		"owner_email_fallback_domain",
		"notify_on_revocation", "classic_notify_on_revocation", "fine_grained_notify_on_revocation",
		"revocation_notification_template", "classic_revocation_notification_template",
		"fine_grained_revocation_notification_template",
		"classic_noncompliant_revoke_after_days", "fine_grained_noncompliant_revoke_after_days",
		"auto_revoke_after_reminders", "classic_auto_revoke_after_reminders",
		"fine_grained_auto_revoke_after_reminders",
		"use_tenant_policy",
	}
	// Every attribute the resource exposes must mirror a field of the API
	// policy; the two lists drift otherwise.
	assert.Len(t, resp.Schema.Attributes, len(expectedAttrs), "schema has attributes this test does not list")
	for _, attrName := range expectedAttrs {
		if _, exists := resp.Schema.Attributes[attrName]; !exists {
			t.Errorf("Expected attribute %s not found in schema", attrName)
		}
	}

	assert.True(t, resp.Schema.Attributes["owner"].IsRequired(), "owner should be required")
	assert.True(t, resp.Schema.Attributes["enabled"].IsRequired(), "enabled should be required")
	assert.True(t, resp.Schema.Attributes["id"].IsComputed(), "id should be computed")
	assert.True(t, resp.Schema.Attributes["fine_grained_max_age_days"].IsOptional(), "fine_grained_max_age_days should be optional")
	assert.True(t, resp.Schema.Attributes["over_scoped_scopes"].IsOptional(), "over_scoped_scopes should be optional")
	assert.True(t, resp.Schema.Attributes["expiry_reminder_days"].IsOptional(), "expiry_reminder_days should be optional")

	// Three-state fields (inherit when omitted) must not be computed, or an
	// omitted value could never mean "inherit".
	for _, name := range []string{
		"fine_grained_unused_days", "classic_unused_days",
		"classic_notify_on_revocation", "fine_grained_notify_on_revocation",
		"classic_auto_revoke_after_reminders", "fine_grained_auto_revoke_after_reminders",
		"use_tenant_policy",
	} {
		assert.True(t, resp.Schema.Attributes[name].IsOptional(), "%s should be optional", name)
		assert.False(t, resp.Schema.Attributes[name].IsComputed(), "%s must stay null when omitted", name)
	}
}

func TestGithubPATGovernancePolicyClient_GetHandlesNullPolicy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		mockResponse *stepsecurityapi.PATGovernancePolicy
		mockError    error
		expectNil    bool
		expectError  bool
	}{
		{
			name: "configured policy",
			mockResponse: &stepsecurityapi.PATGovernancePolicy{
				Enabled:               true,
				FineGrainedMaxAgeDays: 90,
			},
			expectNil: false,
		},
		{
			// The API returns 200 with a null policy for an org that has
			// never configured one.
			name:         "unconfigured policy",
			mockResponse: nil,
			expectNil:    true,
		},
		{
			name:        "api error",
			mockError:   errors.New("boom"),
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockClient := &stepsecurityapi.MockStepSecurityClient{}
			mockClient.On("GetPATGovernancePolicy", mock.Anything, "tf-acc-test").Return(tc.mockResponse, tc.mockError)

			policy, err := mockClient.GetPATGovernancePolicy(context.Background(), "tf-acc-test")
			if tc.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if tc.expectNil {
				assert.Nil(t, policy)
			} else {
				assert.NotNil(t, policy)
				assert.True(t, policy.Enabled)
			}
		})
	}
}

func TestGithubPATGovernancePolicyModel_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	fineGrainedUnused := int64(45)
	yes, no := true, false
	apiPolicy := &stepsecurityapi.PATGovernancePolicy{
		Enabled:               true,
		FineGrainedMaxAgeDays: 90,
		ClassicMaxAgeDays:     60,
		FlagNoExpiry:          true,
		FlagOverScoped:        true,
		OverScopedScopes:      []string{"repo", "admin:org"},
		UnusedDays:            180,
		GitHubIssueRepo:       "widgets",
		ExpiryReminderDays:    []int64{14, 3},

		FineGrainedUnusedDays:         &fineGrainedUnused,
		FineGrainedExpiryReminderDays: []int64{21, 2},
		ClassicExpiryReminderDays:     []int64{0},
		ExpiryReminderTemplates: map[string]map[string]stepsecurityapi.PATReminderTemplate{
			"classic":      {"7": {Subject: "Token expiring", Body: "<p>Rotate it.</p>"}},
			"fine_grained": {"21": {Subject: "Three weeks left", Body: "<p>Plan the rotation.</p>"}},
		},
		ExpiryReminderCC:         []string{"security@example.com"},
		ExpiryReminderToOwner:    true,
		OwnerEmailFallbackDomain: "example.com",

		NotifyOnRevocation:                        true,
		ClassicNotifyOnRevocation:                 &no,
		RevocationNotificationTemplate:            &stepsecurityapi.PATReminderTemplate{Subject: "Revoked", Body: "<p>Gone.</p>"},
		FineGrainedRevocationNotificationTemplate: &stepsecurityapi.PATReminderTemplate{Subject: "FG revoked", Body: "<p>Gone too.</p>"},

		ClassicNoncompliantRevokeAfterDays:     30,
		FineGrainedNoncompliantRevokeAfterDays: 45,
		AutoRevokeAfterReminders:               true,
		FineGrainedAutoRevokeAfterReminders:    &yes,
		UseTenantPolicy:                        &no,
	}

	var model githubPATGovernancePolicyModel
	model.Owner = types.StringValue("tf-acc-test")
	err := model.setFromAPIPolicy(ctx, apiPolicy)
	assert.NoError(t, err)

	assert.Equal(t, "tf-acc-test", model.ID.ValueString())
	assert.True(t, model.Enabled.ValueBool())
	assert.Equal(t, int64(90), model.FineGrainedMaxAgeDays.ValueInt64())
	assert.Equal(t, int64(60), model.ClassicMaxAgeDays.ValueInt64())
	assert.True(t, model.FlagNoExpiry.ValueBool())
	assert.True(t, model.FlagOverScoped.ValueBool())
	assert.Equal(t, "widgets", model.GitHubIssueRepo.ValueString())
	assert.Equal(t, int64(45), model.FineGrainedUnusedDays.ValueInt64())
	assert.True(t, model.ClassicUnusedDays.IsNull(), "an omitted per-class limit inherits")
	assert.False(t, model.ClassicNotifyOnRevocation.ValueBool())
	assert.True(t, model.FineGrainedNotifyOnRevocation.IsNull())
	assert.True(t, model.ClassicRevocationNotificationTemplate.IsNull())
	assert.False(t, model.RevocationNotificationTemplate.IsNull())
	assert.False(t, model.UseTenantPolicy.ValueBool())

	// Convert back: every field must come out exactly as the API sent it.
	converted, err := model.toAPIPolicy(ctx)
	assert.NoError(t, err)
	assert.Equal(t, *apiPolicy, converted)

	// Empty lists, maps and nil pointers from the API become null in state,
	// so an omitted attribute never drifts.
	minimal := &stepsecurityapi.PATGovernancePolicy{Enabled: false}
	err = model.setFromAPIPolicy(ctx, minimal)
	assert.NoError(t, err)
	assert.True(t, model.OverScopedScopes.IsNull())
	assert.True(t, model.ExpiryReminderDays.IsNull())
	assert.True(t, model.FineGrainedExpiryReminderDays.IsNull())
	assert.True(t, model.ClassicExpiryReminderDays.IsNull())
	assert.True(t, model.ExpiryReminderTemplates.IsNull())
	assert.True(t, model.ExpiryReminderCC.IsNull())
	assert.True(t, model.FineGrainedUnusedDays.IsNull())
	assert.True(t, model.ClassicNotifyOnRevocation.IsNull())
	assert.True(t, model.RevocationNotificationTemplate.IsNull())
	assert.True(t, model.ClassicRevocationNotificationTemplate.IsNull())
	assert.True(t, model.FineGrainedRevocationNotificationTemplate.IsNull())
	assert.True(t, model.ClassicAutoRevokeAfterReminders.IsNull())
	assert.True(t, model.UseTenantPolicy.IsNull())
	assert.Equal(t, "", model.GitHubIssueRepo.ValueString())
	assert.Equal(t, "", model.OwnerEmailFallbackDomain.ValueString())
	assert.False(t, model.NotifyOnRevocation.ValueBool())
	assert.Equal(t, int64(0), model.ClassicNoncompliantRevokeAfterDays.ValueInt64())

	// And the minimal policy converts back without inventing values.
	converted, err = model.toAPIPolicy(ctx)
	assert.NoError(t, err)
	assert.Equal(t, *minimal, converted)
}
