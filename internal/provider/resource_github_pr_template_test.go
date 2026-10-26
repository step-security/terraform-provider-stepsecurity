package provider

import (
	"context"
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

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGitHubPRTemplateResource(t *testing.T) {
	res.Test(t, res.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create and Read testing
			{
				Config: testProviderConfig() + testAccGitHubPRTemplateResourceConfig("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "title", "ci: apply security best practices"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "labels.#", "2"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "labels.0", "bot"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "labels.1", "origin:stepsecurity"),
				),
			},
			// Update and Read testing
			{
				Config: testProviderConfig() + testAccGitHubPRTemplateResourceConfigUpdated("tf-acc-test"),
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "owner", "tf-acc-test"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "title", "fix: apply security updates"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "labels.#", "1"),
					res.TestCheckResourceAttr("stepsecurity_github_pr_template.test", "labels.0", "security"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// Unit Tests
func TestGitHubPRTemplateResource_Metadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		providerTypeName string
		expected         string
	}{
		{
			name:             "default",
			providerTypeName: "stepsecurity",
			expected:         "stepsecurity_github_pr_template",
		},
		{
			name:             "custom_provider",
			providerTypeName: "custom",
			expected:         "custom_github_pr_template",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubPRTemplateResource{}
			ctx := context.Background()

			req := resource.MetadataRequest{
				ProviderTypeName: tc.providerTypeName,
			}
			resp := &resource.MetadataResponse{}

			r.Metadata(ctx, req, resp)

			if resp.TypeName != tc.expected {
				t.Errorf("Expected TypeName %s, got %s", tc.expected, resp.TypeName)
			}
		})
	}
}

func TestGitHubPRTemplateResource_Schema(t *testing.T) {
	t.Parallel()

	r := &githubPRTemplateResource{}
	ctx := context.Background()

	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Schema() returned unexpected errors: %v", resp.Diagnostics)
	}

	// Test required attributes
	expectedAttrs := []string{"id", "owner", "title", "summary", "commit_message", "labels", "branch_name", "replace_stale_prs", "stale_after_days"}
	for _, attr := range expectedAttrs {
		if _, exists := resp.Schema.Attributes[attr]; !exists {
			t.Errorf("Expected attribute %s not found in schema", attr)
		}
	}

	// Test that owner is required
	if ownerAttr, exists := resp.Schema.Attributes["owner"]; exists {
		if !ownerAttr.IsRequired() {
			t.Error("Expected owner attribute to be required")
		}
	}

	// Test that title is required
	if titleAttr, exists := resp.Schema.Attributes["title"]; exists {
		if !titleAttr.IsRequired() {
			t.Error("Expected title attribute to be required")
		}
	}

	// Test that summary is required
	if summaryAttr, exists := resp.Schema.Attributes["summary"]; exists {
		if !summaryAttr.IsRequired() {
			t.Error("Expected summary attribute to be required")
		}
	}

	// Test that commit_message is required
	if commitMsgAttr, exists := resp.Schema.Attributes["commit_message"]; exists {
		if !commitMsgAttr.IsRequired() {
			t.Error("Expected commit_message attribute to be required")
		}
	}

	// Test that labels is optional
	if labelsAttr, exists := resp.Schema.Attributes["labels"]; exists {
		if !labelsAttr.IsOptional() {
			t.Error("Expected labels attribute to be optional")
		}
	}

	// Test that id is computed
	if idAttr, exists := resp.Schema.Attributes["id"]; exists {
		if !idAttr.IsComputed() {
			t.Error("Expected id attribute to be computed")
		}
	}

	// Test that branch_name is optional
	if branchNameAttr, exists := resp.Schema.Attributes["branch_name"]; exists {
		if !branchNameAttr.IsOptional() {
			t.Error("Expected branch_name attribute to be optional")
		}
		if branchNameAttr.IsRequired() {
			t.Error("Expected branch_name attribute not to be required")
		}
	}
}

func TestGitHubPRTemplateResource_Configure(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		providerData  any
		expectedError bool
		errorContains string
	}{
		{
			name:          "valid_client",
			providerData:  &stepsecurityapi.MockStepSecurityClient{},
			expectedError: false,
		},
		{
			name:          "nil_provider_data",
			providerData:  nil,
			expectedError: false,
		},
		{
			name:          "invalid_client_type",
			providerData:  "invalid",
			expectedError: true,
			errorContains: "Unexpected Resource Configure Type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &githubPRTemplateResource{}
			ctx := context.Background()

			req := resource.ConfigureRequest{
				ProviderData: tc.providerData,
			}
			resp := &resource.ConfigureResponse{}

			r.Configure(ctx, req, resp)

			if tc.expectedError {
				if !resp.Diagnostics.HasError() {
					t.Error("Expected error but got none")
				}

				if tc.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if strings.Contains(diag.Summary(), tc.errorContains) || strings.Contains(diag.Detail(), tc.errorContains) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error to contain '%s', but got: %v", tc.errorContains, resp.Diagnostics)
					}
				}
			} else {
				if resp.Diagnostics.HasError() {
					t.Errorf("Expected no error but got: %v", resp.Diagnostics)
				}
			}
		})
	}
}

func TestGitHubPRTemplateResource_ModelConversion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		model    githubPRTemplateModel
		expected stepsecurityapi.GitHubPRTemplate
	}{
		{
			name: "basic_template_with_labels",
			model: githubPRTemplateModel{
				Owner:         types.StringValue("test-org"),
				Title:         types.StringValue("ci: apply security best practices"),
				Summary:       types.StringValue("This PR applies security best practices"),
				CommitMessage: types.StringValue("Apply security best practices\n\nSigned-off-by: StepSecurity Bot <bot@stepsecurity.io>"),
				Labels: func() types.List {
					list, _ := types.ListValueFrom(context.Background(), types.StringType, []string{"bot", "origin:stepsecurity"})
					return list
				}(),
			},
			expected: stepsecurityapi.GitHubPRTemplate{
				Title:         "ci: apply security best practices",
				Summary:       "This PR applies security best practices",
				CommitMessage: "Apply security best practices\n\nSigned-off-by: StepSecurity Bot <bot@stepsecurity.io>",
				Labels:        []string{"bot", "origin:stepsecurity"},
			},
		},
		{
			name: "template_without_labels",
			model: githubPRTemplateModel{
				Owner:         types.StringValue("test-org"),
				Title:         types.StringValue("Security Update"),
				Summary:       types.StringValue("Security improvements"),
				CommitMessage: types.StringValue("Security update"),
				Labels:        types.ListNull(types.StringType),
			},
			expected: stepsecurityapi.GitHubPRTemplate{
				Title:         "Security Update",
				Summary:       "Security improvements",
				CommitMessage: "Security update",
				Labels:        nil,
			},
		},
		{
			name: "template_with_multiline_summary",
			model: githubPRTemplateModel{
				Owner: types.StringValue("test-org"),
				Title: types.StringValue("fix: security hardening"),
				Summary: types.StringValue(`## Summary

This pull request has been generated by StepSecurity.

## Security Fixes

{{STEPSECURITY_SECURITY_FIXES}}

## Feedback
Contact us at support@stepsecurity.io`),
				CommitMessage: types.StringValue("fix: security hardening"),
				Labels: func() types.List {
					list, _ := types.ListValueFrom(context.Background(), types.StringType, []string{"security"})
					return list
				}(),
			},
			expected: stepsecurityapi.GitHubPRTemplate{
				Title: "fix: security hardening",
				Summary: `## Summary

This pull request has been generated by StepSecurity.

## Security Fixes

{{STEPSECURITY_SECURITY_FIXES}}

## Feedback
Contact us at support@stepsecurity.io`,
				CommitMessage: "fix: security hardening",
				Labels:        []string{"security"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Convert model labels to Go slice
			var labels []string
			if !tc.model.Labels.IsNull() && !tc.model.Labels.IsUnknown() {
				elements := tc.model.Labels.Elements()
				labels = make([]string, len(elements))
				for i, elem := range elements {
					labels[i] = elem.(types.String).ValueString()
				}
			}

			result := stepsecurityapi.GitHubPRTemplate{
				Title:         tc.model.Title.ValueString(),
				Summary:       tc.model.Summary.ValueString(),
				CommitMessage: tc.model.CommitMessage.ValueString(),
				Labels:        labels,
			}

			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGitHubPRTemplateResource_StateConversion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		owner    string
		template stepsecurityapi.GitHubPRTemplate
		validate func(t *testing.T, model githubPRTemplateModel)
	}{
		{
			name:  "api_response_with_labels",
			owner: "test-org",
			template: stepsecurityapi.GitHubPRTemplate{
				Title:         "ci: apply security best practices",
				Summary:       "This PR applies security best practices",
				CommitMessage: "Apply security best practices",
				Labels:        []string{"bot", "security"},
			},
			validate: func(t *testing.T, model githubPRTemplateModel) {
				assert.Equal(t, "test-org", model.Owner.ValueString())
				assert.Equal(t, "ci: apply security best practices", model.Title.ValueString())
				assert.Equal(t, "This PR applies security best practices", model.Summary.ValueString())
				assert.Equal(t, "Apply security best practices", model.CommitMessage.ValueString())
				assert.False(t, model.Labels.IsNull())
				assert.Equal(t, 2, len(model.Labels.Elements()))
			},
		},
		{
			name:  "api_response_without_labels",
			owner: "test-org",
			template: stepsecurityapi.GitHubPRTemplate{
				Title:         "Security Update",
				Summary:       "Updates",
				CommitMessage: "Update",
				Labels:        []string{},
			},
			validate: func(t *testing.T, model githubPRTemplateModel) {
				assert.Equal(t, "test-org", model.Owner.ValueString())
				assert.Equal(t, "Security Update", model.Title.ValueString())
				assert.True(t, model.Labels.IsNull())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			model := githubPRTemplateModel{
				ID:            types.StringValue(tc.owner),
				Owner:         types.StringValue(tc.owner),
				Title:         types.StringValue(tc.template.Title),
				Summary:       types.StringValue(tc.template.Summary),
				CommitMessage: types.StringValue(tc.template.CommitMessage),
			}

			// Convert labels
			if len(tc.template.Labels) > 0 {
				labelElements := make([]types.String, len(tc.template.Labels))
				for i, label := range tc.template.Labels {
					labelElements[i] = types.StringValue(label)
				}
				labelList, _ := types.ListValueFrom(ctx, types.StringType, labelElements)
				model.Labels = labelList
			} else {
				model.Labels = types.ListNull(types.StringType)
			}

			tc.validate(t, model)
		})
	}
}

// Test configuration helpers
func testAccGitHubPRTemplateResourceConfig(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_pr_template" "test" {
  owner          = %[1]q
  title          = "ci: apply security best practices"
  summary        = "This PR applies security best practices"
  commit_message = "Apply security best practices\n\nSigned-off-by: StepSecurity Bot <bot@stepsecurity.io>"
  labels         = ["bot", "origin:stepsecurity"]
}
`, owner)
}

func testAccGitHubPRTemplateResourceConfigUpdated(owner string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_pr_template" "test" {
  owner          = %[1]q
  title          = "fix: apply security updates"
  summary        = "This PR applies security updates"
  commit_message = "Apply security updates"
  labels         = ["security"]
}
`, owner)
}

// runGitHubPRTemplateValidateConfig drives the real ValidateConfig with the given stale
// PR settings and every other attribute set to a valid value.
func runGitHubPRTemplateValidateConfig(t *testing.T, replaceStalePRs types.Bool, staleAfterDays types.Int64) *resource.ValidateConfigResponse {
	t.Helper()

	ctx := context.Background()
	r := &githubPRTemplateResource{}

	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError(), "schema errors: %v", schemaResp.Diagnostics)

	model := githubPRTemplateModel{
		ID:              types.StringNull(),
		Owner:           types.StringValue("test-org"),
		Title:           types.StringValue("[StepSecurity] Apply security best practices"),
		Summary:         types.StringValue("summary"),
		CommitMessage:   types.StringValue("commit message"),
		Labels:          types.ListNull(types.StringType),
		BranchName:      types.StringNull(),
		ReplaceStalePRs: replaceStalePRs,
		StaleAfterDays:  staleAfterDays,
	}
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	require.False(t, plan.Set(ctx, model).HasError())

	resp := &resource.ValidateConfigResponse{}
	r.ValidateConfig(ctx, resource.ValidateConfigRequest{
		Config: tfsdk.Config{Raw: plan.Raw, Schema: schemaResp.Schema},
	}, resp)
	return resp
}

// TestGitHubPRTemplateResource_ValidateConfig_StaleAfterDaysRequired: turning on
// replace_stale_prs without a threshold fails at plan time, not as an API error.
func TestGitHubPRTemplateResource_ValidateConfig_StaleAfterDaysRequired(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		replaceStalePRs types.Bool
		staleAfterDays  types.Int64
		wantError       bool
	}{
		{"on with threshold", types.BoolValue(true), types.Int64Value(14), false},
		{"on without threshold", types.BoolValue(true), types.Int64Null(), true},
		{"off without threshold", types.BoolValue(false), types.Int64Null(), false},
		{"unset without threshold", types.BoolNull(), types.Int64Null(), false},
		{"on with unknown threshold", types.BoolValue(true), types.Int64Unknown(), false},
		{"unknown with no threshold", types.BoolUnknown(), types.Int64Null(), false},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := runGitHubPRTemplateValidateConfig(t, tc.replaceStalePRs, tc.staleAfterDays)
			assert.Equal(t, tc.wantError, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
		})
	}
}

// TestGitHubPRTemplateResource_StaleAfterDaysMinimum drives the schema validator: the
// API rejects a threshold under 7 days, so it is rejected at plan time too.
func TestGitHubPRTemplateResource_StaleAfterDaysMinimum(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &githubPRTemplateResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)

	attr, ok := schemaResp.Schema.Attributes["stale_after_days"].(interface {
		Int64Validators() []validator.Int64
	})
	require.True(t, ok, "stale_after_days should expose int64 validators")

	for days, wantError := range map[int64]bool{6: true, 7: false, 30: false} {
		resp := &validator.Int64Response{}
		for _, v := range attr.Int64Validators() {
			v.ValidateInt64(ctx, validator.Int64Request{ConfigValue: types.Int64Value(days)}, resp)
		}
		assert.Equal(t, wantError, resp.Diagnostics.HasError(), "stale_after_days = %d: %v", days, resp.Diagnostics)
	}
}

// fakePRTemplateBackend stores the PR template the provider writes and returns it the
// way agent-api does: replace_stale_prs, stale_after_days and branch_name are omitted
// when empty, so a read cannot tell "false" or "0" from "never set".
type fakePRTemplateBackend struct {
	mu       sync.Mutex
	template map[string]any
}

// storeConsoleDefaultThreshold sets stale_after_days to 7 on the stored template,
// which is what the console saves even when replacement is off.
func (b *fakePRTemplateBackend) storeConsoleDefaultThreshold() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.template["stale_after_days"] = float64(7)
}

func (b *fakePRTemplateBackend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !strings.HasSuffix(req.URL.Path, "/pr-template") {
		http.Error(w, "unexpected path "+req.URL.Path, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	b.mu.Lock()
	defer b.mu.Unlock()

	switch req.Method {
	case http.MethodPost:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		var template map[string]any
		if err := json.Unmarshal(body, &template); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		for _, key := range []string{"replace_stale_prs", "stale_after_days", "branch_name"} {
			switch v := template[key].(type) {
			case bool:
				if !v {
					delete(template, key)
				}
			case float64:
				if v == 0 {
					delete(template, key)
				}
			case string:
				if v == "" {
					delete(template, key)
				}
			}
		}
		b.template = template
		_, _ = w.Write([]byte(`{"message":"PR template updated successfully"}`))
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(b.template)
	default:
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	}
}

func githubPRTemplateStaleFixture(staleSettings string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_pr_template" "test" {
  owner          = "test-org"
  title          = "[StepSecurity] Apply security best practices"
  summary        = "summary"
  commit_message = "commit message"
  %s
}
`, staleSettings)
}

// TestAccGitHubPRTemplateStalePRSettingsPlanIsStable applies each stale PR configuration
// against a backend that drops empty fields, and checks the plan is empty afterwards:
// omitted settings, on with a threshold, then switched off again.
func TestAccGitHubPRTemplateStalePRSettingsPlanIsStable(t *testing.T) {
	tfPath := os.Getenv("TF_ACC_TERRAFORM_PATH")
	if tfPath == "" {
		found, err := exec.LookPath("terraform")
		if err != nil {
			t.Skip("terraform CLI not found in PATH; set TF_ACC_TERRAFORM_PATH to run this test")
		}
		tfPath = found
	}

	backend := &fakePRTemplateBackend{}
	server := httptest.NewServer(backend)
	t.Cleanup(server.Close)

	t.Setenv("TF_ACC", "1")
	t.Setenv("TF_ACC_TERRAFORM_PATH", tfPath)
	t.Setenv("STEP_SECURITY_API_BASE_URL", server.URL)
	t.Setenv("STEP_SECURITY_API_KEY", "test-key")
	t.Setenv("STEP_SECURITY_CUSTOMER", "test-customer")

	res.Test(t, res.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		// The invalid configs come first: the harness destroys using the last step's
		// config, so the run has to end on a valid one.
		Steps: []res.TestStep{
			{
				Config:      githubPRTemplateStaleFixture("replace_stale_prs = true"),
				ExpectError: regexp.MustCompile(`stale_after_days is required`),
			},
			{
				Config:      githubPRTemplateStaleFixture("replace_stale_prs = true\n  stale_after_days  = 3"),
				ExpectError: regexp.MustCompile(`Invalid Attribute Value`),
			},
			{Config: githubPRTemplateStaleFixture("")},
			// The template is then saved in the console, which stores 7 with replacement
			// off. A config that omits stale_after_days must still plan clean.
			{
				PreConfig: backend.storeConsoleDefaultThreshold,
				Config:    githubPRTemplateStaleFixture(""),
				PlanOnly:  true,
			},
			{Config: githubPRTemplateStaleFixture("replace_stale_prs = true\n  stale_after_days  = 14")},
			{Config: githubPRTemplateStaleFixture("replace_stale_prs = false")},
			{
				PreConfig: backend.storeConsoleDefaultThreshold,
				Config:    githubPRTemplateStaleFixture("replace_stale_prs = false"),
				PlanOnly:  true,
			},
		},
	})
}
