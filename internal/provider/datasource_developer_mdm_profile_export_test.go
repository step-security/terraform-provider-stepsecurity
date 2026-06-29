package provider

import (
	"context"
	"regexp"
	"testing"

	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	resourcehelper "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func exportDataSourceSchema(t *testing.T) datasourceschema.Schema {
	t.Helper()
	resp := &fwdatasource.SchemaResponse{}
	NewDeveloperMDMProfileExportDataSource().Schema(context.Background(), fwdatasource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError())
	return resp.Schema
}

func exportReadRequest(t *testing.T, model developerMDMProfileExportDataSourceModel) (fwdatasource.ReadRequest, *fwdatasource.ReadResponse) {
	t.Helper()
	schema := exportDataSourceSchema(t)
	state := tfsdk.State{Schema: schema}
	require.False(t, state.Set(context.Background(), model).HasError())
	req := fwdatasource.ReadRequest{Config: tfsdk.Config{Raw: state.Raw, Schema: schema}}
	resp := &fwdatasource.ReadResponse{State: tfsdk.State{Schema: schema}}
	return req, resp
}

func TestDeveloperMDMProfileExportDataSource_Schema(t *testing.T) {
	t.Parallel()

	attrs := exportDataSourceSchema(t).Attributes
	for _, name := range []string{"profile_id", "os", "category", "filename", "content_type", "content", "hash", "notes"} {
		assert.Contains(t, attrs, name, "missing attribute %q", name)
	}
}

func TestDeveloperMDMProfileExportDataSource_Read(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.On("ExportDeveloperMDMProfile", mock.Anything, "prof1", "linux", "ide_extension").Return(&stepsecurityapi.DeveloperMDMExportArtifact{
		OS:          "linux",
		Category:    "ide_extension",
		Filename:    "policy.json",
		ContentType: "application/json; charset=utf-8",
		Content:     "{\n  \"AllowedExtensions\": \"{\\\"*\\\":false}\"\n}\n",
		Hash:        "sha256:abc",
		Notes:       "Place at /etc/vscode/policy.json",
	}, nil).Once()

	d := &developerMDMProfileExportDataSource{client: mockClient}
	req, resp := exportReadRequest(t, developerMDMProfileExportDataSourceModel{
		ProfileID: types.StringValue("prof1"),
		OS:        types.StringValue("linux"),
		Category:  types.StringValue("ide_extension"),
	})

	d.Read(ctx, req, resp)
	require.False(t, resp.Diagnostics.HasError(), "read errors: %v", resp.Diagnostics)
	mockClient.AssertExpectations(t)

	var state developerMDMProfileExportDataSourceModel
	require.False(t, resp.State.Get(ctx, &state).HasError())

	assert.Equal(t, "policy.json", state.Filename.ValueString())
	assert.Equal(t, "application/json; charset=utf-8", state.ContentType.ValueString())
	assert.Equal(t, "sha256:abc", state.Hash.ValueString())
	assert.Equal(t, "Place at /etc/vscode/policy.json", state.Notes.ValueString())
}

func TestDeveloperMDMProfileExportDataSource_DefaultCategory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	// Null category must resolve to ide_extension before calling the API.
	mockClient.On("ExportDeveloperMDMProfile", mock.Anything, "prof1", "macos", "ide_extension").Return(&stepsecurityapi.DeveloperMDMExportArtifact{
		OS:       "macos",
		Category: "ide_extension",
		Filename: "policy.mobileconfig",
	}, nil).Once()

	d := &developerMDMProfileExportDataSource{client: mockClient}
	req, resp := exportReadRequest(t, developerMDMProfileExportDataSourceModel{
		ProfileID: types.StringValue("prof1"),
		OS:        types.StringValue("macos"),
		Category:  types.StringNull(),
	})

	d.Read(ctx, req, resp)
	require.False(t, resp.Diagnostics.HasError(), "read errors: %v", resp.Diagnostics)
	mockClient.AssertExpectations(t)

	var state developerMDMProfileExportDataSourceModel
	require.False(t, resp.State.Get(ctx, &state).HasError())
	assert.Equal(t, "ide_extension", state.Category.ValueString())
}

func TestDeveloperMDMProfileExportDataSource_ContentIsDecodedArtifact(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// The API client already decoded the HTTP JSON string into the real file body.
	decoded := "{\n  \"AllowedExtensions\": \"{\\\"*\\\":false}\"\n}\n"

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.On("ExportDeveloperMDMProfile", mock.Anything, "prof1", "linux", "ide_extension").Return(&stepsecurityapi.DeveloperMDMExportArtifact{
		OS:       "linux",
		Category: "ide_extension",
		Filename: "policy.json",
		Content:  decoded,
	}, nil).Once()

	d := &developerMDMProfileExportDataSource{client: mockClient}
	req, resp := exportReadRequest(t, developerMDMProfileExportDataSourceModel{
		ProfileID: types.StringValue("prof1"),
		OS:        types.StringValue("linux"),
		Category:  types.StringValue("ide_extension"),
	})

	d.Read(ctx, req, resp)
	require.False(t, resp.Diagnostics.HasError(), "read errors: %v", resp.Diagnostics)

	var state developerMDMProfileExportDataSourceModel
	require.False(t, resp.State.Get(ctx, &state).HasError())

	// State content is the decoded body, passable directly to local_file.content.
	assert.Equal(t, decoded, state.Content.ValueString())
	assert.Contains(t, state.Content.ValueString(), "\n")
	assert.Contains(t, state.Content.ValueString(), `"AllowedExtensions"`)
	assert.NotContains(t, state.Content.ValueString(), `\n`)
}

// TestAccDeveloperMDMProfileExportDataSource runs against the real API.
// Requires TF_ACC=1 and env vars STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER.
func TestAccDeveloperMDMProfileExportDataSource(t *testing.T) {
	const dsName = "data.stepsecurity_developer_mdm_profile_export.linux"
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			{
				Config: testAccDeveloperMDMProfileExportConfig(),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttrSet(dsName, "filename"),
					resourcehelper.TestCheckResourceAttrSet(dsName, "content_type"),
					resourcehelper.TestCheckResourceAttrSet(dsName, "hash"),
					resourcehelper.TestCheckResourceAttrSet(dsName, "content"),
					resourcehelper.TestCheckResourceAttr(dsName, "category", "ide_extension"),
					// The decoded Linux artifact contains the literal AllowedExtensions key,
					// not escaped \n sequences from the raw HTTP JSON response.
					resourcehelper.TestMatchResourceAttr(dsName, "content", regexp.MustCompile(`"AllowedExtensions"`)),
				),
			},
		},
	})
}

func testAccDeveloperMDMProfileExportConfig() string {
	return testProviderConfig() + `
resource "stepsecurity_developer_mdm_ide_extension_policy" "test" {
  name = "tf-acc export policy"
  mode = "allowlist"

  rules = [
    {
      publisher = "ms-python"
      name      = "python"
      stable    = true
    },
  ]
}

resource "stepsecurity_developer_mdm_profile" "test" {
  name       = "tf-acc export profile"
  policy_ids = [stepsecurity_developer_mdm_ide_extension_policy.test.policy_id]
}

data "stepsecurity_developer_mdm_profile_export" "linux" {
  profile_id = stepsecurity_developer_mdm_profile.test.profile_id
  os         = "linux"
}
`
}
