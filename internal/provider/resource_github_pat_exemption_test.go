package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestGithubPATExemptionResource_Metadata(t *testing.T) {
	t.Parallel()

	resp := &resource.MetadataResponse{}
	(&githubPATExemptionResource{}).Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "stepsecurity"}, resp)
	assert.Equal(t, "stepsecurity_github_pat_exemption", resp.TypeName)
}

func TestGithubPATExemptionResource_Schema(t *testing.T) {
	t.Parallel()

	resp := &resource.SchemaResponse{}
	(&githubPATExemptionResource{}).Schema(context.Background(), resource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)

	expected := []string{
		"id", "organization", "instance", "token_suffix", "token_id", "user_login", "token_class",
		"expires_at", "reason", "record_id", "source", "scope", "key", "approved_at", "created_by",
	}
	for _, name := range expected {
		assert.Contains(t, resp.Schema.Attributes, name)
	}
	assert.Len(t, resp.Schema.Attributes, len(expected))

	for _, name := range []string{"organization", "instance", "token_suffix", "token_id", "user_login", "token_class", "reason", "record_id"} {
		assert.True(t, resp.Schema.Attributes[name].IsOptional(), "%s should be optional", name)
		assert.False(t, resp.Schema.Attributes[name].IsComputed(), "%s must stay null when omitted", name)
	}
	for _, name := range []string{"id", "scope", "key", "approved_at", "created_by"} {
		assert.True(t, resp.Schema.Attributes[name].IsComputed(), "%s is server-owned", name)
		assert.False(t, resp.Schema.Attributes[name].IsOptional(), "%s is server-owned", name)
	}
	// The server fills these in when omitted.
	for _, name := range []string{"expires_at", "source"} {
		assert.True(t, resp.Schema.Attributes[name].IsOptional(), name)
		assert.True(t, resp.Schema.Attributes[name].IsComputed(), name)
	}
}

func TestPATExemptionConfigProblems(t *testing.T) {
	t.Parallel()

	str := types.StringValue
	cases := []struct {
		name string
		cfg  githubPATExemptionModel
		want int
	}{
		{"classic token in an organization", githubPATExemptionModel{Organization: str("widgets"), TokenSuffix: str("abcd1234")}, 0},
		{"fine-grained token narrowed to its user", githubPATExemptionModel{TokenID: types.Int64Value(42), UserLogin: str("someone")}, 0},
		{"every classic token of a user on one instance, tenant-wide", githubPATExemptionModel{UserLogin: str("someone"), TokenClass: str("classic"), Instance: str("ghes.example.com")}, 0},
		{"both token identifiers", githubPATExemptionModel{TokenSuffix: str("abcd1234"), TokenID: types.Int64Value(42)}, 1},
		{"no identity at all", githubPATExemptionModel{Reason: str("why")}, 1},
		{"token class on a single-token exemption", githubPATExemptionModel{TokenSuffix: str("abcd1234"), TokenClass: str("classic")}, 1},
		{"instance on an organization exemption", githubPATExemptionModel{Organization: str("widgets"), TokenSuffix: str("abcd1234"), Instance: str("github.com")}, 1},
		{"unparseable expiry", githubPATExemptionModel{TokenSuffix: str("abcd1234"), ExpiresAt: str("tomorrow")}, 1},
		{"expiry known only at apply", githubPATExemptionModel{TokenSuffix: str("abcd1234"), ExpiresAt: types.StringUnknown()}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Len(t, patExemptionConfigProblems(tc.cfg), tc.want)
		})
	}
}

func TestPATExemptionModel_RecordRoundTrip(t *testing.T) {
	t.Parallel()

	// A classic token in an organization.
	model := githubPATExemptionModel{
		Organization: types.StringValue("widgets"),
		TokenSuffix:  types.StringValue("abcd1234"),
		Reason:       types.StringValue("break glass"),
		RecordID:     types.StringValue("CHG-1"),
		Source:       types.StringValue("terraform"),
		ExpiresAt:    types.StringValue("2027-01-01T00:00:00Z"),
	}
	record := model.toAPIRecord("")
	assert.Equal(t, patExemptionScopeToken, record.Scope)
	assert.Equal(t, "abcd1234", record.TokenSuffix)
	assert.Equal(t, "", record.TokenClass)
	assert.Equal(t, int64(0), record.TokenID)
	assert.Equal(t, "", record.ApprovedAt)

	row := stepsecurityapi.PATExemption{
		TokenSuffix: "abcd1234", ExpiresAt: "2027-01-01T00:00:00Z", Source: "terraform", RecordID: "CHG-1",
		Reason: "break glass", ApprovedAt: "2026-10-19T00:00:00Z", CreatedBy: "key-1", Key: "abcd1234",
	}
	assert.True(t, exemptionMatches(row, record))
	model.setFromAPI(&row)
	assert.Equal(t, "abcd1234", model.TokenSuffix.ValueString())
	assert.Equal(t, patExemptionScopeToken, model.Scope.ValueString(), "an empty server scope means token")
	assert.Equal(t, "widgets/abcd1234", model.ID.ValueString())
	assert.Equal(t, "abcd1234", model.Key.ValueString())
	assert.Equal(t, "2026-10-19T00:00:00Z", model.ApprovedAt.ValueString())
	assert.Equal(t, "key-1", model.CreatedBy.ValueString())
	assert.True(t, model.TokenID.IsNull())
	assert.True(t, model.UserLogin.IsNull())
	assert.True(t, model.TokenClass.IsNull())
	assert.True(t, model.Instance.IsNull())

	// An update keeps the original approval time.
	assert.Equal(t, "2026-10-19T00:00:00Z", model.toAPIRecord(model.ApprovedAt.ValueString()).ApprovedAt)

	// Every classic token of a user, tenant-wide, on one instance.
	user := githubPATExemptionModel{
		UserLogin:  types.StringValue("Someone"),
		TokenClass: types.StringValue("classic"),
		Instance:   types.StringValue("ghes.example.com"),
		Source:     types.StringValue("terraform"),
	}
	record = user.toAPIRecord("")
	assert.Equal(t, patExemptionScopeOwner, record.Scope)
	assert.Equal(t, "classic", record.TokenClass)
	assert.Equal(t, "ghes.example.com", record.Instance)
	row = stepsecurityapi.PATExemption{
		Owner: "Someone", Scope: "owner", TokenClass: "classic", Instance: "ghes.example.com",
		Organization: stepsecurityapi.PATExemptionTenantWideOrganization,
		Key:          "instance:ghes.example.com/owner:someone#classic", ExpiresAt: "2026-10-27T00:00:00Z", Source: "terraform",
	}
	assert.True(t, exemptionMatches(row, record))
	assert.False(t, exemptionMatches(stepsecurityapi.PATExemption{Owner: "Someone", Scope: "owner", Instance: "ghes.example.com"}, record), "both classes is a different exemption")
	assert.False(t, exemptionMatches(stepsecurityapi.PATExemption{Owner: "Someone", Scope: "owner", TokenClass: "classic"}, record), "every instance is a different exemption")
	assert.False(t, exemptionMatches(stepsecurityapi.PATExemption{TokenSuffix: "abcd1234", Instance: "ghes.example.com"}, record), "a token record never matches a user exemption")
	user.setFromAPI(&row)
	assert.Equal(t, "/instance:ghes.example.com/owner:someone#classic", user.ID.ValueString())
	assert.Equal(t, "Someone", user.UserLogin.ValueString())
	assert.True(t, user.Reason.IsNull(), "an omitted reason stays null")

	// A fine-grained token matches on its id only.
	fineGrained := githubPATExemptionModel{TokenID: types.Int64Value(42)}
	record = fineGrained.toAPIRecord("")
	assert.True(t, exemptionMatches(stepsecurityapi.PATExemption{TokenID: 42, Key: "fg:42"}, record))
	assert.False(t, exemptionMatches(stepsecurityapi.PATExemption{TokenID: 43, Key: "fg:43"}, record))
	assert.False(t, exemptionMatches(stepsecurityapi.PATExemption{TokenSuffix: "abcd1234"}, record))
	assert.False(t, exemptionMatches(stepsecurityapi.PATExemption{TokenID: 42, Scope: "owner", Owner: "someone"}, record))
}

func TestParsePATExemptionID(t *testing.T) {
	t.Parallel()

	organization, key, err := parsePATExemptionID("widgets/abcd1234")
	require.NoError(t, err)
	assert.Equal(t, "widgets", organization)
	assert.Equal(t, "abcd1234", key)

	organization, key, err = parsePATExemptionID("/instance:ghes.example.com/owner:someone#classic")
	require.NoError(t, err)
	assert.Equal(t, "", organization)
	assert.Equal(t, "instance:ghes.example.com/owner:someone#classic", key, "only the first slash separates the registry from the key")

	_, _, err = parsePATExemptionID("abcd1234")
	assert.Error(t, err)
	_, _, err = parsePATExemptionID("widgets/")
	assert.Error(t, err)
}
