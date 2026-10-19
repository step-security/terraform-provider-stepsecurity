package provider

import (
	"context"
	"fmt"
	"regexp"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// maxPATThresholdDays mirrors the agent-api bound on every day-valued
// threshold in the PAT governance policy.
const maxPATThresholdDays = 3650

// ownerEmailFallbackDomainPattern mirrors the agent-api rule for
// owner_email_fallback_domain: empty, or a bare domain without "@" or spaces.
var ownerEmailFallbackDomainPattern = regexp.MustCompile(`^$|^[^@\s]+\.[^@\s]+$`)

// Template limits mirror the agent-api bounds on custom reminder and
// revocation emails.
const (
	maxPATTemplateSubjectChars = 200
	maxPATTemplateBodyChars    = 20000
)

// patTemplateAttrTypes is the shape of one custom email, used both for the
// nested revocation templates and the per-band reminder template map.
var patTemplateAttrTypes = map[string]attr.Type{
	"subject": types.StringType,
	"body":    types.StringType,
}

// patTemplateObjectType is one custom email; patTemplateBandMapType maps a
// reminder band (days before expiry, as a string) to its email.
var (
	patTemplateObjectType  = types.ObjectType{AttrTypes: patTemplateAttrTypes}
	patTemplateBandMapType = types.MapType{ElemType: patTemplateObjectType}
)

// patTemplateModel is the Terraform view of PATReminderTemplate.
type patTemplateModel struct {
	Subject types.String `tfsdk:"subject"`
	Body    types.String `tfsdk:"body"`
}

// patTemplateSchema is the nested attribute shared by the three revocation
// notice templates.
func patTemplateSchema(description string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Optional:    true,
		Description: description,
		Attributes: map[string]schema.Attribute{
			"subject": schema.StringAttribute{
				Optional:    true,
				Description: "Email subject, at most 200 characters.",
				Validators:  []validator.String{stringvalidator.LengthAtMost(maxPATTemplateSubjectChars)},
			},
			"body": schema.StringAttribute{
				Optional:    true,
				Description: "Email body as HTML, at most 20000 characters.",
				Validators:  []validator.String{stringvalidator.LengthAtMost(maxPATTemplateBodyChars)},
			},
		},
	}
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &githubPATGovernancePolicyResource{}
	_ resource.ResourceWithConfigure   = &githubPATGovernancePolicyResource{}
	_ resource.ResourceWithImportState = &githubPATGovernancePolicyResource{}
)

// NewGithubPATGovernancePolicyResource is a helper function to simplify the provider implementation.
func NewGithubPATGovernancePolicyResource() resource.Resource {
	return &githubPATGovernancePolicyResource{}
}

// githubPATGovernancePolicyResource is the resource implementation.
type githubPATGovernancePolicyResource struct {
	client stepsecurityapi.Client
}

// Configure adds the provider configured client to the resource.
func (r *githubPATGovernancePolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(stepsecurityapi.Client)

	if !ok || client == nil {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

// Metadata returns the resource type name.
func (r *githubPATGovernancePolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_pat_governance_policy"
}

// Schema defines the schema for the resource.
func (r *githubPATGovernancePolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the PAT governance policy for a GitHub organization. The policy drives the " +
			"personal-access-token controls on the StepSecurity dashboard (max age, no expiration, over-scoped, " +
			"unused, inactive owner) and the resulting violation alerts and pre-expiry reminders. " +
			"An enabled policy needs at least one active control. The resource is the organization's own policy; an organization without one follows the customer's tenant-wide policy, which this resource does not manage. Destroying the resource removes the organization's own policy, so it follows the tenant-wide policy (or the built-in default) again.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The ID of the PAT governance policy. This is same as the owner/organization name.",
			},
			"owner": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The owner/organization name the policy applies to.",
			},
			"enabled": schema.BoolAttribute{
				Required:    true,
				Description: "Whether the PAT governance policy is enforced. An enabled policy needs at least one active control.",
			},
			"fine_grained_max_age_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Maximum allowed age in days for fine-grained PATs, measured from the org-access grant time. 0 disables the check.",
				Validators: []validator.Int64{
					int64validator.Between(0, maxPATThresholdDays),
				},
			},
			"classic_max_age_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Maximum allowed age in days for classic PATs, measured from the SSO authorization time. 0 disables the check.",
				Validators: []validator.Int64{
					int64validator.Between(0, maxPATThresholdDays),
				},
			},
			"flag_no_expiry": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Flag tokens without an expiration date, or whose expiration is set further out than the class max age allows.",
			},
			"flag_over_scoped": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Flag over-scoped tokens: classic PATs carrying coarse scopes, and fine-grained PATs granting write access across all repositories.",
			},
			"over_scoped_scopes": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Classic PAT scopes treated as over-scoped. Omit to use the server default (repo, admin:org, workflow). Only used when flag_over_scoped is true.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
			},
			"unused_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Flag tokens with no sign of use for more than this many days (never-used tokens count from their grant/authorization time). 0 disables the check.",
				Validators: []validator.Int64{
					int64validator.Between(0, maxPATThresholdDays),
				},
			},
			"github_issue_repo": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "Bare repository name in this organization where a violations issue is filed and kept up to date on each alert. Empty disables the GitHub-issue alert channel.",
			},
			"expiry_reminder_days": schema.ListAttribute{
				ElementType: types.Int64Type,
				Optional:    true,
				Description: "Pre-expiry reminder bands in days before expiry, each reminded once per token, shared by both token classes unless a per-class list is set. Omit to use the server default (30, 7, 1); a 0 entry disables that band.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueInt64sAre(int64validator.Between(0, maxPATThresholdDays)),
				},
			},
			"fine_grained_unused_days": schema.Int64Attribute{
				Optional:    true,
				Description: "Unused limit in days for fine-grained PATs. Omit to use unused_days; 0 disables the staleness check for this class.",
				Validators:  []validator.Int64{int64validator.Between(0, maxPATThresholdDays)},
			},
			"classic_unused_days": schema.Int64Attribute{
				Optional:    true,
				Description: "Unused limit in days for classic PATs. Omit to use unused_days; 0 disables the staleness check for this class.",
				Validators:  []validator.Int64{int64validator.Between(0, maxPATThresholdDays)},
			},
			"fine_grained_expiry_reminder_days": schema.ListAttribute{
				ElementType: types.Int64Type,
				Optional:    true,
				Description: "Reminder bands for fine-grained PATs. A class with its own list ignores expiry_reminder_days entirely; omit to share it, set [0] to send no reminders for this class.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueInt64sAre(int64validator.Between(0, maxPATThresholdDays)),
				},
			},
			"classic_expiry_reminder_days": schema.ListAttribute{
				ElementType: types.Int64Type,
				Optional:    true,
				Description: "Reminder bands for classic PATs. A class with its own list ignores expiry_reminder_days entirely; omit to share it, set [0] to send no reminders for this class.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueInt64sAre(int64validator.Between(0, maxPATThresholdDays)),
				},
			},
			"expiry_reminder_templates": schema.MapAttribute{
				ElementType: patTemplateBandMapType,
				Optional:    true,
				Description: "Custom reminder emails keyed by token class (\"classic\" or \"fine_grained\") and then by reminder band in whole days before expiry (as a string, e.g. \"7\"), each with a subject (at most 200 characters) and body (HTML, at most 20000 characters). Bands without a template use the built-in email. Subject and body may use {{owner}}, {{token_name}}, {{organization}}, {{days_left}}, {{expires_at}} and {{manage_url}}.",
				Validators:  []validator.Map{mapvalidator.KeysAre(stringvalidator.OneOf("classic", "fine_grained"))},
			},
			"expiry_reminder_cc": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Email addresses copied on every reminder email and revocation notice, at most 10.",
				Validators:  []validator.List{listvalidator.SizeBetween(1, 10)},
			},
			"expiry_reminder_to_owner": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Address each reminder email to the token's user at their linked SSO identity when it is an email address, falling back to the organization's notification address when unknown.",
			},
			"owner_email_fallback_domain": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "Bare email domain (for example example.com) used to derive an address for a token's user when the SSO directory returns nothing, from the enterprise managed user login convention: the trailing _shortcode is dropped, the first hyphen becomes a dot and the domain is appended. The derived address counts as a linked identity. Empty disables the fallback.",
				Validators:  []validator.String{stringvalidator.RegexMatches(ownerEmailFallbackDomainPattern, "must be a bare domain like example.com")},
			},
			"notify_on_revocation": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Email the token's user when StepSecurity itself revokes the token (after the final reminder, or at the end of the non-compliance window), copying expiry_reminder_cc. Revocations a person performs from the dashboard are not notified.",
			},
			"classic_notify_on_revocation": schema.BoolAttribute{
				Optional:    true,
				Description: "Revocation notices for classic PATs. Omit to follow notify_on_revocation.",
			},
			"fine_grained_notify_on_revocation": schema.BoolAttribute{
				Optional:    true,
				Description: "Revocation notices for fine-grained PATs. Omit to follow notify_on_revocation.",
			},
			"revocation_notification_template":              patTemplateSchema("Custom revocation notice sent to the token's user, for every token class without a class template. Omit to use the built-in email. Subject and body may use {{owner}}, {{token_name}}, {{token_type}}, {{organization}}, {{revoked_at}}, {{reason}} and {{manage_url}}."),
			"classic_revocation_notification_template":      patTemplateSchema("Custom revocation notice for classic PATs. Omit to use revocation_notification_template, then the built-in email."),
			"fine_grained_revocation_notification_template": patTemplateSchema("Custom revocation notice for fine-grained PATs. Omit to use revocation_notification_template, then the built-in email."),
			"classic_noncompliant_revoke_after_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Revoke classic PATs that have remained non-compliant for this many days without an approved exception. 0 disables the control.",
				Validators:  []validator.Int64{int64validator.Between(0, maxPATThresholdDays)},
			},
			"fine_grained_noncompliant_revoke_after_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Revoke fine-grained PATs that have remained non-compliant for this many days without an approved exception. 0 disables the control.",
				Validators:  []validator.Int64{int64validator.Between(0, maxPATThresholdDays)},
			},
			"auto_revoke_after_reminders": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Revoke a token 24 hours after the last configured reminder band for its class was sent, while it is still active, whether or not it violates a control. Tokens with an approved exception are skipped; a class with no reminder bands never revokes here.",
			},
			"classic_auto_revoke_after_reminders": schema.BoolAttribute{
				Optional:    true,
				Description: "Revoke after the final reminder for classic PATs. Omit to follow auto_revoke_after_reminders.",
			},
			"fine_grained_auto_revoke_after_reminders": schema.BoolAttribute{
				Optional:    true,
				Description: "Revoke after the final reminder for fine-grained PATs. Omit to follow auto_revoke_after_reminders.",
			},
			"use_tenant_policy": schema.BoolAttribute{
				Optional:    true,
				Description: "Follow the customer's tenant-wide PAT policy instead of this organization's own settings, which stay stored but dormant. Omit or set false to enforce the settings in this resource.",
			},
		},
	}
}

// ImportState implements resource.ResourceWithImportState.
func (r *githubPATGovernancePolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should be the owner name
	owner := req.ID

	// Set the owner in the state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("owner"), owner)...)

	// Now call Read to populate the rest of the state
	readReq := resource.ReadRequest{
		State: resp.State,
	}
	readResp := &resource.ReadResponse{
		State: resp.State,
	}

	r.Read(ctx, readReq, readResp)

	// Copy any diagnostics and updated state from Read
	resp.Diagnostics.Append(readResp.Diagnostics...)
	resp.State = readResp.State
}

type githubPATGovernancePolicyModel struct {
	ID                    types.String `tfsdk:"id"`
	Owner                 types.String `tfsdk:"owner"`
	Enabled               types.Bool   `tfsdk:"enabled"`
	FineGrainedMaxAgeDays types.Int64  `tfsdk:"fine_grained_max_age_days"`
	ClassicMaxAgeDays     types.Int64  `tfsdk:"classic_max_age_days"`
	FlagNoExpiry          types.Bool   `tfsdk:"flag_no_expiry"`
	FlagOverScoped        types.Bool   `tfsdk:"flag_over_scoped"`
	OverScopedScopes      types.List   `tfsdk:"over_scoped_scopes"`
	UnusedDays            types.Int64  `tfsdk:"unused_days"`
	GitHubIssueRepo       types.String `tfsdk:"github_issue_repo"`
	ExpiryReminderDays    types.List   `tfsdk:"expiry_reminder_days"`

	FineGrainedUnusedDays         types.Int64  `tfsdk:"fine_grained_unused_days"`
	ClassicUnusedDays             types.Int64  `tfsdk:"classic_unused_days"`
	FineGrainedExpiryReminderDays types.List   `tfsdk:"fine_grained_expiry_reminder_days"`
	ClassicExpiryReminderDays     types.List   `tfsdk:"classic_expiry_reminder_days"`
	ExpiryReminderTemplates       types.Map    `tfsdk:"expiry_reminder_templates"`
	ExpiryReminderCC              types.List   `tfsdk:"expiry_reminder_cc"`
	ExpiryReminderToOwner         types.Bool   `tfsdk:"expiry_reminder_to_owner"`
	OwnerEmailFallbackDomain      types.String `tfsdk:"owner_email_fallback_domain"`

	NotifyOnRevocation                        types.Bool   `tfsdk:"notify_on_revocation"`
	ClassicNotifyOnRevocation                 types.Bool   `tfsdk:"classic_notify_on_revocation"`
	FineGrainedNotifyOnRevocation             types.Bool   `tfsdk:"fine_grained_notify_on_revocation"`
	RevocationNotificationTemplate            types.Object `tfsdk:"revocation_notification_template"`
	ClassicRevocationNotificationTemplate     types.Object `tfsdk:"classic_revocation_notification_template"`
	FineGrainedRevocationNotificationTemplate types.Object `tfsdk:"fine_grained_revocation_notification_template"`

	ClassicNoncompliantRevokeAfterDays     types.Int64 `tfsdk:"classic_noncompliant_revoke_after_days"`
	FineGrainedNoncompliantRevokeAfterDays types.Int64 `tfsdk:"fine_grained_noncompliant_revoke_after_days"`
	AutoRevokeAfterReminders               types.Bool  `tfsdk:"auto_revoke_after_reminders"`
	ClassicAutoRevokeAfterReminders        types.Bool  `tfsdk:"classic_auto_revoke_after_reminders"`
	FineGrainedAutoRevokeAfterReminders    types.Bool  `tfsdk:"fine_grained_auto_revoke_after_reminders"`
	UseTenantPolicy                        types.Bool  `tfsdk:"use_tenant_policy"`
}

// optionalBool maps an omitted attribute to nil (inherit) and a set one to a
// pointer, matching the API's three-state fields.
func optionalBool(v types.Bool) *bool {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	b := v.ValueBool()
	return &b
}

func boolFromOptional(v *bool) types.Bool {
	if v == nil {
		return types.BoolNull()
	}
	return types.BoolValue(*v)
}

func optionalInt64(v types.Int64) *int64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	i := v.ValueInt64()
	return &i
}

func int64FromOptional(v *int64) types.Int64 {
	if v == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*v)
}

// templateFromObject reads a nested template attribute; null means "no
// custom template".
func templateFromObject(ctx context.Context, v types.Object) (*stepsecurityapi.PATReminderTemplate, error) {
	if v.IsNull() || v.IsUnknown() {
		return nil, nil
	}
	var m patTemplateModel
	if diags := v.As(ctx, &m, basetypes.ObjectAsOptions{}); diags.HasError() {
		return nil, fmt.Errorf("failed to read template: %v", diags.Errors())
	}
	return &stepsecurityapi.PATReminderTemplate{Subject: m.Subject.ValueString(), Body: m.Body.ValueString()}, nil
}

func objectFromTemplate(t *stepsecurityapi.PATReminderTemplate) types.Object {
	if t == nil {
		return types.ObjectNull(patTemplateAttrTypes)
	}
	return types.ObjectValueMust(patTemplateAttrTypes, map[string]attr.Value{
		"subject": types.StringValue(t.Subject),
		"body":    types.StringValue(t.Body),
	})
}

// int64ListToAPI and stringListToAPI read optional list attributes; a null
// list stays nil so the field is omitted from the request.
func int64ListToAPI(ctx context.Context, v types.List, name string) ([]int64, error) {
	if v.IsNull() || v.IsUnknown() {
		return nil, nil
	}
	var out []int64
	if diags := v.ElementsAs(ctx, &out, false); diags.HasError() {
		return nil, fmt.Errorf("failed to convert %s: %v", name, diags.Errors())
	}
	return out, nil
}

func stringListToAPI(ctx context.Context, v types.List, name string) ([]string, error) {
	if v.IsNull() || v.IsUnknown() {
		return nil, nil
	}
	var out []string
	if diags := v.ElementsAs(ctx, &out, false); diags.HasError() {
		return nil, fmt.Errorf("failed to convert %s: %v", name, diags.Errors())
	}
	return out, nil
}

func int64ListFromAPI(ctx context.Context, values []int64) (types.List, error) {
	if len(values) == 0 {
		return types.ListNull(types.Int64Type), nil
	}
	l, diags := types.ListValueFrom(ctx, types.Int64Type, values)
	if diags.HasError() {
		return types.ListNull(types.Int64Type), fmt.Errorf("failed to convert list: %v", diags.Errors())
	}
	return l, nil
}

func stringListFromAPI(ctx context.Context, values []string) (types.List, error) {
	if len(values) == 0 {
		return types.ListNull(types.StringType), nil
	}
	l, diags := types.ListValueFrom(ctx, types.StringType, values)
	if diags.HasError() {
		return types.ListNull(types.StringType), fmt.Errorf("failed to convert list: %v", diags.Errors())
	}
	return l, nil
}

// templatesToAPI reads the class -> band -> template map.
func templatesToAPI(ctx context.Context, v types.Map) (map[string]map[string]stepsecurityapi.PATReminderTemplate, error) {
	if v.IsNull() || v.IsUnknown() {
		return nil, nil
	}
	var raw map[string]map[string]patTemplateModel
	if diags := v.ElementsAs(ctx, &raw, false); diags.HasError() {
		return nil, fmt.Errorf("failed to convert expiry_reminder_templates: %v", diags.Errors())
	}
	out := make(map[string]map[string]stepsecurityapi.PATReminderTemplate, len(raw))
	for class, bands := range raw {
		out[class] = make(map[string]stepsecurityapi.PATReminderTemplate, len(bands))
		for band, tmpl := range bands {
			out[class][band] = stepsecurityapi.PATReminderTemplate{Subject: tmpl.Subject.ValueString(), Body: tmpl.Body.ValueString()}
		}
	}
	return out, nil
}

func templatesFromAPI(ctx context.Context, in map[string]map[string]stepsecurityapi.PATReminderTemplate) (types.Map, error) {
	if len(in) == 0 {
		return types.MapNull(patTemplateBandMapType), nil
	}
	classes := make(map[string]attr.Value, len(in))
	for class, bands := range in {
		bandValues := make(map[string]attr.Value, len(bands))
		for band, tmpl := range bands {
			bandValues[band] = types.ObjectValueMust(patTemplateAttrTypes, map[string]attr.Value{
				"subject": types.StringValue(tmpl.Subject),
				"body":    types.StringValue(tmpl.Body),
			})
		}
		bandMap, diags := types.MapValue(patTemplateObjectType, bandValues)
		if diags.HasError() {
			return types.MapNull(patTemplateBandMapType), fmt.Errorf("failed to convert expiry_reminder_templates: %v", diags.Errors())
		}
		classes[class] = bandMap
	}
	m, diags := types.MapValue(patTemplateBandMapType, classes)
	if diags.HasError() {
		return types.MapNull(patTemplateBandMapType), fmt.Errorf("failed to convert expiry_reminder_templates: %v", diags.Errors())
	}
	return m, nil
}

// toAPIPolicy converts the planned model into the API request payload.
func (m *githubPATGovernancePolicyModel) toAPIPolicy(ctx context.Context) (stepsecurityapi.PATGovernancePolicy, error) {
	policy := stepsecurityapi.PATGovernancePolicy{
		Enabled:               m.Enabled.ValueBool(),
		FineGrainedMaxAgeDays: m.FineGrainedMaxAgeDays.ValueInt64(),
		ClassicMaxAgeDays:     m.ClassicMaxAgeDays.ValueInt64(),
		FlagNoExpiry:          m.FlagNoExpiry.ValueBool(),
		FlagOverScoped:        m.FlagOverScoped.ValueBool(),
		UnusedDays:            m.UnusedDays.ValueInt64(),
		GitHubIssueRepo:       m.GitHubIssueRepo.ValueString(),

		FineGrainedUnusedDays:    optionalInt64(m.FineGrainedUnusedDays),
		ClassicUnusedDays:        optionalInt64(m.ClassicUnusedDays),
		ExpiryReminderToOwner:    m.ExpiryReminderToOwner.ValueBool(),
		OwnerEmailFallbackDomain: m.OwnerEmailFallbackDomain.ValueString(),

		NotifyOnRevocation:            m.NotifyOnRevocation.ValueBool(),
		ClassicNotifyOnRevocation:     optionalBool(m.ClassicNotifyOnRevocation),
		FineGrainedNotifyOnRevocation: optionalBool(m.FineGrainedNotifyOnRevocation),

		ClassicNoncompliantRevokeAfterDays:     m.ClassicNoncompliantRevokeAfterDays.ValueInt64(),
		FineGrainedNoncompliantRevokeAfterDays: m.FineGrainedNoncompliantRevokeAfterDays.ValueInt64(),
		AutoRevokeAfterReminders:               m.AutoRevokeAfterReminders.ValueBool(),
		ClassicAutoRevokeAfterReminders:        optionalBool(m.ClassicAutoRevokeAfterReminders),
		FineGrainedAutoRevokeAfterReminders:    optionalBool(m.FineGrainedAutoRevokeAfterReminders),
		UseTenantPolicy:                        optionalBool(m.UseTenantPolicy),
	}

	var err error
	if policy.OverScopedScopes, err = stringListToAPI(ctx, m.OverScopedScopes, "over_scoped_scopes"); err != nil {
		return policy, err
	}
	if policy.ExpiryReminderDays, err = int64ListToAPI(ctx, m.ExpiryReminderDays, "expiry_reminder_days"); err != nil {
		return policy, err
	}
	if policy.FineGrainedExpiryReminderDays, err = int64ListToAPI(ctx, m.FineGrainedExpiryReminderDays, "fine_grained_expiry_reminder_days"); err != nil {
		return policy, err
	}
	if policy.ClassicExpiryReminderDays, err = int64ListToAPI(ctx, m.ClassicExpiryReminderDays, "classic_expiry_reminder_days"); err != nil {
		return policy, err
	}
	if policy.ExpiryReminderCC, err = stringListToAPI(ctx, m.ExpiryReminderCC, "expiry_reminder_cc"); err != nil {
		return policy, err
	}
	if policy.ExpiryReminderTemplates, err = templatesToAPI(ctx, m.ExpiryReminderTemplates); err != nil {
		return policy, err
	}
	if policy.RevocationNotificationTemplate, err = templateFromObject(ctx, m.RevocationNotificationTemplate); err != nil {
		return policy, err
	}
	if policy.ClassicRevocationNotificationTemplate, err = templateFromObject(ctx, m.ClassicRevocationNotificationTemplate); err != nil {
		return policy, err
	}
	if policy.FineGrainedRevocationNotificationTemplate, err = templateFromObject(ctx, m.FineGrainedRevocationNotificationTemplate); err != nil {
		return policy, err
	}

	return policy, nil
}

// setFromAPIPolicy refreshes the model from the API response.
func (m *githubPATGovernancePolicyModel) setFromAPIPolicy(ctx context.Context, policy *stepsecurityapi.PATGovernancePolicy) error {
	m.ID = types.StringValue(m.Owner.ValueString())
	m.Enabled = types.BoolValue(policy.Enabled)
	m.FineGrainedMaxAgeDays = types.Int64Value(policy.FineGrainedMaxAgeDays)
	m.ClassicMaxAgeDays = types.Int64Value(policy.ClassicMaxAgeDays)
	m.FlagNoExpiry = types.BoolValue(policy.FlagNoExpiry)
	m.FlagOverScoped = types.BoolValue(policy.FlagOverScoped)
	m.UnusedDays = types.Int64Value(policy.UnusedDays)
	m.GitHubIssueRepo = types.StringValue(policy.GitHubIssueRepo)

	m.FineGrainedUnusedDays = int64FromOptional(policy.FineGrainedUnusedDays)
	m.ClassicUnusedDays = int64FromOptional(policy.ClassicUnusedDays)
	m.ExpiryReminderToOwner = types.BoolValue(policy.ExpiryReminderToOwner)
	m.OwnerEmailFallbackDomain = types.StringValue(policy.OwnerEmailFallbackDomain)

	m.NotifyOnRevocation = types.BoolValue(policy.NotifyOnRevocation)
	m.ClassicNotifyOnRevocation = boolFromOptional(policy.ClassicNotifyOnRevocation)
	m.FineGrainedNotifyOnRevocation = boolFromOptional(policy.FineGrainedNotifyOnRevocation)
	m.RevocationNotificationTemplate = objectFromTemplate(policy.RevocationNotificationTemplate)
	m.ClassicRevocationNotificationTemplate = objectFromTemplate(policy.ClassicRevocationNotificationTemplate)
	m.FineGrainedRevocationNotificationTemplate = objectFromTemplate(policy.FineGrainedRevocationNotificationTemplate)

	m.ClassicNoncompliantRevokeAfterDays = types.Int64Value(policy.ClassicNoncompliantRevokeAfterDays)
	m.FineGrainedNoncompliantRevokeAfterDays = types.Int64Value(policy.FineGrainedNoncompliantRevokeAfterDays)
	m.AutoRevokeAfterReminders = types.BoolValue(policy.AutoRevokeAfterReminders)
	m.ClassicAutoRevokeAfterReminders = boolFromOptional(policy.ClassicAutoRevokeAfterReminders)
	m.FineGrainedAutoRevokeAfterReminders = boolFromOptional(policy.FineGrainedAutoRevokeAfterReminders)
	m.UseTenantPolicy = boolFromOptional(policy.UseTenantPolicy)

	var err error
	if m.OverScopedScopes, err = stringListFromAPI(ctx, policy.OverScopedScopes); err != nil {
		return fmt.Errorf("over_scoped_scopes: %w", err)
	}
	if m.ExpiryReminderDays, err = int64ListFromAPI(ctx, policy.ExpiryReminderDays); err != nil {
		return fmt.Errorf("expiry_reminder_days: %w", err)
	}
	if m.FineGrainedExpiryReminderDays, err = int64ListFromAPI(ctx, policy.FineGrainedExpiryReminderDays); err != nil {
		return fmt.Errorf("fine_grained_expiry_reminder_days: %w", err)
	}
	if m.ClassicExpiryReminderDays, err = int64ListFromAPI(ctx, policy.ClassicExpiryReminderDays); err != nil {
		return fmt.Errorf("classic_expiry_reminder_days: %w", err)
	}
	if m.ExpiryReminderCC, err = stringListFromAPI(ctx, policy.ExpiryReminderCC); err != nil {
		return fmt.Errorf("expiry_reminder_cc: %w", err)
	}
	if m.ExpiryReminderTemplates, err = templatesFromAPI(ctx, policy.ExpiryReminderTemplates); err != nil {
		return err
	}

	return nil
}

// Create creates the resource and sets the initial Terraform state.
func (r *githubPATGovernancePolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubPATGovernancePolicyModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := plan.toAPIPolicy(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Create PAT Governance Policy", err.Error())
		return
	}

	if err := r.client.UpdatePATGovernancePolicy(ctx, plan.Owner.ValueString(), policy); err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create PAT Governance Policy",
			err.Error(),
		)
		return
	}

	// Set the ID (use owner as the unique identifier)
	plan.ID = types.StringValue(plan.Owner.ValueString())

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *githubPATGovernancePolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state githubPATGovernancePolicyModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.GetPATGovernancePolicy(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read PAT Governance Policy",
			err.Error(),
		)
		return
	}

	// No policy of its own (the org follows the tenant-wide policy or the
	// built-in default) means the resource no longer exists.
	if policy == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	if err := state.setFromAPIPolicy(ctx, policy); err != nil {
		resp.Diagnostics.AddError("Unable to Read PAT Governance Policy", err.Error())
		return
	}

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *githubPATGovernancePolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan githubPATGovernancePolicyModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := plan.toAPIPolicy(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Update PAT Governance Policy", err.Error())
		return
	}

	if err := r.client.UpdatePATGovernancePolicy(ctx, plan.Owner.ValueString(), policy); err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update PAT Governance Policy",
			err.Error(),
		)
		return
	}

	// Set the ID (use owner as the unique identifier)
	plan.ID = types.StringValue(plan.Owner.ValueString())

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *githubPATGovernancePolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state githubPATGovernancePolicyModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Removes the org's own policy; the org then follows the customer's
	// tenant-wide policy (or the built-in default) again.
	err := r.client.DeletePATGovernancePolicy(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Delete PAT Governance Policy",
			err.Error(),
		)
		return
	}
}
