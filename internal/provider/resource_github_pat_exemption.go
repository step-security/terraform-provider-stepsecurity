package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	patExemptionScopeToken = "token"
	patExemptionScopeOwner = "owner"
	// patExemptionDefaultSource is recorded on every exemption Terraform
	// creates, so the audit trail says where it came from.
	patExemptionDefaultSource    = "terraform"
	maxPATExemptionReasonChars   = 500
	maxPATExemptionInstanceChars = 200
)

// patExemptionSuffixPattern is the lower-case form the server stores and
// lists a classic token suffix in; requiring it in the configuration keeps
// imported records free of case-only differences.
var patExemptionSuffixPattern = regexp.MustCompile(`^[a-z0-9]{8}$`)

// patExemptionRegistryLocks serializes this process's writes to one registry.
// The API keeps a registry in a single record that it reads, changes and
// writes back, so two saves running at the same time (Terraform applies
// resources in parallel) can overwrite each other's record.
var patExemptionRegistryLocks sync.Map

// lockPATExemptionRegistry takes the registry's lock and returns the unlock.
func lockPATExemptionRegistry(organization string) func() {
	name := organization
	if name == "" {
		name = "\x00tenant-wide"
	}
	entry, _ := patExemptionRegistryLocks.LoadOrStore(name, &sync.Mutex{})
	mutex := entry.(*sync.Mutex)
	mutex.Lock()
	return mutex.Unlock
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &githubPATExemptionResource{}
	_ resource.ResourceWithConfigure      = &githubPATExemptionResource{}
	_ resource.ResourceWithImportState    = &githubPATExemptionResource{}
	_ resource.ResourceWithValidateConfig = &githubPATExemptionResource{}
)

// NewGithubPATExemptionResource is a helper function to simplify the provider implementation.
func NewGithubPATExemptionResource() resource.Resource {
	return &githubPATExemptionResource{}
}

// githubPATExemptionResource manages one exemption from the PAT governance
// policy, in an organization's registry or in the tenant-wide registry.
type githubPATExemptionResource struct {
	client stepsecurityapi.Client
}

type githubPATExemptionModel struct {
	ID           types.String `tfsdk:"id"`
	Organization types.String `tfsdk:"organization"`
	Instance     types.String `tfsdk:"instance"`
	TokenSuffix  types.String `tfsdk:"token_suffix"`
	TokenID      types.Int64  `tfsdk:"token_id"`
	UserLogin    types.String `tfsdk:"user_login"`
	TokenClass   types.String `tfsdk:"token_class"`
	ExpiresAt    types.String `tfsdk:"expires_at"`
	Reason       types.String `tfsdk:"reason"`
	RecordID     types.String `tfsdk:"record_id"`
	Source       types.String `tfsdk:"source"`
	Scope        types.String `tfsdk:"scope"`
	Key          types.String `tfsdk:"key"`
	ApprovedAt   types.String `tfsdk:"approved_at"`
	CreatedBy    types.String `tfsdk:"created_by"`
}

// Configure adds the provider configured client to the resource.
func (r *githubPATExemptionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *githubPATExemptionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_pat_exemption"
}

// Schema defines the schema for the resource.
func (r *githubPATExemptionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replaceString := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	keepString := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}

	resp.Schema = schema.Schema{
		Description: "Manages one exemption from the PAT governance policy. An exempt token is not evaluated against " +
			"the policy, receives no pre-expiry reminders and is skipped by every automatic revocation until the " +
			"exemption expires, after which it re-enters normal enforcement. The exemption names either one token " +
			"(a classic token by token_suffix, a fine-grained token by token_id) or, with user_login alone, every token " +
			"of one GitHub user, current and future. It lives in the registry of one organization, or in the tenant-wide " +
			"registry when organization is omitted. The server removes a record thirty days after it expires; remove " +
			"the resource from the configuration by then, otherwise Terraform recreates it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: keepString,
				Description:   "The organization and the registry key, as organization/key; a tenant-wide exemption has an empty organization, so its ID starts with a slash.",
			},
			"organization": schema.StringAttribute{
				Optional:      true,
				PlanModifiers: replaceString,
				Description:   "The GitHub organization whose registry holds the exemption. Omit for a tenant-wide exemption, which applies to every organization of the tenant, or to the organizations of one instance when instance is set.",
			},
			"instance": schema.StringAttribute{
				Optional:      true,
				PlanModifiers: replaceString,
				Description:   "Tenant-wide exemptions only: limit the exemption to the organizations of one instance, a GitHub Enterprise Server or data residency server by its registered name, or github.com for GitHub.com organizations. Omit to cover every organization of the tenant.",
				Validators:    []validator.String{stringvalidator.LengthBetween(1, maxPATExemptionInstanceChars)},
			},
			"token_suffix": schema.StringAttribute{
				Optional:      true,
				PlanModifiers: replaceString,
				Description:   "The last eight characters of the classic token to exempt, in lower case (the form the dashboard and the API list).",
				Validators:    []validator.String{stringvalidator.RegexMatches(patExemptionSuffixPattern, "must be the last eight characters of the token, in lower case")},
			},
			"token_id": schema.Int64Attribute{
				Optional:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
				Description:   "The id of the fine-grained token to exempt: the token id shown on the Apps & PATs page, or the grant id from the token's URL in the GitHub organization settings.",
				Validators:    []validator.Int64{int64validator.AtLeast(1)},
			},
			"user_login": schema.StringAttribute{
				Optional:      true,
				PlanModifiers: replaceString,
				Description:   "GitHub login of the token's user. On its own it exempts every token of this user, current and future; together with token_suffix or token_id it narrows the exemption to that user's token.",
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"token_class": schema.StringAttribute{
				Optional:      true,
				PlanModifiers: replaceString,
				Description:   "For an exemption of every token of a user only: limit it to classic or fine_grained tokens. Omit to cover both classes.",
				Validators:    []validator.String{stringvalidator.OneOf("classic", "fine_grained")},
			},
			"expires_at": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				PlanModifiers: keepString,
				Description:   "When the exemption ends, in RFC 3339 form (for example 2026-12-31T00:00:00Z). Omit to let the server set eight days after the approval.",
			},
			"reason": schema.StringAttribute{
				Optional:    true,
				Description: "Why the exemption was granted, at most 500 characters.",
				Validators:  []validator.String{stringvalidator.LengthBetween(1, maxPATExemptionReasonChars)},
			},
			"record_id": schema.StringAttribute{
				Optional:    true,
				Description: "Reference of the approving record, for example a change ticket. Saving an exemption with a record_id replaces any earlier exemption in the same registry that carries the same record_id.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"source": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(patExemptionDefaultSource),
				Description: "Name of the approving system, recorded for audit. Defaults to terraform.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"scope": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: keepString,
				Description:   "token when the exemption names one token, owner when it covers every token of a user.",
			},
			"key": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: keepString,
				Description:   "The server's registry key for this exemption.",
			},
			"approved_at": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: keepString,
				Description:   "When the exemption was first recorded, in RFC 3339 form.",
			},
			"created_by": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: keepString,
				Description:   "The principal that recorded the exemption: the API key's identifier, or a user's email.",
			},
		},
	}
}

// ValidateConfig checks the combinations the API would reject at apply time.
func (r *githubPATExemptionResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg githubPATExemptionModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, problem := range patExemptionConfigProblems(cfg) {
		resp.Diagnostics.AddError("Invalid PAT Exemption", problem)
	}
}

// patExemptionConfigProblems lists what is wrong with a configuration. Unknown
// values (references resolved at apply) count as set, so only known values
// are inspected in detail.
func patExemptionConfigProblems(cfg githubPATExemptionModel) []string {
	var problems []string
	hasSuffix := !cfg.TokenSuffix.IsNull()
	hasID := !cfg.TokenID.IsNull()
	hasLogin := !cfg.UserLogin.IsNull()

	if hasSuffix && hasID {
		problems = append(problems, "token_suffix and token_id name different tokens; set only one of them.")
	}
	if !hasSuffix && !hasID && !hasLogin {
		problems = append(problems, "an exemption needs token_suffix (a classic token), token_id (a fine-grained token) or user_login (every token of a user).")
	}
	if !cfg.TokenClass.IsNull() && (hasSuffix || hasID) {
		problems = append(problems, "token_class applies only to an exemption of every token of a user (user_login without token_suffix or token_id); a token's class is already fixed by its identifier.")
	}
	if !cfg.Instance.IsNull() && !cfg.Organization.IsNull() {
		problems = append(problems, "instance applies only to tenant-wide exemptions; remove organization to make this exemption tenant-wide, or remove instance.")
	}
	if !cfg.ExpiresAt.IsNull() && !cfg.ExpiresAt.IsUnknown() {
		if _, err := time.Parse(time.RFC3339, cfg.ExpiresAt.ValueString()); err != nil {
			problems = append(problems, "expires_at must be an RFC 3339 timestamp such as 2026-12-31T00:00:00Z.")
		}
	}
	return problems
}

// knownString returns the value of a known, non-null string, else "".
func knownString(v types.String) string {
	if v.IsNull() || v.IsUnknown() {
		return ""
	}
	return v.ValueString()
}

// toAPIRecord builds the request payload. approvedAt carries the original
// approval time across updates, since the API treats every save as new.
func (m *githubPATExemptionModel) toAPIRecord(approvedAt string) stepsecurityapi.PATExemption {
	record := stepsecurityapi.PATExemption{
		TokenSuffix: knownString(m.TokenSuffix),
		Owner:       knownString(m.UserLogin),
		ExpiresAt:   knownString(m.ExpiresAt),
		Reason:      knownString(m.Reason),
		RecordID:    knownString(m.RecordID),
		Source:      knownString(m.Source),
		Instance:    knownString(m.Instance),
		ApprovedAt:  approvedAt,
	}
	if !m.TokenID.IsNull() && !m.TokenID.IsUnknown() {
		record.TokenID = m.TokenID.ValueInt64()
	}
	if record.TokenSuffix == "" && record.TokenID == 0 {
		record.Scope = patExemptionScopeOwner
		record.TokenClass = knownString(m.TokenClass)
	} else {
		record.Scope = patExemptionScopeToken
	}
	return record
}

// optionalStringFromAPI keeps an omitted attribute null when the API has no
// value for it, so a configuration that never set it does not drift.
func optionalStringFromAPI(value string) types.String {
	if value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}

// setFromAPI refreshes the model from a registry row. The user login,
// token class and instance keep the configured spelling when the server only
// changed their case; the token suffix is lower case on both sides.
func (m *githubPATExemptionModel) setFromAPI(record *stepsecurityapi.PATExemption) {
	m.TokenSuffix = optionalStringFromAPI(record.TokenSuffix)
	if record.TokenID > 0 {
		m.TokenID = types.Int64Value(record.TokenID)
	} else {
		m.TokenID = types.Int64Null()
	}
	if !strings.EqualFold(knownString(m.UserLogin), record.Owner) {
		m.UserLogin = optionalStringFromAPI(record.Owner)
	}
	if !strings.EqualFold(knownString(m.TokenClass), record.TokenClass) {
		m.TokenClass = optionalStringFromAPI(record.TokenClass)
	}
	if !strings.EqualFold(knownString(m.Instance), record.Instance) {
		m.Instance = optionalStringFromAPI(record.Instance)
	}
	m.Reason = optionalStringFromAPI(record.Reason)
	m.RecordID = optionalStringFromAPI(record.RecordID)
	m.ExpiresAt = types.StringValue(record.ExpiresAt)
	m.Source = types.StringValue(record.Source)
	scope := strings.ToLower(record.Scope)
	if scope == "" {
		scope = patExemptionScopeToken
	}
	m.Scope = types.StringValue(scope)
	m.Key = types.StringValue(record.Key)
	m.ApprovedAt = types.StringValue(record.ApprovedAt)
	m.CreatedBy = types.StringValue(record.CreatedBy)
	m.ID = types.StringValue(patExemptionID(knownString(m.Organization), record.Key))
}

// patExemptionID joins the registry and the key: organization/key, or /key for
// the tenant-wide registry.
func patExemptionID(organization, key string) string {
	return organization + "/" + key
}

// parsePATExemptionID splits an import ID at its first slash. Keys may contain
// slashes (instance-limited ones do), organizations never do.
func parsePATExemptionID(id string) (organization, key string, err error) {
	organization, key, found := strings.Cut(id, "/")
	if !found || key == "" {
		return "", "", fmt.Errorf("import ID %q must be organization/key, or /key for a tenant-wide exemption", id)
	}
	return organization, key, nil
}

// exemptionMatches reports whether a registry row is the record the model
// describes: same identity, compared the way the server builds its key.
func exemptionMatches(row stepsecurityapi.PATExemption, want stepsecurityapi.PATExemption) bool {
	if !strings.EqualFold(row.Instance, want.Instance) {
		return false
	}
	rowOwnerScoped := strings.EqualFold(row.Scope, patExemptionScopeOwner)
	if want.Scope == patExemptionScopeOwner {
		return rowOwnerScoped && strings.EqualFold(row.Owner, want.Owner) && strings.EqualFold(row.TokenClass, want.TokenClass)
	}
	if rowOwnerScoped {
		return false
	}
	if want.TokenSuffix != "" {
		return strings.EqualFold(row.TokenSuffix, want.TokenSuffix)
	}
	return want.TokenID > 0 && row.TokenID == want.TokenID
}

// findByIdentity looks the saved record up in its registry to learn the key
// and the server-side fields. The registry is read with eventual consistency,
// so a record saved a moment ago may take a retry to show up.
func (r *githubPATExemptionResource) findByIdentity(ctx context.Context, organization string, want stepsecurityapi.PATExemption) (*stepsecurityapi.PATExemption, error) {
	for attempt := 0; attempt < 5; attempt++ {
		rows, err := r.client.ListPATExemptions(ctx, organization)
		if err != nil {
			return nil, err
		}
		for i := range rows {
			if exemptionMatches(rows[i], want) {
				return &rows[i], nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 400 * time.Millisecond):
		}
	}
	return nil, nil
}

// findByKey looks a record up by its registry key.
func (r *githubPATExemptionResource) findByKey(ctx context.Context, organization, key string) (*stepsecurityapi.PATExemption, error) {
	rows, err := r.client.ListPATExemptions(ctx, organization)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Key == key {
			return &rows[i], nil
		}
	}
	return nil, nil
}

// save writes the planned record and refreshes the model from the registry.
func (r *githubPATExemptionResource) save(ctx context.Context, plan *githubPATExemptionModel, approvedAt, summary string, addError func(summary, detail string)) {
	organization := knownString(plan.Organization)
	record := plan.toAPIRecord(approvedAt)
	unlock := lockPATExemptionRegistry(organization)
	defer unlock()
	if _, err := r.client.UpsertPATExemption(ctx, organization, record); err != nil {
		addError(summary, err.Error())
		return
	}
	saved, err := r.findByIdentity(ctx, organization, record)
	if err != nil {
		addError(summary, err.Error())
		return
	}
	if saved == nil {
		addError(summary, "the exemption was saved but the registry does not list it; it may already have expired")
		return
	}
	plan.setFromAPI(saved)
}

// Create records the exemption and sets the initial Terraform state.
func (r *githubPATExemptionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubPATExemptionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.save(ctx, &plan, "", "Unable to Create PAT Exemption", resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state from the registry.
func (r *githubPATExemptionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state githubPATExemptionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	organization := knownString(state.Organization)
	key := knownString(state.Key)
	if key == "" {
		var err error
		if organization, key, err = parsePATExemptionID(knownString(state.ID)); err != nil {
			resp.Diagnostics.AddError("Unable to Read PAT Exemption", err.Error())
			return
		}
		state.Organization = optionalStringFromAPI(organization)
	}

	record, err := r.findByKey(ctx, organization, key)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Read PAT Exemption", err.Error())
		return
	}

	// Gone from the registry (deleted elsewhere, or purged after expiry).
	if record == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.setFromAPI(record)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update rewrites the record with the same identity and new details, keeping
// the original approval time.
func (r *githubPATExemptionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state githubPATExemptionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.save(ctx, &plan, knownString(state.ApprovedAt), "Unable to Update PAT Exemption", resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete removes the record from its registry.
func (r *githubPATExemptionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state githubPATExemptionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	unlock := lockPATExemptionRegistry(knownString(state.Organization))
	defer unlock()
	if err := r.client.DeletePATExemption(ctx, knownString(state.Organization), knownString(state.Key)); err != nil {
		resp.Diagnostics.AddError("Unable to Delete PAT Exemption", err.Error())
	}
}

// ImportState accepts organization/key (or /key for a tenant-wide exemption),
// as listed by the API, and reads the record.
func (r *githubPATExemptionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	organization, key, err := parsePATExemptionID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key"), key)...)
	if organization != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("organization"), organization)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	readResp := &resource.ReadResponse{State: resp.State}
	r.Read(ctx, resource.ReadRequest{State: resp.State}, readResp)
	resp.Diagnostics.Append(readResp.Diagnostics...)
	resp.State = readResp.State
}
