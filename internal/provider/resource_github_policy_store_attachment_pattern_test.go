package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var patternTestRepoAttrTypes = map[string]attr.Type{
	"name":          types.StringType,
	"apply_to_repo": types.BoolType,
	"workflows":     types.ListType{ElemType: types.StringType},
}

// patternTestRepoObject builds a repository attachment object for validator tests.
// A nil workflows slice produces a null list; an empty slice produces an empty list.
func patternTestRepoObject(name string, applyToRepo bool, workflows []string) attr.Value {
	var workflowsList types.List
	if workflows == nil {
		workflowsList = types.ListNull(types.StringType)
	} else {
		workflowValues := make([]attr.Value, 0, len(workflows))
		for _, workflow := range workflows {
			workflowValues = append(workflowValues, types.StringValue(workflow))
		}
		workflowsList = types.ListValueMust(types.StringType, workflowValues)
	}

	return types.ObjectValueMust(patternTestRepoAttrTypes, map[string]attr.Value{
		"name":          types.StringValue(name),
		"apply_to_repo": types.BoolValue(applyToRepo),
		"workflows":     workflowsList,
	})
}

func TestRepoPatternValidator(t *testing.T) {
	t.Parallel()

	repoObjType := types.ObjectType{AttrTypes: patternTestRepoAttrTypes}

	tests := []struct {
		name       string
		repos      []attr.Value
		wantErrors int
		wantSubstr string
	}{
		{
			name:       "exact repo without workflows is valid",
			repos:      []attr.Value{patternTestRepoObject("widgets", true, nil)},
			wantErrors: 0,
		},
		{
			name:       "exact repo with workflows is valid",
			repos:      []attr.Value{patternTestRepoObject("widgets", false, []string{"ci.yml"})},
			wantErrors: 0,
		},
		{
			name:       "wildcard all repos with workflow is valid",
			repos:      []attr.Value{patternTestRepoObject("*", false, []string{"security-scan.yml"})},
			wantErrors: 0,
		},
		{
			name:       "prefix pattern with workflow is valid",
			repos:      []attr.Value{patternTestRepoObject("service-*", false, []string{"security-scan.yml"})},
			wantErrors: 0,
		},
		{
			name:       "pattern with null workflows is rejected",
			repos:      []attr.Value{patternTestRepoObject("service-*", false, nil)},
			wantErrors: 1,
			wantSubstr: "requires at least one workflow",
		},
		{
			name:       "pattern with empty workflows is rejected",
			repos:      []attr.Value{patternTestRepoObject("service-*", false, []string{})},
			wantErrors: 1,
			wantSubstr: "requires at least one workflow",
		},
		{
			name:       "consecutive stars are rejected",
			repos:      []attr.Value{patternTestRepoObject("svc-**", false, []string{"ci.yml"})},
			wantErrors: 1,
			wantSubstr: "consecutive '*' are not allowed",
		},
		{
			name:       "wildcard in workflow name is rejected",
			repos:      []attr.Value{patternTestRepoObject("*", false, []string{"ci-*.yml"})},
			wantErrors: 1,
			wantSubstr: "must not contain '*'",
		},
		{
			name:       "wildcard in workflow name with exact repo is rejected",
			repos:      []attr.Value{patternTestRepoObject("widgets", false, []string{"ci-*.yml"})},
			wantErrors: 1,
			wantSubstr: "must not contain '*'",
		},
		{
			name: "mixed exact and pattern entries are valid",
			repos: []attr.Value{
				patternTestRepoObject("widgets", true, nil),
				patternTestRepoObject("service-*", false, []string{"security-scan.yml"}),
			},
			wantErrors: 0,
		},
		{
			name: "only the invalid entry is flagged",
			repos: []attr.Value{
				patternTestRepoObject("widgets", true, nil),
				patternTestRepoObject("service-*", false, nil),
			},
			wantErrors: 1,
			wantSubstr: "requires at least one workflow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := validator.ListRequest{
				Path:        path.Root("org").AtName("repositories"),
				ConfigValue: types.ListValueMust(repoObjType, tt.repos),
			}
			resp := &validator.ListResponse{}

			repoPatternValidator{}.ValidateList(context.Background(), req, resp)

			if got := resp.Diagnostics.ErrorsCount(); got != tt.wantErrors {
				t.Fatalf("expected %d errors, got %d: %v", tt.wantErrors, got, resp.Diagnostics.Errors())
			}

			if tt.wantSubstr != "" {
				found := false
				for _, diag := range resp.Diagnostics.Errors() {
					if strings.Contains(diag.Detail(), tt.wantSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected an error containing %q, got: %v", tt.wantSubstr, resp.Diagnostics.Errors())
				}
			}
		})
	}
}

func TestRepoPatternValidator_NullAndUnknown(t *testing.T) {
	t.Parallel()

	repoObjType := types.ObjectType{AttrTypes: patternTestRepoAttrTypes}

	// Null list is skipped entirely
	req := validator.ListRequest{
		Path:        path.Root("org").AtName("repositories"),
		ConfigValue: types.ListNull(repoObjType),
	}
	resp := &validator.ListResponse{}
	repoPatternValidator{}.ValidateList(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("expected no errors for null list, got: %v", resp.Diagnostics.Errors())
	}

	// Unknown list is skipped entirely
	req = validator.ListRequest{
		Path:        path.Root("org").AtName("repositories"),
		ConfigValue: types.ListUnknown(repoObjType),
	}
	resp = &validator.ListResponse{}
	repoPatternValidator{}.ValidateList(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("expected no errors for unknown list, got: %v", resp.Diagnostics.Errors())
	}

	// Pattern entry with unknown workflows must not fail at plan time
	repoWithUnknownWorkflows := types.ObjectValueMust(patternTestRepoAttrTypes, map[string]attr.Value{
		"name":          types.StringValue("service-*"),
		"apply_to_repo": types.BoolValue(false),
		"workflows":     types.ListUnknown(types.StringType),
	})
	req = validator.ListRequest{
		Path:        path.Root("org").AtName("repositories"),
		ConfigValue: types.ListValueMust(repoObjType, []attr.Value{repoWithUnknownWorkflows}),
	}
	resp = &validator.ListResponse{}
	repoPatternValidator{}.ValidateList(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("expected no errors for unknown workflows, got: %v", resp.Diagnostics.Errors())
	}
}
