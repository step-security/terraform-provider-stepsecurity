package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	res "github.com/hashicorp/terraform-plugin-testing/helper/resource"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// TestAccRoleResource is a standard CRUD acceptance test: create a role,
// import it, then update it (rename + add a permission). Acceptance tests
// require TF_ACC=1 and a live STEP_SECURITY_API_KEY/CUSTOMER.
func TestAccRoleResource(t *testing.T) {
	res.Test(t, res.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []res.TestStep{
			// Create + Read
			{
				Config: testProviderConfig() + `
resource "stepsecurity_role" "test" {
  name        = "tf-acc-test-role"
  description = "acceptance-test role"
  permissions = [
    { resource = "detections",   action = "read" },
    { resource = "run-policies", action = "read" },
  ]
}
`,
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_role.test", "name", "tf-acc-test-role"),
					res.TestCheckResourceAttr("stepsecurity_role.test", "description", "acceptance-test role"),
					res.TestCheckResourceAttr("stepsecurity_role.test", "permissions.#", "2"),
					res.TestCheckResourceAttrSet("stepsecurity_role.test", "id"),
				),
			},
			// Import
			{
				ResourceName:      "stepsecurity_role.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Rename + add a permission
			{
				Config: testProviderConfig() + `
resource "stepsecurity_role" "test" {
  name        = "tf-acc-test-role-renamed"
  description = "acceptance-test role"
  permissions = [
    { resource = "detections",    action = "read" },
    { resource = "run-policies",  action = "read" },
    { resource = "developer-mdm", action = "read" },
  ]
}
`,
				Check: res.ComposeAggregateTestCheckFunc(
					res.TestCheckResourceAttr("stepsecurity_role.test", "name", "tf-acc-test-role-renamed"),
					res.TestCheckResourceAttr("stepsecurity_role.test", "permissions.#", "3"),
				),
			},
		},
	})
}

// Unit-level checks (no live API needed).
func TestRoleResource_Metadata(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		providerType string
		expected     string
	}{
		{"stepsecurity", "stepsecurity_role"},
		{"custom", "custom_role"},
	} {
		t.Run(tc.providerType, func(t *testing.T) {
			t.Parallel()
			r := &roleResource{}
			req := resource.MetadataRequest{ProviderTypeName: tc.providerType}
			resp := &resource.MetadataResponse{}
			r.Metadata(context.Background(), req, resp)
			if resp.TypeName != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, resp.TypeName)
			}
		})
	}
}

func TestRoleResource_Schema(t *testing.T) {
	t.Parallel()
	r := &roleResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema returned diagnostics: %v", resp.Diagnostics)
	}
	for _, attr := range []string{"id", "name", "description", "permissions"} {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing attribute %q in schema", attr)
		}
	}
	if !resp.Schema.Attributes["id"].IsComputed() {
		t.Error("id must be computed")
	}
	if !resp.Schema.Attributes["name"].IsRequired() {
		t.Error("name must be required")
	}
	if !resp.Schema.Attributes["permissions"].IsRequired() {
		t.Error("permissions must be required")
	}
}

func TestRoleResource_Configure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		data        any
		wantErr     bool
		errContains string
	}{
		{name: "valid_client", data: &stepsecurityapi.MockStepSecurityClient{}},
		{name: "nil_data", data: nil},
		{name: "wrong_type", data: "not-a-client", wantErr: true, errContains: "Unexpected Resource Configure Type"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &roleResource{}
			req := resource.ConfigureRequest{ProviderData: tc.data}
			resp := &resource.ConfigureResponse{}
			r.Configure(context.Background(), req, resp)

			if tc.wantErr {
				if !resp.Diagnostics.HasError() {
					t.Fatal("expected error but got none")
				}
				found := false
				for _, d := range resp.Diagnostics.Errors() {
					if strings.Contains(d.Summary(), tc.errContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing %q, got %v", tc.errContains, resp.Diagnostics)
				}
			} else if resp.Diagnostics.HasError() {
				t.Errorf("unexpected error: %v", resp.Diagnostics)
			}
		})
	}
}

// permissionsMatchAsSets is the order-insensitive comparator used by
// applyAPIToState. Verify the obvious cases plus the tricky one: permissions
// list of identical length but different members.
func TestPermissionsMatchAsSets(t *testing.T) {
	t.Parallel()
	mkState := func(pairs ...[2]string) []rolePermissionTF {
		out := make([]rolePermissionTF, 0, len(pairs))
		for _, p := range pairs {
			out = append(out, rolePermissionTF{
				Resource: types.StringValue(p[0]),
				Action:   types.StringValue(p[1]),
			})
		}
		return out
	}
	mkAPI := func(pairs ...[2]string) []stepsecurityapi.Permission {
		out := make([]stepsecurityapi.Permission, 0, len(pairs))
		for _, p := range pairs {
			out = append(out, stepsecurityapi.Permission{Resource: p[0], Action: p[1]})
		}
		return out
	}

	for _, tc := range []struct {
		name  string
		state []rolePermissionTF
		api   []stepsecurityapi.Permission
		want  bool
	}{
		{
			name:  "empty_match",
			state: mkState(),
			api:   mkAPI(),
			want:  true,
		},
		{
			name:  "same_order",
			state: mkState([2]string{"detections", "read"}, [2]string{"run-policies", "read"}),
			api:   mkAPI([2]string{"detections", "read"}, [2]string{"run-policies", "read"}),
			want:  true,
		},
		{
			name:  "reordered",
			state: mkState([2]string{"detections", "read"}, [2]string{"run-policies", "read"}),
			api:   mkAPI([2]string{"run-policies", "read"}, [2]string{"detections", "read"}),
			want:  true,
		},
		{
			name:  "different_count",
			state: mkState([2]string{"detections", "read"}),
			api:   mkAPI([2]string{"detections", "read"}, [2]string{"run-policies", "read"}),
			want:  false,
		},
		{
			name:  "same_count_different_members",
			state: mkState([2]string{"detections", "read"}, [2]string{"baseline", "read"}),
			api:   mkAPI([2]string{"detections", "read"}, [2]string{"run-policies", "read"}),
			want:  false,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := permissionsMatchAsSets(tc.state, tc.api)
			if got != tc.want {
				t.Errorf("permissionsMatchAsSets(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
