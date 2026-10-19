package stepsecurityapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Both list endpoints mix in rows of the other level for display; the client
// must return only the registry it was asked for.
func TestListPATExemptions_KeepsOnlyTheRequestedRegistry(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/github/widgets/apps/pats/approvals":
			_, _ = w.Write([]byte(`{"approvals":[
				{"token_suffix":"abcd1234","key":"abcd1234"},
				{"token_suffix":"ffff0000","organization":"Tenant-wide","key":"ffff0000"}]}`))
		case "/v1/test-customer/github/pats/approvals":
			_, _ = w.Write([]byte(`{"approvals":[
				{"token_suffix":"abcd1234","organization":"widgets","key":"abcd1234"},
				{"token_suffix":"ffff0000","organization":"Tenant-wide","key":"ffff0000"},
				{"owner":"someone","scope":"owner","instance":"ghes.example.com","organization":"Tenant-wide","key":"instance:ghes.example.com/owner:someone"}]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}

	organization, err := client.ListPATExemptions(context.Background(), "widgets")
	require.NoError(t, err)
	require.Len(t, organization, 1, "the tenant-wide row shown for display is not the organization's")
	assert.Equal(t, "abcd1234", organization[0].Key)

	tenant, err := client.ListPATExemptions(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, tenant, 2, "rolled-up organization rows are not tenant-wide records")
	assert.Equal(t, "ffff0000", tenant[0].Key)
	assert.Equal(t, "instance:ghes.example.com/owner:someone", tenant[1].Key)
}

func TestUpsertAndDeletePATExemption_UseTheRegistryRoutes(t *testing.T) {
	t.Parallel()

	var method, path, rawQuery, keyParam string
	var sent map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, rawQuery, keyParam = r.Method, r.URL.Path, r.URL.RawQuery, r.URL.Query().Get("key")
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			require.NoError(t, json.NewDecoder(r.Body).Decode(&sent))
			_, _ = w.Write([]byte(`{"approval":{"token_suffix":"abcd1234","scope":"token","expires_at":"2026-10-27T00:00:00Z","source":"terraform","reason":"why","approved_at":"2026-10-19T00:00:00Z","created_by":"key-1"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"deleted"}`))
	}))
	defer server.Close()
	client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}

	saved, err := client.UpsertPATExemption(context.Background(), "widgets", PATExemption{TokenSuffix: "abcd1234", Scope: "token", Source: "terraform", Reason: "why"})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, method)
	assert.Equal(t, "/v1/github/widgets/apps/pats/approvals", path)
	assert.Equal(t, "abcd1234", sent["token_suffix"])
	assert.Equal(t, "token", sent["scope"])
	assert.NotContains(t, sent, "token_id", "an unset identifier is omitted, not sent as zero")
	assert.NotContains(t, sent, "key")
	assert.NotContains(t, sent, "organization")
	assert.Equal(t, "2026-10-27T00:00:00Z", saved.ExpiresAt)
	assert.Equal(t, "key-1", saved.CreatedBy)

	// Tenant-wide delete: the key goes in the query string, fully escaped.
	require.NoError(t, client.DeletePATExemption(context.Background(), "", "instance:ghes.example.com/owner:someone#classic"))
	assert.Equal(t, http.MethodDelete, method)
	assert.Equal(t, "/v1/test-customer/github/pats/approvals", path)
	assert.Equal(t, "instance:ghes.example.com/owner:someone#classic", keyParam)
	assert.Equal(t, "key=instance%3Aghes.example.com%2Fowner%3Asomeone%23classic", rawQuery)
}

func TestTenantPATGovernancePolicyClient_Read(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		response string
		want     *PATGovernancePolicy
	}{
		{
			name:     "stored tenant policy",
			response: `{"policy":{"enabled":true,"classic_max_age_days":30},"has_tenant_policy":true}`,
			want:     &PATGovernancePolicy{Enabled: true, ClassicMaxAgeDays: 30},
		},
		{
			// The server shows the built-in default for display; it is not a resource.
			name:     "nothing stored",
			response: `{"policy":{"enabled":true,"classic_max_age_days":7},"has_tenant_policy":false}`,
			want:     nil,
		},
		{
			name:     "older server without the flag",
			response: `{"policy":{"enabled":true,"classic_max_age_days":7}}`,
			want:     &PATGovernancePolicy{Enabled: true, ClassicMaxAgeDays: 7},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "/v1/test-customer/github/pat-policy", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.response))
			}))
			defer server.Close()
			client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}
			got, err := client.GetTenantPATGovernancePolicy(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTenantPATGovernancePolicyClient_WriteAndDelete(t *testing.T) {
	t.Parallel()

	var methods []string
	var sent map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/test-customer/github/pat-policy", r.URL.Path)
		methods = append(methods, r.Method)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			require.NoError(t, json.NewDecoder(r.Body).Decode(&sent))
			_, _ = w.Write([]byte(`{"policy":{}}`))
			return
		}
		_, _ = w.Write([]byte(`{"deleted":true}`))
	}))
	defer server.Close()
	client := &APIClient{HTTPClient: server.Client(), BaseURL: server.URL, Customer: "test-customer"}

	require.NoError(t, client.UpdateTenantPATGovernancePolicy(context.Background(), PATGovernancePolicy{Enabled: true, FlagNoExpiry: true}))
	assert.Equal(t, true, sent["enabled"])
	assert.Equal(t, true, sent["flag_no_expiry"])
	assert.NotContains(t, sent, "use_tenant_policy")
	require.NoError(t, client.DeleteTenantPATGovernancePolicy(context.Background()))
	assert.Equal(t, []string{http.MethodPut, http.MethodDelete}, methods)
}
