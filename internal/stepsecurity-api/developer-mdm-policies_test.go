package stepsecurityapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(server *httptest.Server) *APIClient {
	return &APIClient{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
		APIKey:     "key",
		Customer:   "test-customer",
	}
}

func TestDeveloperMDMPolicyClient_CreatePolicy(t *testing.T) {
	t.Parallel()

	var gotPath, gotMethod, gotAuth string
	var gotBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusCreated)
		//nolint:errcheck
		w.Write([]byte(`{"customer_id":"test-customer","policy_id":"p1","name":"allow","category":"ide_extension","target":"vscode","spec_version":1,"mode":"allowlist","spec":{"rules":[{"publisher":"ms-python","name":"python","stable":true}]}}`))
	}))
	defer server.Close()

	c := newTestClient(server)
	req := DeveloperMDMPolicyRequest{
		Name:        "allow",
		Category:    DeveloperMDMCategoryIDEExtension,
		Target:      DeveloperMDMTargetVSCode,
		SpecVersion: DeveloperMDMSpecVersionIDEExtension,
		Mode:        DeveloperMDMModeAllowlist,
		Spec:        json.RawMessage(`{"rules":[{"publisher":"ms-python","name":"python","stable":true}]}`),
	}

	got, err := c.CreateDeveloperMDMPolicy(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/v1/test-customer/developer-mdm/policies", gotPath)
	assert.Equal(t, "Bearer key", gotAuth)
	assert.Equal(t, "ide_extension", gotBody["category"])
	assert.Equal(t, "vscode", gotBody["target"])
	assert.Equal(t, float64(1), gotBody["spec_version"])
	assert.Equal(t, "allowlist", gotBody["mode"])
	spec, ok := gotBody["spec"].(map[string]any)
	require.True(t, ok, "spec should be an object")
	rules, ok := spec["rules"].([]any)
	require.True(t, ok, "spec.rules should be an array")
	assert.Len(t, rules, 1)

	assert.Equal(t, "p1", got.PolicyID)
	assert.Equal(t, "ide_extension", got.Category)
	assert.Equal(t, "vscode", got.Target)
}

func TestDeveloperMDMPolicyClient_ListPolicies(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/v1/test-customer/developer-mdm/policies", r.URL.Path)
		//nolint:errcheck
		w.Write([]byte(`{"policies":[{"policy_id":"p1","name":"allow","category":"ide_extension","target":"vscode"}],"count":1}`))
	}))
	defer server.Close()

	c := newTestClient(server)
	got, err := c.ListDeveloperMDMPolicies(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "p1", got[0].PolicyID)
	assert.Equal(t, "ide_extension", got[0].Category)
	assert.Equal(t, "vscode", got[0].Target)
}

func TestDeveloperMDMPolicyClient_GetUpdateDeletePolicy(t *testing.T) {
	t.Parallel()

	var methods []string
	var paths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.EscapedPath())
		switch r.Method {
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			//nolint:errcheck
			w.Write([]byte(`{"policy_id":"p 1","name":"allow","category":"ide_extension","target":"vscode","mode":"allowlist"}`))
		}
	}))
	defer server.Close()

	c := newTestClient(server)
	ctx := context.Background()

	// Space in ID verifies url.QueryEscape on the path segment.
	getPolicy, err := c.GetDeveloperMDMPolicy(ctx, "p 1")
	require.NoError(t, err)
	assert.Equal(t, "p 1", getPolicy.PolicyID)

	_, err = c.UpdateDeveloperMDMPolicy(ctx, "p 1", DeveloperMDMPolicyRequest{Name: "allow", Category: DeveloperMDMCategoryIDEExtension, Target: DeveloperMDMTargetVSCode, SpecVersion: 1, Mode: DeveloperMDMModeAllowlist, Spec: json.RawMessage(`{"rules":[]}`)})
	require.NoError(t, err)

	require.NoError(t, c.DeleteDeveloperMDMPolicy(ctx, "p 1"))

	assert.Equal(t, []string{http.MethodGet, http.MethodPut, http.MethodDelete}, methods)
	for _, p := range paths {
		assert.Equal(t, "/v1/test-customer/developer-mdm/policies/p%201", p)
	}
}

func TestDeveloperMDMPolicyClient_ProfileCRUD(t *testing.T) {
	t.Parallel()

	var createBody map[string]any
	var methods []string
	var paths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		switch {
		case r.Method == http.MethodPost:
			require.NoError(t, json.NewDecoder(r.Body).Decode(&createBody))
			//nolint:errcheck
			w.Write([]byte(`{"profile_id":"prof1","name":"eng","policy_ids":["p1"],"assignment":{"all_devices":true}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/profiles"):
			// List endpoint returns the wrapped collection, not a bare object.
			//nolint:errcheck
			w.Write([]byte(`{"profiles":[{"profile_id":"prof1","name":"eng","policy_ids":["p1"],"assignment":{"all_devices":true}}],"count":1}`))
		case r.Method == http.MethodGet:
			//nolint:errcheck
			w.Write([]byte(`{"profile_id":"prof1","name":"eng","policy_ids":["p1"],"assignment":{"all_devices":true}}`))
		case r.Method == http.MethodPut:
			//nolint:errcheck
			w.Write([]byte(`{"profile_id":"prof1","name":"eng2","policy_ids":["p1"],"assignment":{"all_devices":false,"device_ids":["d1"]}}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	c := newTestClient(server)
	ctx := context.Background()

	created, err := c.CreateDeveloperMDMProfile(ctx, DeveloperMDMProfileRequest{
		Name:       "eng",
		PolicyIDs:  []string{"p1"},
		Assignment: DeveloperMDMAssignment{AllDevices: true},
	})
	require.NoError(t, err)
	assert.Equal(t, "prof1", created.ProfileID)
	assert.True(t, created.Assignment.AllDevices)
	assert.Equal(t, []any{"p1"}, createBody["policy_ids"])

	list, err := c.ListDeveloperMDMProfiles(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "prof1", list[0].ProfileID)
	assert.Equal(t, []string{"p1"}, list[0].PolicyIDs)

	got, err := c.GetDeveloperMDMProfile(ctx, "prof1")
	require.NoError(t, err)
	assert.Equal(t, []string{"p1"}, got.PolicyIDs)

	updated, err := c.UpdateDeveloperMDMProfile(ctx, "prof1", DeveloperMDMProfileRequest{
		Name:       "eng2",
		PolicyIDs:  []string{"p1"},
		Assignment: DeveloperMDMAssignment{DeviceIDs: []string{"d1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"d1"}, updated.Assignment.DeviceIDs)

	require.NoError(t, c.DeleteDeveloperMDMProfile(ctx, "prof1"))

	assert.Contains(t, paths, "/v1/test-customer/developer-mdm/profiles")
	assert.Contains(t, paths, "/v1/test-customer/developer-mdm/profiles/prof1")
}

func TestDeveloperMDMPolicyClient_ExportProfile(t *testing.T) {
	t.Parallel()

	var gotQuery map[string][]string
	var gotPath string

	// The HTTP body serializes content as a JSON string with escaped
	// newlines and quotes. json.Unmarshal must decode it to the real body.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query()
		//nolint:errcheck
		w.Write([]byte(`{"os":"linux","category":"ide_extension","target":"vscode","filename":"policy.json","content_type":"application/json; charset=utf-8","content":"{\n  \"AllowedExtensions\": \"{\\\"*\\\":false}\"\n}\n","hash":"sha256:abc","notes":"Place at /etc/vscode/policy.json"}`))
	}))
	defer server.Close()

	c := newTestClient(server)
	got, err := c.ExportDeveloperMDMProfile(context.Background(), "prof1", "linux", DeveloperMDMCategoryIDEExtension, DeveloperMDMTargetVSCode)
	require.NoError(t, err)

	assert.Equal(t, "/v1/test-customer/developer-mdm/profiles/prof1/export", gotPath)
	assert.Equal(t, []string{"linux"}, gotQuery["os"])
	assert.Equal(t, []string{"ide_extension"}, gotQuery["category"])
	assert.Equal(t, []string{"vscode"}, gotQuery["target"])

	assert.Equal(t, "policy.json", got.Filename)
	assert.Equal(t, "vscode", got.Target)
	assert.Equal(t, "sha256:abc", got.Hash)
	// Decoded content must contain a real newline and the literal key, not escaped sequences.
	assert.Contains(t, got.Content, "\n")
	assert.Contains(t, got.Content, `"AllowedExtensions"`)
	assert.NotContains(t, got.Content, `\n`)
}

func TestDeveloperMDMPolicyClient_Compliance(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/devices/"):
			assert.Equal(t, "/v1/test-customer/developer-mdm/devices/dev1/compliance", r.URL.Path)
			//nolint:errcheck
			w.Write([]byte(`{"device_id":"dev1","compliance":[{"device_id":"dev1","category":"ide_extension","target":"vscode","state":"compliant","last_seen_at":1780000000}]}`))
		case strings.Contains(r.URL.Path, "/profiles/"):
			assert.Equal(t, "/v1/test-customer/developer-mdm/profiles/prof1/compliance", r.URL.Path)
			//nolint:errcheck
			w.Write([]byte(`{"profile_id":"prof1","compliance":[{"device_id":"dev1","category":"ide_extension","target":"vscode","profile_id":"prof1","state":"pending"}]}`))
		}
	}))
	defer server.Close()

	c := newTestClient(server)
	ctx := context.Background()

	dev, err := c.GetDeveloperMDMDeviceCompliance(ctx, "dev1")
	require.NoError(t, err)
	assert.Equal(t, "dev1", dev.DeviceID)
	require.Len(t, dev.Compliance, 1)
	assert.Equal(t, "vscode", dev.Compliance[0].Target)
	assert.Equal(t, "compliant", dev.Compliance[0].State)
	assert.Equal(t, int64(1780000000), dev.Compliance[0].LastSeenAt)

	prof, err := c.GetDeveloperMDMProfileCompliance(ctx, "prof1")
	require.NoError(t, err)
	assert.Equal(t, "prof1", prof.ProfileID)
	require.Len(t, prof.Compliance, 1)
	assert.Equal(t, "vscode", prof.Compliance[0].Target)
	assert.Equal(t, "pending", prof.Compliance[0].State)
}
