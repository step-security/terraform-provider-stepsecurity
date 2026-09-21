package stepsecurityapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRule() SuppressionRule {
	return SuppressionRule{
		ID:          AnomalousOutboundNetworkCall,
		Name:        "silence chickfila-ios outbound",
		Description: "noisy endpoint",
		Conditions: map[string]string{
			"owner":    "acme-org",
			"repo":     "*",
			"endpoint": "example.com:443",
		},
		SeverityAction: SeverityAction{Type: "ignore"},
	}
}

// The derived id is the idempotency key, so the same configuration must always
// produce the same id — including across processes, where Go's map iteration
// order differs run to run.
func TestDeriveSuppressionRuleIDIsStable(t *testing.T) {
	t.Parallel()

	first := DeriveSuppressionRuleID("acme", testRule())
	for i := 0; i < 50; i++ {
		assert.Equal(t, first, DeriveSuppressionRuleID("acme", testRule()),
			"derived rule id must not depend on map iteration order")
	}

	parsed, err := uuid.Parse(first)
	require.NoError(t, err, "derived id must be a UUID: the API rejects anything else")
	assert.Equal(t, uuid.Version(5), parsed.Version())
}

func TestDeriveSuppressionRuleIDDistinguishesRules(t *testing.T) {
	t.Parallel()

	base := testRule()
	baseID := DeriveSuppressionRuleID("acme", base)

	differentName := base
	differentName.Name = "a different rule"
	assert.NotEqual(t, baseID, DeriveSuppressionRuleID("acme", differentName))

	differentType := base
	differentType.ID = SuspiciousNetworkCall
	assert.NotEqual(t, baseID, DeriveSuppressionRuleID("acme", differentType))

	differentCondition := base
	differentCondition.Conditions = map[string]string{
		"owner":    "acme-org",
		"repo":     "*",
		"endpoint": "other.example.com:443",
	}
	assert.NotEqual(t, baseID, DeriveSuppressionRuleID("acme", differentCondition))

	differentCustomer := base
	assert.NotEqual(t, baseID, DeriveSuppressionRuleID("other-customer", differentCustomer))
}

// Description is deliberately excluded: it does not change which detections the
// rule matches, and including it would mean an edited description derives a new
// id and so creates a second rule.
func TestDeriveSuppressionRuleIDIgnoresDescription(t *testing.T) {
	t.Parallel()

	withDesc := testRule()
	withoutDesc := testRule()
	withoutDesc.Description = ""

	assert.Equal(t, DeriveSuppressionRuleID("acme", withDesc), DeriveSuppressionRuleID("acme", withoutDesc))
}

// An empty condition must be equivalent to an absent one, so that adding a
// condition and then clearing it leaves the rule's identity where it started.
func TestDeriveSuppressionRuleIDIgnoresEmptyConditions(t *testing.T) {
	t.Parallel()

	sparse := testRule()
	padded := testRule()
	padded.Conditions["workflow"] = ""
	padded.Conditions["job"] = ""

	assert.Equal(t, DeriveSuppressionRuleID("acme", sparse), DeriveSuppressionRuleID("acme", padded))
}

func TestCreateSuppressionRuleSendsDerivedRuleID(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusCreated)
		//nolint:errcheck
		w.Write([]byte(`{"rule_id":"` + gotBody["rule_id"].(string) + `","name":"silence chickfila-ios outbound"}`))
	}))
	defer server.Close()

	client := newTestClient(server)
	created, err := client.CreateSuppressionRule(context.Background(), testRule())
	require.NoError(t, err)

	want := DeriveSuppressionRuleID("test-customer", testRule())
	assert.Equal(t, want, gotBody["rule_id"], "create must carry the derived id as its idempotency key")
	assert.Equal(t, want, created.RuleID)
}

func TestCreateSuppressionRuleRespectsCallerSuppliedRuleID(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusCreated)
		//nolint:errcheck
		w.Write([]byte(`{"rule_id":"11111111-2222-3333-4444-555555555555"}`))
	}))
	defer server.Close()

	rule := testRule()
	rule.RuleID = "11111111-2222-3333-4444-555555555555"

	client := newTestClient(server)
	_, err := client.CreateSuppressionRule(context.Background(), rule)
	require.NoError(t, err)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", gotBody["rule_id"])
}

// This is the reported failure: the backend commits the rule but times out
// before responding, so API Gateway returns 503. The retry must carry the same
// rule_id, which is what lets the backend answer with the rule it already has
// instead of creating a duplicate.
func TestCreateSuppressionRuleRetriesTransientFailureWithSameID(t *testing.T) {
	t.Parallel()

	var calls int32
	var ruleIDs []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		ruleIDs = append(ruleIDs, body["rule_id"].(string))

		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			//nolint:errcheck
			w.Write([]byte(`{"message":"Service Unavailable"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		//nolint:errcheck
		w.Write([]byte(`{"rule_id":"` + body["rule_id"].(string) + `","name":"silence chickfila-ios outbound"}`))
	}))
	defer server.Close()

	client := newTestClient(server)
	created, err := client.CreateSuppressionRule(context.Background(), testRule())
	require.NoError(t, err, "a 503 must be retried rather than surfaced as an apply failure")

	require.Len(t, ruleIDs, 2, "expected one retry after the 503")
	assert.Equal(t, ruleIDs[0], ruleIDs[1], "the retry must reuse the rule id, or it creates a duplicate")
	assert.Equal(t, DeriveSuppressionRuleID("test-customer", testRule()), created.RuleID)
}

// A 4xx means the request itself is wrong; repeating it just delays the error.
func TestCreateSuppressionRuleDoesNotRetryClientErrors(t *testing.T) {
	t.Parallel()

	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		//nolint:errcheck
		w.Write([]byte(`"error: rule_id must be a UUID"`))
	}))
	defer server.Close()

	client := newTestClient(server)
	_, err := client.CreateSuppressionRule(context.Background(), testRule())
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "a 400 must not be retried")
}

func TestIsRetryableFailure(t *testing.T) {
	t.Parallel()

	assert.True(t, isRetryableFailure(&apiStatusError{StatusCode: http.StatusServiceUnavailable}))
	assert.True(t, isRetryableFailure(&apiStatusError{StatusCode: http.StatusInternalServerError}))
	assert.True(t, isRetryableFailure(&apiStatusError{StatusCode: http.StatusTooManyRequests}))
	assert.False(t, isRetryableFailure(&apiStatusError{StatusCode: http.StatusBadRequest}))
	assert.False(t, isRetryableFailure(&apiStatusError{StatusCode: http.StatusForbidden}))
	assert.False(t, isRetryableFailure(&apiStatusError{StatusCode: http.StatusNotFound}))
}

// gh-policy-driven-prs.go branches on the literal text "status: 503", so the
// typed error must keep formatting the same way.
func TestAPIStatusErrorPreservesLegacyMessage(t *testing.T) {
	t.Parallel()

	err := &apiStatusError{StatusCode: http.StatusServiceUnavailable, Body: "Service Unavailable"}
	assert.Equal(t, "status: 503, body: Service Unavailable", err.Error())
}

// End-to-end reproduction of the reported incident, against a server that
// behaves the way the fixed backend does: a create is a conditional write on
// rule_id, and a repeat of an existing id returns the stored rule with 200
// rather than creating a second one.
//
// The sequence is the one that produced duplicates in production:
//
//	apply #1 - the backend commits the rule but every attempt times out at the
//	           gateway, so Terraform records nothing and the resource is absent
//	           from state
//	apply #2 - a NEW provider process, with only the .tf config to go on,
//	           creates the same resource again
//
// Before the fix apply #2 minted a fresh uuid and produced a second rule. The
// assertion here is that it instead presents the same derived id and adopts
// the rule apply #1 left behind.
func TestCreateSuppressionRuleSecondApplyAdoptsOrphanedRule(t *testing.T) {
	t.Parallel()

	store := map[string]map[string]any{} // rule_id -> stored rule
	var mu sync.Mutex
	failuresRemaining := retryableAttempts // apply #1 exhausts its retries

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		ruleID, _ := body["rule_id"].(string)
		require.NotEmpty(t, ruleID, "every create must carry an idempotency key")

		mu.Lock()
		defer mu.Unlock()

		existing, found := store[ruleID]
		if !found {
			// The conditional write succeeds and the row is durable BEFORE the
			// response is produced - which is exactly why a later timeout left
			// a rule behind with no state to match it.
			body["rule_id"] = ruleID
			store[ruleID] = body
		}

		if failuresRemaining > 0 {
			failuresRemaining--
			w.WriteHeader(http.StatusServiceUnavailable)
			//nolint:errcheck
			w.Write([]byte(`{"message":"Service Unavailable"}`))
			return
		}

		if found {
			w.WriteHeader(http.StatusOK) // replay: hand back what already exists
			//nolint:errcheck
			json.NewEncoder(w).Encode(existing)
			return
		}
		w.WriteHeader(http.StatusCreated)
		//nolint:errcheck
		json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()

	// apply #1 - fails, records nothing, but leaves a rule on the server
	clientA := newTestClient(server)
	_, err := clientA.CreateSuppressionRule(context.Background(), testRule())
	require.Error(t, err, "apply #1 is expected to fail once its retries are exhausted")
	require.Len(t, store, 1, "the backend committed the rule even though the caller saw an error")

	// apply #2 - a fresh provider process with only the configuration to go on
	clientB := newTestClient(server)
	adopted, err := clientB.CreateSuppressionRule(context.Background(), testRule())
	require.NoError(t, err, "apply #2 must succeed by adopting the existing rule")

	assert.Len(t, store, 1, "apply #2 must NOT create a second rule - this is the reported bug")
	assert.Equal(t, DeriveSuppressionRuleID("test-customer", testRule()), adopted.RuleID,
		"the adopted rule must be the one apply #1 left behind")
	_, stillThere := store[adopted.RuleID]
	assert.True(t, stillThere, "the adopted id must be the stored id")
}
