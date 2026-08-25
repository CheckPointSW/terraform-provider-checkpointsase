package checkpointsase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
)

/*
The offline client used throughout this file is newTestUserAPIClient, from
resource_user_test.go. It is resource-agnostic -- it only pre-seeds a bearer
token so that no test here exchanges an API key -- and reusing it keeps one
fixture rather than several. Nothing in this file makes a network call: every
server is an httptest.Server on localhost.
*/

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/*
accessPolicyRuleJSON renders one rule EXACTLY as the server returns it: every
property AccessPolicyRule.UnmarshalJSON declares required, plus the three the
write model refuses (className, fromDefault, objectId -- API-FINDINGS 1.17).

The refused fields are the point of the fixture. A rule fixture that omits them
cannot prove anything about stripping, because the round trip would succeed by
accident; with them present, an implementation that echoes the GET body back is
visible in the POST body the test reads.
*/
func accessPolicyRuleJSON(id, name string, priority int) string {
	return fmt.Sprintf(`{"id":%q,"name":%q,"appliedOn":"both","action":"block",`+
		`"conditions":[{"type":"datetime","value":[]}],`+
		`"destinations":[{"type":"categories","value":[]}],`+
		`"sources":[{"type":"users","value":[]}],`+
		`"log":"summaryWithUrls","status":"enabled","priority":%d,`+
		`"className":"RuleWeb","fromDefault":false,"objectId":"obj-%s"}`,
		id, name, priority, id)
}

// accessPolicyGetBody wraps rules in the envelope GET /v3/ia/access/policy
// returns. controlledBy is included because the live tenant returns it (W3) and
// a fixture that omits it would not exercise the same decode path.
func accessPolicyGetBody(rules ...string) string {
	return fmt.Sprintf(`{"status":200,"data":{"controlledBy":"hsase","webRules":[%s]}}`,
		strings.Join(rules, ","))
}

// httpsInspectionRuleJSON is the HTTPS-inspection equivalent. Its refused field
// list differs -- the server returns _created_at here and not on the access
// policy -- which is the whole reason the two lists are defined separately.
func httpsInspectionRuleJSON(id, name string, priority int) string {
	return fmt.Sprintf(`{"id":%q,"name":%q,"appliedOn":"sites","action":"bypass",`+
		`"destinations":[{"type":"domains","value":[]}],`+
		`"sources":[{"type":"users","value":[]}],`+
		`"log":"disabled","status":"enabled","priority":%d,`+
		`"_created_at":"2026-08-25T09:00:00.000Z"}`,
		id, name, priority)
}

func httpsInspectionGetBody(rules ...string) string {
	return fmt.Sprintf(`{"status":200,"data":{"controlledBy":"hsase","bypassRules":[%s]}}`,
		strings.Join(rules, ","))
}

// requestLog records the method and path of every request an httptest server
// receives, in order. Phase 3 established why the LIST and not the last request
// is the assertion: a guard that inspects only the final request cannot see an
// extra call, and an extra call on this endpoint is a deleted tenant policy.
type requestLog struct {
	mu    sync.Mutex
	calls []string
	// bodies[i] is the request body of calls[i], "" for methods without one.
	bodies []string
}

func (l *requestLog) record(r *http.Request) {
	body := ""
	if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		// Put it back. A handler that also wants to decode the payload would
		// otherwise read an empty stream, and the test would be measuring the
		// recorder rather than the provider.
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, r.Method+" "+r.URL.Path)
	l.bodies = append(l.bodies, body)
}

func (l *requestLog) snapshot() ([]string, []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...), append([]string(nil), l.bodies...)
}

// ---------------------------------------------------------------------------
// stripServerFields
// ---------------------------------------------------------------------------

/*
TestStripServerFieldsRemovesExactlyTheRefusedKeys pins the strip list against
what the server actually rejects. Echoing a GET body back unmodified returns
422 "fromDefault is not allowed" (API-FINDINGS 1.17); id and log are accepted
and MUST survive, because the id is how a rewrite identifies its own rule.

The table runs both field lists over the same input on purpose. The two lists
are NOT the same -- the access policy refuses className, fromDefault and
objectId, HTTPS inspection additionally returns _created_at -- and the rows that
differ are the evidence that they were defined separately rather than merged
into a union that happens to work.
*/
func TestStripServerFieldsRemovesExactlyTheRefusedKeys(t *testing.T) {
	// One input carrying every key either server has been observed to return.
	input := func() map[string]interface{} {
		return map[string]interface{}{
			"className":             "RuleWeb",
			"fromDefault":           false,
			"objectId":              "obj-1",
			"_created_at":           "2026-08-25T09:00:00.000Z",
			"someFutureServerField": "value the server added after this was written",
		}
	}

	for _, tc := range []struct {
		name    string
		refused []string
		want    []string // the keys that must remain, sorted
	}{
		{
			name:    "access policy refuses three fields and leaves _created_at alone",
			refused: accessPolicyRefusedFields,
			// _created_at survives here because the access policy does not
			// return it; if it ever does, this row is where that shows up.
			want: []string{"_created_at", "someFutureServerField"},
		},
		{
			name:    "https inspection additionally refuses _created_at",
			refused: httpsInspectionRefusedFields,
			want:    []string{"someFutureServerField"},
		},
		{
			name:    "an empty refusal list is a no-op, not a wipe",
			refused: nil,
			want: []string{"_created_at", "className", "fromDefault", "objectId",
				"someFutureServerField"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := stripServerFields(input(), tc.refused)
			var keys []string
			for k := range got {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if !testComparableArraiesEq(keys, tc.want) {
				t.Errorf("kept %v, want %v", keys, tc.want)
			}
		})
	}

	// The refusal lists themselves, pinned literally. A field quietly dropped
	// from either list produces a 422 on every write, and a field quietly added
	// removes something the server wanted.
	if !testComparableArraiesEq(accessPolicyRefusedFields,
		[]string{"className", "fromDefault", "objectId"}) {
		t.Errorf("accessPolicyRefusedFields = %v; API-FINDINGS 1.17 measured exactly "+
			"className, fromDefault, objectId", accessPolicyRefusedFields)
	}
	if !testComparableArraiesEq(httpsInspectionRefusedFields,
		[]string{"_created_at", "className", "fromDefault", "objectId"}) {
		t.Errorf("httpsInspectionRefusedFields = %v; the HTTPS-inspection read model "+
			"additionally carries _created_at (phase4-verification W1)",
			httpsInspectionRefusedFields)
	}
}

/*
TestStripServerFieldsKeepsID is separate because losing the id is the failure
with the worst blast radius: a rewrite that drops it makes the server mint a new
rule instead of updating the existing one, silently doubling the policy. log is
checked alongside it because it is the other field the write model accepts
(API-FINDINGS 1.17) and the obvious over-eager strip removes both.

Both halves are asserted: the map-level function, and the typed sanitisers the
resources actually call, because the id lives on the struct rather than in
AdditionalProperties and a sanitiser that rebuilt the rule from its map form
could lose it while stripServerFields stayed correct.
*/
func TestStripServerFieldsKeepsID(t *testing.T) {
	for _, refused := range [][]string{accessPolicyRefusedFields, httpsInspectionRefusedFields} {
		got := stripServerFields(map[string]interface{}{
			"id":          "rule-1",
			"log":         "summaryWithUrls",
			"className":   "RuleWeb",
			"fromDefault": false,
			"objectId":    "obj-1",
			"_created_at": "2026-08-25T09:00:00.000Z",
		}, refused)
		if got["id"] != "rule-1" {
			t.Errorf("refused=%v: id is %v, want rule-1. A rewrite that drops the id "+
				"makes the server mint a duplicate instead of updating.", refused, got["id"])
		}
		if got["log"] != "summaryWithUrls" {
			t.Errorf("refused=%v: log is %v, want summaryWithUrls. The write model "+
				"accepts log (API-FINDINGS 1.17).", refused, got["log"])
		}
	}

	// The typed path, which is what the resources use.
	access := perimeter81Sdk.AccessPolicyRule{
		Id:                   perimeter81Sdk.PtrString("rule-1"),
		Name:                 "keep-me",
		Log:                  perimeter81Sdk.PtrString("summaryWithUrls"),
		AdditionalProperties: map[string]interface{}{"fromDefault": false},
	}
	if s := sanitiseAccessPolicyRule(access); s.GetId() != "rule-1" || s.GetLog() != "summaryWithUrls" {
		t.Errorf("sanitiseAccessPolicyRule lost id or log: id=%q log=%q", s.GetId(), s.GetLog())
	} else if _, still := s.AdditionalProperties["fromDefault"]; still {
		t.Error("sanitiseAccessPolicyRule left fromDefault in AdditionalProperties; " +
			"the write model refuses it with a 422")
	}

	https := perimeter81Sdk.HttpsInspectionRule{
		Id:                   perimeter81Sdk.PtrString("rule-2"),
		Name:                 "keep-me-too",
		Log:                  perimeter81Sdk.PtrString("disabled"),
		AdditionalProperties: map[string]interface{}{"_created_at": "2026-08-25T09:00:00.000Z"},
	}
	if s := sanitiseHttpsInspectionRule(https); s.GetId() != "rule-2" || s.GetLog() != "disabled" {
		t.Errorf("sanitiseHttpsInspectionRule lost id or log: id=%q log=%q", s.GetId(), s.GetLog())
	} else if _, still := s.AdditionalProperties["_created_at"]; still {
		t.Error("sanitiseHttpsInspectionRule left _created_at in AdditionalProperties")
	}
}

/*
TestSanitiseNeverSendsANullArray pins the guard against the failure that is
hardest to diagnose from its symptom.

conditions, destinations and sources are required arrays. A rule built in Go
with any of them left unset carries a nil slice, and a nil slice serialises as
JSON null -- a TYPE error, which this endpoint answers with
500 "RuleWeb#upsert internal server error occurred" (API-FINDINGS 1.19) rather
than a 400 naming the field. That 500 was read as "the endpoint is down" when it
was measured, and cost real time. Normalising in the sanitiser means neither
resource can reach it, however its rule was assembled.

The assertion is on the serialised bytes, not on the slice, because the slice is
only a problem once it reaches the wire.
*/
func TestSanitiseNeverSendsANullArray(t *testing.T) {
	access, err := json.Marshal(sanitiseAccessPolicyRule(perimeter81Sdk.AccessPolicyRule{
		Name: "unset arrays", AppliedOn: "both", Action: "block", Status: "enabled",
	}))
	if err != nil {
		t.Fatalf("marshalling a sanitised access policy rule: %v", err)
	}
	for _, field := range []string{"conditions", "destinations", "sources"} {
		if strings.Contains(string(access), `"`+field+`":null`) {
			t.Errorf("access policy rule serialises %s as null: %s", field, access)
		}
	}

	https, err := json.Marshal(sanitiseHttpsInspectionRule(perimeter81Sdk.HttpsInspectionRule{
		Name: "unset arrays", AppliedOn: "sites", Status: "enabled",
	}))
	if err != nil {
		t.Fatalf("marshalling a sanitised HTTPS inspection rule: %v", err)
	}
	for _, field := range []string{"destinations", "sources"} {
		if strings.Contains(string(https), `"`+field+`":null`) {
			t.Errorf("HTTPS inspection rule serialises %s as null: %s", field, https)
		}
	}
}

/*
TestStripServerFieldsDoesNotMutateTheCallersMap pins the copy contract. The
caller is mid-rewrite: it holds the list it is about to re-POST, and on the
delete path it holds the list it may instead have to DECIDE not to POST. A
strip that edited the caller's map in place would leave that list altered even
on the branches that never write, and the damage would only be visible on the
next apply.
*/
func TestStripServerFieldsDoesNotMutateTheCallersMap(t *testing.T) {
	original := map[string]interface{}{"className": "RuleWeb", "id": "rule-1"}
	got := stripServerFields(original, accessPolicyRefusedFields)

	if _, gone := original["className"]; !gone {
		t.Error("stripServerFields edited the caller's map in place; it must return a copy")
	}
	if _, present := got["className"]; present {
		t.Error("the returned map still carries className")
	}
	// And the copy must be independent in the other direction too.
	got["id"] = "mutated"
	if original["id"] != "rule-1" {
		t.Error("writing to the returned map reached the caller's map")
	}
}

// ---------------------------------------------------------------------------
// The delete-the-last-rule guard
// ---------------------------------------------------------------------------

/*
TestRewriteAccessPolicyWithoutDeletesOnlyWhenTheLastRuleGoes tests the one call
in this phase that can destroy a tenant's policy, from both sides.

DELETE /v3/ia/access/policy clears the ENTIRE tenant policy -- the API documents
it as "all internet traffic will be allowed after deletion". It is correct in
exactly one situation: the rule being removed is the last one, because POST
rejects an empty array (400 VALIDATION_WEB_RULES_REQUIRED, API-FINDINGS 1.18)
and there is no other way to express it.

The assertion is on the request LIST, not the last request. A test that checked
only the final request would pass on an implementation that issued DELETE and
then POSTed the remainder, which is a wiped policy followed by a partial
restore -- the worst outcome available and the one that looks most like success.
*/
func TestRewriteAccessPolicyWithoutDeletesOnlyWhenTheLastRuleGoes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stored    []string // the server's list before the rewrite
		removeID  string
		wantCalls []string
		wantBody  string // a fragment the POST body must contain, "" if no POST
		wantGone  bool
	}{
		{
			name:      "the last rule can only go via DELETE",
			stored:    []string{accessPolicyRuleJSON("rule-1", "only", 0)},
			removeID:  "rule-1",
			wantCalls: []string{"GET /v3/ia/access/policy", "DELETE /v3/ia/access/policy"},
			wantGone:  true,
		},
		{
			// The other side of the guard, and the one that matters most: with
			// a remainder there must be NO DELETE anywhere in the list.
			name: "one of two rules goes via POST and issues no DELETE at all",
			stored: []string{
				accessPolicyRuleJSON("rule-1", "keep", 0),
				accessPolicyRuleJSON("rule-2", "remove", 1),
			},
			removeID:  "rule-2",
			wantCalls: []string{"GET /v3/ia/access/policy", "POST /v3/ia/access/policy"},
			wantBody:  `"id":"rule-1"`,
			wantGone:  true,
		},
		{
			// Three rules, the FIRST removed: the remainder is non-empty and
			// keeps both survivors. A rewrite that dropped a bystander is the
			// silent failure this whole file exists to prevent.
			name: "removing the first of three keeps both survivors",
			stored: []string{
				accessPolicyRuleJSON("rule-1", "remove", 0),
				accessPolicyRuleJSON("rule-2", "keep-a", 1),
				accessPolicyRuleJSON("rule-3", "keep-b", 2),
			},
			removeID:  "rule-1",
			wantCalls: []string{"GET /v3/ia/access/policy", "POST /v3/ia/access/policy"},
			wantBody:  `"id":"rule-3"`,
			wantGone:  true,
		},
		{
			// Idempotency, and the second place DELETE must not be reached. An
			// implementation guarding only on len(remaining)==0 would DELETE
			// the tenant's whole policy here -- the list is empty, but not
			// because we removed anything from it.
			name:      "a rule that is not on the server writes nothing",
			stored:    nil,
			removeID:  "rule-1",
			wantCalls: []string{"GET /v3/ia/access/policy"},
			wantGone:  false,
		},
		{
			// Same guard with somebody else's rules present. Nothing may be
			// written, because nothing of ours was found.
			name:      "an unknown id leaves a populated policy untouched",
			stored:    []string{accessPolicyRuleJSON("rule-9", "someone else's", 0)},
			removeID:  "rule-1",
			wantCalls: []string{"GET /v3/ia/access/policy"},
			wantGone:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &requestLog{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.record(r)
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodGet:
					_, _ = w.Write([]byte(accessPolicyGetBody(tc.stored...)))
				case http.MethodPost:
					_, _ = w.Write([]byte(accessPolicyGetBody(tc.stored...)))
				case http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			defer srv.Close()

			removed, err := rewriteAccessPolicyWithout(
				context.Background(), newTestUserAPIClient(srv.URL), tc.removeID)
			if err != nil {
				t.Fatalf("rewriteAccessPolicyWithout: %v", err)
			}
			if removed != tc.wantGone {
				t.Errorf("removed = %v, want %v", removed, tc.wantGone)
			}

			calls, bodies := log.snapshot()
			if !testComparableArraiesEq(calls, tc.wantCalls) {
				t.Fatalf("requests were %v, want exactly %v", calls, tc.wantCalls)
			}
			for _, c := range calls {
				if strings.HasPrefix(c, http.MethodDelete) && len(tc.stored) > 1 {
					t.Fatalf("DELETE issued while %d rules remained: that clears the "+
						"ENTIRE tenant policy", len(tc.stored)-1)
				}
			}
			if tc.wantBody != "" {
				post := bodies[len(bodies)-1]
				if !strings.Contains(post, tc.wantBody) {
					t.Errorf("POST body %s does not contain %s", post, tc.wantBody)
				}
				// The removed rule must not be in the body, and neither may the
				// fields the write model refuses (API-FINDINGS 1.17).
				if strings.Contains(post, `"id":"`+tc.removeID+`"`) {
					t.Errorf("POST body still carries the removed rule %s: %s", tc.removeID, post)
				}
				for _, refused := range accessPolicyRefusedFields {
					if strings.Contains(post, `"`+refused+`"`) {
						t.Errorf("POST body carries %q, which the write model refuses with a "+
							"422 (API-FINDINGS 1.17): %s", refused, post)
					}
				}
			}
		})
	}
}

/*
TestRewriteHttpsInspectionPolicyWithoutDeletesOnlyWhenTheLastRuleGoes is the
same guard on the other endpoint. It is not a copy for symmetry's sake: the
HTTPS-inspection list has its own path, its own array name (bypassRules, whose
empty-array refusal is 400 VALIDATION_BYPASS_RULES_REQUIRED) and its own strip
list, so nothing about the access-policy test constrains it.
*/
func TestRewriteHttpsInspectionPolicyWithoutDeletesOnlyWhenTheLastRuleGoes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stored    []string
		removeID  string
		wantCalls []string
	}{
		{
			"the last rule can only go via DELETE",
			[]string{httpsInspectionRuleJSON("rule-1", "only", 0)},
			"rule-1",
			[]string{"GET /v3/ia/https-inspection/policy", "DELETE /v3/ia/https-inspection/policy"},
		},
		{
			"one of two rules goes via POST and issues no DELETE at all",
			[]string{
				httpsInspectionRuleJSON("rule-1", "keep", 0),
				httpsInspectionRuleJSON("rule-2", "remove", 1),
			},
			"rule-2",
			[]string{"GET /v3/ia/https-inspection/policy", "POST /v3/ia/https-inspection/policy"},
		},
		{
			"a rule that is not on the server writes nothing",
			nil,
			"rule-1",
			[]string{"GET /v3/ia/https-inspection/policy"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &requestLog{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.record(r)
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				default:
					_, _ = w.Write([]byte(httpsInspectionGetBody(tc.stored...)))
				}
			}))
			defer srv.Close()

			if _, err := rewriteHttpsInspectionPolicyWithout(
				context.Background(), newTestUserAPIClient(srv.URL), tc.removeID); err != nil {
				t.Fatalf("rewriteHttpsInspectionPolicyWithout: %v", err)
			}

			calls, bodies := log.snapshot()
			if !testComparableArraiesEq(calls, tc.wantCalls) {
				t.Fatalf("requests were %v, want exactly %v", calls, tc.wantCalls)
			}
			if calls[len(calls)-1] != "POST /v3/ia/https-inspection/policy" {
				return
			}
			post := bodies[len(bodies)-1]
			for _, refused := range httpsInspectionRefusedFields {
				if strings.Contains(post, `"`+refused+`"`) {
					t.Errorf("POST body carries %q, which the write model refuses: %s",
						refused, post)
				}
			}
			if !strings.Contains(post, `"bypassRules"`) {
				t.Errorf("POST body is not a bypassRules payload: %s", post)
			}
		})
	}
}

/*
TestWritePolicyRulesRefusesAnEmptyList pins the reason the DELETE branch cannot
be generalised. POST with an empty array is rejected by the server
(400 VALIDATION_WEB_RULES_REQUIRED, API-FINDINGS 1.18), so a writer that
accepted one would either fail every time or -- far worse -- be "fixed" later by
routing it to DELETE, which would put the destructive call on the ordinary write
path. The writer refuses instead, before any request leaves.
*/
func TestWritePolicyRulesRefusesAnEmptyList(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(context.Context, *perimeter81Sdk.APIClient) error
	}{
		{"access policy", func(ctx context.Context, c *perimeter81Sdk.APIClient) error {
			return writeAccessPolicyRules(ctx, c, nil)
		}},
		{"https inspection", func(ctx context.Context, c *perimeter81Sdk.APIClient) error {
			return writeHttpsInspectionRules(ctx, c, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("unexpected %s %s: an empty list must be refused before any "+
					"request, and must never be turned into a DELETE", r.Method, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()

			err := tc.write(context.Background(), newTestUserAPIClient(srv.URL))
			if err == nil {
				t.Fatal("writing an empty rule list succeeded; the server rejects it with " +
					"400 VALIDATION_WEB_RULES_REQUIRED (API-FINDINGS 1.18)")
			}
		})
	}
}

/*
TestRewritePolicyWithoutRefusesAnEmptyRuleID guards the same call from the other
direction. An empty id is not reachable from a healthy state, but it matches a
rule the server has not assigned an id to, and on a one-rule list that would put
an otherwise untouched policy on the DELETE branch. The refusal happens before
any request, which is what the zero-request assertion checks.
*/
func TestRewritePolicyWithoutRefusesAnEmptyRuleID(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		t.Errorf("unexpected %s %s: an empty rule id must be refused before any request",
			r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(accessPolicyGetBody()))
	}))
	defer srv.Close()

	client := newTestUserAPIClient(srv.URL)
	if _, err := rewriteAccessPolicyWithout(context.Background(), client, ""); err == nil {
		t.Error("rewriteAccessPolicyWithout accepted an empty rule id")
	}
	if _, err := rewriteHttpsInspectionPolicyWithout(context.Background(), client, ""); err == nil {
		t.Error("rewriteHttpsInspectionPolicyWithout accepted an empty rule id")
	}
	if calls, _ := log.snapshot(); len(calls) != 0 {
		t.Errorf("requests were %v, want none", calls)
	}
}

/*
TestPolicyReadDoesNotTreatA404AsAnEmptyPolicy pins the Phase 3 lesson on the
endpoint where getting it wrong is most expensive.

These are COLLECTION endpoints: they do not 404 because a rule is missing --
absence arrives as an empty array. A 404 means the URL is wrong, which is the
documented failure when BASE_URL is unset and every call goes to the US
production host. If a 404 were read as "the policy is empty", the delete path
would see len(remaining) == 0 and fire the DELETE that clears a tenant policy
the provider never managed to read.
*/
func TestPolicyReadDoesNotTreatA404AsAnEmptyPolicy(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Cannot GET /api/v3/ia/access/policy"}`))
	}))
	defer srv.Close()

	removed, err := rewriteAccessPolicyWithout(
		context.Background(), newTestUserAPIClient(srv.URL), "rule-1")
	if err == nil {
		t.Fatal("a 404 from the collection was swallowed; it means the URL is wrong, " +
			"not that the policy is empty")
	}
	if removed {
		t.Error("removed = true after a failed read")
	}
	calls, _ := log.snapshot()
	want := []string{"GET /v3/ia/access/policy"}
	if !testComparableArraiesEq(calls, want) {
		t.Fatalf("requests were %v, want exactly %v: a read that failed must not be "+
			"followed by a write of any kind", calls, want)
	}
}

// ---------------------------------------------------------------------------
// policyMutex
// ---------------------------------------------------------------------------

/*
TestPolicyMutexSerialisesRewrites runs N concurrent read-modify-write cycles
against an httptest server that records the interleaving, and asserts no two
cycles overlap. Without the mutex this fails; Terraform's default parallelism is
10, so SAP-01's three concurrent applies would silently lose rules.

The server delays every GET. That is what makes the failure deterministic rather
than a race that shows up one run in fifty: with the delay, unserialised cycles
all read the same snapshot and each POST then overwrites the previous one's
work, so the tenant ends up with a fraction of the rules Terraform believes it
created. Two independent assertions catch it -- the request sequence, which must
be the per-cycle pattern repeated end to end, and the final rule count.

NOTE: policyMutex serialises ONE provider process. Two concurrent `terraform
apply` runs against the same tenant can still lose rules; that is out of scope
for Phase 4 and documented as a resource caveat.
*/
func TestPolicyMutexSerialisesRewrites(t *testing.T) {
	const cycles = 6
	const readDelay = 15 * time.Millisecond

	log := &requestLog{}
	var mu sync.Mutex
	stored := []string{accessPolicyRuleJSON("rule-0", "pre-existing", 0)}
	minted := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			snapshot := append([]string(nil), stored...)
			mu.Unlock()
			// The snapshot is taken BEFORE the delay so that a serialised run
			// still sees every earlier POST. The delay only widens the window
			// in which an unserialised run reads a stale list.
			time.Sleep(readDelay)
			_, _ = w.Write([]byte(accessPolicyGetBody(snapshot...)))

		case http.MethodPost:
			var payload struct {
				WebRules []map[string]interface{} `json:"webRules"`
			}
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Errorf("undecodable POST body: %v", err)
			}
			mu.Lock()
			var next []string
			for i, rule := range payload.WebRules {
				id, _ := rule["id"].(string)
				if id == "" {
					minted++
					id = fmt.Sprintf("minted-%d", minted)
				}
				name, _ := rule["name"].(string)
				next = append(next, accessPolicyRuleJSON(id, name, i))
			}
			stored = next
			body := accessPolicyGetBody(stored...)
			mu.Unlock()
			_, _ = w.Write([]byte(body))

		default:
			t.Errorf("unexpected %s: appending a rule never deletes anything", r.Method)
		}
	}))
	defer srv.Close()

	client := newTestUserAPIClient(srv.URL)
	var wg sync.WaitGroup
	errs := make([]error, cycles)
	ids := make([]string, cycles)
	for i := 0; i < cycles; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			created, err := appendAccessPolicyRule(context.Background(), client,
				perimeter81Sdk.AccessPolicyRule{
					Name:      fmt.Sprintf("concurrent-%d", i),
					AppliedOn: "both",
					Action:    "block",
					Status:    "enabled",
				})
			errs[i], ids[i] = err, created.GetId()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("cycle %d: %v", i, err)
		}
		if ids[i] == "" {
			t.Errorf("cycle %d recorded no id; the resource would then have no way to "+
				"find its own rule again", i)
		}
	}

	// Assertion 1: the request sequence. One cycle is GET, POST, GET; N cycles
	// end to end are that pattern repeated. Any other order means two cycles
	// were in flight at once.
	var want []string
	for i := 0; i < cycles; i++ {
		want = append(want,
			"GET /v3/ia/access/policy",
			"POST /v3/ia/access/policy",
			"GET /v3/ia/access/policy")
	}
	calls, _ := log.snapshot()
	if !testComparableArraiesEq(calls, want) {
		t.Errorf("request sequence was\n  %v\nwant\n  %v\nTwo overlapping cycles read the "+
			"same list and the second POST discards the first one's rule.", calls, want)
	}

	// Assertion 2: the consequence. Every rule survived, and so did the one
	// that was there before Terraform touched the policy.
	mu.Lock()
	final := append([]string(nil), stored...)
	mu.Unlock()
	if len(final) != cycles+1 {
		t.Errorf("the policy ended with %d rules, want %d (%d appended plus the "+
			"pre-existing one): a lost update deletes somebody else's rule silently",
			len(final), cycles+1, cycles)
	}
	if !strings.Contains(strings.Join(final, ","), `"name":"pre-existing"`) {
		t.Error("the rule that existed before the applies is gone")
	}
}

/*
TestAppendAccessPolicyRuleStripsBeforeWriting is the create-side half of
API-FINDINGS 1.17. The rules already on the server arrive carrying className,
fromDefault and objectId, and an append that re-POSTs them unmodified is
rejected with 422 -- so the strip has to happen to the EXISTING rules, not just
to the new one. That asymmetry is easy to miss and produces a resource that
works on an empty policy and fails on every populated one.
*/
func TestAppendAccessPolicyRuleStripsBeforeWriting(t *testing.T) {
	log := &requestLog{}
	stored := []string{accessPolicyRuleJSON("rule-1", "pre-existing", 0)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			stored = append(stored, accessPolicyRuleJSON("rule-2", "new", 1))
		}
		_, _ = w.Write([]byte(accessPolicyGetBody(stored...)))
	}))
	defer srv.Close()

	created, err := appendAccessPolicyRule(context.Background(), newTestUserAPIClient(srv.URL),
		perimeter81Sdk.AccessPolicyRule{
			Name: "new", AppliedOn: "both", Action: "block", Status: "enabled",
		})
	if err != nil {
		t.Fatalf("appendAccessPolicyRule: %v", err)
	}
	if created.GetId() != "rule-2" {
		t.Errorf("created id = %q, want rule-2: the new rule is the one whose id was not "+
			"in the list before the write", created.GetId())
	}

	calls, bodies := log.snapshot()
	want := []string{
		"GET /v3/ia/access/policy",
		"POST /v3/ia/access/policy",
		"GET /v3/ia/access/policy",
	}
	if !testComparableArraiesEq(calls, want) {
		t.Fatalf("requests were %v, want exactly %v", calls, want)
	}
	post := bodies[1]
	for _, refused := range accessPolicyRefusedFields {
		if strings.Contains(post, `"`+refused+`"`) {
			t.Errorf("the POST body carries %q from the rule that was already on the "+
				"server; the server answers 422 (API-FINDINGS 1.17): %s", refused, post)
		}
	}
	if !strings.Contains(post, `"id":"rule-1"`) {
		t.Errorf("the POST body lost the existing rule's id, so the server would mint a "+
			"duplicate of it instead of keeping it: %s", post)
	}
	if !strings.Contains(post, `"name":"new"`) {
		t.Errorf("the POST body does not contain the appended rule: %s", post)
	}
}
