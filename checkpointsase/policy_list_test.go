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

/*
TestWritePolicyRulesRefusesAnEmptyList pins the reason DELETE cannot be reached
from the write path. POST with an empty array is rejected by the server
(400 VALIDATION_WEB_RULES_REQUIRED, API-FINDINGS 1.18), so a writer that
accepted one would either fail every time or -- far worse -- be "fixed" later by
routing it to DELETE, which would put the call that clears a tenant's entire
policy on the ordinary write path. The writer refuses instead, before any request
leaves; emptying a policy is the resource's Delete calling deleteAll.
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
TestPolicyReReadRetriesAndNeverFailsSilently covers the window on the far side of
a successful POST.

The write has landed: the tenant is enforcing the new list. The re-read is the
only authoritative account of what that list became, because the server expands
empty sources, destinations and conditions and reassigns priority positionally
(API-FINDINGS 1.15/1.16), so state built from the REQUEST would diff forever.
Fail here and the apply reports failure over a change that succeeded, leaving the
resource absent from state or tainted -- and recreating a tainted whole-policy
resource BEGINS with the DELETE that clears the tenant's policy.

Two behaviours are pinned. A transient failure is retried, so the common case
recovers. A permanent failure is not retried, and the error says the policy WAS
written before it says what went wrong.

It also pins what the message must NOT say. The per-rule version told the
operator that re-applying would create a SECOND copy and that they should import
or hand-remove first. Under a whole-list write that is false and actively
harmful: re-applying replaces the array and is the fix.
*/
func TestPolicyReReadRetriesAndNeverFailsSilently(t *testing.T) {
	for _, tc := range []struct {
		name string
		// status is returned for each GET in order; a 0 means "answer normally".
		status    []int
		wantCalls int
		wantErr   bool
	}{
		{"a transient 500 is retried", []int{http.StatusInternalServerError, 0}, 2, false},
		{"two transient failures are still within budget", []int{502, 503, 0}, 3, false},
		{
			// 422 is not transient. Repeating it changes nothing, so it is not
			// repeated -- but it still has to be reported loudly.
			"a permanent failure is not retried and is still reported",
			[]int{http.StatusUnprocessableEntity}, 1, true,
		},
		{
			"a transient failure that outlives the budget is reported",
			[]int{500, 500, 500, 500}, 4, true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &requestLog{}
			stored := []string{
				accessPolicyRuleJSON("rule-1", "pre-existing", 0),
				accessPolicyRuleJSON("rule-2", "just written", 1),
			}
			attempt := 0

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.record(r)
				w.Header().Set("Content-Type", "application/json")
				status := 0
				if attempt < len(tc.status) {
					status = tc.status[attempt]
				}
				attempt++
				if status != 0 {
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"message":"re-read failed"}`))
					return
				}
				_, _ = w.Write([]byte(accessPolicyGetBody(stored...)))
			}))
			defer srv.Close()

			rules, err := rereadAfterWrite(context.Background(),
				accessPolicyOps(newTestUserAPIClient(srv.URL)))

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want an error = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				// It has to lead with the fact that the tenant is already
				// enforcing the new policy, then say what to do about it.
				for _, fragment := range []string{"WAS written", "Re-applying is safe",
					"access policy"} {
					if !strings.Contains(err.Error(), fragment) {
						t.Errorf("the error does not contain %q, so it does not tell the "+
							"operator the policy was written but not recorded: %v", fragment, err)
					}
				}
				// And it must not carry the per-rule model's advice, which is
				// now wrong in both halves.
				for _, gone := range []string{"SECOND copy", "import it"} {
					if strings.Contains(err.Error(), gone) {
						t.Errorf("the error still says %q. A whole-list write replaces the "+
							"array, so re-applying cannot duplicate anything and this sends "+
							"the operator to hand-edit a policy that only needs re-applying: %v",
							gone, err)
					}
				}
				if rules != nil {
					t.Errorf("rules = %v after a failed re-read, want nil: a read that "+
						"failed must never be handed back as a list", rules)
				}
			} else {
				if len(rules) != 2 {
					t.Fatalf("read back %d rules, want 2", len(rules))
				}
				if rules[1].GetId() != "rule-2" {
					t.Errorf("rules[1] id = %q, want rule-2: the retry must return the "+
						"server's list, in the server's order", rules[1].GetId())
				}
			}

			calls, _ := log.snapshot()
			if len(calls) != tc.wantCalls {
				t.Errorf("requests were %v (%d), want %d: a retry budget that does not "+
					"match means either a transient failure was given up on or a "+
					"permanent one was hammered", calls, len(calls), tc.wantCalls)
			}
		})
	}
}

/*
TestPolicyReadDoesNotTreatA404AsAnEmptyPolicy pins the Phase 3 lesson on the
endpoints where getting it wrong is most expensive.

These are COLLECTION endpoints: they do not 404 because a rule is missing --
absence arrives as an empty array. A 404 means the URL is wrong, which is the
documented failure when BASE_URL is unset and every call goes to the US
production host. Swallowing it as "the policy is empty" hands a resource's Read
an empty list, which Terraform then plans as "every rule was deleted outside
Terraform" and the next apply re-POSTs -- or, if the whole list is now absent
from the server's account of itself, offers to destroy the resource, and destroy
is the DELETE that clears the tenant policy the provider never managed to read.

The assertion is on both endpoints because the discipline now lives in the two
read closures rather than in one shared caller: nothing about the access policy's
closure constrains the HTTPS-inspection one.
*/
func TestPolicyReadDoesNotTreatA404AsAnEmptyPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		read func(context.Context, *perimeter81Sdk.APIClient) (int, error)
	}{
		{"access policy", "/v3/ia/access/policy",
			func(ctx context.Context, c *perimeter81Sdk.APIClient) (int, error) {
				rules, _, err := accessPolicyOps(c).read(ctx)
				return len(rules), err
			}},
		{"https inspection policy", "/v3/ia/https-inspection/policy",
			func(ctx context.Context, c *perimeter81Sdk.APIClient) (int, error) {
				rules, _, err := httpsInspectionPolicyOps(c).read(ctx)
				return len(rules), err
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &requestLog{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.record(r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Cannot GET /api` + tc.path + `"}`))
			}))
			defer srv.Close()

			count, err := tc.read(context.Background(), newTestUserAPIClient(srv.URL))
			if err == nil {
				t.Fatal("a 404 from the collection was swallowed; it means the URL is " +
					"wrong, not that the policy is empty")
			}
			if count != 0 {
				t.Errorf("read returned %d rules alongside its error, want none", count)
			}
			calls, _ := log.snapshot()
			want := []string{"GET " + tc.path}
			if !testComparableArraiesEq(calls, want) {
				t.Fatalf("requests were %v, want exactly %v: a read that failed must not "+
					"be followed by a request of any kind", calls, want)
			}
		})
	}
}
