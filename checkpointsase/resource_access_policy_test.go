package checkpointsase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
Everything in this file is offline: the servers are httptest.Servers on
localhost and the client is newTestUserAPIClient, which pre-seeds a bearer token
so that no test exchanges an API key. No test here makes a network call.

The fixture below is the one thing worth reading before the tests. It is the
CANONICALISED form -- what the server returns, not what a client sends -- because
that difference is the whole design problem this resource has.
*/

/*
accessPolicyCanonicalRuleJSON renders one rule exactly as GET /v3/ia/access/policy
returns it, with the bucket expansion API-FINDINGS 1.15 measured spelled out
literally:

	sources      [] -> users, groups, addresses, each with an empty value
	destinations [] -> customUrls, categories, applicationControlApplications,
	                   updatableObjects, each with an empty value
	conditions   [] -> one datetime bucket with an empty value

and with the three fields the write model refuses -- className, fromDefault,
objectId (API-FINDINGS 1.17) -- present, because a fixture that omits them cannot
prove anything about stripping them.

The caller supplies the buckets that are NOT empty, so one helper produces both
the "unrestricted rule" case and the populated one. The empty buckets are always
emitted: that is the point.

  - @param id, name string - the rule's identity
  - @param priority int - what the server assigned, which is len-1-index (API-FINDINGS 1.16)
  - @param sources, destinations, conditions string - the non-empty buckets, already rendered, or "" for none
*/
func accessPolicyCanonicalRuleJSON(id, name string, priority int,
	sources, destinations, conditions string) string {
	join := func(populated string, empties ...string) string {
		parts := empties
		if populated != "" {
			parts = append([]string{populated}, empties...)
		}
		return strings.Join(parts, ",")
	}

	return fmt.Sprintf(`{"id":%q,"name":%q,"appliedOn":"both","action":"block",`+
		`"status":"active","priority":%d,"log":"summaryWithUrls",`+
		`"sources":[%s],"destinations":[%s],"conditions":[%s],`+
		`"className":"RuleWeb","fromDefault":false,"objectId":"obj-%s"}`,
		id, name, priority,
		join(sources,
			`{"type":"users","value":[]}`,
			`{"type":"groups","value":[]}`,
			`{"type":"addresses","value":[]}`),
		join(destinations,
			`{"type":"customUrls","value":[]}`,
			`{"type":"categories","value":[]}`,
			`{"type":"applicationControlApplications","value":[]}`,
			`{"type":"updatableObjects","value":[]}`),
		join(conditions, `{"type":"datetime","value":[]}`),
		id)
}

/*
accessPolicyProbeBody is the three-rule policy the tests round-trip, in the form
the server returns it.

Rule order is array order and the priorities descend with it -- 2, 1, 0 across
positions 0, 1, 2 -- which is what API-FINDINGS 1.16 measured for three rules
posted in one array. Getting that backwards in the fixture would make the
ordering assertions vacuous, so it is written out rather than computed.
*/
var accessPolicyProbeBody = accessPolicyGetBody(
	// Position 0: nothing restricted. Every bucket the server added is empty,
	// and none of them may reach state.
	accessPolicyCanonicalRuleJSON("rule-aaa", "block-everything", 2, "", "", ""),
	// Position 1: two populated buckets among the empty ones.
	accessPolicyCanonicalRuleJSON("rule-bbb", "block-for-contractors", 1,
		`{"type":"users","value":["user-1","user-2"]}`,
		`{"type":"categories","value":["100000034"]}`, ""),
	// Position 2: a time window, which is the same empty-bucket problem in its
	// least obvious form -- the datetime bucket is present on every rule.
	accessPolicyCanonicalRuleJSON("rule-ccc", "block-out-of-hours", 0, "", "",
		`{"type":"datetime","value":[{"weekdays":["Mon","Tue"],`+
			`"startTime":{"hour":9,"minute":0},"endTime":{"hour":17,"minute":30}}]}`),
)

// accessPolicyProbeConfig is the configuration a user would have written to
// produce accessPolicyProbeBody. Nothing in it mentions an empty bucket, an id
// or a priority, which is exactly why the round-trip is a real test.
func accessPolicyProbeConfig() map[string]interface{} {
	return map[string]interface{}{
		"rule": []interface{}{
			map[string]interface{}{
				"name":       "block-everything",
				"applied_on": "both",
				"action":     "block",
				"status":     "active",
			},
			map[string]interface{}{
				"name":       "block-for-contractors",
				"applied_on": "both",
				"action":     "block",
				"status":     "active",
				"sources": []interface{}{map[string]interface{}{
					"users": []interface{}{"user-1", "user-2"},
				}},
				"destinations": []interface{}{map[string]interface{}{
					"categories": []interface{}{"100000034"},
				}},
			},
			map[string]interface{}{
				"name":       "block-out-of-hours",
				"applied_on": "both",
				"action":     "block",
				"status":     "active",
				"conditions": []interface{}{map[string]interface{}{
					"weekdays":     []interface{}{"Mon", "Tue"},
					"start_hour":   9,
					"start_minute": 0,
					"end_hour":     17,
					"end_minute":   30,
				}},
			},
		},
	}
}

// accessPolicyRulesFromBody decodes a GET body the way the read closure does, so
// that the tests below start from the same []AccessPolicyRule the resource sees.
func accessPolicyRulesFromBody(t *testing.T, body string) []interface{} {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	rules, _, err := accessPolicyOps(newTestUserAPIClient(srv.URL)).read(context.Background())
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	return flattenAccessPolicyRules(rules)
}

// ---------------------------------------------------------------------------
// Order: the reason this resource exists
// ---------------------------------------------------------------------------

/*
TestAccessPolicyRuleListIsOrderedNotASet is the smallest test in this file and
guards the largest mistake.

`rule` must be a TypeList. A TypeSet stores elements by hash, so the order the
configuration was written in would be DISCARDED -- and discarded silently: the
provider would compile, a test that only checked rule contents would pass, and
the tenant's policy would come out in an order nobody chose. Rule order is
precedence, so that is not a cosmetic difference; it is which rule wins.

Asserted directly on the schema rather than only through behaviour, because a
behavioural test can pass by luck when a set's iteration order happens to match.
TestAccessPolicyWritePreservesConfigurationOrder is the behavioural half.
*/
func TestAccessPolicyRuleListIsOrderedNotASet(t *testing.T) {
	rule := resourceAccessPolicy().Schema["rule"]

	if rule.Type != schema.TypeList {
		t.Fatalf("rule is a %v, want schema.TypeList. Order is the entire reason this "+
			"resource owns the whole policy: a TypeSet discards it, and it does so with no "+
			"error, no diff and no failing contents assertion -- the tenant simply ends up "+
			"with its rules in an order nobody chose.", rule.Type)
	}
	if _, ok := rule.Elem.(*schema.Resource); !ok {
		t.Fatalf("rule.Elem is %T, want *schema.Resource: a rule is a block, not a scalar", rule.Elem)
	}
}

/*
TestAccessPolicyWritePreservesConfigurationOrder is the behavioural half: it
drives the real write path and reads the array that actually went out.

Three things are asserted on one request, because they are one property seen from
three angles:

  - the names arrive in configuration order, so nothing sorted or reordered;
  - the priorities descend 2, 1, 0, which is what the server assigns for that
    order (API-FINDINGS 1.16), so the body we send already describes the policy
    the server will build;
  - exactly one POST is issued, followed by exactly one GET. An extra call on
    this endpoint family is how a tenant's policy gets deleted.
*/
func TestAccessPolicyWritePreservesConfigurationOrder(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(accessPolicyProbeBody))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceAccessPolicy().Schema, accessPolicyProbeConfig())
	if diags := resourceAccessPolicyWrite(context.Background(), d,
		newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("the write failed: %v", diags)
	}

	calls, bodies := log.snapshot()
	want := []string{"POST /v3/ia/access/policy", "GET /v3/ia/access/policy"}
	if !testComparableArraiesEq(calls, want) {
		t.Fatalf("requests were %v, want exactly %v: create and update are one POST, and "+
			"the GET after it is the re-read that gives state the canonical form", calls, want)
	}

	var sent struct {
		WebRules []struct {
			Name     string `json:"name"`
			Priority int    `json:"priority"`
		} `json:"webRules"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &sent); err != nil {
		t.Fatalf("the POST body is not the expected shape: %v\n%s", err, bodies[0])
	}

	var names []string
	var priorities []int
	for _, rule := range sent.WebRules {
		names = append(names, rule.Name)
		priorities = append(priorities, rule.Priority)
	}
	wantNames := []string{"block-everything", "block-for-contractors", "block-out-of-hours"}
	if !testComparableArraiesEq(names, wantNames) {
		t.Errorf("the POSTed rules are %v, want %v. Array position IS rule precedence on this "+
			"endpoint, so a reordered body is a different security posture.", names, wantNames)
	}
	if !testComparableArraiesEq(priorities, []int{2, 1, 0}) {
		t.Errorf("the POSTed priorities are %v, want [2 1 0]: priority descends with array "+
			"position, len-1-index (API-FINDINGS 1.16)", priorities)
	}
}

// ---------------------------------------------------------------------------
// The canonicalised read shape
// ---------------------------------------------------------------------------

/*
TestAccessPolicyFlattenDropsTheServerEmptyBuckets covers the single most likely
defect in this resource, at the level where the cause is legible.

The server answers an empty sources/destinations/conditions by EXPANDING it into
one bucket per legal type with an empty value (API-FINDINGS 1.15). A flattener
that copies those into state puts `sources { users = [] groups = [] addresses = [] }`
in state against a configuration with no sources block at all -- and then every
plan proposes a change to a resource nobody touched, forever, with an apply that
cannot converge because the next read produces the same thing again.

TestAccessPolicyReadProducesNoPermanentDiff proves the consequence; this proves
the mechanism, so a failure says which of the three flatteners is wrong.
*/
func TestAccessPolicyFlattenDropsTheServerEmptyBuckets(t *testing.T) {
	rules := accessPolicyRulesFromBody(t, accessPolicyProbeBody)
	if len(rules) != 3 {
		t.Fatalf("flattened %d rules, want 3", len(rules))
	}

	// Position 0 restricted nothing, so all twelve buckets the server returned
	// are empty and NONE of the three blocks may be emitted.
	unrestricted := rules[0].(map[string]interface{})
	for _, attr := range []string{"sources", "destinations", "conditions"} {
		if got := unrestricted[attr].([]interface{}); len(got) != 0 {
			t.Errorf("an unrestricted rule flattened %s to %v; want an empty list. The server "+
				"expands an empty %s into one bucket per legal type with an empty value "+
				"(API-FINDINGS 1.15), and writing those into state is a diff on every plan, "+
				"forever.", attr, got, attr)
		}
	}

	// Position 1 populated two buckets. The populated ones survive; the empty
	// ones alongside them still have to go.
	populated := rules[1].(map[string]interface{})
	sources := populated["sources"].([]interface{})
	if len(sources) != 1 {
		t.Fatalf("a rule with users flattened sources to %v, want one block", sources)
	}
	source := sources[0].(map[string]interface{})
	if got, ok := source["users"].([]string); !ok || !testComparableArraiesEq(got, []string{"user-1", "user-2"}) {
		t.Errorf("sources.users = %v, want [user-1 user-2]", source["users"])
	}
	for _, empty := range []string{"groups", "addresses"} {
		if _, present := source[empty]; present {
			t.Errorf("sources carries %s, which the server returned as an empty bucket; an "+
				"empty bucket means \"unrestricted\" and must not become a set attribute", empty)
		}
	}
	destinations := destinationBlock(t, populated)
	if got, ok := destinations["categories"].([]string); !ok || !testComparableArraiesEq(got, []string{"100000034"}) {
		t.Errorf("destinations.categories = %v, want [100000034]", destinations["categories"])
	}
	for _, empty := range []string{"custom_urls", "application_control_applications", "updatable_objects"} {
		if _, present := destinations[empty]; present {
			t.Errorf("destinations carries %s from an empty bucket", empty)
		}
	}

	// Position 2 has the time window. The datetime bucket is present on EVERY
	// rule, so this is the empty-bucket problem in its least visible form.
	conditions := rules[2].(map[string]interface{})["conditions"].([]interface{})
	if len(conditions) != 1 {
		t.Fatalf("a rule with one time window flattened conditions to %v, want one block", conditions)
	}
	window := conditions[0].(map[string]interface{})
	for attr, want := range map[string]int{
		"start_hour": 9, "start_minute": 0, "end_hour": 17, "end_minute": 30,
	} {
		if got := window[attr].(int); got != want {
			t.Errorf("conditions.0.%s = %d, want %d", attr, got, want)
		}
	}
	if got, ok := window["weekdays"].([]string); !ok || !testComparableArraiesEq(got, []string{"Mon", "Tue"}) {
		t.Errorf("conditions.0.weekdays = %v, want [Mon Tue]", window["weekdays"])
	}

	// And the identity the server assigned, in the server's order.
	for i, want := range []string{"rule-aaa", "rule-bbb", "rule-ccc"} {
		if got := rules[i].(map[string]interface{})["id"].(string); got != want {
			t.Errorf("rule %d id = %q, want %q: the flattener reordered or mislabelled the list",
				i, got, want)
		}
	}
	for i, want := range []int{2, 1, 0} {
		if got := rules[i].(map[string]interface{})["priority"].(int); got != want {
			t.Errorf("rule %d priority = %d, want %d", i, got, want)
		}
	}
}

// destinationBlock unwraps the single destinations block of a flattened rule,
// failing the test rather than panicking when it is absent.
func destinationBlock(t *testing.T, rule map[string]interface{}) map[string]interface{} {
	t.Helper()
	blocks := rule["destinations"].([]interface{})
	if len(blocks) != 1 {
		t.Fatalf("destinations flattened to %v, want one block", blocks)
	}
	return blocks[0].(map[string]interface{})
}

/*
TestAccessPolicyReadProducesNoPermanentDiff reproduces a whole refresh and then
plans the original configuration against the state it produced.

This is the test that matters most in practice. It takes the body the probe
recorded, runs it through the same flatten and d.Set the resource's Read makes,
and asks the resource to plan the user's configuration against the result. A
resource that does not read back what it writes shows a diff here -- which in a
real run is a diff on every plan, for every rule, with an apply that never
converges.
*/
func TestAccessPolicyReadProducesNoPermanentDiff(t *testing.T) {
	r := resourceAccessPolicy()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})
	d.SetId(accessPolicyResourceID)

	if err := d.Set("rule", accessPolicyRulesFromBody(t, accessPolicyProbeBody)); err != nil {
		t.Fatalf("could not set rule from the read: %v", err)
	}

	state := d.State()
	// The server assigns both of these, so a refresh puts them in state where the
	// configuration has nothing. That is what Computed-only is for.
	for i, want := range []string{"rule-aaa", "rule-bbb", "rule-ccc"} {
		if got := state.Attributes[fmt.Sprintf("rule.%d.id", i)]; got != want {
			t.Errorf("rule.%d.id = %q after the read, want %q", i, got, want)
		}
	}
	if got := state.Attributes["rule.0.priority"]; got != "2" {
		t.Errorf("rule.0.priority = %q after the read, want 2", got)
	}

	diff, err := r.Diff(context.Background(), state,
		terraform.NewResourceConfigRaw(accessPolicyProbeConfig()), nil)
	if err != nil {
		t.Fatalf("planning the original configuration against the read state failed: %v", err)
	}
	if diff != nil && !diff.Empty() {
		var report string
		for key, attr := range diff.Attributes {
			report += fmt.Sprintf("  %s: %q -> %q\n", key, attr.Old, attr.New)
		}
		t.Errorf("the configuration still shows a diff after a refresh that changed nothing "+
			"-- this is a permanent diff, on every plan, forever:\n%s", report)
	}
}

// ---------------------------------------------------------------------------
// What goes out on the wire
// ---------------------------------------------------------------------------

/*
TestAccessPolicyWriteSendsNeitherRefusedFieldsNorNullArrays pins the two ways a
POST built from a previous read gets rejected.

className, fromDefault and objectId are returned on a read and refused on a
write: echoing a GET body back answers 422 `"fromDefault" is not allowed`
(API-FINDINGS 1.17). And a nil Go slice serialises as JSON null, which is a type
error, which this endpoint answers with 500 "RuleWeb#upsert internal server
error occurred" (API-FINDINGS 1.19) -- indistinguishable from the endpoint being
down, and misread as exactly that when it was first measured.

The assertion is on the serialised bytes because both problems only exist on the
wire.
*/
func TestAccessPolicyWriteSendsNeitherRefusedFieldsNorNullArrays(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(accessPolicyProbeBody))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceAccessPolicy().Schema, accessPolicyProbeConfig())
	if diags := resourceAccessPolicyWrite(context.Background(), d,
		newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("the write failed: %v", diags)
	}

	_, bodies := log.snapshot()
	body := bodies[0]

	for _, refused := range accessPolicyRefusedFields {
		if strings.Contains(body, `"`+refused+`"`) {
			t.Errorf("the POST body carries %q, which the write model refuses with a 422 "+
				"(API-FINDINGS 1.17):\n%s", refused, body)
		}
	}
	for _, array := range []string{"conditions", "destinations", "sources"} {
		if strings.Contains(body, `"`+array+`":null`) {
			t.Errorf("the POST body sends %s as null; a type error here answers 500, not 400 "+
				"(API-FINDINGS 1.19):\n%s", array, body)
		}
	}
}

/*
TestAccessPolicyExpandOmitsEmptyBucketsAndKeepsOrder covers the write side of the
same normalisation the flattener does on the read side.

A bucket with no members is omitted rather than sent with an empty value: both
mean "unrestricted" to the server -- molecules.types.json gives every one of
these a `value` of `minItems: 0`, and perimeter81-swg-api's own fixtures spell
"any source" as buckets with empty values -- so this is a choice about what we
send, and the reason to make it is that it is what the flattener produces, which
keeps the two halves symmetrical.

A rule that restricts nothing therefore sends empty arrays, which API-FINDINGS
1.15 measured as accepted and is the form the server canonicalises FROM.
*/
func TestAccessPolicyExpandOmitsEmptyBucketsAndKeepsOrder(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAccessPolicy().Schema, accessPolicyProbeConfig())
	rules := expandAccessPolicyRules(d.Get("rule").([]interface{}))

	if len(rules) != 3 {
		t.Fatalf("expanded %d rules, want 3", len(rules))
	}

	if got := rules[0]; len(got.Sources) != 0 || len(got.Destinations) != 0 || len(got.Conditions) != 0 {
		t.Errorf("a rule that restricts nothing expanded to sources=%v destinations=%v "+
			"conditions=%v; all three must be empty arrays", got.Sources, got.Destinations,
			got.Conditions)
	}

	restricted := rules[1]
	if len(restricted.Sources) != 1 || restricted.Sources[0].Type != "users" {
		t.Fatalf("sources expanded to %v, want exactly the users bucket -- an empty groups or "+
			"addresses bucket alongside it is noise the server would only echo back",
			restricted.Sources)
	}
	if !testComparableArraiesEq(restricted.Sources[0].Value, []string{"user-1", "user-2"}) {
		t.Errorf("sources.users expanded to %v, want [user-1 user-2] IN THAT ORDER",
			restricted.Sources[0].Value)
	}
	if len(restricted.Destinations) != 1 || restricted.Destinations[0].Type != "categories" {
		t.Errorf("destinations expanded to %v, want exactly the categories bucket",
			restricted.Destinations)
	}

	timed := rules[2]
	if len(timed.Conditions) != 1 || timed.Conditions[0].Type != accessPolicyConditionTypeDatetime {
		t.Fatalf("conditions expanded to %v, want one datetime bucket", timed.Conditions)
	}
	window := timed.Conditions[0].Value
	if len(window) != 1 {
		t.Fatalf("the datetime bucket holds %d windows, want 1", len(window))
	}
	if window[0].StartTime.Hour != 9 || window[0].StartTime.Minute != 0 ||
		window[0].EndTime.Hour != 17 || window[0].EndTime.Minute != 30 {
		t.Errorf("the time window expanded to %v-%v, want 09:00-17:30",
			window[0].StartTime, window[0].EndTime)
	}
	if !testComparableArraiesEq(window[0].Weekdays, []string{"Mon", "Tue"}) {
		t.Errorf("weekdays expanded to %v, want [Mon Tue]", window[0].Weekdays)
	}
}

// ---------------------------------------------------------------------------
// Plan-time refusals
// ---------------------------------------------------------------------------

/*
TestAccessPolicyEmptyRuleListIsRejectedAtPlanTime pins MinItems on `rule`.

POST with an empty array answers 400 VALIDATION_WEB_RULES_REQUIRED
(API-FINDINGS 1.18), so an empty list can never succeed and there is no reason to
spend a round trip discovering that. Worse, the tempting "fix" for the failure is
to route an empty write to DELETE -- which would put the call that clears a
tenant's entire policy onto the ordinary apply path.

Both spellings of "no rules" are checked. `rule = []` reaches MinItems; a
configuration that omits the block entirely is caught by Required, because
Terraform's config shim drops an empty list before validation sees it. The
resource needs both, and this test would pass with only one of them if it checked
only one.
*/
func TestAccessPolicyEmptyRuleListIsRejectedAtPlanTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config map[string]interface{}
	}{
		{"an explicitly empty list", map[string]interface{}{"rule": []interface{}{}}},
		{"no rule block at all", map[string]interface{}{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := resourceAccessPolicy().Validate(terraform.NewResourceConfigRaw(tc.config))
			if !diags.HasError() {
				t.Fatalf("this configuration validated cleanly; a policy with no rules must " +
					"fail at plan time, not with a 400 after the round trip -- and emptying " +
					"the policy is terraform destroy, which is the endpoint's DELETE")
			}
			var joined string
			for _, d := range diags {
				joined += d.Summary + " " + d.Detail + " "
			}
			if !strings.Contains(joined, "rule") {
				t.Errorf("the plan error does not name `rule`, so it cannot be acted on:\n%s", joined)
			}
		})
	}
}

/*
TestAccessPolicyRejectsValuesTheServerRejects covers the enum and format checks
that are safe to make at plan time -- meaning the ones where the API contract and
the stored-document schema agree, so the answer cannot be tenant-dependent.

Deliberately NOT covered, and this is the point of naming the test this way: the
`action` list is narrowed to the OpenAPI document's three values even though
p81-mongo-validation-schemas' shared SWGAction enum has four. See
accessPolicyActionValues for that argument.
*/
func TestAccessPolicyRejectsValuesTheServerRejects(t *testing.T) {
	valid := func(overrides map[string]interface{}) map[string]interface{} {
		rule := map[string]interface{}{
			"name": "ok", "applied_on": "both", "action": "block", "status": "active",
		}
		for k, v := range overrides {
			rule[k] = v
		}
		return map[string]interface{}{"rule": []interface{}{rule}}
	}

	for _, tc := range []struct {
		name      string
		overrides map[string]interface{}
		wantIn    string
	}{
		{"an appliedOn the API does not have", map[string]interface{}{"applied_on": "everywhere"}, "applied_on"},
		{"an action the API does not have", map[string]interface{}{"action": "drop"}, "action"},
		{"the v2.3 spelling of status", map[string]interface{}{"status": "enabled"}, "status"},
		{"a name containing an angle bracket", map[string]interface{}{"name": "<script>"}, "name"},
		{"an empty name", map[string]interface{}{"name": ""}, "name"},
		{"a lowercased weekday", map[string]interface{}{
			"conditions": []interface{}{map[string]interface{}{
				"weekdays": []interface{}{"mon"}, "start_hour": 9, "end_hour": 17,
			}},
		}, "weekdays"},
		{"an hour that is not a clock hour", map[string]interface{}{
			"conditions": []interface{}{map[string]interface{}{
				"weekdays": []interface{}{"Mon"}, "start_hour": 24, "end_hour": 17,
			}},
		}, "start_hour"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := resourceAccessPolicy().Validate(
				terraform.NewResourceConfigRaw(valid(tc.overrides)))
			if !diags.HasError() {
				t.Fatalf("this configuration validated cleanly; the server refuses it")
			}
			var joined string
			for _, d := range diags {
				joined += d.Summary + " " + d.Detail + " "
			}
			if !strings.Contains(joined, tc.wantIn) {
				t.Errorf("the plan error does not name %s:\n%s", tc.wantIn, joined)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Shape of the resource itself
// ---------------------------------------------------------------------------

/*
TestAccessPolicyCreateAndUpdateAreOneFunction pins that there is no second write
path.

The endpoint has no partial update: POST replaces the whole array, so creating
the policy and changing it are byte-for-byte the same request. Two functions
would be two copies of one call, and the only thing that could ever differ
between them is a bug -- most likely one that appends instead of replacing, which
on this endpoint doubles the tenant's policy.
*/
func TestAccessPolicyCreateAndUpdateAreOneFunction(t *testing.T) {
	r := resourceAccessPolicy()
	if r.CreateContext == nil || r.UpdateContext == nil {
		t.Fatal("the resource must have both a CreateContext and an UpdateContext")
	}
	create := reflect.ValueOf(r.CreateContext).Pointer()
	update := reflect.ValueOf(r.UpdateContext).Pointer()
	if create != update {
		t.Error("CreateContext and UpdateContext are different functions. There is no partial " +
			"update on this endpoint -- both POST the whole list -- so they must be the same " +
			"function, or the two will drift.")
	}
}

/*
TestAccessPolicyIDAndPriorityAreComputedOnly pins that neither server-assigned
field can be written.

Both are assigned by the server, and `priority` is not merely overwritten but
DISCARDED: a rule created with priority 1 reads back as priority 0
(API-FINDINGS 1.16). An Optional priority would let a user write a number into
HCL, see it accepted at plan time, and get something else -- with no error and no
diff, because the read overwrites it.
*/
func TestAccessPolicyIDAndPriorityAreComputedOnly(t *testing.T) {
	rule := resourceAccessPolicy().Schema["rule"].Elem.(*schema.Resource)
	for _, name := range []string{"id", "priority"} {
		attr := rule.Schema[name]
		if attr == nil {
			t.Fatalf("rule has no %s attribute", name)
		}
		if !attr.Computed || attr.Optional || attr.Required {
			t.Errorf("rule.%s is Computed=%t Optional=%t Required=%t, want Computed only: "+
				"the server assigns it and a value sent by a client is discarded "+
				"(API-FINDINGS 1.16)", name, attr.Computed, attr.Optional, attr.Required)
		}
	}
}

/*
TestAccessPolicyDescriptionStatesWhatDestroyAndApplyDo is a documentation test,
and it is here because the two facts it checks are the two that surprise people,
and neither is visible from the configuration.

Destroy removes EVERY rule in the tenant and the API's own wording for the
consequence is "all internet traffic will be allowed after deletion". Apply
removes any rule that is not in the configuration, including rules made in the
console. Both belong in the resource description, where `terraform providers
schema` and the registry both show them, rather than only in a docs page.

The `priority` description is checked for the opposite reason: it must NOT claim
an evaluation order. Which end of the list wins has not been measured, and a
resource that guesses would be telling users their new rule is safe when it might
pre-empt everything.
*/
func TestAccessPolicyDescriptionStatesWhatDestroyAndApplyDo(t *testing.T) {
	description := resourceAccessPolicy().Description

	for _, fragment := range []string{
		"all internet traffic will be allowed after deletion",
		"not in your configuration is removed",
		"console",
	} {
		if !strings.Contains(description, fragment) {
			t.Errorf("the resource description does not contain %q, so an operator running "+
				"terraform destroy or terraform apply is not warned:\n%s", fragment, description)
		}
	}

	priority := resourceAccessPolicy().Schema["rule"].Elem.(*schema.Resource).Schema["priority"].Description
	if !strings.Contains(priority, "not established") {
		t.Errorf("the priority description does not say that the evaluation order is not "+
			"established. It is not: API-FINDINGS 1.16 measured the NUMBERING and explicitly "+
			"did not measure whether priority 0 is evaluated first or last.\n%s", priority)
	}
	/*
		And it must not assert one anywhere else. The blacklist is phrases that can
		only ever be a CLAIM -- "is evaluated first" is deliberately absent from it,
		because the honest sentence above contains that substring inside its own
		negation, and a check that cannot tell the two apart would push a future
		editor towards vaguer wording rather than towards a measurement.
	*/
	for _, guess := range []string{"takes precedence", "highest precedence",
		"is consulted first", "is evaluated before", "wins"} {
		if strings.Contains(priority, guess) {
			t.Errorf("the priority description claims %q. Which end of the range the policy "+
				"engine consults first has NOT been measured -- see API-FINDINGS 1.16, which "+
				"says so explicitly -- and for a policy engine the difference is whether a new "+
				"rule silently pre-empts every existing one.", guess)
		}
	}
}

// ---------------------------------------------------------------------------
// Delete, and the read error that must never become an empty policy
// ---------------------------------------------------------------------------

/*
TestAccessPolicyDeleteIssuesTheEndpointDeleteAndNothingElse pins the one
destructive call in this resource.

It is unguarded on purpose: this resource owns the whole policy, so destroying it
means the policy is gone, and there is no remainder to preserve. What must not
happen is anything ELSE -- a read first, a POST of the survivors, a retry. The
assertion is on the whole request list rather than the last request, because a
guard that inspects only the final call cannot see an extra one, and an extra
call on this endpoint is a deleted tenant policy.
*/
func TestAccessPolicyDeleteIssuesTheEndpointDeleteAndNothingElse(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":200}`))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceAccessPolicy().Schema, accessPolicyProbeConfig())
	d.SetId(accessPolicyResourceID)

	if diags := resourceAccessPolicyDelete(context.Background(), d,
		newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("the delete failed: %v", diags)
	}
	if d.Id() != "" {
		t.Errorf("the id is still %q after a successful delete", d.Id())
	}

	calls, _ := log.snapshot()
	want := []string{"DELETE /v3/ia/access/policy"}
	if !testComparableArraiesEq(calls, want) {
		t.Errorf("requests were %v, want exactly %v", calls, want)
	}
}

/*
TestAccessPolicyDeleteKeepsTheIDWhenTheServerRefuses is the other half. A failed
DELETE must leave the resource in state: clearing the id would tell Terraform the
policy is gone while the tenant is still enforcing every rule in it, and nothing
would then be tracking them.
*/
func TestAccessPolicyDeleteKeepsTheIDWhenTheServerRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceAccessPolicy().Schema, accessPolicyProbeConfig())
	d.SetId(accessPolicyResourceID)

	if diags := resourceAccessPolicyDelete(context.Background(), d,
		newTestUserAPIClient(srv.URL)); !diags.HasError() {
		t.Fatal("a 403 from the DELETE was reported as success")
	}
	if d.Id() != accessPolicyResourceID {
		t.Errorf("the id was cleared after a FAILED delete; Terraform would drop a live "+
			"policy from state and nothing would be tracking its rules (id is now %q)", d.Id())
	}
}

/*
TestAccessPolicyReadReportsAnErrorRatherThanAnEmptyPolicy is the Phase 3 lesson
applied at the resource level.

policy_list_test.go pins it on the read closure; this pins it on the function
that writes state, because those are two different places to get it wrong and
only the second one can produce the damage. On these endpoints absence arrives as
an empty ARRAY -- a 404 means the URL is wrong, which is the documented symptom of
an unset BASE_URL. Swallowing it as "the policy is empty" would hand Read an empty
list, Terraform would plan that as "every rule was deleted outside Terraform", and
the next apply would re-POST over a tenant the provider never managed to read.

The empty-but-real case is asserted in the same test, because the two must be
distinguishable and a resource that errors on both would be just as wrong in the
other direction: an empty policy is a legitimate state.
*/
func TestAccessPolicyReadReportsAnErrorRatherThanAnEmptyPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		wantErr   bool
		wantRules int
	}{
		{"a 404, which means the URL is wrong", http.StatusNotFound,
			`{"message":"Cannot GET /api/v3/ia/access/policy"}`, true, 0},
		{"a 500", http.StatusInternalServerError, `{"message":"boom"}`, true, 0},
		{"a genuinely empty policy, which is a real state", http.StatusOK,
			accessPolicyGetBody(), false, 0},
		{"a policy with rules", http.StatusOK, accessPolicyProbeBody, false, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &requestLog{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.record(r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceAccessPolicy().Schema,
				map[string]interface{}{})
			d.SetId(accessPolicyResourceID)

			diags := resourceAccessPolicyRead(context.Background(), d, newTestUserAPIClient(srv.URL))

			if diags.HasError() != tc.wantErr {
				t.Fatalf("HasError() = %t, want %t (diags: %v)", diags.HasError(), tc.wantErr, diags)
			}
			if tc.wantErr {
				// The id must survive. Clearing it on a failed read is how a
				// transport problem becomes "the policy does not exist", and the
				// recreate that follows BEGINS with the destructive DELETE.
				if d.Id() != accessPolicyResourceID {
					t.Errorf("the id was cleared by a failed read; the next plan would offer "+
						"to recreate a policy that already exists, and recreating it starts "+
						"with the DELETE that empties the tenant (id is now %q)", d.Id())
				}
			} else if got := len(d.Get("rule").([]interface{})); got != tc.wantRules {
				t.Errorf("read %d rules into state, want %d", got, tc.wantRules)
			}

			calls, _ := log.snapshot()
			if want := []string{"GET /v3/ia/access/policy"}; !testComparableArraiesEq(calls, want) {
				t.Errorf("requests were %v, want exactly %v: a read must never be followed "+
					"by a write of any kind", calls, want)
			}
		})
	}
}

/*
TestAccessPolicyImportAdoptsTheTenantPolicy covers the import path, including the
part that is easy to get wrong: the id a user types is ignored, and the stored id
is the constant, so an imported resource is byte-identical in state to a created
one.
*/
func TestAccessPolicyImportAdoptsTheTenantPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(accessPolicyProbeBody))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceAccessPolicy().Schema, map[string]interface{}{})
	d.SetId("whatever-the-user-typed")

	imported, err := resourceAccessPolicyImportState(context.Background(), d,
		newTestUserAPIClient(srv.URL))
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("import returned %d resources, want 1", len(imported))
	}
	if got := imported[0].Id(); got != accessPolicyResourceID {
		t.Errorf("the imported id is %q, want the constant %q -- an imported resource must be "+
			"identical in state to a created one", got, accessPolicyResourceID)
	}
	if got := len(imported[0].Get("rule").([]interface{})); got != 3 {
		t.Errorf("import read %d rules, want 3", got)
	}
}

/*
TestAccessPolicyImportFailsLoudlyWhenTheReadFails pins that a failed import is an
error rather than an empty resource. Importing a policy as "no rules" and then
applying would replace the tenant's real policy with whatever the configuration
happened to say, without anyone having seen the real one.
*/
func TestAccessPolicyImportFailsLoudlyWhenTheReadFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Cannot GET /api/v3/ia/access/policy"}`))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceAccessPolicy().Schema, map[string]interface{}{})
	if _, err := resourceAccessPolicyImportState(context.Background(), d,
		newTestUserAPIClient(srv.URL)); err == nil {
		t.Fatal("import succeeded over a failed read; it must report the error instead of " +
			"adopting a policy it never saw")
	}
}
