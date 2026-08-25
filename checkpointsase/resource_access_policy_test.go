package checkpointsase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"gopkg.in/yaml.v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
This file holds BOTH tiers, and the split is by name.

TestSwgAccessPolicy* are offline: the servers are httptest.Servers on localhost
and the client is newTestUserAPIClient, which pre-seeds a bearer token so that no
test exchanges an API key. None of them makes a network call.

TestAccCheckpointsaseAccessPolicy* at the bottom of the file are ACCEPTANCE
tests. They run only under TF_ACC, against a real tenant, and they replace that
tenant's entire web access policy. Read the header on
swg_acc_check_helpers_test.go before touching them.

The offline prefix used to be TestAccessPolicy*, which `go test -run TestAcc`
matches. Twenty-one tests that never touch the API answered a filter meaning
"show me the acceptance coverage", and that is precisely why nobody noticed there
was none. The prefix now means what it says.

The fixture below is the one thing worth reading before the offline tests. It is
the CANONICALISED form -- what the server returns, not what a client sends --
because that difference is the whole design problem this resource has.
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

// sortedCopy sorts a copy, so that an assertion on a set-valued attribute compares
// membership without depending on an order neither the API nor Terraform promises.
func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
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

	rules, _, _, err := accessPolicyOps(newTestUserAPIClient(srv.URL)).read(context.Background())
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	return flattenAccessPolicyRules(rules)
}

// ---------------------------------------------------------------------------
// Order: the reason this resource exists
// ---------------------------------------------------------------------------

/*
TestSwgAccessPolicyRuleListIsOrderedNotASet is the smallest test in this file and
guards the largest mistake.

`rule` must be a TypeList. A TypeSet stores elements by hash, so the order the
configuration was written in would be DISCARDED -- and discarded silently: the
provider would compile, a test that only checked rule contents would pass, and
the tenant's policy would come out in an order nobody chose. Rule order is
precedence, so that is not a cosmetic difference; it is which rule wins.

Asserted directly on the schema rather than only through behaviour, because a
behavioural test can pass by luck when a set's iteration order happens to match.
TestSwgAccessPolicyWritePreservesConfigurationOrder is the behavioural half.
*/
func TestSwgAccessPolicyRuleListIsOrderedNotASet(t *testing.T) {
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
TestSwgAccessPolicyWritePreservesConfigurationOrder is the behavioural half: it
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
func TestSwgAccessPolicyWritePreservesConfigurationOrder(t *testing.T) {
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
TestSwgAccessPolicyFlattenDropsTheServerEmptyBuckets covers the single most likely
defect in this resource, at the level where the cause is legible.

The server answers an empty sources/destinations/conditions by EXPANDING it into
one bucket per legal type with an empty value (API-FINDINGS 1.15). A flattener
that copies those into state puts `sources { users = [] groups = [] addresses = [] }`
in state against a configuration with no sources block at all -- and then every
plan proposes a change to a resource nobody touched, forever, with an apply that
cannot converge because the next read produces the same thing again.

TestSwgAccessPolicyReadProducesNoPermanentDiff proves the consequence; this proves
the mechanism, so a failure says which of the three flatteners is wrong.
*/
func TestSwgAccessPolicyFlattenDropsTheServerEmptyBuckets(t *testing.T) {
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
	if got, ok := source["users"].([]string); !ok || !testComparableArraiesEq(
		sortedCopy(got), []string{"user-1", "user-2"}) {
		t.Errorf("sources.users = %v, want the members user-1 and user-2", source["users"])
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
	if got, ok := window["weekdays"].([]string); !ok || !testComparableArraiesEq(
		sortedCopy(got), []string{"Mon", "Tue"}) {
		t.Errorf("conditions.0.weekdays = %v, want the members Mon and Tue", window["weekdays"])
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
TestSwgAccessPolicyReadProducesNoPermanentDiff reproduces a whole refresh and then
plans the original configuration against the state it produced.

This is the test that matters most in practice. It takes the body the probe
recorded, runs it through the same flatten and d.Set the resource's Read makes,
and asks the resource to plan the user's configuration against the result. A
resource that does not read back what it writes shows a diff here -- which in a
real run is a diff on every plan, for every rule, with an apply that never
converges.
*/
func TestSwgAccessPolicyReadProducesNoPermanentDiff(t *testing.T) {
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
TestSwgAccessPolicyWriteSendsNeitherRefusedFieldsNorNullArrays pins the two ways a
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
func TestSwgAccessPolicyWriteSendsNeitherRefusedFieldsNorNullArrays(t *testing.T) {
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
TestSwgAccessPolicyExpandOmitsEmptyBuckets covers the write side of the same
normalisation the flattener does on the read side.

A bucket with no members is omitted rather than sent with an empty value: both
mean "unrestricted" to the server -- molecules.types.json gives every one of
these a `value` of `minItems: 0`, and perimeter81-swg-api's own fixtures spell
"any source" as buckets with empty values -- so this is a choice about what we
send, and the reason to make it is that it is what the flattener produces, which
keeps the two halves symmetrical.

A rule that restricts nothing therefore sends empty arrays, which API-FINDINGS
1.15 measured as accepted and is the form the server canonicalises FROM.
*/
func TestSwgAccessPolicyExpandOmitsEmptyBuckets(t *testing.T) {
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
	/*
		MEMBERSHIP, not order. `users` is a TypeSet: nothing in the API assigns an
		order to a bucket's ids and nothing was measured preserving one, so the
		provider must not depend on either. This assertion used to say "IN THAT
		ORDER" and failed the moment the attribute became a set -- which is the
		evidence that the conversion took effect rather than being cosmetic.
	*/
	got := append([]string(nil), restricted.Sources[0].Value...)
	sort.Strings(got)
	if !testComparableArraiesEq(got, []string{"user-1", "user-2"}) {
		t.Errorf("sources.users expanded to %v, want the members user-1 and user-2",
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
	weekdays := append([]string(nil), window[0].Weekdays...)
	sort.Strings(weekdays)
	if !testComparableArraiesEq(weekdays, []string{"Mon", "Tue"}) {
		t.Errorf("weekdays expanded to %v, want the members Mon and Tue", window[0].Weekdays)
	}
}

// ---------------------------------------------------------------------------
// Plan-time refusals
// ---------------------------------------------------------------------------

/*
TestSwgAccessPolicyEmptyRuleListIsRejectedAtPlanTime pins MinItems on `rule`.

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
func TestSwgAccessPolicyEmptyRuleListIsRejectedAtPlanTime(t *testing.T) {
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
TestSwgAccessPolicyRejectsValuesTheServerRejects covers the enum and format checks
that are safe to make at plan time -- meaning the ones where the API contract and
the stored-document schema agree, so the answer cannot be tenant-dependent.

Deliberately NOT covered, and this is the point of naming the test this way: the
`action` list is narrowed to the OpenAPI document's three values even though
p81-mongo-validation-schemas' shared SWGAction enum has four. See
accessPolicyActionValues for that argument.
*/
func TestSwgAccessPolicyRejectsValuesTheServerRejects(t *testing.T) {
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
		{"a name of 101 characters", map[string]interface{}{
			"name": strings.Repeat("a", 101)}, "name"},
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

/*
TestSwgAccessPolicyRuleNameLengthIsCountedInCharactersNotBytes is the row the
Rejects table above could not carry, because it asserts in both directions.

`AccessPolicyRule.name` declares `maxLength: 100` in the OpenAPI document and
p81-mongo-validation-schemas resolves it through `$defs.ruleName` to
`string-1-100`. Both count CHARACTERS. validation.StringLenBetween compares
len(v), which counts BYTES, so a name of 34 CJK characters (102 bytes) is well
inside the server's limit and outside a byte-counting one -- and there is no
workaround but to shorten a name the server would have accepted, against a
diagnostic naming a limit the server does not enforce.

This provider already found, measured and removed exactly this defect on
checkpointsase_group; resource_group.go:119-129 carries the reasoning and
TestGroupNameValidationAcceptsUnicodeAndRejectsEmpty carries the table. Both
whole-policy resources reintroduced it. THE ASCII ROWS CANNOT DISTINGUISH THE
TWO BEHAVIOURS -- that is why the earlier version of the group table shipped a
byte-counting check -- so every boundary below is run in CJK and in "é" as well.

The last two rows keep the fix honest in the other direction: deleting the
length rule altogether would pass every accepting row above.
*/
func TestSwgAccessPolicyRuleNameLengthIsCountedInCharactersNotBytes(t *testing.T) {
	validate := resourceAccessPolicy().Schema["rule"].Elem.(*schema.Resource).
		Schema["name"].ValidateFunc
	if validate == nil {
		t.Fatal("rule.name has no ValidateFunc, so SAP-N02's empty name reaches POST " +
			"/v3/ia/access/policy")
	}

	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"ascii, comfortably inside", "Allow engineering to the internet", false},
		{"exactly 100 ascii characters", strings.Repeat("a", 100), false},
		// 3 bytes each. 34 of them is 102 bytes: inside 100 characters, outside
		// 100 bytes. This is the name from the failure scenario.
		{"34 CJK characters, 102 bytes", strings.Repeat("研", 34), false},
		{"100 CJK characters, 300 bytes -- the boundary, in the wide case",
			strings.Repeat("研", 100), false},
		// 2 bytes each. 51 is 102 bytes.
		{"51 e-acute, 102 bytes", strings.Repeat("é", 51), false},
		{"100 e-acute, 200 bytes", strings.Repeat("é", 100), false},
		{"empty", "", true},
		{"101 ascii characters", strings.Repeat("a", 101), true},
		{"101 CJK characters", strings.Repeat("研", 101), true},
		{"101 e-acute", strings.Repeat("é", 101), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := validate(tc.value, "name")
			if gotErr := len(errs) > 0; gotErr != tc.wantErr {
				t.Fatalf("ValidateFunc(%d characters, %d bytes) errors = %v, want error = %v",
					utf8.RuneCountInString(tc.value), len(tc.value), errs, tc.wantErr)
			}
		})
	}

	// SAP-N02 says "refused at plan time", and Resource.Validate is the path
	// `terraform plan` actually takes.
	t.Run("a 100-character CJK name plans cleanly", func(t *testing.T) {
		diags := resourceAccessPolicy().Validate(terraform.NewResourceConfigRaw(
			map[string]interface{}{"rule": []interface{}{map[string]interface{}{
				"name": strings.Repeat("研", 100), "applied_on": "both",
				"action": "warning", "status": "active",
			}}}))
		if diags.HasError() {
			t.Errorf("a 100-character rule name was refused at plan time: %v. The server "+
				"accepts it -- maxLength counts characters -- and the operator has no "+
				"workaround but to shorten a legal name", diags)
		}
	})
}

// ---------------------------------------------------------------------------
// Shape of the resource itself
// ---------------------------------------------------------------------------

/*
TestSwgAccessPolicyCreateAndUpdateAreOneFunction pins that there is no second write
path.

The endpoint has no partial update: POST replaces the whole array, so creating
the policy and changing it are byte-for-byte the same request. Two functions
would be two copies of one call, and the only thing that could ever differ
between them is a bug -- most likely one that appends instead of replacing, which
on this endpoint doubles the tenant's policy.
*/
func TestSwgAccessPolicyCreateAndUpdateAreOneFunction(t *testing.T) {
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
TestSwgAccessPolicyIDAndPriorityAreComputedOnly pins that neither server-assigned
field can be written.

Both are assigned by the server, and `priority` is not merely overwritten but
DISCARDED: a rule created with priority 1 reads back as priority 0
(API-FINDINGS 1.16). An Optional priority would let a user write a number into
HCL, see it accepted at plan time, and get something else -- with no error and no
diff, because the read overwrites it.
*/
func TestSwgAccessPolicyIDAndPriorityAreComputedOnly(t *testing.T) {
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
TestSwgAccessPolicyDescriptionStatesWhatDestroyAndApplyDo is a documentation test,
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
func TestSwgAccessPolicyDescriptionStatesWhatDestroyAndApplyDo(t *testing.T) {
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

	/*
		The two endpoint blocks must say that OMITTING is the only spelling of
		"any". They said "omit the block, or leave every attribute in it empty"
		once, and the second half was a trap: an empty block is a permanent diff,
		so the description was recommending a configuration that cannot converge.
		checkpointsase_firewall_policy has said "the only way" since it shipped;
		this pins that the two resources agree, and that the description agrees
		with resourceAccessPolicyCustomizeDiff, which now refuses the other
		spelling outright.
	*/
	rule := resourceAccessPolicy().Schema["rule"].Elem.(*schema.Resource)
	for _, attr := range []string{"sources", "destinations"} {
		block := rule.Schema[attr].Description
		if !strings.Contains(block, "only way") {
			t.Errorf("the %s description does not say that omitting the block is the ONLY way "+
				"to express \"any\":\n%s", attr, block)
		}
		if strings.Contains(block, "leave every attribute in it empty") {
			t.Errorf("the %s description still recommends an empty block, which is a permanent "+
				"diff and is now refused at plan time:\n%s", attr, block)
		}
	}

	priority := rule.Schema["priority"].Description
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
TestSwgAccessPolicyDeleteIssuesTheEndpointDeleteAndNothingElse pins the one
destructive call in this resource.

It is unguarded on purpose: this resource owns the whole policy, so destroying it
means the policy is gone, and there is no remainder to preserve. What must not
happen is anything ELSE -- a read first, a POST of the survivors, a retry. The
assertion is on the whole request list rather than the last request, because a
guard that inspects only the final call cannot see an extra one, and an extra
call on this endpoint is a deleted tenant policy.
*/
func TestSwgAccessPolicyDeleteIssuesTheEndpointDeleteAndNothingElse(t *testing.T) {
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
TestSwgAccessPolicyDeleteKeepsTheIDWhenTheServerRefuses is the other half. A failed
DELETE must leave the resource in state: clearing the id would tell Terraform the
policy is gone while the tenant is still enforcing every rule in it, and nothing
would then be tracking them.
*/
func TestSwgAccessPolicyDeleteKeepsTheIDWhenTheServerRefuses(t *testing.T) {
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
TestSwgAccessPolicyReadReportsAnErrorRatherThanAnEmptyPolicy is the Phase 3 lesson
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
func TestSwgAccessPolicyReadReportsAnErrorRatherThanAnEmptyPolicy(t *testing.T) {
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
TestSwgAccessPolicyImportAdoptsTheTenantPolicy covers the import path, including the
part that is easy to get wrong: the id a user types is ignored, and the stored id
is the constant, so an imported resource is byte-identical in state to a created
one.
*/
func TestSwgAccessPolicyImportAdoptsTheTenantPolicy(t *testing.T) {
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
TestSwgAccessPolicyImportFailsLoudlyWhenTheReadFails pins that a failed import is an
error rather than an empty resource. Importing a policy as "no rules" and then
applying would replace the tenant's real policy with whatever the configuration
happened to say, without anyone having seen the real one.
*/
func TestSwgAccessPolicyImportFailsLoudlyWhenTheReadFails(t *testing.T) {
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

// ---------------------------------------------------------------------------
// The empty endpoint block, which used to be a permanent diff
// ---------------------------------------------------------------------------

/*
TestSwgAccessPolicyEmptyEndpointBlockIsRefusedAtPlanTime covers the trap the schema
descriptions used to recommend.

An unrestricted rule comes back from the server as empty buckets, which the
flatteners correctly drop, so it always reads back as ZERO `sources` blocks. A
configuration that spells "any source" as `sources {}` or `sources { users = [] }`
holds ONE. Those two can never meet. Measured on this resource's own probe
fixture, through the real Diff path, before the guard existed:

	config: sources { users = [] }   ->  rule.0.sources.#: "0" -> "1"
	config: sources {}               ->  rule.0.sources.#: "0" -> "1"

non-empty on every plan, forever, with an apply that "succeeds" each time and
changes nothing. That is the failure Step 2 of the brief exists to prevent,
arriving from the configuration side rather than the response side.

The guard turns it into a plan-time error naming the block. When the guard is
removed this test does not merely fail -- it PRINTS the perpetual diff, so the
failure output is the evidence rather than a claim about it.
*/
func TestSwgAccessPolicyEmptyEndpointBlockIsRefusedAtPlanTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rule   map[string]interface{}
		wantIn string
	}{
		{
			name: "a sources block with no attributes at all",
			rule: map[string]interface{}{
				"sources": []interface{}{map[string]interface{}{}},
			},
			wantIn: "rule.0.sources",
		},
		{
			name: "a sources block whose only attribute is empty",
			rule: map[string]interface{}{
				"sources": []interface{}{map[string]interface{}{"users": []interface{}{}}},
			},
			wantIn: "rule.0.sources",
		},
		{
			name: "a sources block with every attribute empty",
			rule: map[string]interface{}{
				"sources": []interface{}{map[string]interface{}{
					"users": []interface{}{}, "groups": []interface{}{},
					"addresses": []interface{}{},
				}},
			},
			wantIn: "rule.0.sources",
		},
		{
			name: "an empty destinations block",
			rule: map[string]interface{}{
				"destinations": []interface{}{map[string]interface{}{}},
			},
			wantIn: "rule.0.destinations",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]interface{}{
				"name": "unrestricted", "applied_on": "both",
				"action": "block", "status": "active",
			}
			for k, v := range tc.rule {
				rule[k] = v
			}
			config := map[string]interface{}{"rule": []interface{}{rule}}

			r := resourceAccessPolicy()
			diff, err := r.Diff(context.Background(), nil,
				terraform.NewResourceConfigRaw(config), nil)

			if err == nil {
				var report string
				if diff != nil {
					for key, attr := range diff.Attributes {
						report += fmt.Sprintf("  %s: %q -> %q\n", key, attr.Old, attr.New)
					}
				}
				t.Fatalf("this configuration planned cleanly. An empty block can never "+
					"converge: the server returns an unrestricted rule as empty buckets, "+
					"which read back as no block at all, so this plan repeats forever. "+
					"The plan it produced:\n%s", report)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("the plan error does not name %s, so it cannot be acted on: %v",
					tc.wantIn, err)
			}
			// It has to say what to DO, not only that something is wrong.
			for _, fragment := range []string{"Remove the block", "only way"} {
				if !strings.Contains(err.Error(), fragment) {
					t.Errorf("the plan error does not contain %q, so it diagnoses without "+
						"prescribing: %v", fragment, err)
				}
			}
		})
	}
}

/*
TestSwgAccessPolicyPopulatedEndpointBlockStillPlans is the control for the guard
above, and it is the half that matters more.

A guard that refuses empty blocks is trivial to write in a form that also refuses
a block with one populated attribute among several empty ones -- which is the
COMMON configuration, and refusing it would be a worse bug than the one being
fixed. This pins that the guard is narrow.

The unknown-value row is the specific case that would break real configurations:
`sources { users = [checkpointsase_user.x.id] }` where the id does not exist yet
reads as an empty set during plan, indistinguishable from an empty block. A guard
without the NewValueKnown check refuses every rule that references a resource
created in the same apply.
*/
func TestSwgAccessPolicyPopulatedEndpointBlockStillPlans(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule map[string]interface{}
	}{
		{"one populated attribute among empties", map[string]interface{}{
			"sources": []interface{}{map[string]interface{}{
				"users": []interface{}{"user-1"}, "groups": []interface{}{},
			}},
		}},
		{"no block at all, which is how any source is spelled", map[string]interface{}{}},
		{"a value that is not known until apply", map[string]interface{}{
			"sources": []interface{}{map[string]interface{}{
				"users": []interface{}{hcl2ValueNotYetKnown},
			}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]interface{}{
				"name": "restricted", "applied_on": "both",
				"action": "block", "status": "active",
			}
			for k, v := range tc.rule {
				rule[k] = v
			}
			if _, err := resourceAccessPolicy().Diff(context.Background(), nil,
				terraform.NewResourceConfigRaw(
					map[string]interface{}{"rule": []interface{}{rule}}), nil); err != nil {
				t.Fatalf("this configuration was refused at plan time, and it is legal: %v", err)
			}
		})
	}
}

/*
hcl2ValueNotYetKnown is the sentinel terraform-plugin-sdk uses inside a
ResourceConfig for a value that will not be known until apply. It is unexported
in the SDK (config.UnknownVariableValue), so it is transcribed here rather than
imported; the constant has been stable since Terraform 0.12.
*/
const hcl2ValueNotYetKnown = "74D93920-ED26-11E3-AC10-0800200C9A66"

// ---------------------------------------------------------------------------
// Order, where it does NOT exist
// ---------------------------------------------------------------------------

/*
TestSwgAccessPolicyReadIsInsensitiveToCollectionOrder is the answer to the one
assumption the first version of this resource made and never checked.

`rule` is ordered, because array position IS rule precedence (API-FINDINGS 1.16).
Nothing else in this resource is. A rule's source ids, destination ids, weekdays
and time windows have no order anywhere in the API -- RuleWeb.json even declares
weekdays `uniqueItems`, which is set semantics outright -- and no probe ever
measured the server preserving the order they were sent in.

Modelling them as ordered lists would be asserting a property nobody checked, and
the cost of being wrong is a permanent diff. `weekdays` is the one that would
have bitten: EVERY rule with a time constraint has one, so it is the common case
rather than the rare one.

This test hands the flattener a response whose every collection is in a DIFFERENT
order from the configuration, and asks for a plan. Sets make it empty. Lists make
every element a diff.
*/
func TestSwgAccessPolicyReadIsInsensitiveToCollectionOrder(t *testing.T) {
	// The server's answer, with every collection deliberately shuffled relative
	// to the configuration below: users reversed, categories reversed, weekdays
	// out of calendar order, and the two time windows swapped.
	shuffled := accessPolicyGetBody(accessPolicyCanonicalRuleJSON("rule-zzz", "shuffled", 0,
		`{"type":"users","value":["user-2","user-1"]}`,
		`{"type":"categories","value":["100000034","100000001"]}`,
		`{"type":"datetime","value":[`+
			`{"weekdays":["Wed","Mon"],"startTime":{"hour":18,"minute":0},`+
			`"endTime":{"hour":23,"minute":59}},`+
			`{"weekdays":["Sat"],"startTime":{"hour":0,"minute":0},`+
			`"endTime":{"hour":6,"minute":0}}]}`))

	config := map[string]interface{}{
		"rule": []interface{}{map[string]interface{}{
			"name": "shuffled", "applied_on": "both", "action": "block", "status": "active",
			"sources": []interface{}{map[string]interface{}{
				"users": []interface{}{"user-1", "user-2"},
			}},
			"destinations": []interface{}{map[string]interface{}{
				"categories": []interface{}{"100000001", "100000034"},
			}},
			"conditions": []interface{}{
				// Written in the opposite order from the response, and with the
				// minutes OMITTED on one window -- which also pins that the
				// Default on a nested attribute inside a set does not itself
				// produce a hash mismatch.
				map[string]interface{}{
					"weekdays": []interface{}{"Sat"}, "start_hour": 0, "end_hour": 6,
					"end_minute": 0,
				},
				map[string]interface{}{
					"weekdays":   []interface{}{"Mon", "Wed"},
					"start_hour": 18, "start_minute": 0, "end_hour": 23, "end_minute": 59,
				},
			},
		}},
	}

	r := resourceAccessPolicy()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})
	d.SetId(accessPolicyResourceID)
	if err := d.Set("rule", accessPolicyRulesFromBody(t, shuffled)); err != nil {
		t.Fatalf("could not set rule from the read: %v", err)
	}

	diff, err := r.Diff(context.Background(), d.State(),
		terraform.NewResourceConfigRaw(config), nil)
	if err != nil {
		t.Fatalf("planning against the read state failed: %v", err)
	}
	if diff != nil && !diff.Empty() {
		var report string
		for key, attr := range diff.Attributes {
			report += fmt.Sprintf("  %s: %q -> %q\n", key, attr.Old, attr.New)
		}
		t.Errorf("the plan is not empty even though the server returned exactly what was "+
			"configured, only in a different order. Nothing in the API assigns an order to "+
			"a bucket's ids, to weekdays or to time windows, so these must be sets:\n%s", report)
	}
}

// ---------------------------------------------------------------------------
// Bucket types this provider does not know
// ---------------------------------------------------------------------------

/*
findOpenAPIDocument locates the OpenAPI document the SDK is generated from.

It walks up from the test's working directory rather than hard-coding a relative
path, so the test survives being run from a different depth. It SKIPS rather than
fails when the document is absent: the SDK is consumed as a module and a checkout
that has only the module cache genuinely cannot answer this question. The skip
message says exactly what was looked for, so a skip is actionable rather than
mysterious.
*/
func findOpenAPIDocument(t *testing.T) map[string]interface{} {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	const relative = "perimeter-81-client-sdk/api/openapi.yaml"
	for {
		candidate := filepath.Join(dir, relative)
		if body, err := os.ReadFile(candidate); err == nil {
			var doc map[string]interface{}
			if err := yaml.Unmarshal(body, &doc); err != nil {
				t.Fatalf("parsing %s: %v", candidate, err)
			}
			return doc
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skipf("no %s found in any parent of the working directory. This check needs the "+
				"SDK's source checkout, which the go.mod replace directive points at; a "+
				"module-cache-only build cannot run it.", relative)
		}
		dir = parent
	}
}

// openAPITypeEnum returns the `type` property's enum for one schema in the
// document, failing rather than skipping if the schema is missing -- a schema
// that has disappeared is a real signal, not an absent input.
func openAPITypeEnum(t *testing.T, doc map[string]interface{}, schemaName string) []string {
	t.Helper()

	components, ok := doc["components"].(map[string]interface{})
	if !ok {
		t.Fatal("the OpenAPI document has no components section")
	}
	schemas, ok := components["schemas"].(map[string]interface{})
	if !ok {
		t.Fatal("the OpenAPI document has no components.schemas section")
	}
	definition, ok := schemas[schemaName].(map[string]interface{})
	if !ok {
		t.Fatalf("the OpenAPI document has no %s schema", schemaName)
	}
	properties, ok := definition["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("%s has no properties", schemaName)
	}
	typeProperty, ok := properties["type"].(map[string]interface{})
	if !ok {
		t.Fatalf("%s has no type property", schemaName)
	}
	raw, ok := typeProperty["enum"].([]interface{})
	if !ok {
		t.Fatalf("%s.type has no enum", schemaName)
	}

	values := make([]string, 0, len(raw))
	for _, value := range raw {
		values = append(values, fmt.Sprint(value))
	}
	return values
}

/*
TestSwgAccessPolicyBucketTablesCoverTheAPIEnums fails when the API grows a bucket
type this provider has no attribute for.

Without it, a new type is invisible and the invisibility is the damage. Trace it:
the server holds a rule restricted by the new type; Read has nowhere to put it so
it is dropped; state therefore says the block is absent; the configuration also
has no block, so THE PLAN IS EMPTY and the operator is shown nothing; and the
next apply for any unrelated reason POSTs the whole array without the
restriction. A policy widened with no plan output is the one outcome a
declarative tool exists to make impossible.

So this converts "the spec grew a type" from a runtime silence into a failing
test at the moment the SDK is regenerated, which is the moment somebody is
already looking. unknownAccessPolicyBucketTypes is the runtime backstop for a
server that is ahead of its own spec.

The condition type is checked in the same place and for the same reason: the
resource does not expose `conditions[].type` at all, on the grounds that
`datetime` is the only legal value. That is only safe while it stays true.
*/
func TestSwgAccessPolicyBucketTablesCoverTheAPIEnums(t *testing.T) {
	doc := findOpenAPIDocument(t)

	for _, tc := range []struct {
		schemaName string
		attr       string
		buckets    []accessPolicyBucket
	}{
		{"AccessPolicySource", "sources", accessPolicySourceBuckets},
		{"AccessPolicyDestination", "destinations", accessPolicyDestinationBuckets},
	} {
		t.Run(tc.schemaName, func(t *testing.T) {
			declared := openAPITypeEnum(t, doc, tc.schemaName)

			mapped := map[string]bool{}
			for _, bucket := range tc.buckets {
				mapped[bucket.apiType] = true
			}

			for _, apiType := range declared {
				if !mapped[apiType] {
					t.Errorf("the API declares %s.type = %q and this provider has no attribute "+
						"for it, so a rule restricted by it is DROPPED on read -- and because "+
						"the configuration has no block for it either, the plan is empty and "+
						"the next apply silently removes the restriction. Add it to "+
						"accessPolicy%sBuckets and to the %s element schema.",
						tc.schemaName, apiType, strings.Title(tc.attr[:len(tc.attr)-1]), tc.attr)
				}
			}

			// And the other direction: an attribute mapping to a type the API no
			// longer has would be accepted at plan time and rejected on apply.
			for _, bucket := range tc.buckets {
				found := false
				for _, apiType := range declared {
					if apiType == bucket.apiType {
						found = true
					}
				}
				if !found {
					t.Errorf("this provider maps %s.%s to API type %q, which %s.type no longer "+
						"declares: %v", tc.attr, bucket.attr, bucket.apiType, tc.schemaName,
						declared)
				}
			}
		})
	}

	// conditions[].type is not exposed at all, which is only correct while
	// datetime is the only value.
	if declared := openAPITypeEnum(t, doc, "Condition"); !testComparableArraiesEq(
		declared, []string{accessPolicyConditionTypeDatetime}) {
		t.Errorf("Condition.type now declares %v. This resource exposes `conditions` as a flat "+
			"list of time windows precisely because %q was the only legal type; with more than "+
			"one, the type level has to be exposed or the others are silently unmanageable.",
			declared, accessPolicyConditionTypeDatetime)
	}
}

/*
TestSwgAccessPolicyReadWarnsAboutBucketTypesItDropped is the runtime half of the
same problem, for the case the build-time test cannot reach: a server that
returns a type its own published spec does not declare.

The warning does not prevent the loss -- nothing in a whole-policy resource can,
because the configuration is the policy -- but it converts an empty plan that
silently widens a tenant's rules into something the operator is shown on the
refresh before it happens.
*/
func TestSwgAccessPolicyReadWarnsAboutBucketTypesItDropped(t *testing.T) {
	body := accessPolicyGetBody(accessPolicyCanonicalRuleJSON("rule-new", "future-type", 0,
		`{"type":"serviceAccounts","value":["sa-1"]}`, "", ""))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceAccessPolicy().Schema, map[string]interface{}{})
	d.SetId(accessPolicyResourceID)

	diags := resourceAccessPolicyRead(context.Background(), d, newTestUserAPIClient(srv.URL))
	if diags.HasError() {
		t.Fatalf("the read failed: %v", diags)
	}

	var warnings string
	for _, diagnostic := range diags {
		if diagnostic.Severity == diag.Warning {
			warnings += diagnostic.Summary + " " + diagnostic.Detail + " "
		}
	}
	if warnings == "" {
		t.Fatal("a source bucket of an unknown type was dropped with no warning. The " +
			"configuration has no block for it either, so the plan is EMPTY and the next " +
			"apply removes the restriction with nothing shown to the operator.")
	}
	for _, fragment := range []string{"serviceAccounts", "future-type"} {
		if !strings.Contains(warnings, fragment) {
			t.Errorf("the warning does not name %q, so it cannot be acted on: %s",
				fragment, warnings)
		}
	}

	// The rule itself must still be read; a dropped bucket is not a dropped rule.
	if got := len(d.Get("rule").([]interface{})); got != 1 {
		t.Errorf("read %d rules into state, want 1", got)
	}
}

/*
TestUnknownBucketWarningIgnoresEmptyBuckets pins the gate added on 2026-08-25.

The server returns one bucket per legal type with an empty `value` for every
unrestricted rule (API-FINDINGS 1.15). Without the len(value) > 0 gate, the day
the API grows a bucket type EVERY unrestricted rule on the tenant reports that
the next apply is about to remove entries it does not have.

That is worse than missing the warning entirely: a warning that fires on healthy
configuration is one operators learn to scroll past, and this one exists to catch
a silent widening of a security policy.
*/
func TestUnknownBucketWarningIgnoresEmptyBuckets(t *testing.T) {
	unknownEmpty := perimeter81Sdk.AccessPolicyRule{Name: "unrestricted"}
	unknownEmpty.SetSources([]perimeter81Sdk.AccessPolicySource{
		{Type: "somethingNew", Value: []string{}},
	})
	if got := unknownAccessPolicyBucketTypes([]perimeter81Sdk.AccessPolicyRule{unknownEmpty}); len(got) != 0 {
		t.Errorf("an EMPTY bucket of an unknown type warned: %v. The server sends one "+
			"empty bucket per legal type on every unrestricted rule, so this would fire "+
			"on healthy configuration the day the enum grows", got)
	}

	unknownPopulated := perimeter81Sdk.AccessPolicyRule{Name: "restricted"}
	unknownPopulated.SetSources([]perimeter81Sdk.AccessPolicySource{
		{Type: "somethingNew", Value: []string{"id-1"}},
	})
	got := unknownAccessPolicyBucketTypes([]perimeter81Sdk.AccessPolicyRule{unknownPopulated})
	if len(got) != 1 {
		t.Fatalf("a POPULATED bucket of an unknown type must warn; got %v. Silence here is "+
			"the silent policy-widening this function exists to prevent", got)
	}
}

/*
================================================================================
ACCEPTANCE TESTS -- SAP-01 through SAP-08 and SAP-I01.

Everything above this line is offline. Everything below runs only under TF_ACC
and REPLACES THE TENANT'S ENTIRE WEB ACCESS POLICY. Read the header on
swg_acc_check_helpers_test.go first; the short version is:

  - PreCheck refuses to run unless the tenant's policy is already empty, so the
    suite cannot delete rules it did not create.
  - CheckDestroy asserts the policy reads back EMPTY, which is the tenant state
    these tests start from and the one they must leave behind.
  - No test here calls t.Parallel(). Two of them at once would be two writers of
    one tenant-wide array and the loser's rules would vanish silently.

The rules these tests create are shaped for safety as well as for coverage. The
only rule ever created with status = "active" is an unrestricted `allow`, which
is what an EMPTY policy already means -- the API documents DELETE as "all
internet traffic will be allowed after deletion" -- so it cannot tighten or widen
anything even on a tenant whose Internet Access is switched on. Every `block` and
`warning` rule is created `inactive`: it keeps its position in the array and its
place in these assertions, and is never evaluated against traffic.
================================================================================
*/

// testAccAccessPolicyRule is one `rule` block, in configuration order. A struct
// rather than a formatted string so that SAP-03 can express "the same rules
// minus the middle one" as a slice operation instead of as a second literal that
// has to be kept in step with the first by eye.
type testAccAccessPolicyRule struct {
	name      string
	action    string
	appliedOn string
	status    string
}

/*
testAccAccessPolicyRules is the three-rule set shared by the tests below.

It covers both matrices SAP-01 and SAP-04 ask for in ONE apply, which is also one
POST: three `action` values (allow, block, warning -- the OpenAPI document's
three, deliberately not the backend enum's four), three `applied_on` values
(agents, sites, both), and both `status` values.

The names carry their array position, because SAP-08's assertion is about order
and a failure that prints `[rule-b rule-a rule-c]` should be readable without
cross-referencing anything.

  - @param suffix string - a per-run random suffix, so a leftover from an aborted run is identifiable

@return []testAccAccessPolicyRule
*/
func testAccAccessPolicyRules(suffix string) []testAccAccessPolicyRule {
	return []testAccAccessPolicyRule{
		{name: "tf-acc-" + suffix + "-1-allow", action: "allow", appliedOn: "agents", status: "active"},
		{name: "tf-acc-" + suffix + "-2-block", action: "block", appliedOn: "sites", status: "inactive"},
		{name: "tf-acc-" + suffix + "-3-warning", action: "warning", appliedOn: "both", status: "inactive"},
	}
}

// testAccAccessPolicyNames projects the rule names in order, for
// testAccCheckRuleNamesInOrder.
func testAccAccessPolicyNames(rules []testAccAccessPolicyRule) []string {
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		names = append(names, rule.name)
	}
	return names
}

/*
testAccAccessPolicyConfig renders the resource with these rules, in this order.

NO `sources` OR `destinations` BLOCK IS EMITTED, and that is a test of §1.15
rather than a shortcut. Omitting the block is the only way to spell "any source"
(SAP-N04: a present-but-empty block is refused at plan time), and the server
answers such a rule with one EMPTY BUCKET PER LEGAL TYPE -- three for sources,
four for destinations, one for conditions. The flattener has to drop all eight,
or state disagrees with configuration and every plan diffs forever. The
`sources.# = 0` assertions and the PlanOnly step are the two halves of checking
that it does, against the real server rather than against a fixture.

  - @param rules ...testAccAccessPolicyRule - the blocks, in order

@return string - HCL
*/
func testAccAccessPolicyConfig(rules ...testAccAccessPolicyRule) string {
	var config strings.Builder
	config.WriteString("resource \"checkpointsase_access_policy\" \"test\" {\n")
	for _, rule := range rules {
		fmt.Fprintf(&config, `
  rule {
    name       = %q
    action     = %q
    applied_on = %q
    status     = %q
  }
`, rule.name, rule.action, rule.appliedOn, rule.status)
	}
	config.WriteString("}\n")
	return config.String()
}

/*
testAccAccessPolicyConfigWithDataSource adds the data source reading the same
policy back, which is SAP-07 and the second half of SAP-08.

The `depends_on` is required and is not a stylistic choice. The data source takes
no arguments, so nothing in it references the resource, and without an explicit
dependency Terraform is free to read the policy BEFORE the apply writes it --
which on a tenant that starts empty means asserting the ordering of an empty
list. The same pattern, for the same reason, is on
checkpointsase_standard_networks in testAccDataSourceStandardNetworkScopedConfig.

  - @param rules ...testAccAccessPolicyRule - the blocks, in order

@return string - HCL
*/
func testAccAccessPolicyConfigWithDataSource(rules ...testAccAccessPolicyRule) string {
	return testAccAccessPolicyConfig(rules...) + `
data "checkpointsase_access_policy" "read_back" {
  depends_on = [checkpointsase_access_policy.test]
}
`
}

/*
TestAccCheckpointsaseAccessPolicy_basic covers SAP-01 (three actions, explicit
applied_on, everything read back as configured, then an EMPTY re-plan), SAP-04
(all three applied_on values in one POST) and SAP-I01 (import, then no diff).

The empty re-plan is the assertion that matters most and the one most likely to
break. §1.15 is invisible from the OpenAPI document: the server rewrites
`sources: []` into three typed buckets, `destinations: []` into four and
`conditions: []` into one, so what a client sends is never what it reads back. A
flattener that carried those buckets into state would produce a resource that
applies cleanly and then proposes the same change on every plan for the rest of
its life. PlanOnly is what catches that; the `.# = 0` checks say which of the
three buckets went wrong when it does.
*/
func TestAccCheckpointsaseAccessPolicy_basic(t *testing.T) {
	const address = "checkpointsase_access_policy.test"
	rules := testAccAccessPolicyRules(randStringBytesRmndr())
	config := testAccAccessPolicyConfig(rules...)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t); testAccPreCheckAccessPolicyEmpty(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckAccessPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					// The resource id is the policy itself and is a constant. A
					// timestamp here would change on every read and break every
					// depends_on and output pointing at it (L16c).
					resource.TestCheckResourceAttr(address, "id", accessPolicyResourceID),
					resource.TestCheckResourceAttr(address, "rule.#", "3"),

					// SAP-01 and SAP-04: every configured field, read back.
					resource.TestCheckResourceAttr(address, "rule.0.name", rules[0].name),
					resource.TestCheckResourceAttr(address, "rule.0.action", "allow"),
					resource.TestCheckResourceAttr(address, "rule.0.applied_on", "agents"),
					resource.TestCheckResourceAttr(address, "rule.0.status", "active"),
					resource.TestCheckResourceAttr(address, "rule.1.name", rules[1].name),
					resource.TestCheckResourceAttr(address, "rule.1.action", "block"),
					resource.TestCheckResourceAttr(address, "rule.1.applied_on", "sites"),
					resource.TestCheckResourceAttr(address, "rule.1.status", "inactive"),
					resource.TestCheckResourceAttr(address, "rule.2.name", rules[2].name),
					resource.TestCheckResourceAttr(address, "rule.2.action", "warning"),
					resource.TestCheckResourceAttr(address, "rule.2.applied_on", "both"),
					resource.TestCheckResourceAttr(address, "rule.2.status", "inactive"),

					// §1.15: the server expanded each empty collection into one
					// bucket per legal type. State must hold ZERO blocks, not one
					// block of empty lists.
					resource.TestCheckResourceAttr(address, "rule.0.sources.#", "0"),
					resource.TestCheckResourceAttr(address, "rule.0.destinations.#", "0"),
					resource.TestCheckResourceAttr(address, "rule.0.conditions.#", "0"),
					resource.TestCheckResourceAttr(address, "rule.2.sources.#", "0"),
					resource.TestCheckResourceAttr(address, "rule.2.destinations.#", "0"),
					resource.TestCheckResourceAttr(address, "rule.2.conditions.#", "0"),

					// The server minted an id for every rule, and a priority the
					// configuration never mentions (§1.16).
					resource.TestCheckResourceAttrSet(address, "rule.0.id"),
					resource.TestCheckResourceAttrSet(address, "rule.1.id"),
					resource.TestCheckResourceAttrSet(address, "rule.2.id"),
					testAccCheckRulePrioritiesDescend(address),
				),
			},
			// SAP-01's second half: the same configuration, no diff.
			{
				Config:   config,
				PlanOnly: true,
			},
			// SAP-I01. ImportStateId is set explicitly rather than defaulting to
			// the resource's own id, so this also pins the documented import
			// command. No ImportStateVerifyIgnore: every attribute is either
			// configured or server-reported and nothing here is write-only.
			{
				ResourceName:      address,
				ImportState:       true,
				ImportStateId:     accessPolicyResourceID,
				ImportStateVerify: true,
			},
		},
	})
}

/*
TestAccCheckpointsaseAccessPolicy_orderIsConfigurationOrder covers SAP-08 and
SAP-07.

THIS IS THE ROW THE WHOLE PHASE 4 DESIGN EXISTS TO DELIVER, and until now it had
no live evidence at all. The API has no per-rule endpoint, so a rule's precedence
is its position in the array and nothing else. Under a per-rule resource the
array would be composed by Terraform's scheduler -- independent resources,
arbitrary order, in parallel -- so the same configuration applied twice could
produce two different policies, with no error and no diff to notice. Under the
shipped whole-policy resource the composer is the configuration. This test is the
proof, and a fixture cannot supply it: the claim is about what the SERVER stored
and hands back.

It asserts the order twice, from two directions. The resource's own state is what
Terraform read back after its write; the data source is an independent GET of the
same policy, which is what SAP-07 asks for and is the only one of the two that
could not have been fabricated by the resource's own flattener.

The priority assertion is the third leg. `priority` is Computed-only, so nothing
in this configuration mentions one; every number checked descends with array
position exactly as §1.16 measured. NOTHING is asserted about which end is
evaluated first -- that is unmeasured, it is the overclaim §1.16 was corrected
for, and it is tracked as LEFTOVERS L24.
*/
func TestAccCheckpointsaseAccessPolicy_orderIsConfigurationOrder(t *testing.T) {
	const (
		address    = "checkpointsase_access_policy.test"
		dataSource = "data.checkpointsase_access_policy.read_back"
	)
	rules := testAccAccessPolicyRules(randStringBytesRmndr())
	names := testAccAccessPolicyNames(rules)
	config := testAccAccessPolicyConfigWithDataSource(rules...)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t); testAccPreCheckAccessPolicyEmpty(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckAccessPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					// Configuration order is array order, seen from the resource.
					testAccCheckRuleNamesInOrder(address, names...),
					testAccCheckRulePrioritiesDescend(address),

					// SAP-07/SAP-08: the same policy, read back independently.
					testAccCheckRuleNamesInOrder(dataSource, names...),
					testAccCheckRulePrioritiesDescend(dataSource),
					resource.TestCheckResourceAttr(dataSource, "id", accessPolicyDataSourceID),
					testAccCheckControlledBySurfaced(dataSource),

					// The data source drops the server's empty buckets too. It
					// shares the resource's flattener, so this is a check that
					// the sharing is real rather than two copies that drifted.
					resource.TestCheckResourceAttr(dataSource, "rule.0.sources.#", "0"),
					resource.TestCheckResourceAttr(dataSource, "rule.0.destinations.#", "0"),
					resource.TestCheckResourceAttr(dataSource, "rule.0.conditions.#", "0"),
				),
			},
			{
				Config:   config,
				PlanOnly: true,
			},
		},
	})
}

/*
TestAccCheckpointsaseAccessPolicy_removingTheMiddleRuleRenumbersPriority covers
SAP-03, and with it the half of SAP-02 that can be asserted live.

It is the strongest available evidence that `priority` is server-assigned rather
than round-tripped: the surviving rules' configurations do not change at all
between the two steps, and their priorities change anyway, because priority is
positional and the server renumbers the whole array on every write (§1.16). A
provider that stored a sent priority would show the old numbers here and the
re-plan would then be non-empty forever.

SAP-02's "in-place, never a replace" is asserted through the FIRST rule's
server-assigned id surviving the rewrite -- measured in phase4-verification,
where re-POSTing a list preserved the existing rule's id. It cannot be asserted
through the resource id, which is the constant `access-policy` whether the
resource was updated or recreated.

WHAT IS DELIBERATELY NOT ASSERTED is the id at index 1 after the removal. The
expander sends each rule the id state holds AT THAT POSITION, which the resource
documents at expandAccessPolicyRules: remove the middle block and the third
rule's block inherits the second rule's id. So the id at index 1 is expected to
be the MIDDLE rule's old id, not the third's -- harmless, because the whole array
is replaced and the content at every position is exactly what the configuration
says, but not something to write an equality against as though rules carried
their ids with them. What is checked instead is that no id at all is NEW: a
rewrite that minted fresh ids would mean the server deleted and recreated
everything, which is the defect this row is really about.
*/
func TestAccCheckpointsaseAccessPolicy_removingTheMiddleRuleRenumbersPriority(t *testing.T) {
	const address = "checkpointsase_access_policy.test"
	rules := testAccAccessPolicyRules(randStringBytesRmndr())
	survivors := []testAccAccessPolicyRule{rules[0], rules[2]}

	var idsBefore [3]string

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t); testAccPreCheckAccessPolicyEmpty(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckAccessPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAccessPolicyConfig(rules...),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(address, "rule.#", "3"),
					testAccCaptureResourceAttr(address, "rule.0.id", &idsBefore[0]),
					testAccCaptureResourceAttr(address, "rule.1.id", &idsBefore[1]),
					testAccCaptureResourceAttr(address, "rule.2.id", &idsBefore[2]),
					// 2, 1, 0 before the removal.
					testAccCheckRulePrioritiesDescend(address),
				),
			},
			{
				Config: testAccAccessPolicyConfig(survivors...),
				Check: resource.ComposeTestCheckFunc(
					// Only the middle rule went; the survivors kept their
					// relative order.
					testAccCheckRuleNamesInOrder(address, rules[0].name, rules[2].name),
					// Renumbered to 1, 0. Neither survivor's configuration
					// changed, so this is the server reassigning, not drift.
					testAccCheckRulePrioritiesDescend(address),
					// SAP-02: the untouched first rule kept its server id, so
					// this was an in-place rewrite and not a recreate.
					testAccCheckResourceAttrMatchesCaptured(address, "rule.0.id", &idsBefore[0]),
					// And nothing was minted fresh.
					func(s *terraform.State) error {
						attrs, err := dataSourceAttrs(s, address)
						if err != nil {
							return err
						}
						for index := 0; index < 2; index++ {
							got := attrs[fmt.Sprintf("rule.%d.id", index)]
							if got != idsBefore[0] && got != idsBefore[1] && got != idsBefore[2] {
								return fmt.Errorf(
									"rule.%d.id is %q, which is none of the three ids the server "+
										"had already assigned (%v): removing one rule from the list "+
										"minted new ids for the survivors, so the server deleted and "+
										"recreated them rather than rewriting the array",
									index, got, idsBefore)
							}
						}
						return nil
					},
				),
			},
			{
				Config:   testAccAccessPolicyConfig(survivors...),
				PlanOnly: true,
			},
		},
	})
}

/*
TestAccCheckpointsaseAccessPolicy_destroyClearsTheWholePolicy covers SAP-05, and
it is the §1.18 case specifically: a policy holding exactly ONE rule.

That case is the whole reason the milestone spec's "never call the raw DELETE"
could not be implemented. Removing a rule from a list of several is a POST of the
remainder; removing the LAST one cannot be, because POST of an empty array is
answered `400 VALIDATION_WEB_RULES_REQUIRED`. DELETE is the only route to an
empty policy, and under this design it is exactly correct -- the resource owns
the whole policy, so destroying it means the policy is gone.

CheckDestroy is a GET returning an EMPTY list, not a 404. The policy endpoint
always exists; a tenant that never had a rule and a tenant whose policy was just
deleted answer identically, and a failed read is neither (see
testAccCheckPolicyDestroyed).

Note what a user CANNOT do and why this test is the row: `rule = []` is refused
at plan time by MinItems (SAP-N03), so there is no configuration that empties the
policy. Destroy is the only way, which makes this the only live exercise of
DELETE /v3/ia/access/policy in the suite.
*/
func TestAccCheckpointsaseAccessPolicy_destroyClearsTheWholePolicy(t *testing.T) {
	const address = "checkpointsase_access_policy.test"
	only := testAccAccessPolicyRules(randStringBytesRmndr())[0]

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t); testAccPreCheckAccessPolicyEmpty(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckAccessPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAccessPolicyConfig(only),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(address, "rule.#", "1"),
					resource.TestCheckResourceAttr(address, "rule.0.name", only.name),
					// One rule, so the server's only priority is 0.
					resource.TestCheckResourceAttr(address, "rule.0.priority", "0"),
				),
			},
		},
	})
}
