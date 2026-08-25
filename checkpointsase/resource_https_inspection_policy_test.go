package checkpointsase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
This file holds BOTH tiers, and the split is by name.

TestHttpsInspection* are offline: the servers are httptest.Servers on localhost
and the client is newTestUserAPIClient, which pre-seeds a bearer token so that no
test exchanges an API key. None of them makes a network call.

TestAccCheckpointsaseHttpsInspectionPolicy* at the bottom of the file are
ACCEPTANCE tests. They run only under TF_ACC, against a real tenant, and they
replace that tenant's entire HTTPS-inspection policy. Read the header on
swg_acc_check_helpers_test.go before touching them.

WHERE THE FIXTURE COMES FROM: a real GET, and the provenance lives on the builder
that produces it, not here. See the comment inside
httpsInspectionCanonicalRuleJSON.

THIS BLOCK USED TO SAY THE OPPOSITE, and that is worth one line of history. Until
2026-08-25 no raw GET body from /v3/ia/https-inspection/policy existed anywhere in
this repository, so the fixture was CONSTRUCTED from the OpenAPI document and the
sibling endpoint's measurements, and this header said so at length -- including
that the destination bucket order was "the OpenAPI `type` enums in the document's
own order", which it called an inference. A body was then captured and it
disagreed on three points; the builder was replaced and the replacement documented
on the builder, and this header was left behind asserting the inference.

A header that contradicts the code forty lines below it is worse than no header,
because the fixture is the one thing in this file a reader cannot check by
reading: the next engineer to notice that the bucket order is not the document's
order would have found a header telling them it was supposed to be, and
"corrected" the one captured body this endpoint has. Nothing would have failed --
the flatteners key on `type`.

Enum values used below (`appliedOn`, `action`, `status`, `log`, and every bucket
`type`) were each checked against the OpenAPI document rather than carried over
from the access-policy fixture -- which is where a wrong `status: "enabled"`
survived last time.
*/

/*
httpsInspectionCanonicalRuleJSON renders one bypass rule in the canonicalised
form -- what the server returns, not what a client sends -- with the bucket
expansion spelled out literally:

	sources      [] -> users, groups, applications, addresses, each empty
	destinations [] -> addresses, categories, domains, updatableObjects,
	                   each empty

The caller supplies the buckets that are NOT empty, so one helper produces both
the "unrestricted rule" case and the populated one. The empty buckets are always
emitted: that is the point.

  - @param id, name string - the rule's identity
  - @param appliedOn, action string - the cross-field pair the server judges together
  - @param priority int - what the server assigned, which is len-1-index (API-FINDINGS 1.16)
  - @param sources, destinations string - the non-empty buckets, already rendered, or "" for none
*/
func httpsInspectionCanonicalRuleJSON(id, name, appliedOn, action string, priority int,
	sources, destinations string) string {
	join := func(populated string, empties ...string) string {
		parts := empties
		if populated != "" {
			parts = append([]string{populated}, empties...)
		}
		return strings.Join(parts, ",")
	}

	// CAPTURED, NOT CONSTRUCTED, as of 2026-08-25. An earlier version of this
	// builder was assembled from the OpenAPI document and diverged from the wire
	// in three ways, none of which broke a test -- which is exactly why it was
	// worth measuring. A real GET now settles it:
	//
	//   - DESTINATION ORDER is addresses, categories, domains, updatableObjects.
	//     The constructed version led with categories.
	//   - The captured rule's canonicalised destinations carried NO
	//     applicationControlApplications bucket, and the constructed version
	//     emitted one. Note what that does and does not establish: it is one
	//     rule's canonicalisation, not the endpoint's legal vocabulary.
	//     HttpsInspectionDestination.type declares applicationControlApplications
	//     (v3.yaml:5644), this resource ships it in
	//     httpsInspectionDestinationBuckets, and
	//     TestHttpsInspectionBucketTablesCoverTheAPIEnums holds the table to that
	//     enum in both directions. Whether a POST carrying one is accepted here
	//     is UNMEASURED (API-FINDINGS 1.20, as corrected). So the fixture omits
	//     the bucket because the server omitted it, and nothing in this file may
	//     assert that the type is illegal.
	//   - The rule carries NO className, objectId or fromDefault. Only
	//     _created_at. The constructed version added two the server never sends,
	//     so the strip list was being exercised against fields that never arrive.
	//
	// Source order (users, groups, applications, addresses) was already right.
	// `action` is always present -- a rule POSTed without one reads back as
	// "bypass", the server's documented default -- so a Required schema
	// attribute reading it through GetAction() cannot land on "".
	return fmt.Sprintf(`{"id":%q,"_created_at":"2026-08-25T09:28:22.958Z",`+
		`"name":%q,"appliedOn":%q,"status":"active","priority":%d,"action":%q,`+
		`"sources":[%s],"destinations":[%s],"log":"disabled"}`,
		id, name, appliedOn, priority, action,
		join(sources,
			`{"type":"users","value":[]}`,
			`{"type":"groups","value":[]}`,
			`{"type":"applications","value":[]}`,
			`{"type":"addresses","value":[]}`),
		join(destinations,
			`{"type":"addresses","value":[]}`,
			`{"type":"categories","value":[]}`,
			`{"type":"domains","value":[]}`,
			`{"type":"updatableObjects","value":[]}`))
}

// httpsInspectionGetBody wraps rules in the envelope
// GET /v3/ia/https-inspection/policy returns. controlledBy is included because
// the live tenant returns it (phase4-verification W3) and a fixture that omits
// it would not exercise the same decode path. cleanupBypassRuleDefaultAction is
// deliberately absent: the OpenAPI document says the field is omitted entirely
// when the tenant lacks the Inspection Policy feature, and W4 measured that this
// tenant lacks it.
func httpsInspectionGetBody(rules ...string) string {
	return fmt.Sprintf(`{"status":200,"data":{"controlledBy":"hsase","bypassRules":[%s]}}`,
		strings.Join(rules, ","))
}

/*
httpsInspectionProbeBody is the three-rule policy the tests round-trip.

Rule order is array order and the priorities descend with it -- 2, 1, 0 across
positions 0, 1, 2 -- which is what API-FINDINGS 1.16 measured for three rules
posted in one array. Getting that backwards in the fixture would make the
ordering assertions vacuous, so it is written out rather than computed.

The three rules between them exercise every way this vocabulary differs from the
access policy's: `applications` as a source, `domains` as a destination, and
`addresses` on BOTH sides -- which is the case a table lookup keyed on attribute
name alone would get wrong.
*/
var httpsInspectionProbeBody = httpsInspectionGetBody(
	// Position 0: nothing restricted. Every bucket the server added is empty,
	// and none of them may reach state.
	httpsInspectionCanonicalRuleJSON("rule-aaa", "bypass-everything", "both", "bypass", 2, "", ""),
	// Position 1: populated buckets among the empty ones, including the two
	// types the access policy does not have.
	httpsInspectionCanonicalRuleJSON("rule-bbb", "bypass-for-finance", "both", "bypass", 1,
		`{"type":"users","value":["user-1","user-2"]},`+
			`{"type":"applications","value":["app-1"]}`,
		`{"type":"categories","value":["100000018"]},`+
			`{"type":"domains","value":["domain-1"]}`),
	// Position 2: `addresses` populated on BOTH sides, and the one action the
	// tenant's measured matrix allows outside `bypass`.
	httpsInspectionCanonicalRuleJSON("rule-ccc", "inspect-on-sites", "sites", "inspect", 0,
		`{"type":"addresses","value":["addr-1"]}`,
		`{"type":"addresses","value":["addr-2"]}`),
)

// httpsInspectionProbeConfig is the configuration a user would have written to
// produce httpsInspectionProbeBody. Nothing in it mentions an empty bucket, an
// id or a priority, which is exactly why the round-trip is a real test.
func httpsInspectionProbeConfig() map[string]interface{} {
	return map[string]interface{}{
		"rule": []interface{}{
			map[string]interface{}{
				"name":       "bypass-everything",
				"applied_on": "both",
				"action":     "bypass",
				"status":     "active",
			},
			map[string]interface{}{
				"name":       "bypass-for-finance",
				"applied_on": "both",
				"action":     "bypass",
				"status":     "active",
				"sources": []interface{}{map[string]interface{}{
					"users":        []interface{}{"user-1", "user-2"},
					"applications": []interface{}{"app-1"},
				}},
				"destinations": []interface{}{map[string]interface{}{
					"categories": []interface{}{"100000018"},
					"domains":    []interface{}{"domain-1"},
				}},
			},
			map[string]interface{}{
				"name":       "inspect-on-sites",
				"applied_on": "sites",
				"action":     "inspect",
				"status":     "active",
				"sources": []interface{}{map[string]interface{}{
					"addresses": []interface{}{"addr-1"},
				}},
				"destinations": []interface{}{map[string]interface{}{
					"addresses": []interface{}{"addr-2"},
				}},
			},
		},
	}
}

// httpsInspectionRulesFromBody decodes a GET body the way the read closure does,
// so that the tests below start from the same []HttpsInspectionRule the resource
// sees.
func httpsInspectionRulesFromBody(t *testing.T, body string) []interface{} {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	rules, _, _, err := httpsInspectionPolicyOps(newTestUserAPIClient(srv.URL)).read(context.Background())
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	return flattenHttpsInspectionRules(rules)
}

// httpsInspectionValidRule is a rule that passes every check, so that a test can
// override exactly the one attribute it is about.
func httpsInspectionValidRule(overrides map[string]interface{}) map[string]interface{} {
	rule := map[string]interface{}{
		"name": "ok", "applied_on": "agents", "action": "bypass", "status": "active",
	}
	for k, v := range overrides {
		rule[k] = v
	}
	return rule
}

// ---------------------------------------------------------------------------
// Order: the reason this resource exists
// ---------------------------------------------------------------------------

/*
TestHttpsInspectionRuleListIsOrderedNotASet is the smallest test in this file and
guards the largest mistake.

`rule` must be a TypeList. A TypeSet stores elements by hash, so the order the
configuration was written in would be DISCARDED -- and discarded silently: the
provider would compile, a test that only checked rule contents would pass, and
the tenant's policy would come out in an order nobody chose. Rule order is
precedence, so that is not a cosmetic difference; it is which rule wins.

It also asserts the other half of the same contract: `rule` is the ONLY ordered
list in this resource. Every id collection is a TypeSet, because nothing in the
API assigns an order to a bucket's ids and nothing measured the server preserving
one -- and the two wrapper blocks are MaxItems-1 lists where order is vacuous.
The sibling resource had to be corrected for this after review; asserting it here
means the correction cannot be lost.
*/
func TestHttpsInspectionRuleListIsOrderedNotASet(t *testing.T) {
	rule := resourceHttpsInspectionPolicy().Schema["rule"]

	if rule.Type != schema.TypeList {
		t.Fatalf("rule is a %v, want schema.TypeList. Order is the entire reason this "+
			"resource owns the whole policy: a TypeSet discards it, and it does so with no "+
			"error, no diff and no failing contents assertion -- the tenant simply ends up "+
			"with its rules in an order nobody chose.", rule.Type)
	}
	element, ok := rule.Elem.(*schema.Resource)
	if !ok {
		t.Fatalf("rule.Elem is %T, want *schema.Resource: a rule is a block, not a scalar", rule.Elem)
	}

	for _, endpoint := range []struct {
		attr    string
		buckets []httpsInspectionBucket
	}{
		{"sources", httpsInspectionSourceBuckets},
		{"destinations", httpsInspectionDestinationBuckets},
	} {
		block := element.Schema[endpoint.attr]
		if block.Type != schema.TypeList || block.MaxItems != 1 {
			t.Errorf("rule.%s is %v with MaxItems %d, want a MaxItems-1 TypeList wrapper block",
				endpoint.attr, block.Type, block.MaxItems)
			continue
		}
		inner := block.Elem.(*schema.Resource)
		for _, bucket := range endpoint.buckets {
			attr := inner.Schema[bucket.attr]
			if attr == nil {
				t.Errorf("rule.%s has no %s attribute, but %q is a legal API type",
					endpoint.attr, bucket.attr, bucket.apiType)
				continue
			}
			if attr.Type != schema.TypeSet {
				t.Errorf("rule.%s.%s is a %v, want schema.TypeSet. Nothing in the API assigns "+
					"an order to a bucket's ids and nothing measured the server preserving one, "+
					"so a list here asserts a property nobody checked -- and the cost of being "+
					"wrong is a permanent diff. `rule` is the only ordered list in this resource.",
					endpoint.attr, bucket.attr, attr.Type)
			}
		}
	}
}

/*
TestHttpsInspectionWritePreservesConfigurationOrder is the behavioural half: it
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
func TestHttpsInspectionWritePreservesConfigurationOrder(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(httpsInspectionProbeBody))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceHttpsInspectionPolicy().Schema,
		httpsInspectionProbeConfig())
	if diags := resourceHttpsInspectionPolicyWrite(context.Background(), d,
		newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("the write failed: %v", diags)
	}

	calls, bodies := log.snapshot()
	want := []string{"POST /v3/ia/https-inspection/policy", "GET /v3/ia/https-inspection/policy"}
	if !testComparableArraiesEq(calls, want) {
		t.Fatalf("requests were %v, want exactly %v: create and update are one POST, and "+
			"the GET after it is the re-read that gives state the canonical form", calls, want)
	}

	var sent struct {
		BypassRules []struct {
			Name     string `json:"name"`
			Priority int    `json:"priority"`
		} `json:"bypassRules"`
		// The tenant-wide cleanup default is out of scope and must not be sent;
		// see below.
		Cleanup *string `json:"cleanupBypassRuleDefaultAction"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &sent); err != nil {
		t.Fatalf("the POST body is not the expected shape: %v\n%s", err, bodies[0])
	}

	var names []string
	var priorities []int
	for _, rule := range sent.BypassRules {
		names = append(names, rule.Name)
		priorities = append(priorities, rule.Priority)
	}
	wantNames := []string{"bypass-everything", "bypass-for-finance", "inspect-on-sites"}
	if !testComparableArraiesEq(names, wantNames) {
		t.Errorf("the POSTed rules are %v, want %v. Array position IS rule precedence on this "+
			"endpoint, so a reordered body is a different security posture.", names, wantNames)
	}
	if !testComparableArraiesEq(priorities, []int{2, 1, 0}) {
		t.Errorf("the POSTed priorities are %v, want [2 1 0]: priority descends with array "+
			"position, len-1-index (API-FINDINGS 1.16)", priorities)
	}

	/*
		cleanupBypassRuleDefaultAction is OUT OF SCOPE and must stay off the
		wire. It is feature-gated off on the only tenant available -- both values
		answer 422 "Cleanup rule default action is not available on your tenant"
		(phase4-verification W4) -- so this provider cannot exercise it, and
		sending any value for it would fail every apply on such a tenant. Leaving
		the key absent is also what keeps a feature-ENABLED tenant's existing
		setting untouched by a write from here.
	*/
	if sent.Cleanup != nil {
		t.Errorf("the POST body carries cleanupBypassRuleDefaultAction = %q. It is feature-gated "+
			"off on the only tenant available (422, phase4-verification W4), so this provider "+
			"does not manage it and must not send it:\n%s", *sent.Cleanup, bodies[0])
	}
}

// ---------------------------------------------------------------------------
// The canonicalised read shape
// ---------------------------------------------------------------------------

/*
TestHttpsInspectionFlattenDropsTheServerEmptyBuckets covers the single most
likely defect in this resource, at the level where the cause is legible.

The server answers an empty sources/destinations by EXPANDING it into one bucket
per legal type with an empty value (API-FINDINGS 1.15; phase4-verification W1
records that this list canonicalises the same way). A flattener that copies those
into state puts `sources { users = [] groups = [] ... }` in state against a
configuration with no sources block at all -- and then every plan proposes a
change to a resource nobody touched, forever, with an apply that cannot converge
because the next read produces the same thing again.

TestHttpsInspectionReadProducesNoPermanentDiff proves the consequence; this
proves the mechanism, so a failure says which flattener is wrong.
*/
func TestHttpsInspectionFlattenDropsTheServerEmptyBuckets(t *testing.T) {
	rules := httpsInspectionRulesFromBody(t, httpsInspectionProbeBody)
	if len(rules) != 3 {
		t.Fatalf("flattened %d rules, want 3", len(rules))
	}

	// Position 0 restricted nothing, so all nine buckets the server returned are
	// empty and NEITHER block may be emitted.
	unrestricted := rules[0].(map[string]interface{})
	for _, attr := range []string{"sources", "destinations"} {
		if got := unrestricted[attr].([]interface{}); len(got) != 0 {
			t.Errorf("an unrestricted rule flattened %s to %v; want an empty list. The server "+
				"expands an empty %s into one bucket per legal type with an empty value, and "+
				"writing those into state is a diff on every plan, forever.", attr, got, attr)
		}
	}

	// Position 1 populated four buckets, two of them types the access policy
	// does not have. The populated ones survive; the empty ones alongside them
	// still have to go.
	populated := rules[1].(map[string]interface{})
	sources := populated["sources"].([]interface{})
	if len(sources) != 1 {
		t.Fatalf("a restricted rule flattened sources to %v, want one block", sources)
	}
	source := sources[0].(map[string]interface{})
	if got, ok := source["users"].([]string); !ok || !testComparableArraiesEq(
		sortedCopy(got), []string{"user-1", "user-2"}) {
		t.Errorf("sources.users = %v, want the members user-1 and user-2", source["users"])
	}
	if got, ok := source["applications"].([]string); !ok || !testComparableArraiesEq(
		got, []string{"app-1"}) {
		t.Errorf("sources.applications = %v, want [app-1]. `applications` is a source type "+
			"this policy has and the access policy does not; a table copied from the sibling "+
			"resource would drop it silently.", source["applications"])
	}
	for _, empty := range []string{"groups", "addresses"} {
		if _, present := source[empty]; present {
			t.Errorf("sources carries %s, which the server returned as an empty bucket; an "+
				"empty bucket means \"unrestricted\" and must not become a set attribute", empty)
		}
	}

	destinations := destinationBlock(t, populated)
	if got, ok := destinations["categories"].([]string); !ok || !testComparableArraiesEq(
		got, []string{"100000018"}) {
		t.Errorf("destinations.categories = %v, want [100000018]", destinations["categories"])
	}
	if got, ok := destinations["domains"].([]string); !ok || !testComparableArraiesEq(
		got, []string{"domain-1"}) {
		t.Errorf("destinations.domains = %v, want [domain-1]. `domains` is a destination type "+
			"this policy has and the access policy does not.", destinations["domains"])
	}
	// application_control_applications is NOT in this list, and its absence is
	// the point. The captured body does not emit that bucket at all, so asserting
	// it is absent from flattened state asserted nothing: the row could never
	// fail. TestHttpsInspectionFlattensTheApplicationControlApplicationsBucket
	// covers the type against a response that actually contains it.
	for _, empty := range []string{"addresses", "updatable_objects"} {
		if _, present := destinations[empty]; present {
			t.Errorf("destinations carries %s from an empty bucket", empty)
		}
	}

	/*
		Position 2 has `addresses` populated on BOTH sides. This policy is the
		only one where the same attribute name is legal as a source and as a
		destination, so a flattener that looked the type up in the wrong table
		would put the destination's ids into `sources.addresses` -- a rule
		matching the wrong traffic, with nothing failing.
	*/
	both := rules[2].(map[string]interface{})
	bothSources := both["sources"].([]interface{})[0].(map[string]interface{})
	if got, ok := bothSources["addresses"].([]string); !ok || !testComparableArraiesEq(
		got, []string{"addr-1"}) {
		t.Errorf("sources.addresses = %v, want [addr-1]", bothSources["addresses"])
	}
	bothDestinations := destinationBlock(t, both)
	if got, ok := bothDestinations["addresses"].([]string); !ok || !testComparableArraiesEq(
		got, []string{"addr-2"}) {
		t.Errorf("destinations.addresses = %v, want [addr-2]: `addresses` is legal on both "+
			"sides here, so the two must not be crossed", bothDestinations["addresses"])
	}
	if got := both["action"].(string); got != "inspect" {
		t.Errorf("rule 2 action = %q, want inspect", got)
	}
	if got := both["applied_on"].(string); got != "sites" {
		t.Errorf("rule 2 applied_on = %q, want sites", got)
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

/*
TestHttpsInspectionFlattensTheApplicationControlApplicationsBucket replaces an
assertion that could not fail.

`application_control_applications` is one of the five destination types this
resource ships, because HttpsInspectionDestination.type declares it. The captured
GET body does not contain a bucket of that type -- one rule's canonicalisation
did not produce one -- so the row in
TestHttpsInspectionFlattenDropsTheServerEmptyBuckets that required it to be
ABSENT from flattened state was vacuous: the fixture never emitted it, so the
assertion proved nothing about the flattener and would have gone on passing if
the type had been deleted from httpsInspectionDestinationBuckets entirely.

This drives the type through the flattener directly, in both directions, against
a response that does contain it. The response is explicitly HYPOTHETICAL and is
not folded into the captured fixture: whether this endpoint ever emits such a
bucket is unmeasured (API-FINDINGS 1.20, as corrected), and a fixture that
claimed otherwise would be the fidelity defect this file has already shipped
twice.

Delete the table entry and the first half fails; break the empty-bucket rule and
the second half fails.
*/
func TestHttpsInspectionFlattensTheApplicationControlApplicationsBucket(t *testing.T) {
	t.Run("a populated bucket reaches state", func(t *testing.T) {
		block := flattenHttpsInspectionDestinations([]perimeter81Sdk.HttpsInspectionDestination{
			{Type: "applicationControlApplications", Value: []string{"aca-1", "aca-2"}},
		})
		if len(block) != 1 {
			t.Fatalf("flattened to %v, want one destinations block: the type is declared on "+
				"HttpsInspectionDestination.type and this resource offers it, so a server "+
				"that returns one must not have it dropped on the floor", block)
		}
		got, ok := block[0].(map[string]interface{})["application_control_applications"].([]string)
		if !ok || !testComparableArraiesEq(got, []string{"aca-1", "aca-2"}) {
			t.Errorf("destinations.application_control_applications = %v, want [aca-1 aca-2]",
				block[0].(map[string]interface{})["application_control_applications"])
		}
	})

	t.Run("an empty bucket is dropped like every other", func(t *testing.T) {
		block := flattenHttpsInspectionDestinations([]perimeter81Sdk.HttpsInspectionDestination{
			{Type: "applicationControlApplications", Value: []string{}},
			{Type: "categories", Value: []string{}},
		})
		if len(block) != 0 {
			t.Errorf("flattened to %v, want no block at all: empty buckets mean "+
				"\"unrestricted\", and writing them into state is a diff on every plan, "+
				"forever", block)
		}
	})
}

/*
TestHttpsInspectionReadProducesNoPermanentDiff reproduces a whole refresh and
then plans the original configuration against the state it produced.

This is the test that matters most in practice. It takes the canonicalised body,
runs it through the same flatten and d.Set the resource's Read makes, and asks
the resource to plan the user's configuration against the result. A resource that
does not read back what it writes shows a diff here -- which in a real run is a
diff on every plan, for every rule, with an apply that never converges.
*/
func TestHttpsInspectionReadProducesNoPermanentDiff(t *testing.T) {
	r := resourceHttpsInspectionPolicy()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})
	d.SetId(httpsInspectionPolicyResourceID)

	if err := d.Set("rule", httpsInspectionRulesFromBody(t, httpsInspectionProbeBody)); err != nil {
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
		terraform.NewResourceConfigRaw(httpsInspectionProbeConfig()), nil)
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
TestHttpsInspectionWriteSendsNeitherRefusedFieldsNorNullArrays pins the two ways
a POST built from a previous read gets rejected.

This list's read model carries _created_at, which the write model does not
declare (phase4-verification W1), alongside the className/objectId that
perimeter81-swg-api's own stored bypass rules carry -- and echoing a GET body
back on the sibling endpoint answers 422 `"fromDefault" is not allowed`
(API-FINDINGS 1.17). And a nil Go slice serialises as JSON null, which is a type
error. What null itself does is EXTRAPOLATION and this comment used to state it
as measurement: §1.19 measured the STRING "disabled" answering a 500 on the
sibling endpoint -- indistinguishable from the endpoint being down, and misread as
exactly that when it was first measured. null is a type error of the same shape,
so the same 500 is likely but was not observed.

The assertion is on the serialised bytes because both problems only exist on the
wire, and it uses httpsInspectionRefusedFields rather than a literal so that the
test follows the list rather than a copy of it.
*/
func TestHttpsInspectionWriteSendsNeitherRefusedFieldsNorNullArrays(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(httpsInspectionProbeBody))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceHttpsInspectionPolicy().Schema,
		httpsInspectionProbeConfig())
	if diags := resourceHttpsInspectionPolicyWrite(context.Background(), d,
		newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("the write failed: %v", diags)
	}

	_, bodies := log.snapshot()
	body := bodies[0]

	for _, refused := range httpsInspectionRefusedFields {
		if strings.Contains(body, `"`+refused+`"`) {
			t.Errorf("the POST body carries %q, which the write model refuses "+
				"(API-FINDINGS 1.17):\n%s", refused, body)
		}
	}
	for _, array := range []string{"destinations", "sources"} {
		if strings.Contains(body, `"`+array+`":null`) {
			t.Errorf("the POST body sends %s as null; a type error here answers 500, not 400 "+
				"(API-FINDINGS 1.19):\n%s", array, body)
		}
	}
}

/*
TestHttpsInspectionExpandOmitsEmptyBuckets covers the write side of the same
normalisation the flattener does on the read side.

A bucket with no members is omitted rather than sent with an empty value: both
mean "unrestricted" to the server -- molecules.types.json gives every one of
these a `value` of `minItems: 0`, and perimeter81-swg-api's own component
fixtures spell "any source" as buckets with empty values
(`bypassRulesWithAnySource`) -- so this is a choice about what we send, and the
reason to make it is that it is what the flattener produces, which keeps the two
halves symmetrical.
*/
func TestHttpsInspectionExpandOmitsEmptyBuckets(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceHttpsInspectionPolicy().Schema,
		httpsInspectionProbeConfig())
	rules := expandHttpsInspectionRules(d.Get("rule").([]interface{}))

	if len(rules) != 3 {
		t.Fatalf("expanded %d rules, want 3", len(rules))
	}

	if got := rules[0]; len(got.Sources) != 0 || len(got.Destinations) != 0 {
		t.Errorf("a rule that restricts nothing expanded to sources=%v destinations=%v; both "+
			"must be empty arrays", got.Sources, got.Destinations)
	}
	if got := rules[0].GetAction(); got != "bypass" {
		t.Errorf("action expanded to %q, want bypass. The API declares action optional with a "+
			"default, but the schema requires it, so the value sent is always the user's", got)
	}

	restricted := rules[1]
	sourceTypes := map[string][]string{}
	for _, bucket := range restricted.Sources {
		sourceTypes[bucket.Type] = sortedCopy(bucket.Value)
	}
	if len(sourceTypes) != 2 {
		t.Fatalf("sources expanded to %v, want exactly the users and applications buckets -- an "+
			"empty groups or addresses bucket alongside them is noise the server would only "+
			"echo back", restricted.Sources)
	}
	if !testComparableArraiesEq(sourceTypes["users"], []string{"user-1", "user-2"}) {
		t.Errorf("sources.users expanded to %v, want the members user-1 and user-2",
			sourceTypes["users"])
	}
	if !testComparableArraiesEq(sourceTypes["applications"], []string{"app-1"}) {
		t.Errorf("sources.applications expanded to %v, want [app-1]", sourceTypes["applications"])
	}

	destinationTypes := map[string][]string{}
	for _, bucket := range restricted.Destinations {
		destinationTypes[bucket.Type] = sortedCopy(bucket.Value)
	}
	if len(destinationTypes) != 2 ||
		!testComparableArraiesEq(destinationTypes["categories"], []string{"100000018"}) ||
		!testComparableArraiesEq(destinationTypes["domains"], []string{"domain-1"}) {
		t.Errorf("destinations expanded to %v, want exactly the categories and domains buckets",
			restricted.Destinations)
	}

	// `addresses` on both sides, expanded into the right one of the two tables.
	both := rules[2]
	if len(both.Sources) != 1 || both.Sources[0].Type != "addresses" ||
		!testComparableArraiesEq(both.Sources[0].Value, []string{"addr-1"}) {
		t.Errorf("sources expanded to %v, want one addresses bucket holding addr-1", both.Sources)
	}
	if len(both.Destinations) != 1 || both.Destinations[0].Type != "addresses" ||
		!testComparableArraiesEq(both.Destinations[0].Value, []string{"addr-2"}) {
		t.Errorf("destinations expanded to %v, want one addresses bucket holding addr-2",
			both.Destinations)
	}
}

// ---------------------------------------------------------------------------
// Plan-time refusals
// ---------------------------------------------------------------------------

/*
TestHttpsInspectionEmptyRuleListIsRejectedAtPlanTime pins MinItems on `rule`.

POST with an empty array answers 400 VALIDATION_BYPASS_RULES_REQUIRED
(phase4-verification W1, API-FINDINGS 1.18), so an empty list can never succeed
and there is no reason to spend a round trip discovering that. Worse, the
tempting "fix" for the failure is to route an empty write to DELETE -- which
would put the call that clears a tenant's entire policy onto the ordinary apply
path.

Both spellings of "no rules" are checked. `rule = []` reaches MinItems; a
configuration that omits the block entirely is caught by Required, because
Terraform's config shim drops an empty list before validation sees it. The
resource needs both, and this test would pass with only one of them if it checked
only one.
*/
func TestHttpsInspectionEmptyRuleListIsRejectedAtPlanTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config map[string]interface{}
	}{
		{"an explicitly empty list", map[string]interface{}{"rule": []interface{}{}}},
		{"no rule block at all", map[string]interface{}{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := resourceHttpsInspectionPolicy().Validate(terraform.NewResourceConfigRaw(tc.config))
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
TestHttpsInspectionRejectsValuesTheServerRejects covers the single-field enum and
format checks -- the ones where the API contract and the stored-document schema
agree, so the answer cannot be tenant-dependent.

`inspectNoDecrypt` is deliberately NOT in this list even though
p81-mongo-validation-schemas' $defs.bypassAction declares only [bypass, inspect].
See httpsInspectionActionValues: that schema has validationAction "warn", and the
live tenant answered a NAMED validation error for the value rather than an
unknown-value error, so the narrower list is not the authority. Its
appliedOn-dependent refusal is covered by
TestHttpsInspectionRejectsInspectNoDecryptOnSitesAndBoth instead.
*/
func TestHttpsInspectionRejectsValuesTheServerRejects(t *testing.T) {
	for _, tc := range []struct {
		name      string
		overrides map[string]interface{}
		wantIn    string
	}{
		{"an appliedOn the API does not have", map[string]interface{}{"applied_on": "everywhere"}, "applied_on"},
		{"an action the API does not have", map[string]interface{}{"action": "drop"}, "action"},
		{"the access policy's action, which this list does not have",
			map[string]interface{}{"action": "block"}, "action"},
		{"the v2.3 spelling of status", map[string]interface{}{"status": "enabled"}, "status"},
		{"a name containing an angle bracket", map[string]interface{}{"name": "<script>"}, "name"},
		{"an empty name", map[string]interface{}{"name": ""}, "name"},
		{"a name of 101 characters", map[string]interface{}{
			"name": strings.Repeat("a", 101)}, "name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]interface{}{
				"rule": []interface{}{httpsInspectionValidRule(tc.overrides)},
			}
			diags := resourceHttpsInspectionPolicy().Validate(terraform.NewResourceConfigRaw(config))
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
TestHttpsInspectionRuleNameLengthIsCountedInCharactersNotBytes is the sibling of
TestSwgAccessPolicyRuleNameLengthIsCountedInCharactersNotBytes, and it exists
separately because the two resources have separate validators that were broken
in the same way at the same time.

`HttpsInspectionRule.name` declares `maxLength: 100` in the OpenAPI document and
p81-mongo-validation-schemas resolves RuleBypass.name through `$defs.ruleName` to
`string-1-100`. Both count CHARACTERS; validation.StringLenBetween counts BYTES.
See the access-policy twin for the full argument and resource_group.go:119-129
for the first time this repository met it.
*/
func TestHttpsInspectionRuleNameLengthIsCountedInCharactersNotBytes(t *testing.T) {
	validate := resourceHttpsInspectionPolicy().Schema["rule"].Elem.(*schema.Resource).
		Schema["name"].ValidateFunc
	if validate == nil {
		t.Fatal("rule.name has no ValidateFunc, so SHI-N03's empty name reaches POST " +
			"/v3/ia/https-inspection/policy")
	}

	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"ascii, comfortably inside", "Bypass the payroll portal", false},
		{"exactly 100 ascii characters", strings.Repeat("a", 100), false},
		{"34 CJK characters, 102 bytes", strings.Repeat("研", 34), false},
		{"100 CJK characters, 300 bytes -- the boundary, in the wide case",
			strings.Repeat("研", 100), false},
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

	t.Run("a 100-character CJK name plans cleanly", func(t *testing.T) {
		diags := resourceHttpsInspectionPolicy().Validate(terraform.NewResourceConfigRaw(
			map[string]interface{}{"rule": []interface{}{
				httpsInspectionValidRule(map[string]interface{}{
					"name": strings.Repeat("研", 100),
				}),
			}}))
		if diags.HasError() {
			t.Errorf("a 100-character rule name was refused at plan time: %v. The server "+
				"accepts it -- maxLength counts characters -- and the operator has no "+
				"workaround but to shorten a legal name", diags)
		}
	})
}

/*
TestHttpsInspectionRejectsInspectNoDecryptOnSitesAndBoth pins the ONE half of the
action/appliedOn matrix that is tenant-independent.

The API schema states that `inspectNoDecrypt` requires the Inspection Policy
feature and is valid only on `agents` -- "rejected on 'sites' and 'both'
regardless of the feature". Regardless is what makes it safe to encode: no tenant
accepts it, so refusing it at plan time costs nobody a legal configuration and
saves a round trip that could only ever end in
422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED.

TestHttpsInspectionAdmitsTheFeatureGatedCombinations is the control, and it is
the more important of the two.
*/
func TestHttpsInspectionRejectsInspectNoDecryptOnSitesAndBoth(t *testing.T) {
	for _, appliedOn := range []string{"sites", "both"} {
		t.Run("inspectNoDecrypt on "+appliedOn, func(t *testing.T) {
			config := map[string]interface{}{"rule": []interface{}{
				httpsInspectionValidRule(map[string]interface{}{
					"action": "inspectNoDecrypt", "applied_on": appliedOn,
				}),
			}}

			_, err := resourceHttpsInspectionPolicy().Diff(context.Background(), nil,
				terraform.NewResourceConfigRaw(config), nil)
			if err == nil {
				t.Fatalf("action inspectNoDecrypt with applied_on %q planned cleanly. No tenant "+
					"accepts it: the API schema says inspectNoDecrypt is \"rejected on 'sites' "+
					"and 'both' regardless of the feature\", so this can only ever answer 422",
					appliedOn)
			}
			for _, fragment := range []string{"rule.0", "inspectNoDecrypt", appliedOn, "agents"} {
				if !strings.Contains(err.Error(), fragment) {
					t.Errorf("the plan error does not contain %q, so it does not say which rule "+
						"is wrong or what to do instead: %v", fragment, err)
				}
			}
		})
	}
}

/*
TestHttpsInspectionAdmitsTheFeatureGatedCombinations is the control for the guard
above, and it is the half that matters more.

The milestone spec says `action = "inspect"` is valid only with
`applied_on = "sites"`, and the measured matrix on THIS tenant agrees:

	inspect + agents -> 422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED
	inspect + both   -> 422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED

Encoding that would still be wrong. It is true because the tenant's Inspection
Policy feature is DISABLED, not because the rule is absolute -- the API schema
says `inspect` is also valid on `agents` and `both` once the feature is on, and
this provider cannot see the feature flag. A validator that is correct on the
tenant you developed against and wrong elsewhere is worse than no validator, and
the server's 422 is specific, names the field, and is exactly the kind of answer
worth deferring to.

So every row below MUST plan cleanly. If one starts failing, somebody has
"restored" the spec's rule and a feature-enabled tenant can no longer express a
configuration its server accepts.
*/
func TestHttpsInspectionAdmitsTheFeatureGatedCombinations(t *testing.T) {
	for _, tc := range []struct {
		name      string
		overrides map[string]interface{}
	}{
		{"inspect on sites, which every tenant accepts", map[string]interface{}{
			"action": "inspect", "applied_on": "sites"}},
		{"inspect on agents, which needs the Inspection Policy feature", map[string]interface{}{
			"action": "inspect", "applied_on": "agents"}},
		{"inspect on both, which needs the Inspection Policy feature", map[string]interface{}{
			"action": "inspect", "applied_on": "both"}},
		{"inspectNoDecrypt on agents, its one legal appliedOn", map[string]interface{}{
			"action": "inspectNoDecrypt", "applied_on": "agents"}},
		{"bypass on sites", map[string]interface{}{"action": "bypass", "applied_on": "sites"}},
		{"bypass on agents", map[string]interface{}{"action": "bypass", "applied_on": "agents"}},
		{"bypass on both", map[string]interface{}{"action": "bypass", "applied_on": "both"}},
		// An action that is not known until apply cannot be judged, and refusing
		// on the empty-string reading of it would break every configuration that
		// derives the action from another resource or a variable.
		{"an action that is not known until apply", map[string]interface{}{
			"action": hcl2ValueNotYetKnown, "applied_on": "sites"}},
		{"an applied_on that is not known until apply", map[string]interface{}{
			"action": "inspectNoDecrypt", "applied_on": hcl2ValueNotYetKnown}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]interface{}{
				"rule": []interface{}{httpsInspectionValidRule(tc.overrides)},
			}
			if _, err := resourceHttpsInspectionPolicy().Diff(context.Background(), nil,
				terraform.NewResourceConfigRaw(config), nil); err != nil {
				t.Fatalf("this configuration was refused at plan time, and the server may well "+
					"accept it: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Shape of the resource itself
// ---------------------------------------------------------------------------

/*
TestHttpsInspectionCreateAndUpdateAreOneFunction pins that there is no second
write path.

The endpoint has no partial update: POST replaces the whole array, so creating
the policy and changing it are byte-for-byte the same request. Two functions
would be two copies of one call, and the only thing that could ever differ
between them is a bug -- most likely one that appends instead of replacing, which
on this endpoint doubles the tenant's policy.
*/
func TestHttpsInspectionCreateAndUpdateAreOneFunction(t *testing.T) {
	r := resourceHttpsInspectionPolicy()
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
TestHttpsInspectionIDAndPriorityAreComputedOnly pins that neither server-assigned
field can be written.

Both are assigned by the server, and `priority` is not merely overwritten but
DISCARDED: a rule created with priority 1 reads back as priority 0
(API-FINDINGS 1.16). An Optional priority would let a user write a number into
HCL, see it accepted at plan time, and get something else -- with no error and no
diff, because the read overwrites it.
*/
func TestHttpsInspectionIDAndPriorityAreComputedOnly(t *testing.T) {
	rule := resourceHttpsInspectionPolicy().Schema["rule"].Elem.(*schema.Resource)
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
TestHttpsInspectionDescriptionStatesWhatDestroyAndApplyDo is a documentation
test, and it is here because the facts it checks are the ones that surprise
people and none of them is visible from the configuration.

Destroy removes EVERY bypass rule in the tenant. Apply removes any rule that is
not in the configuration, including rules made in the console. Both belong in the
resource description, where `terraform providers schema` and the registry both
show them, rather than only in a docs page.

Two things are checked for the opposite reason -- because they must NOT be said:

  - the `priority` description must not claim an evaluation order. Which end of
    the list wins has not been measured, and a resource that guesses would be
    telling users their new rule is safe when it might pre-empt everything.
  - the `sources`/`destinations` descriptions must not recommend an empty block.
    They said "omit the block, or leave every attribute in it empty" on the
    sibling resource once, and the second half was a trap: an empty block is a
    permanent diff, so the description was recommending a configuration that
    cannot converge. This resource is written with the corrected wording from the
    start; the test is what keeps it.
*/
func TestHttpsInspectionDescriptionStatesWhatDestroyAndApplyDo(t *testing.T) {
	description := resourceHttpsInspectionPolicy().Description

	for _, fragment := range []string{
		"removes EVERY HTTPS-inspection bypass rule",
		"not in your configuration is removed",
		"console",
	} {
		if !strings.Contains(description, fragment) {
			t.Errorf("the resource description does not contain %q, so an operator running "+
				"terraform destroy or terraform apply is not warned:\n%s", fragment, description)
		}
	}

	rule := resourceHttpsInspectionPolicy().Schema["rule"].Elem.(*schema.Resource)
	for _, attr := range []string{"sources", "destinations"} {
		block := rule.Schema[attr].Description
		if !strings.Contains(block, "only way") {
			t.Errorf("the %s description does not say that omitting the block is the ONLY way "+
				"to express \"any\":\n%s", attr, block)
		}
		if strings.Contains(block, "leave every attribute in it empty") {
			t.Errorf("the %s description still recommends an empty block, which is a permanent "+
				"diff and is refused at plan time:\n%s", attr, block)
		}
	}

	priority := rule.Schema["priority"].Description
	if !strings.Contains(priority, "not established") {
		t.Errorf("the priority description does not say that the evaluation order is not "+
			"established. It is not: API-FINDINGS 1.16 measured the NUMBERING and explicitly "+
			"did not measure whether priority 0 is evaluated first or last.\n%s", priority)
	}
	// The blacklist is phrases that can only ever be a CLAIM. "is evaluated
	// first" is deliberately absent from it, because the honest sentence above
	// contains that substring inside its own negation, and a check that cannot
	// tell the two apart would push a future editor towards vaguer wording rather
	// than towards a measurement.
	for _, guess := range []string{"takes precedence", "highest precedence",
		"is consulted first", "is evaluated before", "wins"} {
		if strings.Contains(priority, guess) {
			t.Errorf("the priority description claims %q. Which end of the range the policy "+
				"engine consults first has NOT been measured -- see API-FINDINGS 1.16, which "+
				"says so explicitly -- and for a policy engine the difference is whether a new "+
				"rule silently pre-empts every existing one.", guess)
		}
	}

	/*
		The action description must carry the feature-flag caveat. It is the only
		place a user is told why `inspect` on `agents` planned cleanly and then
		failed with a 422 -- which, on a tenant without the feature, is exactly
		what will happen, and it is the right trade.
	*/
	action := rule.Schema["action"].Description
	for _, fragment := range []string{"Inspection Policy feature", "VALIDATION_ACTION_INSPECT_NOT_ALLOWED"} {
		if !strings.Contains(action, fragment) {
			t.Errorf("the action description does not mention %q, so a user who hits the "+
				"server's refusal has nothing to connect it to:\n%s", fragment, action)
		}
	}
}

// ---------------------------------------------------------------------------
// Delete, and the read error that must never become an empty policy
// ---------------------------------------------------------------------------

/*
TestHttpsInspectionDeleteIssuesTheEndpointDeleteAndNothingElse pins the one
destructive call in this resource.

It is unguarded on purpose: this resource owns the whole policy, so destroying it
means the policy is gone, and there is no remainder to preserve. What must not
happen is anything ELSE -- a read first, a POST of the survivors, a retry. The
assertion is on the whole request list rather than the last request, because a
guard that inspects only the final call cannot see an extra one, and an extra
call on this endpoint is a deleted tenant policy.
*/
func TestHttpsInspectionDeleteIssuesTheEndpointDeleteAndNothingElse(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":200}`))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceHttpsInspectionPolicy().Schema,
		httpsInspectionProbeConfig())
	d.SetId(httpsInspectionPolicyResourceID)

	if diags := resourceHttpsInspectionPolicyDelete(context.Background(), d,
		newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("the delete failed: %v", diags)
	}
	if d.Id() != "" {
		t.Errorf("the id is still %q after a successful delete", d.Id())
	}

	calls, _ := log.snapshot()
	want := []string{"DELETE /v3/ia/https-inspection/policy"}
	if !testComparableArraiesEq(calls, want) {
		t.Errorf("requests were %v, want exactly %v", calls, want)
	}
}

/*
TestHttpsInspectionDeleteKeepsTheIDWhenTheServerRefuses is the other half. A
failed DELETE must leave the resource in state: clearing the id would tell
Terraform the policy is gone while the tenant is still enforcing every rule in
it, and nothing would then be tracking them.
*/
func TestHttpsInspectionDeleteKeepsTheIDWhenTheServerRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceHttpsInspectionPolicy().Schema,
		httpsInspectionProbeConfig())
	d.SetId(httpsInspectionPolicyResourceID)

	if diags := resourceHttpsInspectionPolicyDelete(context.Background(), d,
		newTestUserAPIClient(srv.URL)); !diags.HasError() {
		t.Fatal("a 403 from the DELETE was reported as success")
	}
	if d.Id() != httpsInspectionPolicyResourceID {
		t.Errorf("the id was cleared after a FAILED delete; Terraform would drop a live "+
			"policy from state and nothing would be tracking its rules (id is now %q)", d.Id())
	}
}

/*
TestHttpsInspectionReadReportsAnErrorRatherThanAnEmptyPolicy is the Phase 3
lesson applied at the resource level.

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
func TestHttpsInspectionReadReportsAnErrorRatherThanAnEmptyPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		wantErr   bool
		wantRules int
	}{
		{"a 404, which means the URL is wrong", http.StatusNotFound,
			`{"message":"Cannot GET /api/v3/ia/https-inspection/policy"}`, true, 0},
		{"a 500", http.StatusInternalServerError, `{"message":"boom"}`, true, 0},
		{"a genuinely empty policy, which is a real state", http.StatusOK,
			httpsInspectionGetBody(), false, 0},
		{"a policy with rules", http.StatusOK, httpsInspectionProbeBody, false, 3},
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

			d := schema.TestResourceDataRaw(t, resourceHttpsInspectionPolicy().Schema,
				map[string]interface{}{})
			d.SetId(httpsInspectionPolicyResourceID)

			diags := resourceHttpsInspectionPolicyRead(context.Background(), d,
				newTestUserAPIClient(srv.URL))

			if diags.HasError() != tc.wantErr {
				t.Fatalf("HasError() = %t, want %t (diags: %v)", diags.HasError(), tc.wantErr, diags)
			}
			if tc.wantErr {
				// The id must survive. Clearing it on a failed read is how a
				// transport problem becomes "the policy does not exist", and the
				// recreate that follows BEGINS with the destructive DELETE.
				if d.Id() != httpsInspectionPolicyResourceID {
					t.Errorf("the id was cleared by a failed read; the next plan would offer "+
						"to recreate a policy that already exists, and recreating it starts "+
						"with the DELETE that empties the tenant (id is now %q)", d.Id())
				}
			} else if got := len(d.Get("rule").([]interface{})); got != tc.wantRules {
				t.Errorf("read %d rules into state, want %d", got, tc.wantRules)
			}

			calls, _ := log.snapshot()
			if want := []string{"GET /v3/ia/https-inspection/policy"}; !testComparableArraiesEq(calls, want) {
				t.Errorf("requests were %v, want exactly %v: a read must never be followed "+
					"by a write of any kind", calls, want)
			}
		})
	}
}

/*
TestHttpsInspectionImportAdoptsTheTenantPolicy covers the import path, including
the part that is easy to get wrong: the id a user types is ignored, and the
stored id is the constant, so an imported resource is byte-identical in state to
a created one.
*/
func TestHttpsInspectionImportAdoptsTheTenantPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(httpsInspectionProbeBody))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceHttpsInspectionPolicy().Schema,
		map[string]interface{}{})
	d.SetId("whatever-the-user-typed")

	imported, err := resourceHttpsInspectionPolicyImportState(context.Background(), d,
		newTestUserAPIClient(srv.URL))
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("import returned %d resources, want 1", len(imported))
	}
	if got := imported[0].Id(); got != httpsInspectionPolicyResourceID {
		t.Errorf("the imported id is %q, want the constant %q -- an imported resource must be "+
			"identical in state to a created one", got, httpsInspectionPolicyResourceID)
	}
	if got := len(imported[0].Get("rule").([]interface{})); got != 3 {
		t.Errorf("import read %d rules, want 3", got)
	}
}

/*
TestHttpsInspectionImportFailsLoudlyWhenTheReadFails pins that a failed import is
an error rather than an empty resource. Importing a policy as "no rules" and then
applying would replace the tenant's real policy with whatever the configuration
happened to say, without anyone having seen the real one.
*/
func TestHttpsInspectionImportFailsLoudlyWhenTheReadFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Cannot GET /api/v3/ia/https-inspection/policy"}`))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceHttpsInspectionPolicy().Schema,
		map[string]interface{}{})
	if _, err := resourceHttpsInspectionPolicyImportState(context.Background(), d,
		newTestUserAPIClient(srv.URL)); err == nil {
		t.Fatal("import succeeded over a failed read; it must report the error instead of " +
			"adopting a policy it never saw")
	}
}

// ---------------------------------------------------------------------------
// The empty endpoint block, which would otherwise be a permanent diff
// ---------------------------------------------------------------------------

/*
TestHttpsInspectionEmptyEndpointBlockIsRefusedAtPlanTime covers the trap the
sibling resource's schema descriptions used to recommend.

An unrestricted rule comes back from the server as empty buckets, which the
flatteners correctly drop, so it always reads back as ZERO `sources` blocks. A
configuration that spells "any source" as `sources {}` or `sources { users = [] }`
holds ONE. Those two can never meet. Measured on the access policy, through the
real Diff path, with the expander's own empty-bucket normalisation fully in place:

	config: sources { users = [] }   ->  rule.0.sources.#: "0" -> "1"
	config: sources {}               ->  rule.0.sources.#: "0" -> "1"

non-empty on every plan, forever, with an apply that "succeeds" each time and
changes nothing. The guard turns it into a plan-time error naming the block. When
the guard is removed this test does not merely fail -- it PRINTS the perpetual
diff, so the failure output is the evidence rather than a claim about it.
*/
func TestHttpsInspectionEmptyEndpointBlockIsRefusedAtPlanTime(t *testing.T) {
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
					"applications": []interface{}{}, "addresses": []interface{}{},
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
		{
			name: "a destinations block whose every attribute is empty",
			rule: map[string]interface{}{
				"destinations": []interface{}{map[string]interface{}{
					"categories": []interface{}{}, "domains": []interface{}{},
					"addresses": []interface{}{}, "updatable_objects": []interface{}{},
					"application_control_applications": []interface{}{},
				}},
			},
			wantIn: "rule.0.destinations",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]interface{}{
				"rule": []interface{}{httpsInspectionValidRule(tc.rule)},
			}

			r := resourceHttpsInspectionPolicy()
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
TestHttpsInspectionPopulatedEndpointBlockStillPlans is the control for the guard
above, and it is the half that matters more.

A guard that refuses empty blocks is trivial to write in a form that also refuses
a block with one populated attribute among several empty ones -- which is the
COMMON configuration, and refusing it would be a worse bug than the one being
fixed. This pins that the guard is narrow.

The unknown-value rows are the specific case that would break real
configurations: `sources { users = [checkpointsase_user.x.id] }` where the id
does not exist yet reads as an empty set during plan, indistinguishable from an
empty block. A guard that asked NewValueKnown about the collection key rather
than its `.#` count key gets a confident "known" for a set that reads as empty,
and so refuses every rule that references a resource created in the same apply.
That was a real defect on the sibling resource; the mixed known/unknown row is
the one that pins the fix rather than an approximation of it.
*/
func TestHttpsInspectionPopulatedEndpointBlockStillPlans(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule map[string]interface{}
	}{
		{"one populated attribute among empties", map[string]interface{}{
			"sources": []interface{}{map[string]interface{}{
				"users": []interface{}{"user-1"}, "groups": []interface{}{},
				"applications": []interface{}{}, "addresses": []interface{}{},
			}},
		}},
		{"no block at all, which is how any source is spelled", map[string]interface{}{}},
		{"a value that is not known until apply", map[string]interface{}{
			"sources": []interface{}{map[string]interface{}{
				"users": []interface{}{hcl2ValueNotYetKnown},
			}},
		}},
		{"an unknown value mixed with a known one", map[string]interface{}{
			"sources": []interface{}{map[string]interface{}{
				"users":  []interface{}{"user-1"},
				"groups": []interface{}{hcl2ValueNotYetKnown},
			}},
		}},
		{"an unknown value in the LAST bucket of the table", map[string]interface{}{
			"sources": []interface{}{map[string]interface{}{
				"addresses": []interface{}{hcl2ValueNotYetKnown},
			}},
		}},
		{"an unknown destination id", map[string]interface{}{
			"destinations": []interface{}{map[string]interface{}{
				"domains": []interface{}{hcl2ValueNotYetKnown},
			}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]interface{}{
				"rule": []interface{}{httpsInspectionValidRule(tc.rule)},
			}
			if _, err := resourceHttpsInspectionPolicy().Diff(context.Background(), nil,
				terraform.NewResourceConfigRaw(config), nil); err != nil {
				t.Fatalf("this configuration was refused at plan time, and it is legal: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Order, where it does NOT exist
// ---------------------------------------------------------------------------

/*
TestHttpsInspectionReadIsInsensitiveToCollectionOrder covers the assumption the
sibling resource made and had to have corrected in review.

`rule` is ordered, because array position IS rule precedence (API-FINDINGS 1.16).
Nothing else in this resource is. A rule's source and destination ids have no
order anywhere in the API -- `$defs.ruleBypassSources` and
`$defs.ruleBypassDestinations` are declared `uniqueItems: true`, which is set
semantics outright -- and no probe ever measured the server preserving the order
they were sent in.

This test hands the flattener a response whose every collection is in a DIFFERENT
order from the configuration, and asks for a plan. Sets make it empty. Lists make
every element a diff.
*/
func TestHttpsInspectionReadIsInsensitiveToCollectionOrder(t *testing.T) {
	shuffled := httpsInspectionGetBody(httpsInspectionCanonicalRuleJSON(
		"rule-zzz", "shuffled", "agents", "bypass", 0,
		`{"type":"users","value":["user-2","user-1"]},`+
			`{"type":"applications","value":["app-2","app-1"]}`,
		`{"type":"categories","value":["100000018","100000001"]},`+
			`{"type":"domains","value":["domain-2","domain-1"]}`))

	config := map[string]interface{}{
		"rule": []interface{}{map[string]interface{}{
			"name": "shuffled", "applied_on": "agents", "action": "bypass", "status": "active",
			"sources": []interface{}{map[string]interface{}{
				"users":        []interface{}{"user-1", "user-2"},
				"applications": []interface{}{"app-1", "app-2"},
			}},
			"destinations": []interface{}{map[string]interface{}{
				"categories": []interface{}{"100000001", "100000018"},
				"domains":    []interface{}{"domain-1", "domain-2"},
			}},
		}},
	}

	r := resourceHttpsInspectionPolicy()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})
	d.SetId(httpsInspectionPolicyResourceID)
	if err := d.Set("rule", httpsInspectionRulesFromBody(t, shuffled)); err != nil {
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
			"configured, only in a different order. Nothing in the API assigns an order to a "+
			"bucket's ids, so these must be sets:\n%s", report)
	}
}

// ---------------------------------------------------------------------------
// Bucket types this provider does not know
// ---------------------------------------------------------------------------

/*
TestHttpsInspectionBucketTablesCoverTheAPIEnums fails when the API grows a bucket
type this provider has no attribute for.

Without it, a new type is invisible and the invisibility is the damage. Trace it:
the server holds a rule restricted by the new type; Read has nowhere to put it so
it is dropped; state therefore says the block is absent; the configuration also
has no block, so THE PLAN IS EMPTY and the operator is shown nothing; and the
next apply for any unrelated reason POSTs the whole array without the
restriction. A policy widened with no plan output is the one outcome a
declarative tool exists to make impossible.

This is the test that holds the two bucket tables to the DOCUMENT rather than to
the sibling resource, which is what the brief asked for: the source vocabulary
here has `applications` and the destination vocabulary has `domains`, neither of
which exists on the access policy, and `addresses` is legal on both sides where
there it is legal on neither.
*/
func TestHttpsInspectionBucketTablesCoverTheAPIEnums(t *testing.T) {
	doc := findOpenAPIDocument(t)

	for _, tc := range []struct {
		schemaName string
		attr       string
		buckets    []httpsInspectionBucket
	}{
		{"HttpsInspectionSource", "sources", httpsInspectionSourceBuckets},
		{"HttpsInspectionDestination", "destinations", httpsInspectionDestinationBuckets},
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
						"the next apply silently removes the restriction. Add it to the %s "+
						"bucket table and to the %s element schema.",
						tc.schemaName, apiType, tc.schemaName, tc.attr)
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

			// Every mapped type must also have a schema attribute. A table entry
			// with no attribute behind it passes the two loops above and then
			// silently drops the bucket at runtime.
			element := resourceHttpsInspectionPolicy().Schema["rule"].
				Elem.(*schema.Resource).Schema[tc.attr].Elem.(*schema.Resource)
			for _, bucket := range tc.buckets {
				if element.Schema[bucket.attr] == nil {
					t.Errorf("the %s bucket table maps %q to attribute %q, which the %s element "+
						"schema does not declare", tc.schemaName, bucket.apiType, bucket.attr,
						tc.attr)
				}
			}
		})
	}

	// The two vocabularies must not have been copied from each other. Recorded as
	// an assertion because "same shape, different vocabulary" is exactly the
	// situation where a copy-paste survives every other test in this file.
	sourceTypes := map[string]bool{}
	for _, bucket := range httpsInspectionSourceBuckets {
		sourceTypes[bucket.apiType] = true
	}
	for _, apiType := range []string{"applications"} {
		if !sourceTypes[apiType] {
			t.Errorf("httpsInspectionSourceBuckets has no %q bucket. It is in "+
				"HttpsInspectionSource.type and in no access-policy enum, so its absence is "+
				"the signature of a table copied from the sibling resource.", apiType)
		}
	}
	destinationTypes := map[string]bool{}
	for _, bucket := range httpsInspectionDestinationBuckets {
		destinationTypes[bucket.apiType] = true
	}
	for _, apiType := range []string{"domains", "addresses"} {
		if !destinationTypes[apiType] {
			t.Errorf("httpsInspectionDestinationBuckets has no %q bucket, which "+
				"HttpsInspectionDestination.type declares and AccessPolicyDestination.type "+
				"does not.", apiType)
		}
	}
	if destinationTypes["customUrls"] {
		t.Error("httpsInspectionDestinationBuckets maps customUrls, which is an ACCESS POLICY " +
			"destination type and is not in HttpsInspectionDestination.type at all")
	}
}

/*
TestHttpsInspectionReadWarnsAboutBucketTypesItDropped is the runtime half of the
same problem, for the case the build-time test cannot reach: a server that
returns a type its own published spec does not declare.

The warning does not prevent the loss -- nothing in a whole-policy resource can,
because the configuration is the policy -- but it converts an empty plan that
silently widens a tenant's rules into something the operator is shown on the
refresh before it happens.
*/
func TestHttpsInspectionReadWarnsAboutBucketTypesItDropped(t *testing.T) {
	body := httpsInspectionGetBody(httpsInspectionCanonicalRuleJSON(
		"rule-new", "future-type", "agents", "bypass", 0,
		`{"type":"serviceAccounts","value":["sa-1"]}`, ""))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceHttpsInspectionPolicy().Schema,
		map[string]interface{}{})
	d.SetId(httpsInspectionPolicyResourceID)

	diags := resourceHttpsInspectionPolicyRead(context.Background(), d,
		newTestUserAPIClient(srv.URL))
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
TestHttpsInspectionUnknownBucketWarningIgnoresEmptyBuckets pins the gate that had
to be added to the sibling resource in a fix round and is written in here from
the start.

The server returns one bucket per legal type with an empty `value` for every
unrestricted rule (API-FINDINGS 1.15). Without the len(value) > 0 gate, the day
the API grows a bucket type EVERY unrestricted rule on the tenant reports that
the next apply is about to remove entries it does not have.

That is worse than missing the warning entirely: a warning that fires on healthy
configuration is one operators learn to scroll past, and this one exists to catch
a silent widening of a security policy. Both sides are asserted, because a gate
that silenced the populated case too would pass a test that only checked the
first half.
*/
func TestHttpsInspectionUnknownBucketWarningIgnoresEmptyBuckets(t *testing.T) {
	unknownEmpty := perimeter81Sdk.HttpsInspectionRule{Name: "unrestricted"}
	unknownEmpty.SetSources([]perimeter81Sdk.HttpsInspectionSource{
		{Type: "somethingNew", Value: []string{}},
	})
	unknownEmpty.SetDestinations([]perimeter81Sdk.HttpsInspectionDestination{
		{Type: "alsoNew", Value: []string{}},
	})
	if got := unknownHttpsInspectionBucketTypes(
		[]perimeter81Sdk.HttpsInspectionRule{unknownEmpty}); len(got) != 0 {
		t.Errorf("an EMPTY bucket of an unknown type warned: %v. The server sends one "+
			"empty bucket per legal type on every unrestricted rule, so this would fire "+
			"on healthy configuration the day the enum grows", got)
	}

	unknownPopulated := perimeter81Sdk.HttpsInspectionRule{Name: "restricted"}
	unknownPopulated.SetSources([]perimeter81Sdk.HttpsInspectionSource{
		{Type: "somethingNew", Value: []string{"id-1"}},
	})
	unknownPopulated.SetDestinations([]perimeter81Sdk.HttpsInspectionDestination{
		{Type: "alsoNew", Value: []string{"id-2"}},
	})
	got := unknownHttpsInspectionBucketTypes(
		[]perimeter81Sdk.HttpsInspectionRule{unknownPopulated})
	if len(got) != 2 {
		t.Fatalf("a POPULATED bucket of an unknown type must warn on both sides; got %v. "+
			"Silence here is the silent policy-widening this function exists to prevent", got)
	}
	joined := strings.Join(sortedCopy(got), " ")
	for _, fragment := range []string{"sources.somethingNew", "destinations.alsoNew"} {
		if !strings.Contains(joined, fragment) {
			t.Errorf("the dropped list does not name %q: %v", fragment, got)
		}
	}
}

/*
================================================================================
ACCEPTANCE TESTS -- SHI-01 through SHI-08, SHI-N01(b) and SHI-I01.

Everything above this line is offline. Everything below runs only under TF_ACC
and REPLACES THE TENANT'S ENTIRE HTTPS-INSPECTION POLICY. The safety argument,
the pre-check that refuses to run on a tenant with rules to lose, and the ban on
t.Parallel() are all on swg_acc_check_helpers_test.go.

Every rule these tests create is `status = "inactive"`. It keeps its position in
the array and its place in every ordering assertion, and it is never evaluated
against traffic -- so nothing here can change what is or is not decrypted on a
tenant whose Internet Access happens to be switched on. The access-policy suite
makes one exception for an unrestricted `allow`; there is no equivalently
harmless value here, because both `bypass` and `inspect` change how real traffic
is handled, so this file makes no exception at all.

One thing these tests leave strictly alone: `cleanupBypassRuleDefaultAction`.
The resource never sends it, so it survives every apply and every destroy. It is
feature-gated off on the only tenant available (both values answer 422), which is
why it is out of scope for Phase 4 rather than untested.
================================================================================
*/

// testAccHttpsInspectionRule is one `rule` block, in configuration order. The
// mirror of testAccAccessPolicyRule; kept separate because the two policies'
// `action` vocabularies are different and a shared struct would invite passing
// one resource's actions to the other's config builder.
type testAccHttpsInspectionRule struct {
	name      string
	action    string
	appliedOn string
	status    string
}

/*
testAccHttpsInspectionRules is the four-rule set shared by the tests below, and
it is THE ACTION/APPLIED_ON MATRIX, measured rather than guessed.

phase4-verification recorded what a tenant WITHOUT the Inspection Policy feature
accepts:

	bypass           + sites/agents/both  -> 200
	inspect          + sites              -> 200
	inspect          + agents             -> 422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED
	inspect          + both               -> 422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED
	inspectNoDecrypt + sites/agents/both  -> 422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED

So this set is the four combinations that succeed on such a tenant: `bypass`
against all three `applied_on` values (SHI-04) plus `inspect` + `sites`
(SHI-01). The `inspect`/`sites` pairing is here because it is the one
combination involving `inspect` that works without the feature -- NOT because it
is the only legal one anywhere, which is the reading SHI-N01 was corrected for.

  - @param suffix string - a per-run random suffix

@return []testAccHttpsInspectionRule
*/
func testAccHttpsInspectionRules(suffix string) []testAccHttpsInspectionRule {
	return []testAccHttpsInspectionRule{
		{name: "tf-acc-" + suffix + "-1-bypass-agents", action: "bypass", appliedOn: "agents", status: "inactive"},
		{name: "tf-acc-" + suffix + "-2-bypass-sites", action: "bypass", appliedOn: "sites", status: "inactive"},
		{name: "tf-acc-" + suffix + "-3-bypass-both", action: "bypass", appliedOn: "both", status: "inactive"},
		{name: "tf-acc-" + suffix + "-4-inspect-sites", action: "inspect", appliedOn: "sites", status: "inactive"},
	}
}

// testAccHttpsInspectionNames projects the rule names in order.
func testAccHttpsInspectionNames(rules []testAccHttpsInspectionRule) []string {
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		names = append(names, rule.name)
	}
	return names
}

/*
testAccHttpsInspectionConfig renders the resource with these rules, in order.

No `sources` or `destinations` block is emitted, for the reason spelled out on
testAccAccessPolicyConfig: omitting is the only way to spell "any", the server
answers with one empty bucket per legal type, and the flattener has to drop them
all or every plan diffs forever. This endpoint's vocabulary is its own -- four
source types, four destination types, and no `conditions` at all -- so the buckets
being dropped here are not the ones the access policy drops (§1.20).

  - @param rules ...testAccHttpsInspectionRule - the blocks, in order

@return string - HCL
*/
func testAccHttpsInspectionConfig(rules ...testAccHttpsInspectionRule) string {
	var config strings.Builder
	config.WriteString("resource \"checkpointsase_https_inspection_policy\" \"test\" {\n")
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

// testAccHttpsInspectionConfigWithDataSource adds the data source reading the
// same policy back (SHI-07, SHI-08). The depends_on is required for the reason
// given on testAccAccessPolicyConfigWithDataSource: the data source takes no
// arguments, so without it Terraform may read the policy before the apply writes
// it.
func testAccHttpsInspectionConfigWithDataSource(rules ...testAccHttpsInspectionRule) string {
	return testAccHttpsInspectionConfig(rules...) + `
data "checkpointsase_https_inspection_policy" "read_back" {
  depends_on = [checkpointsase_https_inspection_policy.test]
}
`
}

/*
TestAccCheckpointsaseHttpsInspectionPolicy_basic covers SHI-01 (the `bypass` and
`inspect` rules read back as configured, then an EMPTY re-plan), SHI-04 (all
three `applied_on` values in one POST) and SHI-I01 (import, then no diff).

The empty re-plan carries the same weight it does on the access policy and for
the same reason (§1.15), with one addition specific to this endpoint: §1.21
measured that `action` is absent from the read model's `required` list but is
ALWAYS returned, because the server applies and stores its `bypass` default. A
Required Terraform attribute reading a possibly-absent field would fold to an
empty string and propose a change on every plan. PlanOnly is what would catch
that; there is no offline equivalent, because a fixture is written by whoever
believes the field is present.
*/
func TestAccCheckpointsaseHttpsInspectionPolicy_basic(t *testing.T) {
	const address = "checkpointsase_https_inspection_policy.test"
	rules := testAccHttpsInspectionRules(randStringBytesRmndr())
	config := testAccHttpsInspectionConfig(rules...)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccPreCheckHttpsInspectionPolicyEmpty(t)
		},
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckHttpsInspectionPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(address, "id", httpsInspectionPolicyResourceID),
					resource.TestCheckResourceAttr(address, "rule.#", "4"),

					// SHI-04: bypass against all three applied_on values.
					resource.TestCheckResourceAttr(address, "rule.0.name", rules[0].name),
					resource.TestCheckResourceAttr(address, "rule.0.action", "bypass"),
					resource.TestCheckResourceAttr(address, "rule.0.applied_on", "agents"),
					resource.TestCheckResourceAttr(address, "rule.0.status", "inactive"),
					resource.TestCheckResourceAttr(address, "rule.1.action", "bypass"),
					resource.TestCheckResourceAttr(address, "rule.1.applied_on", "sites"),
					resource.TestCheckResourceAttr(address, "rule.2.action", "bypass"),
					resource.TestCheckResourceAttr(address, "rule.2.applied_on", "both"),

					// SHI-01: the one inspect combination a tenant without the
					// Inspection Policy feature accepts.
					resource.TestCheckResourceAttr(address, "rule.3.name", rules[3].name),
					resource.TestCheckResourceAttr(address, "rule.3.action", "inspect"),
					resource.TestCheckResourceAttr(address, "rule.3.applied_on", "sites"),

					// §1.15/§1.20: this endpoint's own empty buckets, all dropped.
					// There is no `conditions` attribute on this resource at all.
					resource.TestCheckResourceAttr(address, "rule.0.sources.#", "0"),
					resource.TestCheckResourceAttr(address, "rule.0.destinations.#", "0"),
					resource.TestCheckResourceAttr(address, "rule.3.sources.#", "0"),
					resource.TestCheckResourceAttr(address, "rule.3.destinations.#", "0"),

					resource.TestCheckResourceAttrSet(address, "rule.0.id"),
					resource.TestCheckResourceAttrSet(address, "rule.3.id"),
					testAccCheckRulePrioritiesDescend(address),
				),
			},
			// SHI-01's second half.
			{
				Config:   config,
				PlanOnly: true,
			},
			// SHI-I01.
			{
				ResourceName:      address,
				ImportState:       true,
				ImportStateId:     httpsInspectionPolicyResourceID,
				ImportStateVerify: true,
			},
		},
	})
}

/*
TestAccCheckpointsaseHttpsInspectionPolicy_orderIsConfigurationOrder covers
SHI-08 and SHI-07 -- the mirror of the access policy's ordering row, and the
reasoning is identical: read the long comment on
TestAccCheckpointsaseAccessPolicy_orderIsConfigurationOrder.

Both directions are asserted, the resource's own state and an independent read
through the data source. The data source's rule shape is NOT the access policy
data source's -- different source and destination vocabularies, no `conditions`,
and none of `className`/`objectId`/`fromDefault` (§1.20) -- which is why this row
exists separately rather than being assumed to follow from SAP-08.
*/
func TestAccCheckpointsaseHttpsInspectionPolicy_orderIsConfigurationOrder(t *testing.T) {
	const (
		address    = "checkpointsase_https_inspection_policy.test"
		dataSource = "data.checkpointsase_https_inspection_policy.read_back"
	)
	rules := testAccHttpsInspectionRules(randStringBytesRmndr())
	names := testAccHttpsInspectionNames(rules)
	config := testAccHttpsInspectionConfigWithDataSource(rules...)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccPreCheckHttpsInspectionPolicyEmpty(t)
		},
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckHttpsInspectionPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRuleNamesInOrder(address, names...),
					testAccCheckRulePrioritiesDescend(address),

					testAccCheckRuleNamesInOrder(dataSource, names...),
					testAccCheckRulePrioritiesDescend(dataSource),
					resource.TestCheckResourceAttr(dataSource, "id", httpsInspectionPolicyDataSourceID),
					testAccCheckControlledBySurfaced(dataSource),
					resource.TestCheckResourceAttr(dataSource, "rule.0.sources.#", "0"),
					resource.TestCheckResourceAttr(dataSource, "rule.0.destinations.#", "0"),
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
TestAccCheckpointsaseHttpsInspectionPolicy_serverRefusesInspectOnAgents covers
SHI-N01 case (b), AND IT IS THE ONLY ROW IN THIS SUITE WHOSE POINT IS THAT THE
PROVIDER DOES NOT VALIDATE SOMETHING.

`inspect` + `agents` is legal on a tenant with the Inspection Policy feature
enabled and refused on one without it. The provider cannot see that flag, so
rejecting the combination at plan time would refuse configuration that works --
the same mistake as the group-name pattern in Phase 3, where a validator correct
on the development tenant was wrong everywhere else. The cross-field validator
therefore refuses only the part that is unconditional (`inspectNoDecrypt` with
`sites` or `both`, pinned offline by
TestHttpsInspectionRejectsInspectNoDecryptOnSitesAndBoth) and lets the server
answer this one.

So the assertion is: the apply reaches the API and comes back with the SERVER'S
diagnostic. The regexp matches `VALIDATION_ACTION_INSPECT_NOT_ALLOWED`, which is
the token the server sends and which appendErrorDiags surfaces from the response
body -- if this test ever fails because the message arrived as a bare
`422 Unprocessable Entity`, the defect is in the diagnostic plumbing, not here.

THE TOKEN ALONE DOES NOT PROVE THE SERVER ANSWERED, and it is worth being
explicit about why this test does not try to make it. That same string appears in
the PLAN-TIME validator's message for the combination that IS unconditionally
illegal (`inspectNoDecrypt` with `sites`/`both`), so a future validator copying
that wording could satisfy this regexp without a request ever leaving. What rules
that out is the offline row next door:
TestHttpsInspectionAdmitsTheFeatureGatedCombinations asserts `inspect` + `agents`
PLANS CLEANLY, and it fails the moment anyone adds a validator that would refuse
it. The two together are the complete assertion -- we do not reject it, and the
server does -- and neither half is sufficient alone. Matching on the write path's
diagnostic summary as well was considered and rejected: it would pin this test to
Terraform's error-rendering layout, which is not what the row is about.

ON A TENANT THAT HAS THE INSPECTION POLICY FEATURE THIS TEST WILL FAIL, because
the apply will succeed. That is correct and is the point of the row: the failure
would be telling you the tenant's capabilities changed, not that the provider
did. The comment is here so whoever sees it does not "fix" it by adding a
plan-time validator.

IT IS SAFE ON FAILURE EITHER WAY. The configuration holds exactly one rule, so
there is no partial write to leave behind: the POST replaces the whole array or
does nothing. If the apply unexpectedly succeeds, the harness still destroys and
CheckDestroy still asserts the policy is empty.
*/
func TestAccCheckpointsaseHttpsInspectionPolicy_serverRefusesInspectOnAgents(t *testing.T) {
	suffix := randStringBytesRmndr()
	refused := testAccHttpsInspectionRule{
		name:      "tf-acc-" + suffix + "-inspect-agents",
		action:    "inspect",
		appliedOn: "agents",
		status:    "inactive",
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccPreCheckHttpsInspectionPolicyEmpty(t)
		},
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckHttpsInspectionPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccHttpsInspectionConfig(refused),
				ExpectError: regexp.MustCompile(`VALIDATION_ACTION_INSPECT_NOT_ALLOWED`),
			},
		},
	})
}

/*
TestAccCheckpointsaseHttpsInspectionPolicy_destroyClearsTheWholePolicy covers
SHI-05: a policy holding exactly one rule, destroyed.

The §1.18 argument is the access policy's, with this endpoint's error string:
POST of an empty array is `400 VALIDATION_BYPASS_RULES_REQUIRED`, so DELETE is
the only route to an empty policy and `rule = []` is refused at plan time
(SHI-N04). Destroy is the only way to get there, which makes this the suite's
only live exercise of DELETE /v3/ia/https-inspection/policy.

WHAT IS DELIBERATELY NOT ASSERTED is the consequence for traffic. The API
documents only the mechanical effect -- "Delete all HTTPS Inspection policy
rules" -- and says nothing about what happens to traffic those rules were
excluding from inspection, which is decided by the tenant's own settings
including the cleanup-rule default action this provider does not manage.
Reproducing the API's silence is the honest option. The access policy's endpoint
does state its consequence, and SAP-05 quotes it; this one does not.
*/
func TestAccCheckpointsaseHttpsInspectionPolicy_destroyClearsTheWholePolicy(t *testing.T) {
	const address = "checkpointsase_https_inspection_policy.test"
	only := testAccHttpsInspectionRules(randStringBytesRmndr())[0]

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccPreCheckHttpsInspectionPolicyEmpty(t)
		},
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckHttpsInspectionPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccHttpsInspectionConfig(only),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(address, "rule.#", "1"),
					resource.TestCheckResourceAttr(address, "rule.0.name", only.name),
					resource.TestCheckResourceAttr(address, "rule.0.priority", "0"),
				),
			},
		},
	})
}
