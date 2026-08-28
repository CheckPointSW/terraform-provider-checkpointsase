package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
Everything in this file is offline: the servers are httptest.Servers on localhost
and the client is newTestUserAPIClient, which pre-seeds a bearer token so no test
exchanges an API key.

The fixtures are the RESOURCES' fixtures -- accessPolicyProbeBody and
httpsInspectionProbeBody, the second of which is a captured body -- and reusing
them is deliberate rather than lazy. The data sources call the resources'
flatteners, so the two must agree about what a canonicalised rule looks like; a
second fixture would let them stop agreeing and the tests would still pass. It
would also invite the mistake API-FINDINGS 1.20 records and this phase has now
made twice: the two endpoints canonicalise DIFFERENTLY -- different bucket sets,
different order, different server-assigned fields -- so one fixture cannot serve
both.
*/

// swgPolicyDataSource names one of the two data sources and the pieces of it a
// table-driven test needs, so that every property below is asserted for both
// rather than for whichever one was written first.
type swgPolicyDataSource struct {
	name string
	ds   *schema.Resource
	read func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics
	// resource is the writing half of the same name. The schema-mirror test
	// compares against it.
	resource *schema.Resource
	// wantID is the constant the read must set.
	wantID string
	// path is the endpoint, for asserting the request log.
	path string
	// populatedBody is a GET body with three rules; emptyBody has none.
	populatedBody string
	emptyBody     string
	// unrestrictedRuleIndex is the position of the rule with no sources and no
	// destinations, whose empty buckets must all be dropped.
	unrestrictedRuleIndex int
	// wantNames is populatedBody's rule names, in array order.
	wantNames []string
}

func swgPolicyDataSources() []swgPolicyDataSource {
	return []swgPolicyDataSource{
		{
			name:                  "checkpointsase_access_policy",
			ds:                    dataSourceAccessPolicy(),
			read:                  dataSourceAccessPolicyRead,
			resource:              resourceAccessPolicy(),
			wantID:                accessPolicyDataSourceID,
			path:                  "/v3/ia/access/policy",
			populatedBody:         accessPolicyProbeBody,
			emptyBody:             accessPolicyGetBody(),
			unrestrictedRuleIndex: 0,
			wantNames: []string{"block-everything", "block-for-contractors",
				"block-out-of-hours"},
		},
		{
			name:                  "checkpointsase_https_inspection_policy",
			ds:                    dataSourceHttpsInspectionPolicy(),
			read:                  dataSourceHttpsInspectionPolicyRead,
			resource:              resourceHttpsInspectionPolicy(),
			wantID:                httpsInspectionPolicyDataSourceID,
			path:                  "/v3/ia/https-inspection/policy",
			populatedBody:         httpsInspectionProbeBody,
			emptyBody:             httpsInspectionGetBody(),
			unrestrictedRuleIndex: 0,
			wantNames: []string{"bypass-everything", "bypass-for-finance",
				"inspect-on-sites"},
		},
	}
}

// swgPolicyServer serves one body for every request and records what it was
// asked for. The log is the assertion: a data source must issue exactly one GET
// and nothing else.
func swgPolicyServer(body string, status int) (*httptest.Server, *requestLog) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	return srv, log
}

// ---------------------------------------------------------------------------
// The one that matters: a read error is never an empty list
// ---------------------------------------------------------------------------

/*
TestSwgPolicyDataSourcesReportAnErrorRatherThanAnEmptyList is the Phase 3 defect
-- conflating "the read failed" with "there is nothing there" -- caught at the
place where it does the most damage.

On the RESOURCES the wrong answer produces a bad plan, which somebody can read
before applying. On a DATA SOURCE there is no plan to read: the value is consumed
directly, so `length(data.checkpointsase_access_policy.current.rule)` collapses
to 0 and a `for_each` over `rule` yields nothing -- and every resource downstream
of that for_each is planned for DESTRUCTION, out of a transport error. That is
why this test exists twice over, once per data source.

The empty-but-real row is in the same table on purpose, because a data source
that errored on both would be equally wrong in the other direction. An empty
policy is a legitimate state on these endpoints -- reachable from the console, or
from a terraform destroy of the matching resource -- and it arrives as a 200 with
an empty array, never as a 404. A 404 here means the URL is wrong, which is the
documented symptom of an unset BASE_URL sending every call to the US production
host.

Two things are asserted on every failing row:

  - the diagnostics carry an error, and
  - the ID IS NOT SET. A data source that reported an error but still stamped its
    id would be claiming a successful read in state.
*/
func TestSwgPolicyDataSourcesReportAnErrorRatherThanAnEmptyList(t *testing.T) {
	for _, ds := range swgPolicyDataSources() {
		ds := ds
		t.Run(ds.name, func(t *testing.T) {
			for _, tc := range []struct {
				name      string
				status    int
				body      string
				wantErr   bool
				wantRules int
			}{
				{"a 404, which means the URL is wrong", http.StatusNotFound,
					`{"message":"Cannot GET the policy"}`, true, 0},
				{"a 500", http.StatusInternalServerError, `{"message":"boom"}`, true, 0},
				{"a 403", http.StatusForbidden, `{"message":"forbidden"}`, true, 0},
				{"a genuinely empty policy, which is a real state", http.StatusOK,
					ds.emptyBody, false, 0},
				{"a policy with rules", http.StatusOK, ds.populatedBody, false, 3},
			} {
				t.Run(tc.name, func(t *testing.T) {
					srv, log := swgPolicyServer(tc.body, tc.status)
					defer srv.Close()

					d := schema.TestResourceDataRaw(t, ds.ds.Schema, map[string]interface{}{})
					diags := ds.read(context.Background(), d, newTestUserAPIClient(srv.URL))

					if diags.HasError() != tc.wantErr {
						t.Fatalf("HasError() = %t, want %t (diags: %v)",
							diags.HasError(), tc.wantErr, diags)
					}

					if tc.wantErr {
						if d.Id() != "" {
							t.Errorf("the read failed but stamped the id %q. A data source "+
								"that reports an error must not also claim a successful read",
								d.Id())
						}
						// The whole point: a failed read must not leave a
						// consumable empty list behind it.
						if got := len(d.Get("rule").([]interface{})); got != 0 {
							t.Errorf("a failed read left %d rules in state", got)
						}
					} else {
						if d.Id() != ds.wantID {
							t.Errorf("the id is %q, want the constant %q", d.Id(), ds.wantID)
						}
						if got := len(d.Get("rule").([]interface{})); got != tc.wantRules {
							t.Errorf("read %d rules, want %d", got, tc.wantRules)
						}
					}

					calls, _ := log.snapshot()
					want := []string{"GET " + ds.path}
					if !testComparableArraiesEq(calls, want) {
						t.Errorf("requests were %v, want exactly %v: a data source reads "+
							"and must never write, least of all to an endpoint whose "+
							"DELETE empties the tenant's policy", calls, want)
					}
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The id, and the fact that there are no arguments to derive one from
// ---------------------------------------------------------------------------

/*
TestSwgPolicyDataSourcesTakeNoArgumentsSoAConstantIDIsHonest asserts the two
halves of that sentence together, because either alone is only half an argument.

Half one: every attribute is Computed and none is Optional or Required. These
endpoints take no parameters -- no page, no limit, no filter -- so exposing one
would invent surface the server ignores.

Half two: given half one, two instances of the data source in one configuration
read exactly the same thing, so a constant id cannot make two different results
share an identity. That is what makes the constant honest here and what makes it
WRONG for checkpointsase_users, which takes filters:
TestIdentityDataSourceIDsAreStableAndArgumentDerived requires the opposite of
those, and the difference is entirely whether there are arguments.

The stability half is checked directly rather than assumed from the constant: two
reads must produce the same id. Fifteen of the sixteen data sources written
before checkpointsase_web_categories used time.Now(), which changes on every read
and so defeats any depends_on, output or interpolation pointing at it (L16c).
*/
func TestSwgPolicyDataSourcesTakeNoArgumentsSoAConstantIDIsHonest(t *testing.T) {
	for _, ds := range swgPolicyDataSources() {
		ds := ds
		t.Run(ds.name, func(t *testing.T) {
			walkSchema("", ds.ds.Schema, func(path string, attr *schema.Schema) {
				if attr.Optional || attr.Required {
					t.Errorf("%s is Optional=%t Required=%t. These endpoints take no "+
						"parameters at all -- not a page, a limit or a filter -- so an "+
						"argument here would be surface the server ignores, and it would "+
						"also make the constant id dishonest by letting two instances that "+
						"read different things share one identity",
						path, attr.Optional, attr.Required)
				}
				if !attr.Computed {
					t.Errorf("%s is not Computed; everything a read-only data source "+
						"exposes has to be", path)
				}
			})

			readID := func() string {
				srv, _ := swgPolicyServer(ds.populatedBody, http.StatusOK)
				defer srv.Close()
				d := schema.TestResourceDataRaw(t, ds.ds.Schema, map[string]interface{}{})
				if diags := ds.read(context.Background(), d,
					newTestUserAPIClient(srv.URL)); diags.HasError() {
					t.Fatalf("read failed: %v", diags)
				}
				return d.Id()
			}

			first, second := readID(), readID()
			if first != ds.wantID {
				t.Errorf("the id is %q, want the constant %q", first, ds.wantID)
			}
			if first != second {
				t.Errorf("two reads produced %q then %q. An id that changes on every read "+
					"defeats any downstream reference to it (L16c)", first, second)
			}
		})
	}
}

/*
TestSwgPolicyDataSourceIDsDifferFromTheResourceIDs pins that the four constants
are four distinct strings.

A data source and a resource of the same name are different objects and sit in
different parts of a state file. Giving them the same id would make the two
indistinguishable to anybody reading that file -- which is exactly the situation
these two names create, since Terraform allows a data source and a resource to
share a name and this phase used that allowance deliberately.
*/
func TestSwgPolicyDataSourceIDsDifferFromTheResourceIDs(t *testing.T) {
	seen := map[string]string{}
	for label, id := range map[string]string{
		"data.checkpointsase_access_policy":               accessPolicyDataSourceID,
		"data.checkpointsase_https_inspection_policy":     httpsInspectionPolicyDataSourceID,
		"resource.checkpointsase_access_policy":           accessPolicyResourceID,
		"resource.checkpointsase_https_inspection_policy": httpsInspectionPolicyResourceID,
	} {
		if id == "" {
			t.Errorf("%s has an empty id constant", label)
			continue
		}
		if previous, clash := seen[id]; clash {
			t.Errorf("%s and %s both use the id %q. A data source and a resource of the "+
				"same name are different objects; one id string for both makes them "+
				"indistinguishable in state", previous, label, id)
			continue
		}
		seen[id] = label
	}
}

// ---------------------------------------------------------------------------
// controlled_by: surfaced, and not acted on
// ---------------------------------------------------------------------------

/*
TestSwgPolicyDataSourcesExposeControlledBy covers the field the SWG probe found
and the milestone spec never mentioned (API-FINDINGS 1.24).

Both values are exercised, plus the absent case. `controlledBy` is `omitempty` on
the generated model, so a response without it decodes to a nil pointer and
GetControlledBy() answers "" -- which is the right thing to put in state for a
field the server did not send, and is worth pinning because the alternative
(erroring) would make the data source unusable on any tenant or future version
that stops sending it.

What is NOT tested, because it must not exist: any behaviour that depends on the
value. W3 recorded the meaning as uninvestigated, so nothing in this provider may
branch on it. TestSwgPolicyControlledByIsNotActedOn is the other half.
*/
func TestSwgPolicyDataSourcesExposeControlledBy(t *testing.T) {
	bodies := map[string]func(controlledBy string) string{
		"checkpointsase_access_policy": func(controlledBy string) string {
			return fmt.Sprintf(`{"status":200,"data":{%s"webRules":[]}}`, controlledBy)
		},
		"checkpointsase_https_inspection_policy": func(controlledBy string) string {
			return fmt.Sprintf(`{"status":200,"data":{%s"bypassRules":[]}}`, controlledBy)
		},
	}

	for _, ds := range swgPolicyDataSources() {
		ds := ds
		t.Run(ds.name, func(t *testing.T) {
			for _, tc := range []struct {
				name     string
				fragment string
				want     string
			}{
				{"hsase, which the live tenant returned", `"controlledBy":"hsase",`, "hsase"},
				{"quantum, the other documented value", `"controlledBy":"quantum",`, "quantum"},
				{"absent, which the model allows", ``, ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					srv, _ := swgPolicyServer(bodies[ds.name](tc.fragment), http.StatusOK)
					defer srv.Close()

					d := schema.TestResourceDataRaw(t, ds.ds.Schema, map[string]interface{}{})
					if diags := ds.read(context.Background(), d,
						newTestUserAPIClient(srv.URL)); diags.HasError() {
						t.Fatalf("read failed: %v", diags)
					}
					if got := d.Get("controlled_by").(string); got != tc.want {
						t.Errorf("controlled_by = %q, want %q", got, tc.want)
					}
				})
			}
		})
	}
}

/*
TestSwgPolicyControlledByIsReadOnlyAndOnlyOnTheDataSources asserts where the
field is, which is the only enforceable form of "surface it and do not act on
it".

An earlier draft of this test grepped the package source for comparisons against
`controlledBy`. That was dropped: a source grep is not a guard -- it catches the
spellings whoever wrote it thought of and silently passes every other one, while
reading like a proof. What CAN be asserted is structural and is worth asserting:
the field exists on both data sources, on neither resource, and is Computed
wherever it exists.

That is the shape of "not acted on" this provider can enforce. `controlledBy`
says which product owns the policy; the obvious inference -- that a `quantum`
tenant is one this provider should not write to -- is a hypothesis, because
API-FINDINGS 1.24 records the value the tenant returned and records that its
meaning is uninvestigated. Building a plan-time refusal on it would be the
Phase 3 group-name mistake again: a rule that is right on the tenant you
developed against and wrong elsewhere. Keeping it off the resources entirely
means there is no writable path it could ever reach.
*/
func TestSwgPolicyControlledByIsReadOnlyAndOnlyOnTheDataSources(t *testing.T) {
	for _, ds := range swgPolicyDataSources() {
		attr := ds.ds.Schema["controlled_by"]
		if attr == nil {
			t.Errorf("data.%s has no controlled_by; W3 found the field and nothing else in "+
				"this provider surfaces it", ds.name)
			continue
		}
		if !attr.Computed || attr.Optional || attr.Required {
			t.Errorf("data.%s controlled_by is Computed=%t Optional=%t Required=%t, want "+
				"Computed only", ds.name, attr.Computed, attr.Optional, attr.Required)
		}
		if attr.Description == "" || !strings.Contains(attr.Description, "not been investigated") {
			t.Errorf("data.%s controlled_by does not say its meaning has not been "+
				"investigated, which is the one thing a user has to know before using "+
				"it:\n%s", ds.name, attr.Description)
		}

		if _, present := ds.resource.Schema["controlled_by"]; present {
			t.Errorf("resource.%s has a controlled_by attribute. The field is read-only and "+
				"uninvestigated (API-FINDINGS 1.24): putting it on a resource makes it "+
				"reachable from a write path and invites a plan-time rule built on a guess",
				ds.name)
		}
	}
}

// ---------------------------------------------------------------------------
// Reuse: the schemas cannot drift from the flatteners
// ---------------------------------------------------------------------------

/*
TestSwgPolicyDataSourceRulesMirrorTheResourceRules is the guard that makes reuse
of the resources' flatteners safe.

The data sources call flattenAccessPolicyRules and flattenHttpsInspectionRules
UNCHANGED -- no second copy -- and those write a map keyed by the RESOURCE's
attribute names. schema.ResourceData.Set silently drops a key the schema does not
declare, so if the two ever disagree the result is not an error: it is a data
source quietly missing an attribute, which downstream configuration then reads as
absent. That is the same silent-loss shape as the dropped bucket types, arriving
from the schema side instead of the wire side.

Comparing the whole recursive attribute set catches it in both directions -- an
attribute the resource has and the data source lacks (silently dropped), and one
the data source has and the resource lacks (permanently empty, which looks like a
server that never populates it).

TYPES ARE COMPARED TOO, with one deliberate exception. Everything must be the
same schema.Type, because a flattener writing []string into a TypeString is a
runtime error rather than a compile one. The exception is that the data source's
copy is Computed where the resource's is Required or Optional, which is the whole
difference between reading and writing and is asserted separately in
TestSwgPolicyDataSourcesTakeNoArgumentsSoAConstantIDIsHonest.
*/
func TestSwgPolicyDataSourceRulesMirrorTheResourceRules(t *testing.T) {
	for _, ds := range swgPolicyDataSources() {
		ds := ds
		t.Run(ds.name, func(t *testing.T) {
			collect := func(root *schema.Resource) map[string]schema.ValueType {
				out := map[string]schema.ValueType{}
				element, ok := root.Schema["rule"].Elem.(*schema.Resource)
				if !ok {
					t.Fatalf("rule.Elem is %T, want *schema.Resource", root.Schema["rule"].Elem)
				}
				walkSchema("", element.Schema, func(path string, attr *schema.Schema) {
					out[path] = attr.Type
				})
				return out
			}

			fromResource := collect(ds.resource)
			fromDataSource := collect(ds.ds)

			for path, want := range fromResource {
				got, present := fromDataSource[path]
				if !present {
					t.Errorf("the resource's rule has %q and the data source's does not. The "+
						"data source reuses the resource's flattener, which writes that key; "+
						"d.Set DROPS a key the schema does not declare, so this attribute "+
						"would be silently missing from everything downstream", path)
					continue
				}
				if got != want {
					t.Errorf("rule.%s is %v on the resource and %v on the data source. One "+
						"flattener writes both, so a type difference is a runtime failure "+
						"waiting for a policy that populates it", path, want, got)
				}
			}
			for path := range fromDataSource {
				if _, present := fromResource[path]; !present {
					t.Errorf("the data source's rule has %q and the resource's does not. "+
						"Nothing writes it, so it would read as empty forever and look like "+
						"a server that never populates the field", path)
				}
			}
		})
	}
}

/*
TestSwgPolicyDataSourceBucketAttributesComeFromTheBucketTables is the same
argument one level down, and the reason computedIDSetAttributes generates the
`sources` and `destinations` attributes rather than listing them.

The flatteners key on bucket.attr. Generating the schema from the same slice
means the two cannot disagree. This asserts the generation actually happened --
that every table entry has an attribute and there are no extras -- so that
somebody who replaces the generator with a hand-written map has to make this test
pass, at which point the drift is back but at least it is visible.
*/
func TestSwgPolicyDataSourceBucketAttributesComeFromTheBucketTables(t *testing.T) {
	// The same extractors the schema is generated from. Using them here is
	// deliberate: this test is asserting that the generation HAPPENED, not
	// re-deriving the names by a second route that could drift from both.
	accessAttrs := accessPolicyBucketAttrs
	httpsAttrs := httpsInspectionBucketAttrs

	accessRule := dataSourceAccessPolicy().Schema["rule"].Elem.(*schema.Resource)
	httpsRule := dataSourceHttpsInspectionPolicy().Schema["rule"].Elem.(*schema.Resource)

	for _, tc := range []struct {
		name  string
		block *schema.Schema
		want  []string
	}{
		{"access policy sources", accessRule.Schema["sources"],
			accessAttrs(accessPolicySourceBuckets)},
		{"access policy destinations", accessRule.Schema["destinations"],
			accessAttrs(accessPolicyDestinationBuckets)},
		{"https inspection sources", httpsRule.Schema["sources"],
			httpsAttrs(httpsInspectionSourceBuckets)},
		{"https inspection destinations", httpsRule.Schema["destinations"],
			httpsAttrs(httpsInspectionDestinationBuckets)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			element, ok := tc.block.Elem.(*schema.Resource)
			if !ok {
				t.Fatalf("Elem is %T, want *schema.Resource", tc.block.Elem)
			}
			var got []string
			for attr := range element.Schema {
				got = append(got, attr)
			}
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if !testComparableArraiesEq(got, want) {
				t.Errorf("attributes are %v, want exactly the bucket table's %v. The "+
					"flattener writes under bucket.attr, so an attribute missing here is a "+
					"restriction silently absent from the data source's output", got, want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The canonicalised body, read through the real decode path
// ---------------------------------------------------------------------------

/*
TestSwgPolicyDataSourcesDropTheServerEmptyBucketsAndKeepOrder drives each data
source's real Read over its own captured/probe body and asserts the two
properties a policy reader has to get right.

ORDER. The rules arrive in array order and must stay in it: array position is
precedence (API-FINDINGS 1.16), so a data source that sorted or hashed them would
misreport the policy to whatever consumes it. `rule` is a TypeList here for the
same reason it is on the resources.

EMPTY BUCKETS. The server expands an unrestricted rule into one empty bucket per
legal type (API-FINDINGS 1.15), and the two endpoints do it with DIFFERENT bucket
sets in DIFFERENT order (API-FINDINGS 1.20). Those buckets carry no information,
so an unrestricted rule must read as NO sources block -- not a block of empty
sets. Each fixture's first rule is exactly that case.

Note that priority is asserted descending 2, 1, 0 across positions 0, 1, 2, which
is what the server assigns, and that NOTHING here asserts which end is evaluated
first. That has not been measured.
*/
func TestSwgPolicyDataSourcesDropTheServerEmptyBucketsAndKeepOrder(t *testing.T) {
	for _, ds := range swgPolicyDataSources() {
		ds := ds
		t.Run(ds.name, func(t *testing.T) {
			srv, _ := swgPolicyServer(ds.populatedBody, http.StatusOK)
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, ds.ds.Schema, map[string]interface{}{})
			if diags := ds.read(context.Background(), d,
				newTestUserAPIClient(srv.URL)); diags.HasError() {
				t.Fatalf("read failed: %v", diags)
			}

			rules := d.Get("rule").([]interface{})
			if len(rules) != len(ds.wantNames) {
				t.Fatalf("read %d rules, want %d", len(rules), len(ds.wantNames))
			}

			var names []string
			var priorities []int
			for _, raw := range rules {
				rule := raw.(map[string]interface{})
				names = append(names, rule["name"].(string))
				priorities = append(priorities, rule["priority"].(int))
			}
			if !testComparableArraiesEq(names, ds.wantNames) {
				t.Errorf("rules are %v, want %v in that order. Array position is precedence, "+
					"so a reader that reorders misreports the policy", names, ds.wantNames)
			}
			if want := []int{2, 1, 0}; !testComparableArraiesEq(priorities, want) {
				t.Errorf("priorities are %v, want %v: the server assigns "+
					"len-1-index (API-FINDINGS 1.16)", priorities, want)
			}

			unrestricted := rules[ds.unrestrictedRuleIndex].(map[string]interface{})
			for _, block := range []string{"sources", "destinations"} {
				got, ok := unrestricted[block].([]interface{})
				if !ok {
					t.Fatalf("%s is %T, want []interface{}", block, unrestricted[block])
				}
				if len(got) != 0 {
					t.Errorf("the unrestricted rule has %d %s block(s), want 0. The server "+
						"expands an unrestricted rule into one EMPTY bucket per legal type "+
						"(API-FINDINGS 1.15); those carry nothing, and surfacing them as a "+
						"block of empty sets would report a restriction that does not "+
						"exist: %v", len(got), block, got)
				}
			}
		})
	}
}

/*
TestSwgPolicyDataSourcesPopulateTheBucketsTheyDoHave is the other half: the
buckets that are NOT empty must arrive, under the right attribute and on the
right side of the rule.

The HTTPS-inspection case is the one worth having. `addresses` is a legal type on
BOTH sides of a bypass rule and on NEITHER side of an access-policy rule
(API-FINDINGS 1.20), so a lookup keyed on attribute name alone would put a
destination id into sources and match the wrong traffic with nothing failing.
*/
func TestSwgPolicyDataSourcesPopulateTheBucketsTheyDoHave(t *testing.T) {
	read := func(t *testing.T, ds swgPolicyDataSource) []interface{} {
		t.Helper()
		srv, _ := swgPolicyServer(ds.populatedBody, http.StatusOK)
		defer srv.Close()
		d := schema.TestResourceDataRaw(t, ds.ds.Schema, map[string]interface{}{})
		if diags := ds.read(context.Background(), d,
			newTestUserAPIClient(srv.URL)); diags.HasError() {
			t.Fatalf("read failed: %v", diags)
		}
		return d.Get("rule").([]interface{})
	}

	sources := swgPolicyDataSources()

	t.Run("checkpointsase_access_policy", func(t *testing.T) {
		rules := read(t, sources[0])
		rule := rules[1].(map[string]interface{})
		assertSwgBucket(t, rule, "sources", "users", []string{"user-1", "user-2"})
		assertSwgBucket(t, rule, "destinations", "categories", []string{"100000034"})

		windows := rules[2].(map[string]interface{})["conditions"].(*schema.Set).List()
		if len(windows) != 1 {
			t.Fatalf("the third rule has %d time window(s), want 1", len(windows))
		}
		window := windows[0].(map[string]interface{})
		if got := window["start_hour"].(int); got != 9 {
			t.Errorf("start_hour = %d, want 9", got)
		}
		if got := window["end_minute"].(int); got != 30 {
			t.Errorf("end_minute = %d, want 30", got)
		}
	})

	t.Run("checkpointsase_https_inspection_policy", func(t *testing.T) {
		rules := read(t, sources[1])

		second := rules[1].(map[string]interface{})
		assertSwgBucket(t, second, "sources", "applications", []string{"app-1"})
		assertSwgBucket(t, second, "destinations", "domains", []string{"domain-1"})

		// addresses is legal on BOTH sides here, which it is on neither side of
		// an access-policy rule. A table lookup keyed on the attribute name
		// alone would cross them over.
		third := rules[2].(map[string]interface{})
		assertSwgBucket(t, third, "sources", "addresses", []string{"addr-1"})
		assertSwgBucket(t, third, "destinations", "addresses", []string{"addr-2"})
	})
}

// assertSwgBucket checks one id set inside a rule's `sources` or `destinations`
// block. The values are sorted before comparison because the attribute is a
// TypeSet and neither the API nor Terraform promises an order.
func assertSwgBucket(t *testing.T, rule map[string]interface{}, block, attr string, want []string) {
	t.Helper()
	blocks, ok := rule[block].([]interface{})
	if !ok || len(blocks) != 1 {
		t.Fatalf("%s is %v, want exactly one block", block, rule[block])
	}
	set, ok := blocks[0].(map[string]interface{})[attr].(*schema.Set)
	if !ok {
		t.Fatalf("%s.%s is %T, want *schema.Set", block, attr, blocks[0].(map[string]interface{})[attr])
	}
	var got []string
	for _, v := range set.List() {
		got = append(got, v.(string))
	}
	if !testComparableArraiesEq(sortedCopy(got), sortedCopy(want)) {
		t.Errorf("%s.%s = %v, want %v", block, attr, got, want)
	}
}

/*
TestSwgPolicyDataSourcesWarnAboutBucketTypesTheyDropped covers the type this
provider does not know.

The flattener has nowhere to put it, so it is dropped -- and on a data source
that loss is entirely silent: the value never appears, nothing errors, and any
count or for_each downstream is computed from a partial view of the policy. The
warning is the only thing that makes it visible.

The detectors are the RESOURCES' functions, reused. Only the wording differs, and
it has to: the resources warn that the next apply will REMOVE the restriction,
which is true of something that owns the policy and false of something that only
reads it. Asserting the data source's wording is therefore also asserting that
somebody did not simply route both through one message.
*/
func TestSwgPolicyDataSourcesWarnAboutBucketTypesTheyDropped(t *testing.T) {
	bodies := map[string]string{
		"checkpointsase_access_policy": `{"status":200,"data":{"controlledBy":"hsase",` +
			`"webRules":[{"id":"rule-zzz","name":"future","appliedOn":"both","action":"block",` +
			`"status":"active","priority":0,"log":"disabled",` +
			`"sources":[{"type":"someNewType","value":["x-1"]}],` +
			`"destinations":[{"type":"categories","value":[]}],` +
			`"conditions":[{"type":"datetime","value":[]}]}]}}`,
		"checkpointsase_https_inspection_policy": `{"status":200,"data":{"controlledBy":"hsase",` +
			`"bypassRules":[{"id":"rule-zzz","_created_at":"2026-08-25T09:28:22.958Z",` +
			`"name":"future","appliedOn":"both","status":"active","priority":0,"action":"bypass",` +
			`"sources":[{"type":"someNewType","value":["x-1"]}],` +
			`"destinations":[{"type":"categories","value":[]}],"log":"disabled"}]}}`,
	}

	for _, ds := range swgPolicyDataSources() {
		ds := ds
		t.Run(ds.name, func(t *testing.T) {
			srv, _ := swgPolicyServer(bodies[ds.name], http.StatusOK)
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, ds.ds.Schema, map[string]interface{}{})
			diags := ds.read(context.Background(), d, newTestUserAPIClient(srv.URL))
			if diags.HasError() {
				t.Fatalf("read failed: %v", diags)
			}

			var joined string
			var warned bool
			for _, dg := range diags {
				joined += dg.Summary + " " + dg.Detail + " "
				if dg.Severity == diag.Warning {
					warned = true
				}
			}
			if !warned {
				t.Fatalf("a rule restricted by an unknown source type produced no warning. "+
					"The restriction is missing from what the data source returned and "+
					"nothing downstream can see it. Diagnostics: %v", diags)
			}
			if !strings.Contains(joined, "someNewType") {
				t.Errorf("the warning does not name the type that was dropped:\n%s", joined)
			}
			// The resources' wording is wrong here and must not have been reused.
			if strings.Contains(joined, "next apply will REMOVE") {
				t.Errorf("the data source is using the RESOURCE's warning, which says the "+
					"next apply will remove the restriction. A data source never writes; "+
					"telling an operator their policy is about to change is false:\n%s",
					joined)
			}
		})
	}
}
