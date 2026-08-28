package checkpointsase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
Offline tests for the machinery both enhanced private-DNS resources share.

Everything here runs against httptest or against a marshalled body; nothing in
this file makes a network call or needs TF_ACC. None of these names carries the
TestAcc prefix, which in this codebase means "acceptance test, skips without
TF_ACC=1" -- an offline test wearing that prefix reads as 21 skipped acceptance
tests in the summary and as zero offline coverage, which is what Phase 4 shipped.

The fixture bodies are the ones measured on 2026-08-26 and recorded in
API-FINDINGS.md 1.28 and 1.31, not JSON authored here to fit the code.

EXCEPT THE ASYNC STATUS BODIES, WHICH ARE CONSTRUCTIONS. Every
`{"completed":...}` body in this file -- with a `result` and without one -- is
built from async.go's documented envelope, NOT captured. `grep -l completed` over
all 115 files in the phase's probe set returns NOTHING: not one async status body
was ever observed from any endpoint in this phase (LEFTOVERS.md L37). That
includes the bare `{"completed":false}`, which API-FINDINGS.md 1.28 quotes as
though it were a wire body and which has no capture behind it either -- so the
exception covers ALL of them and not merely the result-bearing ones. They are
named with a `synthetic` prefix so the distinction survives a reader who skips
this header. Do not cite any of them as evidence of the wire shape; that is the
precise reasoning error API-FINDINGS.md 1.34 exists to record.
*/

/*
testPrivateDNSResourceSchema is the shared schema as a REGISTERED resource
actually declares it: privateDNSSchema plus that resource's own address.

It returns checkpointsase_enhanced_network_private_dns's real schema rather than
assembling an equivalent one. Task 1 shipped this as a hand-built copy --
privateDNSSchema() with a locally written `network_id` -- because no resource
existed yet to take it from. Now that one does, taking it removes the last
restatement of a schema whose entire reason for being shared is that a second
copy can drift from the expander silently. If a future resource adds an attribute
that expandCustomDnsUpdate never reads, these tests are driving the declaration
that is actually registered when they catch it.

The region resource (Task 3) adds `region_id` on top of the same base. Nothing
below depends on which of the two is used -- every raw config here sets
`network_id`, and the extra attribute a region schema would carry is simply left
unset.
*/
func testPrivateDNSResourceSchema() map[string]*schema.Schema {
	return resourceEnhancedNetworkPrivateDNS().Schema
}

// privateDNSSchemaPaths is every attribute privateDNSSchema declares, written out
// so that adding one is a test failure rather than a silent no-op. See
// TestPrivateDNSSchemaAndExpanderAgreeOnEveryAttribute.
var privateDNSSchemaPaths = []string{
	privateDNSAttrEnabled,
	privateDNSAttrAttributes,
	privateDNSAttrAttributes + "." + privateDNSAttrServers,
	privateDNSAttrAttributes + "." + privateDNSAttrServers + "." + privateDNSAttrAddress,
	privateDNSAttrAttributes + "." + privateDNSAttrServers + "." + privateDNSAttrIsTLS,
	privateDNSAttrAttributes + "." + privateDNSAttrSearchDomains,
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy,
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy + "." + privateDNSAttrPublic,
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy + "." + privateDNSAttrPublic +
		"." + privateDNSAttrDomains,
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy + "." + privateDNSAttrPrivate,
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy + "." + privateDNSAttrPrivate +
		"." + privateDNSAttrMode,
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy + "." + privateDNSAttrPrivate +
		"." + privateDNSAttrPublicFallback,
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy + "." + privateDNSAttrPrivate +
		"." + privateDNSAttrDomains,
}

/*
synthesizePrivateDNSConfig builds a raw config that fills EVERY attribute a schema
declares, deriving itself from the schema rather than from a hand-written list.

That is the point: an attribute added to privateDNSSchema automatically gets a
value here, so the assertion below ("everything declared reaches the wire") keeps
covering it without anyone remembering to extend a fixture. Every string leaf gets
a unique sentinel, appended to sentinels, so a missing one names the attribute
that was dropped.

Sentinels ignore ValidateFunc -- `mode` gets "sentinel-N-mode", not one of its two
enum values -- because TestResourceDataRaw does not validate and because what is
under test is that the expander passes values through untouched. Rejecting a bad
`mode` is the schema's job at plan time, and privateDNSPrivateModes is where that
lives.

  - @param m map[string]*schema.Schema - the schema to fill
  - @param sentinels *[]string - collects every string value planted
  - @param counter *int - makes the sentinels unique across nesting levels

@return map[string]interface{} - a raw config for schema.TestResourceDataRaw
*/
func synthesizePrivateDNSConfig(
	m map[string]*schema.Schema, sentinels *[]string, counter *int) map[string]interface{} {

	plant := func(name string) string {
		*counter++
		value := fmt.Sprintf("sentinel-%d-%s", *counter, name)
		*sentinels = append(*sentinels, value)
		return value
	}

	out := map[string]interface{}{}
	for name, attr := range m {
		switch attr.Type {
		case schema.TypeBool:
			out[name] = true
		case schema.TypeString:
			out[name] = plant(name)
		case schema.TypeList:
			if nested, ok := attr.Elem.(*schema.Resource); ok {
				out[name] = []interface{}{
					synthesizePrivateDNSConfig(nested.Schema, sentinels, counter),
				}
				continue
			}
			out[name] = []interface{}{plant(name)}
		}
	}
	return out
}

/*
TestPrivateDNSSchemaAndExpanderAgreeOnEveryAttribute is the reason privateDNSSchema
lives beside the expander instead of in the two resource files.

expandCustomDnsUpdate reads the resource's attributes BY NAME. A name it reads that
the schema does not declare returns a zero value -- no error, no diff, nothing in
the logs -- and this codebase has shipped that class of defect more than once:
enhanced_dynamic_tunnel sent routingType: "" against a required enum for every
create, and EnhancedTunnel's read blanked eight fields of user configuration
because the generated struct named them somewhere the server did not. Both looked
right in review.

Declaring and reading through the same constants removes the possibility of a
mismatch rather than reducing it: there is one spelling of each name in the
package, so a rename is one edit and a typo does not compile. Two things that
still could go wrong are what this test covers:

 1. An attribute ADDED to the schema that no expander reads. The path list is
    written out, so adding one fails here until someone has been to the expander.
 2. An attribute declared and then not sent. The config is synthesised FROM the
    schema, so every string attribute the schema declares must appear in the
    marshalled body -- including ones added after this test was written.

Booleans carry no sentinel (true is not distinguishable in a body full of them);
`isTLS` and `publicFallback` are pinned exactly by
TestPayloadMarshalCustomDnsUpdate, and assertion 1 above is what stops a new
boolean slipping in unnoticed.
*/
func TestPrivateDNSSchemaAndExpanderAgreeOnEveryAttribute(t *testing.T) {
	declared := map[string]bool{}
	walkSchema("", privateDNSSchema(), func(path string, _ *schema.Schema) {
		declared[path] = true
	})

	expected := map[string]bool{}
	for _, path := range privateDNSSchemaPaths {
		expected[path] = true
	}

	for path := range declared {
		if !expected[path] {
			t.Errorf("privateDNSSchema declares %q, which privateDNSSchemaPaths does not list. "+
				"Add it there AND teach expandCustomDnsUpdate/flattenCustomDnsAttributes to "+
				"read it -- an attribute the expander never reads is sent as a zero value with "+
				"no error and no diff", path)
		}
	}
	for path := range expected {
		if !declared[path] {
			t.Errorf("privateDNSSchemaPaths lists %q, which privateDNSSchema no longer declares. "+
				"If the attribute is gone, remove it from the expander and the flattener too",
				path)
		}
	}

	// TestSchemaEveryAttributeHasADescription only walks REGISTERED resources, and
	// nothing registers this schema until Task 2 lands. Checking it here is what
	// stops Tasks 2 and 3 inheriting a conformance failure they did not cause, on
	// the commit that merely wires the schema up.
	walkSchema("", privateDNSSchema(), func(path string, attr *schema.Schema) {
		if strings.TrimSpace(attr.Description) == "" {
			t.Errorf("privateDNSSchema attribute %q has no Description. tfplugindocs renders the "+
				"registry docs from it, so a blank one ships a blank row", path)
		}
	})

	var sentinels []string
	counter := 0
	raw := synthesizePrivateDNSConfig(testPrivateDNSResourceSchema(), &sentinels, &counter)

	d := schema.TestResourceDataRaw(t, testPrivateDNSResourceSchema(), raw)
	body, err := json.Marshal(expandCustomDnsUpdate(d))
	if err != nil {
		t.Fatalf("json.Marshal(expandCustomDnsUpdate(d)) returned an error: %v", err)
	}

	for _, sentinel := range sentinels {
		// network_id is the resource's address, not part of the body, so its
		// sentinel is expected to be absent.
		if strings.Contains(sentinel, "network_id") {
			continue
		}
		if !strings.Contains(string(body), sentinel) {
			t.Errorf("%q was set in the config and never reached the request body. The attribute "+
				"it came from is declared in privateDNSSchema and dropped by "+
				"expandCustomDnsUpdate.\nbody: %s", sentinel, body)
		}
	}
}

/*
TestPrivateDNSResourcesDeclareAnAsyncTimeout pins the Timeouts block on every
resource that polls this endpoint.

WHY THIS IS NOT COSMETIC. putPrivateDNSAndWait polls a 202 to completion. A
resource with no Timeouts inherits SDKv2's 20-minute system DEFAULT, and -- the
part that actually bites -- the operator cannot raise it, because `timeouts {}`
is only accepted in HCL for a resource that declares the block. So a tenant whose
write legitimately takes longer has no configuration that lets it finish.

Both resources shipped without it: the shared contract in private_dns.go asked
for it and neither task read the line. This test is the version of that contract
that fails.

Delete is asserted ABSENT, not present. Delete makes no API call (D9), so a
declared Delete budget would advertise a wait that cannot happen -- and a future
edit that "completed" the block by adding one is a claim about this resource that
is not true.
*/
func TestPrivateDNSResourcesDeclareAnAsyncTimeout(t *testing.T) {
	for name, r := range map[string]*schema.Resource{
		"checkpointsase_enhanced_network_private_dns": resourceEnhancedNetworkPrivateDNS(),
		"checkpointsase_enhanced_region_private_dns":  resourceEnhancedRegionPrivateDNS(),
	} {
		t.Run(name, func(t *testing.T) {
			if r.Timeouts == nil {
				t.Fatalf("%s declares no Timeouts. The write is asynchronous and polled, so it "+
					"silently inherits SDKv2's 20-minute default and the operator has no "+
					"`timeouts {}` block to raise it with", name)
			}
			for label, got := range map[string]*time.Duration{
				"Create": r.Timeouts.Create,
				"Update": r.Timeouts.Update,
			} {
				if got == nil {
					t.Errorf("%s declares no %s timeout; it polls an async operation and must "+
						"use asyncResourceTimeout", name, label)
					continue
				}
				if *got != asyncResourceTimeout {
					t.Errorf("%s %s timeout = %s, want asyncResourceTimeout (%s)",
						name, label, *got, asyncResourceTimeout)
				}
			}
			if r.Timeouts.Delete != nil {
				t.Errorf("%s declares a Delete timeout of %s, and Delete makes NO API CALL "+
					"(D9). A budget for a wait that cannot happen tells the operator something "+
					"false about this resource", name, *r.Timeouts.Delete)
			}
		})
	}
}

/*
privateDNSListMaximums is every MaxItems privateDNSSchema declares, as a CLOSED
set, with the swagger line each value comes from.

THE FOUR LEAF LIMITS ARE NOT THE SAME NUMBER, AND THAT IS THE POINT. `servers`
and `search_domains` cap at 4; both `domains` lists cap at 100. A table that made
them uniform would be wrong in one direction or the other -- it would either
refuse a legal 100-domain policy or accept a five-server body the API rejects.

Nothing in the suite noticed when they were wrong. A reviewer's mutation on
2026-08-26 set both 4s to 100 and both 100s to 4 in one edit, and the full suite
still ran 285 PASS / 55 SKIP / 0 FAIL. These four constants were a headline
requirement of the task brief and were pinned by nothing.

The four `MaxItems: 1` rows are the wrapper BLOCKS -- `attributes` and the three
dns_policy containers. They are here for the same reason the conformance sweep
counts them: a MaxItems-1 block is a TypeList like any other, so a set that left
them out would not be closed, and "closed" is what makes a NEW list added without
a maximum a failure rather than a silence.
*/
var privateDNSListMaximums = map[string]struct {
	max     int
	swagger string
}{
	privateDNSAttrAttributes: {1, "CustomDnsUpdate.attributes is a $ref to one object, swagger.yaml:4468-4469"},

	privateDNSAttrAttributes + "." + privateDNSAttrServers:       {4, "swagger.yaml:4489"},
	privateDNSAttrAttributes + "." + privateDNSAttrSearchDomains: {4, "swagger.yaml:4496"},

	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy: {1, "CustomDnsUpdateAttributes.dnsPolicy is a $ref to one object, swagger.yaml:4501-4502"},
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy + "." +
		privateDNSAttrPublic: {1, "DnsPolicy.public is one object, swagger.yaml:4593-4594"},
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy + "." +
		privateDNSAttrPublic + "." + privateDNSAttrDomains: {100, "swagger.yaml:4601"},
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy + "." +
		privateDNSAttrPrivate: {1, "DnsPolicy.private is one object, swagger.yaml:4607-4608"},
	privateDNSAttrAttributes + "." + privateDNSAttrDNSPolicy + "." +
		privateDNSAttrPrivate + "." + privateDNSAttrDomains: {100, "swagger.yaml:4626"},
}

/*
TestPrivateDNSSchemaPinsEveryListMaximum asserts the eight MaxItems above and
that there are no others.

Both directions matter. A value that DROPS (100 -> 4) refuses a configuration the
API accepts, and the operator sees a plan error naming a limit that is not real.
A value that RISES (4 -> 100) sends a body the API rejects, and the operator sees
a 422 from the server at apply time instead of a plan error -- after Terraform has
already started an apply.

Asserting the whole map rather than four rows is what makes a NEW list attribute
with no maximum a failure here. That is the shape of the original defect: the
limits existed in the brief, went into the schema correctly, and then nothing
referred to them again.
*/
func TestPrivateDNSSchemaPinsEveryListMaximum(t *testing.T) {
	found := map[string]int{}
	walkSchema("", privateDNSSchema(), func(path string, s *schema.Schema) {
		if s.MaxItems != 0 {
			found[path] = s.MaxItems
		}
	})

	for path, want := range privateDNSListMaximums {
		got, ok := found[path]
		if !ok {
			t.Errorf("%s declares no MaxItems; it must cap at %d (%s)", path, want.max, want.swagger)
			continue
		}
		if got != want.max {
			t.Errorf("%s MaxItems = %d, want %d (%s). Too high sends a body the API rejects at "+
				"apply time; too low refuses a configuration the API accepts",
				path, got, want.max, want.swagger)
		}
	}
	for path, got := range found {
		if _, ok := privateDNSListMaximums[path]; !ok {
			t.Errorf("%s declares MaxItems = %d and is not in privateDNSListMaximums. Add it "+
				"with the swagger line it comes from, so the next reader can check it", path, got)
		}
	}
}

/*
privateDNSValidateConfig runs the SDK's schema validation -- MaxItems, MinItems
and every ValidateFunc -- over a raw configuration, the way `terraform validate`
does before a plan is ever built.

This is deliberately NOT planEnhancedNetworkPrivateDNS. r.Diff runs CustomizeDiff
and does NOT run MaxItems or ValidateFunc, so every plan-time test in this package
is blind to both. That is why the mutation described above survived: the suite had
extensive plan coverage and no validation coverage at all.

The resource is assembled from testPrivateDNSResourceSchema rather than named
directly, so this stays a statement about the SHARED schema and holds for both
private-DNS resources.

  - @param t *testing.T
  - @param raw map[string]interface{} - the configuration, as HCL decodes to

@return error - the joined validation errors, or nil
*/
func privateDNSValidateConfig(t *testing.T, raw map[string]interface{}) error {
	t.Helper()

	r := &schema.Resource{Schema: testPrivateDNSResourceSchema()}
	diags := r.Validate(terraform.NewResourceConfigRaw(raw))

	var sb strings.Builder
	for _, d := range diags {
		if d.Severity != diag.Error {
			continue
		}
		sb.WriteString(d.Summary)
		sb.WriteString(" ")
		sb.WriteString(d.Detail)
		sb.WriteString("\n")
	}
	if sb.Len() == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.TrimSpace(sb.String()))
}

// privateDNSStrings builds n distinct domain-shaped strings.
func privateDNSStrings(n int) []interface{} {
	out := make([]interface{}, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("d%d.example.com", i))
	}
	return out
}

// privateDNSServers builds n distinct server blocks.
func privateDNSServers(n int) []interface{} {
	out := make([]interface{}, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, map[string]interface{}{
			privateDNSAttrAddress: fmt.Sprintf("10.0.0.%d", i+1),
			privateDNSAttrIsTLS:   false,
		})
	}
	return out
}

// privateDNSConfigWithAttributes wraps an `attributes` block in the surrounding
// required arguments, so each case below writes only the part it is about.
func privateDNSConfigWithAttributes(attributes map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		privateDNSAttrNetworkID:  "net-1",
		privateDNSAttrEnabled:    true,
		privateDNSAttrAttributes: []interface{}{attributes},
	}
}

// privateDNSPolicyConfig wraps a `private` policy block, filling the two other
// properties the spec marks required inside it, so a `mode` case can vary `mode`
// alone.
func privateDNSPolicyConfig(mode string) map[string]interface{} {
	return privateDNSConfigWithAttributes(map[string]interface{}{
		privateDNSAttrServers: privateDNSServers(1),
		privateDNSAttrDNSPolicy: []interface{}{map[string]interface{}{
			privateDNSAttrPrivate: []interface{}{map[string]interface{}{
				privateDNSAttrMode:           mode,
				privateDNSAttrPublicFallback: true,
				privateDNSAttrDomains:        privateDNSStrings(1),
			}},
		}},
	})
}

/*
TestPrivateDNSValidationEnforcesTheLimitsAndTheModeEnum is the behavioural half of
the two constants nothing was checking: it drives the SDK's real validator and
asserts each boundary from BOTH sides.

WHY EACH LIMIT IS TESTED AT max AND AT max+1. Asserting only that 101 domains is
refused passes for a schema that refuses 5, and asserting only that 100 is
accepted passes for a schema with no limit at all. The pair is what pins the
number. Because the two limits differ (4 for servers and search_domains, 100 for
both domains lists), the accepted row of one is larger than the refused row of the
other -- so a schema that used one number everywhere fails here whichever number
it picked.

`mode` MUST STAY CASE-SENSITIVE. validation.StringInSlice takes an
`ignoreCase bool` and privateDNSSchema passes false. Phase 3 shipped the opposite
mistake on `access` and the API answered a 422 for "Read" where it accepts "read":
this API does not fold case on enums, so accepting "matchpattern" at plan time
only moves the refusal to apply time and blames the server for it. Flipping that
one boolean to true left the whole suite green before this test existed.
*/
func TestPrivateDNSValidationEnforcesTheLimitsAndTheModeEnum(t *testing.T) {
	publicDomains := func(n int) map[string]interface{} {
		return privateDNSConfigWithAttributes(map[string]interface{}{
			privateDNSAttrServers: privateDNSServers(1),
			privateDNSAttrDNSPolicy: []interface{}{map[string]interface{}{
				privateDNSAttrPublic: []interface{}{map[string]interface{}{
					privateDNSAttrDomains: privateDNSStrings(n),
				}},
			}},
		})
	}
	privateDomains := func(n int) map[string]interface{} {
		return privateDNSConfigWithAttributes(map[string]interface{}{
			privateDNSAttrServers: privateDNSServers(1),
			privateDNSAttrDNSPolicy: []interface{}{map[string]interface{}{
				privateDNSAttrPrivate: []interface{}{map[string]interface{}{
					privateDNSAttrMode:           "matchPattern",
					privateDNSAttrPublicFallback: true,
					privateDNSAttrDomains:        privateDNSStrings(n),
				}},
			}},
		})
	}

	cases := []struct {
		name    string
		config  map[string]interface{}
		refused bool
		why     string
	}{
		{
			name:   "four servers, the documented maximum",
			config: privateDNSConfigWithAttributes(map[string]interface{}{privateDNSAttrServers: privateDNSServers(4)}),
			why:    "swagger.yaml:4489 caps servers at 4, so exactly 4 is legal and must not be refused",
		},
		{
			name:    "five servers, one over",
			config:  privateDNSConfigWithAttributes(map[string]interface{}{privateDNSAttrServers: privateDNSServers(5)}),
			refused: true,
			why:     "swagger.yaml:4489 caps servers at 4; a fifth is a 422 at apply time unless the plan refuses it",
		},
		{
			name: "four search domains, the documented maximum",
			config: privateDNSConfigWithAttributes(map[string]interface{}{
				privateDNSAttrServers:       privateDNSServers(1),
				privateDNSAttrSearchDomains: privateDNSStrings(4),
			}),
			why: "swagger.yaml:4496 caps search_domains at 4",
		},
		{
			name: "five search domains, one over",
			config: privateDNSConfigWithAttributes(map[string]interface{}{
				privateDNSAttrServers:       privateDNSServers(1),
				privateDNSAttrSearchDomains: privateDNSStrings(5),
			}),
			refused: true,
			why:     "swagger.yaml:4496 caps search_domains at 4",
		},
		{
			name:   "one hundred public domains, the documented maximum",
			config: publicDomains(100),
			why: "swagger.yaml:4601 caps dns_policy.public.domains at 100, NOT at 4. A schema that " +
				"reused the servers limit refuses this legal policy",
		},
		{
			name:    "one hundred and one public domains, one over",
			config:  publicDomains(101),
			refused: true,
			why:     "swagger.yaml:4601 caps dns_policy.public.domains at 100",
		},
		{
			name:   "one hundred private domains, the documented maximum",
			config: privateDomains(100),
			why: "swagger.yaml:4626 caps dns_policy.private.domains at 100, NOT at 4. A schema that " +
				"reused the servers limit refuses this legal policy",
		},
		{
			name:    "one hundred and one private domains, one over",
			config:  privateDomains(101),
			refused: true,
			why:     "swagger.yaml:4626 caps dns_policy.private.domains at 100",
		},
		{
			name:   "mode matchPattern, exactly as the API spells it",
			config: privateDNSPolicyConfig("matchPattern"),
			why:    "one of the two values privateDNSPrivateModes declares",
		},
		{
			name:   "mode resolveAllViaPrivate, exactly as the API spells it",
			config: privateDNSPolicyConfig("resolveAllViaPrivate"),
			why:    "the other value privateDNSPrivateModes declares",
		},
		{
			name:    "mode matchpattern, lowercased",
			config:  privateDNSPolicyConfig("matchpattern"),
			refused: true,
			why: "the enum is CASE-SENSITIVE. StringInSlice is passed ignoreCase=false on purpose: " +
				"Phase 3 accepted \"Read\" for `access` and the API answered 422",
		},
		{
			name:    "mode MATCHPATTERN, uppercased",
			config:  privateDNSPolicyConfig("MATCHPATTERN"),
			refused: true,
			why:     "the enum is case-sensitive in both directions, not just for a lowercased first letter",
		},
		{
			name:    "mode resolveallviaprivate, lowercased",
			config:  privateDNSPolicyConfig("resolveallviaprivate"),
			refused: true,
			why:     "the second enum value is case-sensitive too",
		},
		{
			name:    "mode matchPatern, a plain typo",
			config:  privateDNSPolicyConfig("matchPatern"),
			refused: true,
			why:     "the enum is closed, so a misspelling is refused whatever the case rule is",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := privateDNSValidateConfig(t, tc.config)
			switch {
			case tc.refused && err == nil:
				t.Errorf("this configuration was ACCEPTED and must be refused: %s", tc.why)
			case !tc.refused && err != nil:
				t.Errorf("this configuration was REFUSED and is legal: %s\nvalidation said: %v",
					tc.why, err)
			}
		})
	}
}

// jsonValueAt walks a decoded JSON body down a slash-separated path and returns
// what it finds, plus whether the last key was present at all.
//
// It returns interface{} rather than a typed value because the whole point of
// the caller below is to tell `[]` (a non-nil, empty []interface{}) from `null`
// (a nil interface{}) from an absent key -- three states a typed accessor or a
// struct comparison collapses into one.
func jsonValueAt(t *testing.T, body []byte, path string) (interface{}, bool) {
	t.Helper()

	var decoded interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("could not unmarshal the marshalled body: %v\nbody: %s", err, body)
	}

	current := decoded
	for _, key := range strings.Split(path, "/") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		value, present := object[key]
		if !present {
			return nil, false
		}
		current = value
	}
	return current, true
}

// assertMarshalsArrayAt asserts the body carries a JSON array at path -- present,
// and `[]` rather than `null`.
func assertMarshalsArrayAt(t *testing.T, body []byte, path string) {
	t.Helper()

	value, present := jsonValueAt(t, body, path)
	if !present {
		t.Errorf("%s is absent from the body; it is a required key on this endpoint.\nbody: %s",
			path, body)
		return
	}
	if value == nil {
		t.Errorf("%s marshalled as JSON null, not an array. The endpoint's @IsArray rejects "+
			"null with a 400 that names the field the user did set.\nbody: %s", path, body)
		return
	}
	if _, ok := value.([]interface{}); !ok {
		t.Errorf("%s marshalled as %T, want a JSON array.\nbody: %s", path, value, body)
	}
}

/*
TestExpandCustomDnsUpdateNeverMarshalsNullArrays is a MARSHALLING test, not a
struct test.

CustomDnsUpdateAttributes declares Servers and SearchDomains without omitempty
(model_custom_dns_update_attributes.go:24 and :26), and so do DnsPolicyPublic.Domains and
DnsPolicyPrivate.Domains, so a nil slice on any of the four reaches the wire as
`"servers": null` -- not an array, and the endpoint's @IsArray rejects it. The
schema is explicit: "send an empty array if you have none. Omitting it on update
is rejected with 400".

Measured, API-FINDINGS.md 1.31: omitting `servers` from `attributes` returns
400 `attributes.servers must be an array`. `null` fails the same validator, and
the resulting message names `servers` even when the user's config set it -- the
failure is in the empty *neighbouring* case, so the error points at the wrong
place.

The assertions are on json.Marshal output because the Go value being nil vs empty
is exactly the distinction a struct comparison erases: reflect.DeepEqual over
CustomDnsUpdate passes over this defect, and so does any check of len(). Same
class as buildGranularFirewallPolicyClear.
*/
func TestExpandCustomDnsUpdateNeverMarshalsNullArrays(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]interface{}
		// arrays that must be present and non-null in the marshalled body.
		arrays []string
	}{
		{
			// The disable body. This is the one the read cannot produce: an
			// unconfigured network reads back as exactly {"enabled": false},
			// and PUTting that same body is a 422 (API-FINDINGS.md 1.31).
			name:   "disabled with no attributes block at all",
			raw:    map[string]interface{}{"network_id": "net-1", "enabled": false},
			arrays: []string{"attributes/servers", "attributes/searchDomains"},
		},
		{
			name: "attributes block present but every list empty",
			raw: map[string]interface{}{
				"network_id": "net-1",
				"enabled":    false,
				"attributes": []interface{}{map[string]interface{}{
					"servers":        []interface{}{},
					"search_domains": []interface{}{},
				}},
			},
			arrays: []string{"attributes/servers", "attributes/searchDomains"},
		},
		{
			// The asymmetric case that makes this worth a table: servers is set
			// and search_domains is not. A nil search_domains here produces a
			// 400 naming servers as well (measured: the endpoint reports all of
			// its array complaints together), so the operator reads an error
			// about the one field they did configure.
			name: "servers set, search_domains unset",
			raw: map[string]interface{}{
				"network_id": "net-1",
				"enabled":    true,
				"attributes": []interface{}{map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{"address": "10.0.0.53", "is_tls": false},
					},
				}},
			},
			arrays: []string{"attributes/servers", "attributes/searchDomains"},
		},
		{
			// dns_policy carries two more arrays with the same declaration and
			// therefore the same trap. An empty `public` block must not send
			// "domains": null.
			name: "dns_policy blocks present with no domains",
			raw: map[string]interface{}{
				"network_id": "net-1",
				"enabled":    true,
				"attributes": []interface{}{map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{"address": "10.0.0.53", "is_tls": true},
					},
					"search_domains": []interface{}{"a.example.com"},
					"dns_policy": []interface{}{map[string]interface{}{
						"public": []interface{}{map[string]interface{}{}},
						"private": []interface{}{map[string]interface{}{
							"mode":            "matchPattern",
							"public_fallback": true,
						}},
					}},
				}},
			},
			arrays: []string{
				"attributes/servers",
				"attributes/searchDomains",
				"attributes/dnsPolicy/public/domains",
				"attributes/dnsPolicy/private/domains",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, testPrivateDNSResourceSchema(), tt.raw)

			body, err := json.Marshal(expandCustomDnsUpdate(d))
			if err != nil {
				t.Fatalf("json.Marshal(expandCustomDnsUpdate(d)) returned an error: %v", err)
			}

			for _, path := range tt.arrays {
				assertMarshalsArrayAt(t, body, path)
			}
		})
	}
}

/*
TestFlattenCustomDnsAttributesOnUnconfiguredNetwork pins the read half of the
same asymmetry.

Measured, API-FINDINGS.md 1.31: GET .../privateDNS on a network that has never
been configured returns exactly {"enabled": false} -- with NO `attributes` key --
which the generated CustomDns decodes to a nil *CustomDnsAttributes. A flattener
that dereferences it panics the provider on the first Read of any unconfigured
network, which is every Read that runs before the first apply lands.
*/
func TestFlattenCustomDnsAttributesOnUnconfiguredNetwork(t *testing.T) {
	var unconfigured perimeter81Sdk.CustomDns
	if err := json.Unmarshal([]byte(`{"enabled": false}`), &unconfigured); err != nil {
		t.Fatalf("CustomDns could not decode the measured unconfigured body: %v", err)
	}
	if unconfigured.Attributes != nil {
		t.Fatalf("the measured body has no attributes key, so Attributes must decode to nil, got %#v",
			unconfigured.Attributes)
	}

	got := flattenCustomDnsAttributes(unconfigured.Attributes)
	if len(got) != 0 {
		t.Errorf("flattenCustomDnsAttributes(nil) = %#v, want an empty list: an absent "+
			"`attributes` is what an unconfigured network reads back as", got)
	}
}

/*
TestFlattenCustomDnsAttributesRoundTripsAConfiguredNetwork is the companion that
stops the test above passing by having the flattener always return nothing.

The body is the one measured on 2026-08-26 (API-FINDINGS.md 1.31): two servers
with different isTLS values and two search domains sent in deliberately
non-alphabetical order, all returned in the order sent. There is no
canonicalisation for this flattener to reproduce, so position is the contract.
*/
func TestFlattenCustomDnsAttributesRoundTripsAConfiguredNetwork(t *testing.T) {
	const measured = `{"enabled":true,"attributes":{` +
		`"servers":[{"address":"10.0.0.53","isTLS":false},{"address":"10.0.1.53","isTLS":true}],` +
		`"searchDomains":["b.example.com","a.example.com"]}}`

	var configured perimeter81Sdk.CustomDns
	if err := json.Unmarshal([]byte(measured), &configured); err != nil {
		t.Fatalf("CustomDns could not decode the measured configured body: %v", err)
	}

	got := flattenCustomDnsAttributes(configured.Attributes)
	if len(got) != 1 {
		t.Fatalf("flattenCustomDnsAttributes() = %#v, want exactly one attributes block", got)
	}
	block, ok := got[0].(map[string]interface{})
	if !ok {
		t.Fatalf("attributes block is %T, want map[string]interface{}", got[0])
	}

	servers, ok := block["servers"].([]interface{})
	if !ok {
		t.Fatalf("servers is %T, want []interface{}", block["servers"])
	}
	if len(servers) != 2 {
		t.Fatalf("servers = %#v, want the two the API returned", servers)
	}
	first, _ := servers[0].(map[string]interface{})
	second, _ := servers[1].(map[string]interface{})
	if first["address"] != "10.0.0.53" || first["is_tls"] != false {
		t.Errorf("servers[0] = %#v, want address 10.0.0.53 with is_tls false", first)
	}
	// isTLS true on the second entry only: a flattener that dropped the field
	// would still pass on the first, which is why both are asserted.
	if second["address"] != "10.0.1.53" || second["is_tls"] != true {
		t.Errorf("servers[1] = %#v, want address 10.0.1.53 with is_tls true", second)
	}

	wantDomains := []string{"b.example.com", "a.example.com"}
	switch domains := block["search_domains"].(type) {
	case []string:
		if !testComparableArraiesEq(domains, wantDomains) {
			t.Errorf("search_domains = %#v, want %#v in the order the API returned them",
				domains, wantDomains)
		}
	default:
		t.Errorf("search_domains is %T, want []string", block["search_domains"])
	}
}

/*
syntheticPrivateDNSDescendingServers IS NOT A CAPTURE, AND THAT IS THE POINT.

Every other private-DNS body fixture in this package is a measured one. This one
is AUTHORED, and it exists because the measured one cannot do this job: the
captured round trip (p8b, API-FINDINGS.md 1.31) happens to have sent its two
servers in ASCENDING address order, so every positional assertion built on it
passes just as well against a flattener that sorts. That was proven by mutation on
2026-08-26 -- adding a sort to flattenCustomDnsServers left the entire offline
suite green -- which is a test suite that cannot fail against the one defect the
TypeList decision exists to guard.

`servers` IS DOCUMENTED AS PRIORITY-ORDERED, so silently reordering it changes
which DNS server is consulted first. That is a real behaviour change and it must
not be a silent one.

The three addresses are in strictly DESCENDING order, which is what makes this
fixture discriminating: an ascending sort moves every element, a reversal moves
every element, and a rotation moves every element. The differing is_tls values are
kept so that a flattener which dropped the field is also caught. The durable
answer is to re-run the round-trip probe with non-ascending server addresses --
the same trick the probe already applied to searchDomains and forgot to apply to
servers -- and when that capture exists this fixture should be replaced by it.
*/
const syntheticPrivateDNSDescendingServers = `{"enabled":true,"attributes":{` +
	`"servers":[{"address":"10.0.2.53","isTLS":true},{"address":"10.0.1.53","isTLS":false},` +
	`{"address":"10.0.0.53","isTLS":true}],` +
	`"searchDomains":["c.example.com","b.example.com","a.example.com"]}}`

/*
TestFlattenCustomDnsAttributesPreservesServerOrderAgainstASortingServer is the
test the measured round trip could not be.

flattenCustomDnsServers is the ONE function every private-DNS read passes through
-- both enhanced resources and the standard data source share it -- so a sort
introduced here reorders `servers` for all five objects at once. This is the site
the mutation proof used.

WHAT WOULD MAKE THIS FAIL, stated so nobody has to guess whether it is a
tautology: a sort.Strings or sort.Slice anywhere in flattenCustomDnsServers or
flattenCustomDnsAttributes; a server that returns the array sorted; an SDK regen
that changes an allOf merge order; or a refactor that rebuilds the list from a
map. Every one of those moves index 0, and index 0 is asserted.
*/
func TestFlattenCustomDnsAttributesPreservesServerOrderAgainstASortingServer(t *testing.T) {
	var configured perimeter81Sdk.CustomDns
	if err := json.Unmarshal([]byte(syntheticPrivateDNSDescendingServers), &configured); err != nil {
		t.Fatalf("CustomDns could not decode the descending-order fixture: %v", err)
	}

	got := flattenCustomDnsAttributes(configured.Attributes)
	if len(got) != 1 {
		t.Fatalf("flattenCustomDnsAttributes() = %#v, want exactly one attributes block", got)
	}
	block, ok := got[0].(map[string]interface{})
	if !ok {
		t.Fatalf("attributes block is %T, want map[string]interface{}", got[0])
	}

	servers, ok := block["servers"].([]interface{})
	if !ok {
		t.Fatalf("servers is %T, want []interface{}", block["servers"])
	}

	// Descending, so a sorted result differs at EVERY index rather than at one.
	wantAddresses := []string{"10.0.2.53", "10.0.1.53", "10.0.0.53"}
	wantTLS := []bool{true, false, true}
	if len(servers) != len(wantAddresses) {
		t.Fatalf("servers = %#v, want %d entries", servers, len(wantAddresses))
	}
	for i := range wantAddresses {
		entry, ok := servers[i].(map[string]interface{})
		if !ok {
			t.Fatalf("servers[%d] is %T, want map[string]interface{}", i, servers[i])
		}
		if entry["address"] != wantAddresses[i] {
			t.Errorf("servers[%d].address = %#v, want %q.\n"+
				"The fixture sends these DESCENDING on purpose. If this reads back ascending, "+
				"something between the wire and state is sorting a list the API documents as "+
				"priority-ordered, which silently changes which DNS server is consulted first.",
				i, entry["address"], wantAddresses[i])
		}
		if entry["is_tls"] != wantTLS[i] {
			t.Errorf("servers[%d].is_tls = %#v, want %v (asserted so a dropped field is caught "+
				"as well as a reordered one)", i, entry["is_tls"], wantTLS[i])
		}
	}

	// search_domains descending too, for the same reason and at no extra cost.
	wantSearch := []string{"c.example.com", "b.example.com", "a.example.com"}
	switch domains := block["search_domains"].(type) {
	case []string:
		if !testComparableArraiesEq(domains, wantSearch) {
			t.Errorf("search_domains = %#v, want %#v -- descending, so a sort moves every "+
				"element", domains, wantSearch)
		}
	default:
		t.Errorf("search_domains is %T, want []string", block["search_domains"])
	}
}

// fakePrivateDNSAPI is one tenant's v3 API: the PUT that starts the async
// operation, and the status endpoint that reports on it.
//
// It records every request path so a test can assert not only what came back but
// WHERE the helper went -- which is the whole content of API-FINDINGS.md 1.28.
type fakePrivateDNSAPI struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []string

	// putResponse is written verbatim with a 202.
	putResponse string
	// statusBodies are served in order to successive status GETs; the last is
	// repeated if the helper polls more times than there are bodies.
	statusBodies []string
}

func newFakePrivateDNSAPI(t *testing.T, putResponse string, statusBodies ...string) *fakePrivateDNSAPI {
	t.Helper()

	fake := &fakePrivateDNSAPI{putResponse: putResponse, statusBodies: statusBodies}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// The SDK exchanges the API key for a bearer token before any request
		// whose cached token has expired (client.go:517), and an empty token
		// expires immediately, so this fires once per SDK call. It is plumbing,
		// not something any test here asserts on, so it is answered and not
		// recorded. The empty object decodes into Token{} cleanly.
		if strings.HasSuffix(r.URL.Path, "/auth/authorize") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}

		fake.mu.Lock()
		fake.requests = append(fake.requests, r.Method+" "+r.URL.Path)
		statusCalls := 0
		for _, request := range fake.requests {
			if strings.Contains(request, privateDNSStatusPathFragment) {
				statusCalls++
			}
		}
		fake.mu.Unlock()

		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(fake.putResponse))
			return
		}

		// SYNTHETIC, like every status body here -- see syntheticAsyncCompleted200.
		body := syntheticAsyncCompleted200
		if len(fake.statusBodies) > 0 {
			index := statusCalls - 1
			if index < 0 {
				index = 0
			}
			if index >= len(fake.statusBodies) {
				index = len(fake.statusBodies) - 1
			}
			body = fake.statusBodies[index]
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// privateDNSStatusPathFragment is what every async status path carries, on the
// configured host (/v3/networks/status/{id}) and on the one statusUrl names
// (/api/rest/v2.3/networks/status/{id}) alike. Matching on it rather than on the
// method is what lets one recorder count polls against either.
const privateDNSStatusPathFragment = "/networks/status/"

// statusRequests returns the recorded requests that went to a status endpoint,
// wherever it was hosted.
func (f *fakePrivateDNSAPI) statusRequests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var matched []string
	for _, request := range f.requests {
		if strings.Contains(request, privateDNSStatusPathFragment) {
			matched = append(matched, request)
		}
	}
	return matched
}

// client points a generated SDK client at this fake, exactly as the provider
// points one at the operator's configured BASE_URL.
//
// "test-key" is a literal, not a credential: nothing in this package's offline
// tests authenticates against anything.
func (f *fakePrivateDNSAPI) client() *perimeter81Sdk.APIClient {
	return perimeter81Sdk.NewAPIClient(perimeter81Sdk.NewConfiguration("test-key", f.server.URL))
}

// sendPrivateDNSPut is the caller-supplied half of putPrivateDNSAndWait: the
// already-built SDK call. It is the exact call the enhanced network resource
// will make.
func sendPrivateDNSPut(client *perimeter81Sdk.APIClient) func(context.Context) (*perimeter81Sdk.AsyncOperationResponse, *http.Response, error) {
	return func(ctx context.Context) (*perimeter81Sdk.AsyncOperationResponse, *http.Response, error) {
		return client.EnhancedPrivateDNSAPI.UpdateEnhancedNetworkPrivateDNS(ctx, "net-1").
			CustomDnsUpdate(perimeter81Sdk.CustomDnsUpdate{
				Enabled: false,
				Attributes: perimeter81Sdk.CustomDnsUpdateAttributes{
					Servers:       []perimeter81Sdk.CustomDnsServer{},
					SearchDomains: []string{},
				},
			}).Execute()
	}
}

// usePrivateDNSTestPollInterval collapses the production poll interval for the
// duration of one test, so a three-poll test costs microseconds instead of
// twenty seconds. See privateDNSPollInterval's comment for why it is a var.
func usePrivateDNSTestPollInterval(t *testing.T) {
	t.Helper()

	original := privateDNSPollInterval
	privateDNSPollInterval = testInterval
	t.Cleanup(func() { privateDNSPollInterval = original })
}

/*
THE ASYNC STATUS BODIES, ALL OF THEM SYNTHETIC.

Named rather than inlined so that the one thing a reader must know about them
travels with every use: NONE OF THESE WAS EVER CAPTURED. `grep -l completed` over
all 115 files in the phase's probe set returns nothing, so no async status body
has been observed from any endpoint in this phase (LEFTOVERS.md L37). They are
constructed from async.go's documented envelope.

That includes syntheticAsyncNotCompleted. API-FINDINGS.md 1.28 quotes
`{"completed":false}` as though it were a wire body, and it has no capture behind
it either -- which is why the `synthetic` prefix covers the whole family and not
only the result-bearing members. An earlier review of this file scoped the problem
to the `result`-bearing bodies and had to withdraw that; the prefix is deliberately
wider than that first reading.

WHAT THEY ARE STILL GOOD FOR: pinning what the PROVIDER does with each envelope
shape. isSuccessStatus(0) treating a missing `result` as success is the defect
these drive, and that is a fact about async.go, not about the server. What they
must never be cited for is the wire shape.
*/
const (
	syntheticAsyncNotCompleted = `{"completed":false}`
	syntheticAsyncCompleted200 = `{"completed":true,"result":{"statusCode":200}}`
	syntheticAsyncCompleted409 = `{"completed":true,"result":{"statusCode":409,` +
		`"reason":["private DNS is being updated by another operation"]}}`
)

// measuredPrivateDNSAccepted is the 202 body captured on 2026-08-26 from
// PUT /v3/networks/enhanced/{id}/privateDNS with the legal "off" payload
// (API-FINDINGS.md 1.28 and 1.31). Both fields are as measured: the statusUrl is
// absolute, on a DIFFERENT host from the one the request went to, and carries an
// /api/rest/v2.3/ path rather than /v3/.
const measuredPrivateDNSAccepted = `{"statusUrl":"https://api.perimeter81-solo.com/api/rest/v2.3/networks/status/exu7TTfsPg","samplingTime":120}`

/*
TestPutPrivateDNSAndWaitPollsBeforeReturning pins D1.

Both enhanced private-DNS PUTs declare ONLY a 202 (swagger.yaml:633, :699) and
the SDK returns *AsyncOperationResponse, so returning as soon as the PUT succeeds
means the write has not happened yet: Create then reads back pre-write values and
stores them as applied. That is the failure putGranularFirewallPolicy's comment
records shipping three times on this branch.

The server answers `completed:false` twice and then `completed:true` with a 2xx,
so a helper that returns after the first status GET fails here just as loudly as
one that never polls at all.
*/
func TestPutPrivateDNSAndWaitPollsBeforeReturning(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	fake := newFakePrivateDNSAPI(t, measuredPrivateDNSAccepted,
		syntheticAsyncNotCompleted,
		syntheticAsyncNotCompleted,
		syntheticAsyncCompleted200,
	)
	client := fake.client()

	accepted, err := putPrivateDNSAndWait(context.Background(), client, sendPrivateDNSPut(client))
	if err != nil {
		t.Fatalf("putPrivateDNSAndWait() error = %v, want nil for an operation that completes 200", err)
	}
	if !accepted {
		t.Error("putPrivateDNSAndWait() accepted = false, want true: the PUT itself returned 202")
	}

	statusGets := fake.statusRequests()
	if len(statusGets) != 3 {
		t.Errorf("the helper made %d status GETs (%v), want 3 -- it must not return until the "+
			"operation reports completed", len(statusGets), statusGets)
	}
}

/*
TestPutPrivateDNSAndWaitResolvesStatusUrlAgainstTheConfiguredClient pins
API-FINDINGS.md 1.28.

Measured 2026-08-26: every async 202 on this API carries a statusUrl that is
absolute, points at a host the request did not go to, and carries an
/api/rest/v2.3/ path. Following it leaves the operator's configured BASE_URL --
which exists precisely so a non-US tenant talks to its own region -- and polls
whatever tenant lives at the other host. It fails invisibly, because that other
deployment still answers with a well-formed {"completed":...}.

The decoy below is that other deployment. It answers every poll with a completed
200, so a helper that follows statusUrl passes every other assertion in this file
and fails only this one.
*/
func TestPutPrivateDNSAndWaitResolvesStatusUrlAgainstTheConfiguredClient(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	decoy := newFakePrivateDNSAPI(t, measuredPrivateDNSAccepted,
		syntheticAsyncCompleted200)

	// The same shape as the measured statusUrl -- absolute, different host, a
	// v2.3 path -- but pointed at a server this test can count hits on.
	statusUrl := decoy.server.URL + "/api/rest/v2.3/networks/status/exu7TTfsPg"
	fake := newFakePrivateDNSAPI(t, `{"statusUrl":"`+statusUrl+`","samplingTime":120}`,
		syntheticAsyncCompleted200)
	client := fake.client()

	if _, err := putPrivateDNSAndWait(context.Background(), client, sendPrivateDNSPut(client)); err != nil {
		t.Fatalf("putPrivateDNSAndWait() error = %v, want nil", err)
	}

	if hits := decoy.statusRequests(); len(hits) != 0 {
		t.Errorf("the helper followed statusUrl to the other host: %v. It must take the last "+
			"path segment and resolve it against the configured client, or a non-US tenant "+
			"polls the wrong deployment (API-FINDINGS.md 1.28)", hits)
	}

	statusGets := fake.statusRequests()
	if len(statusGets) != 1 {
		t.Fatalf("the configured client got %d status GETs (%v), want 1", len(statusGets), statusGets)
	}
	if got, want := statusGets[0], http.MethodGet+" /v3/networks/status/exu7TTfsPg"; got != want {
		t.Errorf("status GET went to %q, want %q -- the id is the last path segment of "+
			"statusUrl, resolved against the configured base URL", got, want)
	}
}

/*
TestPutPrivateDNSAndWaitFailsOnNon2xxCompletion is separate from the polling test
because `completed:true` alone is not success.

checkNetworkStatus, the per-resource helper pollAsync replaced, failed only on
statusCode 500 -- so a 400 or a 409 completion was reported to Terraform as a
successful apply, and the operator's next plan was the first hint. This is
SPT-N02's requirement applied to the private-DNS path, where no test row asks
for it.

The error must carry the status code and the API's reason, because on this path
they are the only trace of what the backend refused: the PUT itself returned 202
and said nothing.
*/
func TestPutPrivateDNSAndWaitFailsOnNon2xxCompletion(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	fake := newFakePrivateDNSAPI(t, measuredPrivateDNSAccepted,
		syntheticAsyncCompleted409)
	client := fake.client()

	accepted, err := putPrivateDNSAndWait(context.Background(), client, sendPrivateDNSPut(client))
	if err == nil {
		t.Fatal("putPrivateDNSAndWait() error = nil, want an error for a 409 completion")
	}
	if !accepted {
		t.Error("putPrivateDNSAndWait() accepted = false, want true: the API accepted the PUT " +
			"and the operation then failed, which is a different diagnostic from a refused request")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("error %q should include the status code", err)
	}
	if !strings.Contains(err.Error(), "private DNS is being updated by another operation") {
		t.Errorf("error %q should include the API's reason", err)
	}
}

/*
TestPutPrivateDNSAndWaitOnMissingStatusUrl pins a DECISION rather than an
inherited behaviour.

statusUrl is optional on AsyncOperationResponse, and putGranularFirewallPolicy
returns (false, nil) when it is absent -- it silently does not wait, and reports
the apply as successful. This helper deliberately goes the other way and returns
(true, error).

Why: the helper exists for exactly one reason, which is that a 202 means the
write has NOT happened. A 202 with nothing to poll is a write this provider
cannot confirm, and reporting an unconfirmable write as a successful apply is
the failure mode the whole task is against. accepted stays true because the PUT
was accepted -- the caller's diagnostic should say "the update did not complete",
not "the API refused the request".

This costs a false failure if the server ever legitimately returns a 202 with no
statusUrl for a write that did land. Nine probes on 2026-08-26 never saw one:
every async 202 measured carried a statusUrl (API-FINDINGS.md 1.28). If that
changes, this is a deliberate choice to revisit, not an accident to fix.
*/
func TestPutPrivateDNSAndWaitOnMissingStatusUrl(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	for _, tt := range []struct {
		name        string
		putResponse string
	}{
		{"statusUrl absent", `{"samplingTime":120}`},
		{"statusUrl empty", `{"statusUrl":"","samplingTime":120}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakePrivateDNSAPI(t, tt.putResponse)
			client := fake.client()

			accepted, err := putPrivateDNSAndWait(context.Background(), client, sendPrivateDNSPut(client))
			if err == nil {
				t.Fatal("putPrivateDNSAndWait() error = nil, want an error: a 202 with nothing " +
					"to poll is a write this provider cannot confirm, and reporting it as a " +
					"successful apply is exactly what this helper exists to prevent")
			}
			if !accepted {
				t.Error("putPrivateDNSAndWait() accepted = false, want true: the PUT itself was accepted")
			}
			if !strings.Contains(err.Error(), "statusUrl") {
				t.Errorf("error %q should name statusUrl, so an operator can tell this apart "+
					"from an operation that ran and failed", err)
			}
			if gets := fake.statusRequests(); len(gets) != 0 {
				t.Errorf("the helper polled %v with no status id; an empty id builds "+
					"/v3/networks/status/ and 404s against an operation that may have succeeded", gets)
			}
		})
	}
}

/*
TestPutPrivateDNSAndWaitReturnsNotAcceptedWhenThePutItselfFails keeps the
accepted flag honest in the other direction.

The two summaries the callers pick between -- "the API refused the request" and
"the API accepted the request and the operation then failed" -- send a reader to
different places, and accepted is the only thing that distinguishes them.
*/
func TestPutPrivateDNSAndWaitReturnsNotAcceptedWhenThePutItselfFails(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		// The measured 422 from PUTting a read body back (API-FINDINGS.md 1.31).
		_, _ = w.Write([]byte(`{"message":"VALIDATION_ERROR","messageCode":"UNPROCESSABLE_ENTITY","status":422}`))
	}))
	t.Cleanup(server.Close)

	client := perimeter81Sdk.NewAPIClient(perimeter81Sdk.NewConfiguration("test-key", server.URL))

	accepted, err := putPrivateDNSAndWait(context.Background(), client, sendPrivateDNSPut(client))
	if err == nil {
		t.Fatal("putPrivateDNSAndWait() error = nil, want the 422 surfaced")
	}
	if accepted {
		t.Error("putPrivateDNSAndWait() accepted = true, want false: the API refused the request, " +
			"so the caller must not tell the operator the update was accepted and then failed")
	}
}

/*
TestPutPrivateDNSAndWaitSurvivesANullStatusBody pins the poll closure's nil
guard, and it is the async twin of
TestEnhancedNetworkPrivateDNSReadSurvivesANullBody.

A 200 carrying the literal `null` decodes without error and leaves the
*AsyncOperationStatus pointer NIL: encoding/json sets a pointer to nil for `null`
before it consults any Unmarshaler, and the generated client decodes with a plain
json.Unmarshal into the return value. GetCompleted() is generated nil-safe, so it
is not the hazard; status.Result is a DIRECT FIELD ACCESS and dereferences the
receiver. Removing the `status == nil` guard makes this test PANIC rather than
fail -- verified by mutation on 2026-08-26, at private_dns.go:479 -- and a panic
is the one failure mode Terraform cannot report as a diagnostic: no summary, no
statusId, and no statement of whether the write landed.

WHAT THE RIGHT ANSWER IS, since "does not panic" does not choose one: a null
status body says nothing completed, so the closure reports "not completed yet"
and lets the deadline decide. It must NOT be treated as a completion, because
isSuccessStatus(0) is true and a completion with no result is a green apply --
which would turn an empty response into a successful write. So the assertion is
that the call FAILS on the deadline, not merely that it returns.

This is the sibling of TestPutSplitTunnelingAndWaitSurvivesANullStatusBody, and
the guard is the same three lines. Both are unmeasured: no async status body has
ever been captured from any endpoint in this phase (LEFTOVERS.md L37), which is
equally true of every other null-body guard this branch ships.
*/
func TestPutPrivateDNSAndWaitSurvivesANullStatusBody(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	fake := newFakePrivateDNSAPI(t, measuredPrivateDNSAccepted, `null`)
	client := fake.client()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("putPrivateDNSAndWait PANICKED on a 200 with a null status body: %v.\n"+
				"status.Result is a direct field access on a pointer json sets to nil for "+
				"`null`, so the poll closure has to check the pointer before reaching for it.", r)
		}
	}()

	accepted, err := putPrivateDNSAndWait(ctx, client, sendPrivateDNSPut(client))
	if !accepted {
		t.Error("putPrivateDNSAndWait() accepted = false: the PUT itself returned 202, so " +
			"the caller must say \"accepted but did not complete\", not \"refused\"")
	}
	if err == nil {
		t.Fatal("putPrivateDNSAndWait() error = nil for a status endpoint that only ever " +
			"answered `null`: an empty body is not a completion, and reporting it as one makes " +
			"isSuccessStatus(0) turn nothing at all into a successful apply")
	}
}
