package checkpointsase

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
These tests cover the firewall-policy READ shape.

They exist because making Create work exposed a second, independent blocker on the read side:
the generated SourcesAndDestinations oneOf cannot decode two of the three `sources`/
`destinations` shapes the server returns — `{}` and `{"addresses":[...]}` — so
GetGranularFirewallPolicy fails on a 200 for almost every policy this resource can now create.
See the comment on firewallPolicyEndpointWire for the mechanism. TestFirewallPolicyReadShape...
below pins both halves: that the SDK really does fail (so nobody "simplifies" the fallback away
while the SDK is still broken), and that the provider's own decoder produces the right state.

The fixture is NOT a live capture. Task 42 was explicitly not allowed to run against a tenant,
so it is reconstructed from the server's own response builder —
getFirewallRulesGranular.interceptor.ts, whose per-rule shape is
{id, name, enabled, allowed, sources, destinations, services, logEnabled}, with the three
endpoint keys produced by extractRuleResources as `users`, `groups` and `addresses`. Everything
in it is obviously fake and carries no tenant data. What a live run can still invalidate is
noted on TestFirewallPolicyServicesRoundTripIsUnverified.
*/
const firewallPolicyReadFixture = `{
  "id": "fakePolicy1",
  "enabled": true,
  "allowed": false,
  "policyLoggingEnabled": true,
  "policyRules": [
    {
      "id": "fakeRuleAA",
      "name": "fake-any-to-any",
      "enabled": true,
      "allowed": true,
      "sources": {},
      "destinations": {},
      "logEnabled": true
    },
    {
      "id": "fakeRuleBB",
      "name": "fake-branch-to-db",
      "enabled": true,
      "allowed": true,
      "sources": {"addresses": ["fakeAddr1", "fakeAddr2"]},
      "destinations": {"addresses": ["fakeAddr3"]},
      "services": ["fakeSvc1"],
      "logEnabled": false
    },
    {
      "id": "fakeRuleCC",
      "name": "fake-contractors",
      "enabled": false,
      "allowed": false,
      "sources": {"users": ["fakeUser1"], "groups": ["fakeGroup1"]},
      "destinations": {},
      "logEnabled": true
    }
  ]
}`

/*
TestFirewallPolicyReadShapeDefeatsTheGeneratedDecoder is the evidence for the fallback in
getGranularFirewallPolicy. It asserts the generated SDK model cannot decode the response — which
is a claim about somebody else's code, so it is measured here rather than asserted in a comment.

If this test starts failing, that is good news: the SDK's oneOf handling has been fixed, and
getGranularFirewallPolicy's fallback plus firewallPolicyEndpointWire can be deleted. Read it as
"delete this and the code it justifies", not as a specification.
*/
func TestFirewallPolicyReadShapeDefeatsTheGeneratedDecoder(t *testing.T) {
	var policy perimeter81Sdk.GranularFirewallPolicy
	err := json.Unmarshal([]byte(firewallPolicyReadFixture), &policy)
	if err == nil {
		t.Fatal("the generated SDK now decodes this response; delete the fallback in getGranularFirewallPolicy and firewallPolicyEndpointWire, and route the resource back through the SDK model directly")
	}

	// Both failure modes, each on its own, so a partial SDK fix is visible rather than silent.
	for _, tc := range []struct {
		name string
		body string
	}{
		{"unrestricted", `{}`},
		{"addresses", `{"addresses": ["fakeAddr1"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sd perimeter81Sdk.SourcesAndDestinations
			if err := json.Unmarshal([]byte(tc.body), &sd); err == nil {
				t.Errorf("SourcesAndDestinations now decodes %s; the fallback may be narrowable", tc.body)
			}
		})
	}

	// The shapes that always worked, as the control: the defect is specific, not general.
	for _, body := range []string{`{"users": ["fakeUser1"]}`, `{"groups": ["fakeGroup1"]}`, `{"users": ["fakeUser1"], "groups": ["fakeGroup1"]}`} {
		var sd perimeter81Sdk.SourcesAndDestinations
		if err := json.Unmarshal([]byte(body), &sd); err != nil {
			t.Errorf("SourcesAndDestinations no longer decodes %s either: %v", body, err)
		}
	}
}

/*
TestFirewallPolicyDecodeReadsEveryField drives decodeGranularFirewallPolicy over the fixture and
checks every field the resource reads, including the two endpoint objects that the generated
decoder drops.
*/
func TestFirewallPolicyDecodeReadsEveryField(t *testing.T) {
	policy, err := decodeGranularFirewallPolicy([]byte(firewallPolicyReadFixture))
	if err != nil {
		t.Fatalf("decodeGranularFirewallPolicy: %v", err)
	}

	if policy.Id != "fakePolicy1" || !policy.Enabled || policy.Allowed || !policy.PolicyLoggingEnabled {
		t.Errorf("policy scalars decoded as id=%q enabled=%t allowed=%t policyLoggingEnabled=%t", policy.Id, policy.Enabled, policy.Allowed, policy.PolicyLoggingEnabled)
	}
	if len(policy.PolicyRules) != 3 {
		t.Fatalf("decoded %d rules, want 3", len(policy.PolicyRules))
	}

	// Rule 0: unrestricted. Both endpoints must come back as "nothing set", which is what
	// keeps a rule with no sources block from showing a diff on every plan.
	unrestricted := policy.PolicyRules[0]
	if got := flattenFirewallPolicyRuleEndpoint(unrestricted.Sources); len(got) != 0 {
		t.Errorf("an unrestricted sources object flattened to %v; want an empty list, or every plan shows a phantom diff", got)
	}
	if got := flattenFirewallPolicyRuleEndpoint(unrestricted.Destinations); len(got) != 0 {
		t.Errorf("an unrestricted destinations object flattened to %v; want an empty list", got)
	}
	if unrestricted.Id == nil || *unrestricted.Id != "fakeRuleAA" {
		t.Errorf("rule 0 id = %v, want fakeRuleAA", unrestricted.Id)
	}
	if len(unrestricted.Services) != 0 {
		t.Errorf("rule 0 services = %v, want none", unrestricted.Services)
	}

	// Rule 1: addresses on both sides, plus a service.
	addressed := policy.PolicyRules[1]
	if got := addressed.Sources.Addresses; got == nil || !testComparableArraiesEq(got.Addresses, []string{"fakeAddr1", "fakeAddr2"}) {
		t.Errorf("rule 1 sources addresses = %v, want [fakeAddr1 fakeAddr2]", got)
	}
	if got := addressed.Destinations.Addresses; got == nil || !testComparableArraiesEq(got.Addresses, []string{"fakeAddr3"}) {
		t.Errorf("rule 1 destinations addresses = %v, want [fakeAddr3]", got)
	}
	if !testComparableArraiesEq(addressed.Services, []string{"fakeSvc1"}) {
		t.Errorf("rule 1 services = %v, want [fakeSvc1]", addressed.Services)
	}

	// Rule 2: users and groups together.
	identity := policy.PolicyRules[2]
	if got := identity.Sources.UsersAndGroups; got == nil {
		t.Error("rule 2 sources did not decode as users/groups")
	} else {
		if !testComparableArraiesEq(got.Users, []string{"fakeUser1"}) {
			t.Errorf("rule 2 sources users = %v, want [fakeUser1]", got.Users)
		}
		if !testComparableArraiesEq(got.Groups, []string{"fakeGroup1"}) {
			t.Errorf("rule 2 sources groups = %v, want [fakeGroup1]", got.Groups)
		}
	}
	if identity.Enabled || identity.Allowed || !identity.LogEnabled {
		t.Errorf("rule 2 booleans decoded as enabled=%t allowed=%t logEnabled=%t", identity.Enabled, identity.Allowed, identity.LogEnabled)
	}
}

/*
TestFirewallPolicyDecodeRejectsABodyThatIsNotAPolicy covers the guard that stops the fallback
from turning an unexpected 200 into a zero-valued policy. Adopting a policy with an empty ID
would send `"id": ""` back on the next update; reporting the original error is the right
outcome.
*/
func TestFirewallPolicyDecodeRejectsABodyThatIsNotAPolicy(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"error envelope", `{"statusCode": 200, "message": "not a policy"}`},
		{"empty object", `{}`},
		{"not json", `<html>gateway timeout</html>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeGranularFirewallPolicy([]byte(tc.body)); err == nil {
				t.Errorf("this body decoded as a firewall policy: %s", tc.body)
			}
		})
	}
}

/*
TestFirewallPolicyReadProducesNoPermanentDiff is the test that would have caught the missing
sources/destinations in flattenFirewallPolicyRules, and the one that matters most in practice.

It reproduces a whole refresh: decode the server's body, run it through the same flatten and
d.Set calls resourceFirewallPolicyRead makes, take the resulting state, and then plan the
original configuration against that state. A resource that does not read back everything it
writes produces a diff here — which in a real run is a diff on every plan, forever, with an
apply that never converges.
*/
func TestFirewallPolicyReadProducesNoPermanentDiff(t *testing.T) {
	// The configuration a user would have written to produce the fixture policy.
	config := map[string]interface{}{
		"network_id": "fakeNetwork1",
		"enabled":    true,
		"allowed":    false,
		"trace":      true,
		"policy_rules": []interface{}{
			map[string]interface{}{
				"name":        "fake-any-to-any",
				"enabled":     true,
				"allowed":     true,
				"log_enabled": true,
			},
			map[string]interface{}{
				"name":         "fake-branch-to-db",
				"enabled":      true,
				"allowed":      true,
				"log_enabled":  false,
				"services":     []interface{}{"fakeSvc1"},
				"sources":      []interface{}{map[string]interface{}{"addresses": []interface{}{"fakeAddr1", "fakeAddr2"}}},
				"destinations": []interface{}{map[string]interface{}{"addresses": []interface{}{"fakeAddr3"}}},
			},
			map[string]interface{}{
				"name":        "fake-contractors",
				"enabled":     false,
				"allowed":     false,
				"log_enabled": true,
				"sources": []interface{}{map[string]interface{}{
					"users":  []interface{}{"fakeUser1"},
					"groups": []interface{}{"fakeGroup1"},
				}},
			},
		},
	}

	policy, err := decodeGranularFirewallPolicy([]byte(firewallPolicyReadFixture))
	if err != nil {
		t.Fatalf("decodeGranularFirewallPolicy: %v", err)
	}

	// Exactly what resourceFirewallPolicyRead does, minus the HTTP call.
	r := resourceFirewallPolicy()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})
	d.SetId("fakeNetwork1")
	for key, value := range map[string]interface{}{
		"network_id":   "fakeNetwork1",
		"enabled":      policy.Enabled,
		"allowed":      policy.Allowed,
		"trace":        policy.PolicyLoggingEnabled,
		"policy_rules": flattenFirewallPolicyRules(policy.PolicyRules),
	} {
		if err := d.Set(key, value); err != nil {
			t.Fatalf("could not set %s from the read: %v", key, err)
		}
	}

	// The server assigns rule IDs, so a refresh puts them in state where the configuration
	// has none. That is the point of policy_rules.*.id being Optional+Computed.
	state := d.State()
	for i, want := range []string{"fakeRuleAA", "fakeRuleBB", "fakeRuleCC"} {
		key := fmt.Sprintf("policy_rules.%d.id", i)
		if got := state.Attributes[key]; got != want {
			t.Errorf("%s = %q after the read, want %q — rule identity is not round-tripping", key, got, want)
		}
	}

	diff, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(config), nil)
	if err != nil {
		t.Fatalf("planning the original configuration against the read state failed: %v", err)
	}
	if diff != nil && !diff.Empty() {
		var report string
		for key, attr := range diff.Attributes {
			report += fmt.Sprintf("  %s: %q -> %q\n", key, attr.Old, attr.New)
		}
		t.Errorf("the configuration still shows a diff after a refresh that changed nothing — this is a permanent diff:\n%s", report)
	}
}

/*
TestFirewallPolicyServicesRoundTripIsUnverified records the one part of the read path that
offline tests cannot settle, so that it is a known open question rather than an assumption
buried in the code.

On write, the server folds a rule's `services` into its destinations array as bare
`{sharedObjectId}` entries (updateFirewallRulesGranular.interceptor.ts). On read it splits them
back out by the `type` field of each entry (extractRuleResources keys on `${type}s`), and the
public API layer never sets `type` — so the split depends on the internal RPC service adding it
when it returns stored rules. If it does not, a rule's services and its destination addresses
both come back empty, and this resource will show a permanent diff on both attributes.

The provider cannot influence that either way: the fixture here asserts what the provider does
with a correctly-split response, and a live run is what confirms the server splits it. This test
is a placeholder for that question, not a claim it has been answered.
*/
func TestFirewallPolicyServicesRoundTripIsUnverified(t *testing.T) {
	policy, err := decodeGranularFirewallPolicy([]byte(firewallPolicyReadFixture))
	if err != nil {
		t.Fatalf("decodeGranularFirewallPolicy: %v", err)
	}
	rules := flattenFirewallPolicyRules(policy.PolicyRules)
	rule, ok := rules[1].(map[string]interface{})
	if !ok {
		t.Fatalf("flattened rule 1 is %T, want map[string]interface{}", rules[1])
	}
	// Services must stay out of destinations. If a live run shows service IDs appearing in
	// destinations.addresses, the server is not splitting them and this is where to look.
	destinations, _ := rule["destinations"].([]interface{})
	if len(destinations) != 1 {
		t.Fatalf("rule 1 destinations flattened to %v, want one block", destinations)
	}
	block := destinations[0].(map[string]interface{})
	addresses, _ := block["addresses"].([]string)
	for _, address := range addresses {
		if address == "fakeSvc1" {
			t.Error("a service ID appeared in destinations.addresses; the server did not split services back out and this resource cannot round-trip either attribute")
		}
	}
	t.Skip("KNOWN UNVERIFIED: whether the server splits `services` back out of a rule's destinations on read can only be measured live; the provider's half is asserted above")
}
