package checkpointsase

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// schemaResource aliases schema.Resource for use in table-driven schema tests.
type schemaResource = schema.Resource

// v3's GranularFirewallPolicy requires policyLoggingEnabled at the policy level
// and logEnabled per rule. policyLoggingEnabled is already carried by the
// existing `trace` attribute; logEnabled is new. It MUST be Optional with a
// default — if it were Required, every existing policy_rules block would fail
// with "Missing required argument" on upgrade.
func TestFirewallPolicyLogEnabledIsOptionalWithDefault(t *testing.T) {
	r := resourceFirewallPolicy()
	rules, ok := r.Schema["policy_rules"]
	if !ok {
		t.Fatal("schema has no policy_rules attribute")
	}
	elem, ok := rules.Elem.(*schemaResource)
	if !ok {
		t.Fatalf("policy_rules Elem is %T, want *schema.Resource", rules.Elem)
	}
	logEnabled, ok := elem.Schema["log_enabled"]
	if !ok {
		t.Fatal("policy_rules has no log_enabled attribute")
	}
	if logEnabled.Required {
		t.Error("log_enabled must not be Required — it would break existing configs on upgrade")
	}
	if !logEnabled.Optional {
		t.Error("log_enabled must be Optional")
	}
	if logEnabled.Default != false {
		t.Errorf("log_enabled Default = %v, want false", logEnabled.Default)
	}
	if logEnabled.Description == "" {
		t.Error("log_enabled needs a Description — tfplugindocs depends on it")
	}
}

func TestFirewallPolicyTraceStillExists(t *testing.T) {
	r := resourceFirewallPolicy()
	trace, ok := r.Schema["trace"]
	if !ok {
		t.Fatal("trace attribute was removed; it carries policyLoggingEnabled and removing it is a breaking change")
	}
	if trace.Description == "" {
		t.Error("trace needs a Description")
	}
}

/*
planFirewallPolicy runs the SDK's real diff machinery — including CustomizeDiff — over a
configuration, exactly as `terraform plan` would. A nil prior state is a create.
*/
func planFirewallPolicy(t *testing.T, state *terraform.InstanceState, config map[string]interface{}) (*terraform.InstanceDiff, error) {
	t.Helper()
	return resourceFirewallPolicy().Diff(
		context.Background(),
		state,
		terraform.NewResourceConfigRaw(config),
		nil,
	)
}

// firewallPolicyConfigWithRule wraps one policy_rules block in an otherwise minimal, valid
// configuration, so each test below varies only the part it is about.
func firewallPolicyConfigWithRule(rule map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"network_id":   "fake-network-1",
		"enabled":      true,
		"allowed":      false,
		"policy_rules": []interface{}{rule},
	}
}

/*
TestFirewallPolicySourcesAndDestinationsExist is the shape half of the fix that made this
resource usable. Without these two blocks a user could express no rule at all beyond "any to
any, optionally narrowed by service" — and the API rejected even that, because the provider had
to invent a sources value with no user input to build it from.
*/
func TestFirewallPolicySourcesAndDestinationsExist(t *testing.T) {
	rules, ok := resourceFirewallPolicy().Schema["policy_rules"]
	if !ok {
		t.Fatal("schema has no policy_rules attribute")
	}
	elem, ok := rules.Elem.(*schemaResource)
	if !ok {
		t.Fatalf("policy_rules Elem is %T, want *schema.Resource", rules.Elem)
	}

	for _, field := range []string{"sources", "destinations"} {
		attr, ok := elem.Schema[field]
		if !ok {
			t.Fatalf("policy_rules has no %s attribute", field)
		}
		if !attr.Optional {
			t.Errorf("%s must be Optional: omitting it is how a rule says \"any\", which is the only shape the API accepts as unrestricted", field)
		}
		if attr.Required {
			t.Errorf("%s must not be Required", field)
		}
		if attr.MaxItems != 1 {
			t.Errorf("%s MaxItems = %d, want 1 — the API takes a single object per side", field, attr.MaxItems)
		}
		block, ok := attr.Elem.(*schemaResource)
		if !ok {
			t.Fatalf("%s Elem is %T, want *schema.Resource", field, attr.Elem)
		}

		for _, list := range []string{"addresses", "users", "groups"} {
			sub, ok := block.Schema[list]
			if !ok {
				t.Fatalf("%s has no %s attribute", field, list)
			}
			if !sub.Optional {
				t.Errorf("%s.%s must be Optional", field, list)
			}
			// The API applies @ArrayMinSize(1) to each of these whenever the key is
			// present, so an empty list is never a legal body. MinItems turns that
			// into a plan error instead of a 400 — and, more importantly, stops
			// `addresses = []` from being silently read as "any address".
			if sub.MinItems != 1 {
				t.Errorf("%s.%s MinItems = %d, want 1", field, list, sub.MinItems)
			}
			if sub.Description == "" {
				t.Errorf("%s.%s needs a Description", field, list)
			}
		}
		// @ArrayMaxSize(10) on users, server-side.
		if got := block.Schema["users"].MaxItems; got != 10 {
			t.Errorf("%s.users MaxItems = %d, want 10", field, got)
		}
		if block.Schema["addresses"].MaxItems != 0 || block.Schema["groups"].MaxItems != 0 {
			t.Error("only users has a documented server-side maximum; capping addresses or groups would reject valid configurations")
		}
	}
}

/*
TestFirewallPolicyDocumentsWhatIsEasyToGetWrong pins the three things a user cannot discover
from the API's error messages: that addresses and services take shared-object IDs rather than
CIDRs and ports, that rule order is evaluation order, and that omitting a block means "any".

These are wording assertions, which are only worth writing where the wording is the only place
the information exists. All three of these have no other home: the server's 400 for a CIDR in
`addresses` does not mention shared objects, and nothing in the API response hints that list
position becomes rule priority.
*/
func TestFirewallPolicyDocumentsWhatIsEasyToGetWrong(t *testing.T) {
	r := resourceFirewallPolicy()
	rules := r.Schema["policy_rules"]
	elem := rules.Elem.(*schemaResource)

	// Rule order is evaluation order: priority is assigned from array position.
	for _, want := range []string{"order", "evaluates", "priority"} {
		if !strings.Contains(strings.ToLower(rules.Description), want) {
			t.Errorf("policy_rules description does not mention %q; nobody will guess that list order is firewall evaluation order:\n%s", want, rules.Description)
		}
	}

	// Shared-object IDs, not literals.
	for _, tc := range []struct{ path, wantRef, wantLiteral string }{
		{"services", "checkpointsase_object_services", "443"},
		{"sources.addresses", "checkpointsase_object_addresses", "10.0.0.0/8"},
		{"destinations.addresses", "checkpointsase_object_addresses", "10.0.0.0/8"},
	} {
		attr := elem.Schema[tc.path]
		if attr == nil {
			block := elem.Schema[strings.Split(tc.path, ".")[0]].Elem.(*schemaResource)
			attr = block.Schema[strings.Split(tc.path, ".")[1]]
		}
		if !strings.Contains(attr.Description, tc.wantRef) {
			t.Errorf("%s description does not name %s, so a user has no way to learn these are shared-object IDs:\n%s", tc.path, tc.wantRef, attr.Description)
		}
		if !strings.Contains(attr.Description, tc.wantLiteral) {
			t.Errorf("%s description does not show the rejected literal %q, which is the mistake it exists to prevent:\n%s", tc.path, tc.wantLiteral, attr.Description)
		}
	}

	// The XOR, quoted from the server so the two messages are recognisably the same rule.
	for _, field := range []string{"sources", "destinations"} {
		if !strings.Contains(elem.Schema[field].Description, firewallPolicyAddressesXOR) {
			t.Errorf("%s description does not quote the server's own refusal (%q):\n%s", field, firewallPolicyAddressesXOR, elem.Schema[field].Description)
		}
	}
}

/*
TestFirewallPolicySchemaCannotExpressTheXOR is the evidence for the comment on
firewallPolicyRuleEndpointResource, and the reason the exclusion lives in CustomizeDiff.

SDKv2's ExactlyOneOf/ConflictsWith take absolute attribute paths. This asserts that every form
of path that could reach into a policy_rules element is refused by InternalValidate — so the
schema-level option is not merely awkward, it does not compile past validation. If a future SDK
upgrade makes one of these work, this test fails and the CustomizeDiff can be reconsidered.
*/
func TestFirewallPolicySchemaCannotExpressTheXOR(t *testing.T) {
	// A cut-down copy of the real shape: a list of many rules, each with a MaxItems 1 block.
	build := func(constraint string, paths []string) *schema.Resource {
		addresses := &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		}
		switch constraint {
		case "ConflictsWith":
			addresses.ConflictsWith = paths
		case "ExactlyOneOf":
			addresses.ExactlyOneOf = paths
		}
		return &schema.Resource{
			Schema: map[string]*schema.Schema{
				"policy_rules": {
					Type:     schema.TypeList,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"sources": {
								Type:     schema.TypeList,
								Optional: true,
								MaxItems: 1,
								Elem: &schema.Resource{
									Schema: map[string]*schema.Schema{
										"addresses": addresses,
										"users": {
											Type:     schema.TypeList,
											Optional: true,
											Elem:     &schema.Schema{Type: schema.TypeString},
										},
									},
								},
							},
						},
					},
				},
			},
		}
	}

	paths := map[string][]string{
		"indexed":          {"policy_rules.0.sources.0.users"},
		"unindexed":        {"policy_rules.sources.users"},
		"starred":          {"policy_rules.*.sources.0.users"},
		"relative sibling": {"users"},
	}
	for _, constraint := range []string{"ConflictsWith", "ExactlyOneOf"} {
		for name, path := range paths {
			t.Run(constraint+"/"+name, func(t *testing.T) {
				if err := build(constraint, path).InternalValidate(nil, true); err == nil {
					t.Errorf("%s %v is accepted by InternalValidate after all — the XOR may now be expressible in schema, and firewallPolicyRuleEndpointResource's comment plus resourceFirewallPolicyCustomizeDiff should be revisited", constraint, path)
				}
			})
		}
	}
	// Control: the same shape validates cleanly with no cross-field constraint, so the
	// failures above are about the constraint and not about the shape.
	if err := build("", nil).InternalValidate(nil, true); err != nil {
		t.Errorf("the control schema does not validate, so this test proves nothing: %v", err)
	}
}

/*
TestFirewallPolicyEmptyListsAreRejectedAtPlanTime proves MinItems and MaxItems are enforced
inside nested blocks — which is not obvious, since the XOR constraints above are not.

The empty-list case is the important one and it is a correctness issue, not tidiness: the
expand path treats a block with no populated list as unrestricted, so without this refusal
`addresses = []` would quietly widen a rule from "these addresses" to "any address".
*/
func TestFirewallPolicyEmptyListsAreRejectedAtPlanTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rule   map[string]interface{}
		wantIn string
	}{
		{
			name: "empty sources addresses",
			rule: map[string]interface{}{
				"name":    "rule1",
				"enabled": true,
				"allowed": true,
				"sources": []interface{}{map[string]interface{}{"addresses": []interface{}{}}},
			},
			wantIn: "policy_rules.0.sources.0.addresses",
		},
		{
			name: "empty destinations groups",
			rule: map[string]interface{}{
				"name":         "rule1",
				"enabled":      true,
				"allowed":      true,
				"destinations": []interface{}{map[string]interface{}{"groups": []interface{}{}}},
			},
			wantIn: "policy_rules.0.destinations.0.groups",
		},
		{
			name: "empty services",
			rule: map[string]interface{}{
				"name":     "rule1",
				"enabled":  true,
				"allowed":  true,
				"services": []interface{}{},
			},
			wantIn: "policy_rules.0.services",
		},
		{
			name: "eleven users",
			rule: map[string]interface{}{
				"name":    "rule1",
				"enabled": true,
				"allowed": true,
				"sources": []interface{}{map[string]interface{}{
					"users": []interface{}{"u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "u9", "u10", "u11"},
				}},
			},
			wantIn: "policy_rules.0.sources.0.users",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := resourceFirewallPolicy().Validate(terraform.NewResourceConfigRaw(firewallPolicyConfigWithRule(tc.rule)))
			if !diags.HasError() {
				t.Fatalf("this configuration validated cleanly; it must fail at plan time")
			}
			var joined string
			for _, d := range diags {
				joined += d.Summary + " " + d.Detail + " "
			}
			if !strings.Contains(joined, tc.wantIn) {
				t.Errorf("the plan error does not name %s, so it cannot be acted on:\n%s", tc.wantIn, joined)
			}
		})
	}
}

/*
TestFirewallPolicyNameLengthIsValidatedAtPlanTime covers the 5–50 character limit. A four
character name is a 400 (policyRules.0.name must be longer than or equal to 5 characters,
measured live 2026-08-19) — an unhelpfully late failure for a typo.
*/
func TestFirewallPolicyNameLengthIsValidatedAtPlanTime(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ruleName string
		wantErr  bool
	}{
		{name: "four characters", ruleName: "abcd", wantErr: true},
		{name: "five characters", ruleName: "abcde", wantErr: false},
		{name: "fifty characters", ruleName: strings.Repeat("a", 50), wantErr: false},
		{name: "fifty-one characters", ruleName: strings.Repeat("a", 51), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := resourceFirewallPolicy().Validate(terraform.NewResourceConfigRaw(
				firewallPolicyConfigWithRule(map[string]interface{}{
					"name":    tc.ruleName,
					"enabled": true,
					"allowed": true,
				})))
			if diags.HasError() != tc.wantErr {
				t.Errorf("name %q (%d chars): HasError = %t, want %t: %v", tc.ruleName, len(tc.ruleName), diags.HasError(), tc.wantErr, diags)
			}
		})
	}
}

/*
TestFirewallPolicyXORIsRejectedAtPlanTime is the unit test for the refusal that replaces the
server's 400. It goes through the resource's real Diff, so it covers the wiring
(CustomizeDiff being registered at all) as well as validateFirewallPolicyRules.
*/
func TestFirewallPolicyXORIsRejectedAtPlanTime(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rule    map[string]interface{}
		wantErr string
	}{
		{
			name: "addresses with users in sources",
			rule: map[string]interface{}{
				"name":    "rule1",
				"enabled": true,
				"allowed": true,
				"sources": []interface{}{map[string]interface{}{
					"addresses": []interface{}{"fake-addr-1"},
					"users":     []interface{}{"fake-user-1"},
				}},
			},
			wantErr: "policy_rules.0.sources",
		},
		{
			name: "addresses with groups in destinations",
			rule: map[string]interface{}{
				"name":    "rule1",
				"enabled": true,
				"allowed": true,
				"destinations": []interface{}{map[string]interface{}{
					"addresses": []interface{}{"fake-addr-1"},
					"groups":    []interface{}{"fake-group-1"},
				}},
			},
			wantErr: "policy_rules.0.destinations",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := planFirewallPolicy(t, nil, firewallPolicyConfigWithRule(tc.rule))
			if err == nil {
				t.Fatal("planning this rule succeeded; the API refuses it, so the plan must too")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("the refusal does not name the offending block (%s):\n%v", tc.wantErr, err)
			}
			// The server's own wording, so the two errors are recognisably one rule.
			if !strings.Contains(err.Error(), firewallPolicyAddressesXOR) {
				t.Errorf("the refusal does not quote the server's message (%q):\n%v", firewallPolicyAddressesXOR, err)
			}
		})
	}
}

/*
TestFirewallPolicyValidCombinationsPlanCleanly is the other half of the XOR test, and the more
important one: a refusal that also rejects valid configurations is worse than no refusal. Every
combination the API accepts must plan without error, including the users+groups pair and a rule
with no sources or destinations at all.
*/
func TestFirewallPolicyValidCombinationsPlanCleanly(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule map[string]interface{}
	}{
		{
			name: "no sources or destinations at all",
			rule: map[string]interface{}{"name": "rule1", "enabled": true, "allowed": true},
		},
		{
			name: "addresses only, both sides",
			rule: map[string]interface{}{
				"name":         "rule1",
				"enabled":      true,
				"allowed":      true,
				"sources":      []interface{}{map[string]interface{}{"addresses": []interface{}{"fake-addr-1"}}},
				"destinations": []interface{}{map[string]interface{}{"addresses": []interface{}{"fake-addr-2"}}},
			},
		},
		{
			name: "users and groups together",
			rule: map[string]interface{}{
				"name":    "rule1",
				"enabled": true,
				"allowed": true,
				"sources": []interface{}{map[string]interface{}{
					"users":  []interface{}{"fake-user-1"},
					"groups": []interface{}{"fake-group-1"},
				}},
			},
		},
		{
			name: "addresses on one side, users on the other",
			rule: map[string]interface{}{
				"name":         "rule1",
				"enabled":      true,
				"allowed":      true,
				"sources":      []interface{}{map[string]interface{}{"users": []interface{}{"fake-user-1"}}},
				"destinations": []interface{}{map[string]interface{}{"addresses": []interface{}{"fake-addr-1"}}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := planFirewallPolicy(t, nil, firewallPolicyConfigWithRule(tc.rule)); err != nil {
				t.Errorf("this configuration is accepted by the API but refused by the plan:\n%v", err)
			}
		})
	}
}
