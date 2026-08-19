package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// randNameFirewallPolicy is generated once per test binary so that every step
// of this test refers to the *same* network. network_id is ForceNew, so a name
// that changed between steps would replace the network — a 10-15 minute
// rebuild — instead of exercising the update path this test exists to cover.
var randNameFirewallPolicy string = randStringBytesRmndr()

// TestAccFirewallPolicy_basic is the first live exercise of
// checkpointsase_firewall_policy.
//
// What this resource actually is, verified against resource_firewall_policy.go
// rather than assumed: it is a *network-scoped singleton adopted* by Terraform,
// not an independently created object.
//
//   - resourceFirewallPolicyCreate issues no POST. There is no create endpoint.
//     It calls GetGranularFirewallPolicy purely as an existence check, sets
//     d.SetId(networkId), and then delegates straight to
//     resourceFirewallPolicyUpdate. So "Create" really is an update of the
//     policy the server auto-created with the network.
//   - The resource ID *is* the network ID. Step 1 asserts that identity
//     explicitly (testAccCheckFirewallPolicyExists), because every other claim
//     here depends on it.
//   - resourceFirewallPolicyDelete is a no-op that only clears state.
//
// Consequences for this test's shape:
//
//   - Two config steps are correct and worthwhile. Both steps run the same
//     Update code path, but step 2 runs it against an already-adopted resource
//     with server-assigned rule IDs in state, which is the only way to reach
//     the id round-trip in buildGranularFirewallPolicyRule/
//     flattenFirewallPolicyRules. This is test-plan rows FW-01 and FW-02.
//   - There is deliberately NO CheckDestroy. Two independent reasons, both
//     checked rather than assumed: (a) no other TestAcc test in this package
//     defines one — grep CheckDestroy across *_test.go returns nothing; and
//     (b) for this resource a CheckDestroy could not assert anything true.
//     Asserting the policy is gone would be wrong (Delete never deletes it —
//     FW-03), and asserting it still exists would be equally wrong, because
//     CheckDestroy runs after the whole config is destroyed, including the
//     parent network, which does take the policy with it. A CheckDestroy here
//     would be a check written to pass rather than to mean something.
//
// Only one network is created, and it is byte-identical in both config steps.
func TestAccFirewallPolicy_basic(t *testing.T) {
	t.Parallel()
	var policy perimeter81Sdk.GranularFirewallPolicy

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			// Step 1 (FW-01): adopt the auto-created policy and push a
			// configuration with one rule onto it.
			{
				Config: testAccFirewallPolicyConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFirewallPolicyExists("checkpointsase_firewall_policy.fw", &policy),
					testAccCheckFirewallPolicyAttributes(&policy, &testAccFirewallPolicyExpectedAttributes{
						Enabled: true,
						Allowed: false,
						Trace:   true,
						Rules: []testAccFirewallPolicyExpectedRule{
							{
								Name:        "tfacc-allow-https",
								Enabled:     true,
								Allowed:     true,
								LogEnabled:  true,
								ServiceRefs: []string{"checkpointsase_object_services.svc1"},
							},
						},
					}),
					// The API is authoritative above; these confirm Read
					// carried the same values back into Terraform state, so a
					// server/state divergence cannot hide behind a green API
					// assertion.
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "enabled", "true"),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "allowed", "false"),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "trace", "true"),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.#", "1"),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.0.name", "tfacc-allow-https"),
					// policy_rules.*.id is Optional+Computed: the server
					// assigns it and flattenFirewallPolicyRules is supposed to
					// read it back. An empty value here means rule identity is
					// not round-tripping.
					testAccCheckFirewallPolicyRuleIDsPopulated("checkpointsase_firewall_policy.fw", 1),
				),
			},
			// Step 2 (FW-02): in-place update. Every policy-level scalar is
			// flipped, the existing rule's fields are flipped, and a second
			// rule is appended, so the update covers scalar changes, per-rule
			// changes, and growth of the rule list in one apply. The network
			// block is unchanged, so no network is rebuilt.
			{
				Config: testAccFirewallPolicyUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFirewallPolicyExists("checkpointsase_firewall_policy.fw", &policy),
					testAccCheckFirewallPolicyAttributes(&policy, &testAccFirewallPolicyExpectedAttributes{
						Enabled: true,
						Allowed: true,
						Trace:   false,
						Rules: []testAccFirewallPolicyExpectedRule{
							{
								Name:        "tfacc-deny-https",
								Enabled:     false,
								Allowed:     false,
								LogEnabled:  false,
								ServiceRefs: []string{"checkpointsase_object_services.svc1"},
							},
							{
								Name:        "tfacc-allow-dns",
								Enabled:     true,
								Allowed:     true,
								LogEnabled:  true,
								ServiceRefs: []string{"checkpointsase_object_services.svc2"},
							},
						},
					}),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "allowed", "true"),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "trace", "false"),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.#", "2"),
					// FW-04: rule order is submitted positionally by
					// resourceFirewallPolicyUpdate. Whether the API preserves
					// that order has never been verified. If it does not, this
					// pair fails and says so.
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.0.name", "tfacc-deny-https"),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.1.name", "tfacc-allow-dns"),
					testAccCheckFirewallPolicyRuleIDsPopulated("checkpointsase_firewall_policy.fw", 2),
				),
			},
			// Step 3: import into a fresh state and compare it, field for
			// field, against the state step 2 produced. This is the only step
			// that can prove resourceFirewallPolicyRead repopulates every
			// attribute: after an apply, state already holds the configured
			// values whether Read wrote them or not, so a post-apply check
			// cannot distinguish "Read works" from "Read is a no-op". Import
			// starts from an empty state, so anything Read fails to set shows
			// up as a missing attribute. It creates nothing — no second
			// network.
			//
			// No ImportStateVerifyIgnore: nothing is excluded, deliberately.
			// The import ID is the network ID, which is also the resource ID,
			// so the default ImportStateId (the resource's own ID) is correct.
			{
				ResourceName:      "checkpointsase_firewall_policy.fw",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

/*
testAccCheckFirewallPolicyExists confirms the policy is readable server-side
through the SDK, and pins the adopt-style contract that the resource ID is the
network ID. A state-only check cannot substitute for this: because Create never
POSTs anything, a resource ID could be set from configuration alone and look
perfectly healthy in state while nothing was ever pushed to the server.
*/
func testAccCheckFirewallPolicyExists(n string, policy *perimeter81Sdk.GranularFirewallPolicy) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}

		policyResourceId := rs.Primary.ID
		if policyResourceId == "" {
			return fmt.Errorf("No firewall policy id is set")
		}

		networkId := rs.Primary.Attributes["network_id"]
		if networkId == "" {
			return fmt.Errorf("No network_id is set on %s", n)
		}
		// resourceFirewallPolicyCreate does d.SetId(networkId). If that ever
		// changes, every lookup below (and terraform import, which reverses it
		// in resourceFirewallPolicyImportState) silently targets the wrong
		// object.
		if policyResourceId != networkId {
			return fmt.Errorf("got resource id %q; want it to equal network_id %q — this resource is a network-scoped singleton and its id is the network id", policyResourceId, networkId)
		}

		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		ctx := context.Background()
		gotPolicy, _, err := conn.FirewallPolicyAPI.GetGranularFirewallPolicy(ctx, networkId).Execute()
		if err != nil {
			return err
		}
		if gotPolicy == nil {
			return fmt.Errorf("firewall policy for network %q read back as nil", networkId)
		}
		*policy = *gotPolicy
		return nil
	}
}

// testAccFirewallPolicyExpectedRule describes one policy rule as the
// configuration asked for it. ServiceRefs holds Terraform state addresses
// rather than service IDs, because the IDs are assigned at apply time; the
// check resolves each address to its real ID before comparing.
type testAccFirewallPolicyExpectedRule struct {
	Name        string
	Enabled     bool
	Allowed     bool
	LogEnabled  bool
	ServiceRefs []string
}

type testAccFirewallPolicyExpectedAttributes struct {
	Enabled bool
	Allowed bool
	// Trace is the `trace` schema attribute, which the resource maps onto the
	// API's policyLoggingEnabled field.
	Trace bool
	Rules []testAccFirewallPolicyExpectedRule
}

/*
testAccCheckFirewallPolicyAttributes compares what the API holds against what
the configuration asked for, field by field.

The rule-count comparison is load-bearing and is expected to be the first thing
to break if the server does not accept a wholesale replacement of policyRules:
resourceFirewallPolicyUpdate sends exactly the rules in the HCL and nothing
else, so if the auto-created policy's own default rules survive the PUT, or the
server appends rather than replaces, the count will not match and this reports
both numbers.
*/
func testAccCheckFirewallPolicyAttributes(policy *perimeter81Sdk.GranularFirewallPolicy, want *testAccFirewallPolicyExpectedAttributes) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if policy.Enabled != want.Enabled {
			return fmt.Errorf("got enabled %t; want %t", policy.Enabled, want.Enabled)
		}
		if policy.Allowed != want.Allowed {
			return fmt.Errorf("got allowed %t; want %t", policy.Allowed, want.Allowed)
		}
		if policy.PolicyLoggingEnabled != want.Trace {
			return fmt.Errorf("got policyLoggingEnabled (schema attribute `trace`) %t; want %t", policy.PolicyLoggingEnabled, want.Trace)
		}

		if len(policy.PolicyRules) != len(want.Rules) {
			gotNames := make([]string, 0, len(policy.PolicyRules))
			for _, r := range policy.PolicyRules {
				gotNames = append(gotNames, r.Name)
			}
			return fmt.Errorf("got %d policy rules %v; want %d — the provider replaces policyRules wholesale, so a mismatch means the server did not honour the submitted list",
				len(policy.PolicyRules), gotNames, len(want.Rules))
		}

		for i, wantRule := range want.Rules {
			gotRule := policy.PolicyRules[i]

			if gotRule.Name != wantRule.Name {
				return fmt.Errorf("rule %d: got name %q; want %q", i, gotRule.Name, wantRule.Name)
			}
			if gotRule.Enabled != wantRule.Enabled {
				return fmt.Errorf("rule %d (%s): got enabled %t; want %t", i, wantRule.Name, gotRule.Enabled, wantRule.Enabled)
			}
			if gotRule.Allowed != wantRule.Allowed {
				return fmt.Errorf("rule %d (%s): got allowed %t; want %t", i, wantRule.Name, gotRule.Allowed, wantRule.Allowed)
			}
			if gotRule.LogEnabled != wantRule.LogEnabled {
				return fmt.Errorf("rule %d (%s): got logEnabled %t; want %t", i, wantRule.Name, gotRule.LogEnabled, wantRule.LogEnabled)
			}
			if gotRule.Id == nil || *gotRule.Id == "" {
				return fmt.Errorf("rule %d (%s): server returned no rule id; policy_rules.%d.id cannot round-trip", i, wantRule.Name, i)
			}

			wantServices, err := testAccResolveStateIDs(s, wantRule.ServiceRefs)
			if err != nil {
				return fmt.Errorf("rule %d (%s): %s", i, wantRule.Name, err)
			}
			if !testComparableArraiesEq(gotRule.Services, wantServices) {
				return fmt.Errorf("rule %d (%s): got services %v; want %v", i, wantRule.Name, gotRule.Services, wantServices)
			}
		}

		return nil
	}
}

/*
testAccCheckFirewallPolicyRuleIDsPopulated asserts that Terraform state holds a
non-empty, server-assigned id for each of the first wantCount policy rules.
policy_rules.*.id is Optional+Computed, so an empty id in state means
flattenFirewallPolicyRules did not carry the server's id back — which would
make every subsequent update submit rules the server treats as new.
*/
func testAccCheckFirewallPolicyRuleIDsPopulated(n string, wantCount int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}
		for i := 0; i < wantCount; i++ {
			key := fmt.Sprintf("policy_rules.%d.id", i)
			if rs.Primary.Attributes[key] == "" {
				return fmt.Errorf("state attribute %s is empty; want the server-assigned rule id", key)
			}
		}
		return nil
	}
}

/*
testAccResolveStateIDs turns a list of Terraform state addresses (e.g.
"checkpointsase_object_services.svc1") into the primary IDs those resources
were assigned at apply time. Object service IDs cannot be hardcoded in an
expectation because the server mints them.
*/
func testAccResolveStateIDs(s *terraform.State, addresses []string) ([]string, error) {
	ids := make([]string, 0, len(addresses))
	for _, address := range addresses {
		rs, ok := s.RootModule().Resources[address]
		if !ok {
			return nil, fmt.Errorf("Not Found: %s", address)
		}
		if rs.Primary.ID == "" {
			return nil, fmt.Errorf("%s has no id in state", address)
		}
		ids = append(ids, rs.Primary.ID)
	}
	return ids, nil
}

/*
testAccFirewallPolicyConfig is step 1: a network (whose creation implicitly
creates the policy this resource adopts), one TCP/443 service object, and a
policy carrying a single rule that references it.

The rule can only be scoped by `services`: there is no sources/destinations
schema surface on this resource, and buildGranularFirewallPolicyRule hardwires
both to an empty address list.
*/
func testAccFirewallPolicyConfig() string {
	config := `
resource "checkpointsase_network" "n1" {
  network {
    name = "%[1]s"
    tags = ["test"]
  }
  region {
    cpregion_id = "%[2]s"
    idle = true
  }
}

resource "checkpointsase_object_services" "svc1" {
  name        = "tfacc-https-%[1]s"
  description = "TCP 443, matched by the firewall policy acceptance test"

  protocols {
    protocol   = "tcp"
    value_type = "single"
    value      = [443]
  }
}

resource "checkpointsase_firewall_policy" "fw" {
  network_id = checkpointsase_network.n1.id
  enabled    = true
  allowed    = false
  trace      = true

  policy_rules {
    name        = "tfacc-allow-https"
    enabled     = true
    allowed     = true
    services    = [checkpointsase_object_services.svc1.id]
    log_enabled = true
  }
}
  `
	return fmt.Sprintf(config, randNameFirewallPolicy, testAccRegionID())
}

/*
testAccFirewallPolicyUpdateConfig is step 2. The network and svc1 blocks are
identical to step 1 so neither is replaced — only the policy changes. It flips
every policy-level scalar, flips every field of the existing rule, and appends
a second rule against a new UDP/53 service object.
*/
func testAccFirewallPolicyUpdateConfig() string {
	config := `
resource "checkpointsase_network" "n1" {
  network {
    name = "%[1]s"
    tags = ["test"]
  }
  region {
    cpregion_id = "%[2]s"
    idle = true
  }
}

resource "checkpointsase_object_services" "svc1" {
  name        = "tfacc-https-%[1]s"
  description = "TCP 443, matched by the firewall policy acceptance test"

  protocols {
    protocol   = "tcp"
    value_type = "single"
    value      = [443]
  }
}

resource "checkpointsase_object_services" "svc2" {
  name        = "tfacc-dns-%[1]s"
  description = "UDP 53, matched by the firewall policy acceptance test"

  protocols {
    protocol   = "udp"
    value_type = "single"
    value      = [53]
  }
}

resource "checkpointsase_firewall_policy" "fw" {
  network_id = checkpointsase_network.n1.id
  enabled    = true
  allowed    = true
  trace      = false

  policy_rules {
    name        = "tfacc-deny-https"
    enabled     = false
    allowed     = false
    services    = [checkpointsase_object_services.svc1.id]
    log_enabled = false
  }

  policy_rules {
    name        = "tfacc-allow-dns"
    enabled     = true
    allowed     = true
    services    = [checkpointsase_object_services.svc2.id]
    log_enabled = true
  }
}
  `
	return fmt.Sprintf(config, randNameFirewallPolicy, testAccRegionID())
}
