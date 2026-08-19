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
// It was written on 2026-08-18 against a resource that could not create a rule
// at all: with no sources/destinations schema, the provider sent
// `{"addresses": []}` for both sides of every rule, and the API refuses an
// empty array wherever it accepts the key at all. Step 1 therefore never
// passed. Both blocks now exist and are exercised here.
//
// What is NOT here, deliberately: the addresses/users+groups exclusion. It is
// refused during plan by resourceFirewallPolicyCustomizeDiff, so a live run
// would only be measuring an error message that never reaches the API —
// TestFirewallPolicyXORIsRejectedAtPlanTime covers it offline in milliseconds.
// Neither are `users`/`groups`: both need directory objects this test suite
// cannot create, so the fixtures scope rules by address instead.
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
								Name:                   "tfacc-allow-https",
								Enabled:                true,
								Allowed:                true,
								LogEnabled:             true,
								ServiceRefs:            []string{"checkpointsase_object_services.svc1"},
								SourceAddressRefs:      []string{"checkpointsase_object_addresses.branch"},
								DestinationAddressRefs: []string{"checkpointsase_object_addresses.database"},
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
					// Read has to carry both endpoint objects back into state or
					// every subsequent plan reports a diff on a rule nobody
					// touched. TestFirewallPolicyReadProducesNoPermanentDiff
					// covers the same ground offline; this is the live half.
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.0.sources.#", "1"),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.0.sources.0.addresses.#", "1"),
					resource.TestCheckResourceAttrPair(
						"checkpointsase_firewall_policy.fw", "policy_rules.0.sources.0.addresses.0",
						"checkpointsase_object_addresses.branch", "id"),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.0.destinations.#", "1"),
					resource.TestCheckResourceAttrPair(
						"checkpointsase_firewall_policy.fw", "policy_rules.0.destinations.0.addresses.0",
						"checkpointsase_object_addresses.database", "id"),
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
								Name:       "tfacc-deny-https",
								Enabled:    false,
								Allowed:    false,
								LogEnabled: false,
								// The rule keeps its service but loses both endpoint
								// blocks, so this step also covers narrowing a rule
								// back to unrestricted — the update direction that
								// has to send {} rather than an empty list.
								ServiceRefs: []string{"checkpointsase_object_services.svc1"},
							},
							{
								Name:                   "tfacc-allow-dns",
								Enabled:                true,
								Allowed:                true,
								LogEnabled:             true,
								ServiceRefs:            []string{"checkpointsase_object_services.svc2"},
								DestinationAddressRefs: []string{"checkpointsase_object_addresses.database"},
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
					// Rule 0 dropped both endpoint blocks in this step. State must
					// show them gone, not merely emptied: a lingering
					// `sources.# = 1` would mean the update sent an empty list
					// where it had to send {}.
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.0.sources.#", "0"),
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.0.destinations.#", "0"),
					// Rule 1 is scoped only on its destination side, so the source
					// side is the unrestricted case in the same policy.
					resource.TestCheckResourceAttr("checkpointsase_firewall_policy.fw", "policy_rules.1.sources.#", "0"),
					resource.TestCheckResourceAttrPair(
						"checkpointsase_firewall_policy.fw", "policy_rules.1.destinations.0.addresses.0",
						"checkpointsase_object_addresses.database", "id"),
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
		// getGranularFirewallPolicy, not the SDK method directly: the generated
		// SourcesAndDestinations oneOf cannot decode an unrestricted `{}` or an
		// `{"addresses":[...]}` object, so the raw SDK call fails on a 200 for every
		// policy this test creates. See resource_firewall_policy_read_test.go.
		gotPolicy, _, err := getGranularFirewallPolicy(ctx, conn, networkId)
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
	Name       string
	Enabled    bool
	Allowed    bool
	LogEnabled bool
	// ServiceRefs, SourceAddressRefs and DestinationAddressRefs all hold state
	// addresses rather than IDs, for the same reason: the server mints the IDs at
	// apply time. An empty slice means "unrestricted" — the {} case — and is
	// asserted as such rather than skipped, because {} is the shape Create sends
	// for any rule the user did not scope, and a server that stored something else
	// there would be silently changing what the rule matches.
	ServiceRefs            []string
	SourceAddressRefs      []string
	DestinationAddressRefs []string
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

			if err := testAccCheckFirewallPolicyEndpoint(s, i, wantRule.Name, "sources", gotRule.Sources, wantRule.SourceAddressRefs); err != nil {
				return err
			}
			if err := testAccCheckFirewallPolicyEndpoint(s, i, wantRule.Name, "destinations", gotRule.Destinations, wantRule.DestinationAddressRefs); err != nil {
				return err
			}
		}

		return nil
	}
}

/*
testAccCheckFirewallPolicyEndpoint compares one side of a rule — its sources or its
destinations — against the address objects the configuration pointed it at.

Two things make this worth asserting server-side rather than only in state. The write
shape is invisible in state: `{"addresses":[]}` and `{}` both look like "no sources"
in Terraform, and one of them is a 400, so only the API's own copy of the rule
distinguishes a rule that was stored unrestricted from one that was never stored.
And the read shape for an address-scoped rule is the case the generated SDK decoder
cannot represent at all, so this is also where a regression in
getGranularFirewallPolicy's fallback would show up.
*/
func testAccCheckFirewallPolicyEndpoint(s *terraform.State, ruleIndex int, ruleName, field string, got perimeter81Sdk.SourcesAndDestinations, wantRefs []string) error {
	wantIDs, err := testAccResolveStateIDs(s, wantRefs)
	if err != nil {
		return fmt.Errorf("rule %d (%s) %s: %s", ruleIndex, ruleName, field, err)
	}

	var gotAddresses, gotUsers, gotGroups []string
	if got.Addresses != nil {
		gotAddresses = got.Addresses.Addresses
	}
	if got.UsersAndGroups != nil {
		gotUsers = got.UsersAndGroups.Users
		gotGroups = got.UsersAndGroups.Groups
	}

	if len(wantIDs) == 0 {
		if len(gotAddresses) > 0 || len(gotUsers) > 0 || len(gotGroups) > 0 {
			return fmt.Errorf("rule %d (%s): %s should be unrestricted ({}), but the API holds addresses %v users %v groups %v — the rule matches less traffic than the configuration asked for",
				ruleIndex, ruleName, field, gotAddresses, gotUsers, gotGroups)
		}
		return nil
	}
	if !testComparableArraiesEq(gotAddresses, wantIDs) {
		return fmt.Errorf("rule %d (%s): got %s addresses %v; want %v", ruleIndex, ruleName, field, gotAddresses, wantIDs)
	}
	return nil
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
creates the policy this resource adopts), one TCP/443 service object, two
address objects, and a policy carrying a single rule scoped by all three.

Both endpoint blocks are populated deliberately. Until 2026-08-19 this step
could not pass at all — the provider had no sources/destinations schema and sent
`{"addresses": []}` for both, which the API rejects with
`policyRules.0.sources.addresses must contain at least 1 elements` — so the
addresses path is the part of this test with no prior live evidence behind it.
The rule references shared-object IDs, never literals: a CIDR written straight
into `addresses` is a 400.

Both address objects use `value_type = "ip"` on purpose. It is one of the two
types checkpointsase_object_addresses' own acceptance test already exercises
live, so a failure in this test is about the firewall policy rather than about
an address type nobody has measured.
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

resource "checkpointsase_object_addresses" "branch" {
  name        = "tfacc-branch-%[1]s"
  description = "Branch host, the source side of the firewall policy acceptance test"
  value_type  = "ip"
  value       = ["192.0.2.10"]
}

resource "checkpointsase_object_addresses" "database" {
  name        = "tfacc-database-%[1]s"
  description = "Database host, the destination side of the firewall policy acceptance test"
  value_type  = "ip"
  value       = ["198.51.100.10"]
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

    sources {
      addresses = [checkpointsase_object_addresses.branch.id]
    }

    destinations {
      addresses = [checkpointsase_object_addresses.database.id]
    }
  }
}
  `
	return fmt.Sprintf(config, randNameFirewallPolicy, testAccRegionID())
}

/*
testAccFirewallPolicyUpdateConfig is step 2. The network, svc1 and both address
blocks are identical to step 1 so none of them is replaced — only the policy
changes. It flips every policy-level scalar, flips every field of the existing
rule, and appends a second rule against a new UDP/53 service object.

The endpoint blocks move as well as the scalars, which is the part worth having:
rule 0 loses both of its blocks (narrow -> unrestricted, the update that has to
send `{}` and not an empty list), and the appended rule 1 is scoped on its
destination side only, so one policy carries a restricted and an unrestricted
side at once.
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

resource "checkpointsase_object_addresses" "branch" {
  name        = "tfacc-branch-%[1]s"
  description = "Branch host, the source side of the firewall policy acceptance test"
  value_type  = "ip"
  value       = ["192.0.2.10"]
}

resource "checkpointsase_object_addresses" "database" {
  name        = "tfacc-database-%[1]s"
  description = "Database host, the destination side of the firewall policy acceptance test"
  value_type  = "ip"
  value       = ["198.51.100.10"]
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

    destinations {
      addresses = [checkpointsase_object_addresses.database.id]
    }
  }
}
  `
	return fmt.Sprintf(config, randNameFirewallPolicy, testAccRegionID())
}
