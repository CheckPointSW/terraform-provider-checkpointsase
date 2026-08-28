package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
The one ACCEPTANCE test for checkpointsase_enhanced_network_private_dns.

This file holds the only TestAcc-prefixed name for this resource, and it is
genuinely an acceptance test: resource.Test skips it unless TF_ACC=1, and it
creates and destroys a real enhanced network. Every other test for this resource
is offline and lives in resource_enhanced_network_private_dns_test.go under a name
that says what it does. Phase 4 shipped 21 offline tests wearing the TestAcc
prefix, which reads in the summary as 21 skipped acceptance tests and as zero
offline coverage.
*/

// The network this test builds. 10.96.0.0/22 is chosen to avoid every subnet
// already used by an acceptance test in this package (10.90, 10.91, 10.93, 10.94
// and 10.95 are taken -- ENUMERATED rather than given as a range, because
// "10.90-10.95" includes 10.92, which nothing uses),
// because two networks with overlapping subnets are refused and a collision
// would fail whichever test ran second for a reason that has nothing to do with
// private DNS.
//
// THE TWO DNS SERVER ADDRESSES ARE DELIBERATELY NOT INSIDE THAT SUBNET, and
// "tidying" them to match it -- 10.96.0.53 for a 10.96.0.0/22 network, which is
// what they were until 2026-08-26 and which reads as neat -- is what broke this
// test live. A private DNS server MAY NOT sit inside its own network's subnet:
// the API refuses it with 400 {"message":"Invalid IP address"} for an address
// that is perfectly well-formed. Measured three ways on one network,
// API-FINDINGS.md 1.38. Note what the error says: "Invalid IP address" sends you
// to check your TYPING when the problem is your ADDRESSING, which is the whole
// reason this comment exists.
//
// THE FIRST SERVER IS THE LEXICALLY LARGER ADDRESS, AND THAT IS THE POINT.
// 10.200.1.53 is sent at index 0 and 10.200.0.53 at index 1, so the pair is
// DESCENDING. Until 2026-08-26 it was ascending, and an ascending pair makes
// every positional assertion below pass just as well against a server that
// SORTS `servers` -- mutation-proven: sorting the flattener left the entire
// offline suite green. `servers` is documented as priority-ordered, so a
// silent reordering changes which DNS server the tenant consults first. With
// the pair descending, a sorting or reordering server moves index 0 and this
// test goes red. The differing is_tls values (false at index 0, true at
// index 1) independently catch a reversal and a dropped field. Do not
// "tidy" these back into numeric order.
//
// 10.200.x satisfies every constraint at once: it is RFC1918 private, outside
// this network's own 10.96.0.0/22, outside the region test's 10.97.0.0/22 so the
// two tests cannot interfere, and outside the two probe networks that live on the
// test tenant (10.254.0.0/16 and 10.255.0.0/16). The two addresses differ because
// the step-6 assertions are positional and carry different is_tls values.
const (
	testAccEnhancedNetworkPrivateDNSSubnet = "10.96.0.0/22"
	// DESCENDING ON PURPOSE -- .1 BEFORE .0. See the paragraph above.
	testAccEnhancedNetworkPrivateDNSServer = "10.200.1.53"
	testAccEnhancedNetworkPrivateDNSTLSSrv = "10.200.0.53"
)

var randNameEnhancedNetworkPrivateDNS = randStringBytesRmndr()

/*
TestAccEnhancedNetworkPrivateDNS_basic covers test-plan rows EPD-01 (apply, then
an empty re-plan), EPD-03 (flip `enabled` in place), EPD-I01 (import by network
id) and the LIVE half of decision D9 (destroy leaves the setting in force).

IT DOES NOT ASSUME A CLEAN TENANT, and that is a deliberate constraint rather than
a nicety. The test tenant currently holds two probe networks left over from
Phase 5's measurement run, and ONE OF THEM ALREADY HAS PRIVATE DNS ENABLED. So:

  - it creates its OWN enhanced network and touches nothing else, which is what
    makes the starting state known ({"enabled": false} -- API-FINDINGS.md 1.31
    measured a fresh network reading back as exactly that);
  - nothing here asserts a tenant-wide count, lists networks, or reads a network
    it did not create. An assertion of the form "no network has private DNS" would
    fail on this tenant today and would be measuring the tenant rather than the
    provider.

The region comes from the checkpointsase_enhanced_regions data source rather than
from CHECKPOINT_SASE_TEST_REGION_ID, and testAccPreCheckRegion is deliberately NOT
called: enhanced networks draw from a different region catalogue from the standard
resources, so the standard region id is not a valid harmony_sase_region_id here.
This mirrors testAccDataSourceEnhancedNetworkScopedConfig, which is the fixture
shape this reuses.

WHAT EACH STEP IS FOR, because eight steps on one 10-to-15-minute network needs
justifying. THE ORDER IS LOAD-BEARING: step 1 has to be the first write this
network ever receives, and step 2 has to follow it immediately, or neither proves
what it is here to prove.

 1. `enabled = false` with NO attributes block, as the FIRST apply on a fresh
    network. This is the only place the provider's synthesised empty arrays are
    exercised: PUTting back the {"enabled": false} that a never-configured network
    reads as is a 422, so the provider has to send
    {"servers": [], "searchDomains": []} for a configuration that names neither.
    If the expander ever stopped doing that, this step is the 422. It also asserts
    `attributes.# = 1` afterwards -- the live half of the two-shapes finding below.
 2. The SAME configuration, re-planned. This is the live twin of
    TestEnhancedNetworkPrivateDNSDisablingDoesNotDiffForever, and it only works
    directly after step 1. THERE ARE TWO DISABLED READ SHAPES: a never-configured
    network reads back as {"enabled":false} with `attributes` ABSENT, and a network
    that has been explicitly disabled reads back with `attributes` PRESENT and
    empty (both measured 2026-08-26; API-FINDINGS.md 1.31 recorded only the first).
    So step 1 changes what step 2 sees, and with `attributes` Optional-only this
    step is a permanent diff -- every plan proposing a change, every apply re-PUTting
    the same body. Making it Computed is the fix; this is the assertion that the fix
    is still in place.
 3. The dns_policy shape. API-FINDINGS.md 1.34 has now measured this endpoint with
    a dns_policy -- a full policy PUT and read back intact, `publicFallback: false`
    included -- so this step exercises a shape the API is known to accept, through
    the provider's own expander and flattener. A failure here is therefore more
    likely a provider defect than an API surprise, which is the opposite of what
    this comment said before 1.34 was measured. If the server canonicalises the
    policy the way 1.15 found elsewhere, step 4 is where it shows.
 4. An empty re-plan over the dns_policy shape, for exactly that reason.
 5. Import by network id, verified against the state the apply produced. Both sides
    come from the same Read, so any difference is an importer defect.
 6. The MEASURED shape: two servers with different is_tls, two search domains in
    deliberately non-alphabetical order, and NO dns_policy block. Two things at
    once. The order assertions are the live proof that TypeList (not TypeSet) is
    right -- API-FINDINGS.md 1.31 measured this exact write round-tripping
    byte-exactly, and a set would sort b.example.com after a.example.com. And
    dropping dns_policy must CLEAR it, which is the check that `attributes` being
    Computed did not leak into the nested blocks: those are still Optional-only, so
    the full-replacement semantics survive where a schema can express them.
 7. An empty re-plan over that shape.
 8. THE LIVE HALF OF D9. The private-DNS resource is removed from the configuration
    while the network stays, so Terraform destroys the resource alone and the
    network is still there to be read. The check then GETs the network's private DNS
    directly and asserts it is STILL enabled with the two servers step 6 wrote.

Step 8 exists because CheckDestroy cannot do this job here. A full destroy removes
the network too, and Terraform destroys in reverse dependency order -- private DNS
first, then its parent -- so by the time CheckDestroy runs the network is gone and
the GET is a 404 no matter what Delete did. Removing only the resource from the
configuration is the only way to observe "the claim was released and the setting
stayed", which is the entire content of D9.
*/
func TestAccEnhancedNetworkPrivateDNS_basic(t *testing.T) {
	t.Parallel()

	const (
		network    = "checkpointsase_enhanced_network.pdns"
		privateDNS = "checkpointsase_enhanced_network_private_dns.pdns"
	)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckEnhancedNetworkPrivateDNSDestroyRemovedTheResource,
		Steps: []resource.TestStep{
			// 1. The first write this network ever receives: enabled = false with
			//    no attributes block. See the doc comment -- this is the only step
			//    that exercises the synthesised empty arrays.
			{
				Config: testAccEnhancedNetworkPrivateDNSConfigDisabled(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(privateDNS, "network_id", network, "id"),
					// The id IS the network id -- no digest, no timestamp.
					resource.TestCheckResourceAttrPair(privateDNS, "id", network, "id"),
					resource.TestCheckResourceAttr(privateDNS, "enabled", "false"),
					// THE LIVE HALF OF THE TWO-SHAPES FINDING. The configuration
					// names no attributes block; the API returns one anyway once
					// anything has been written, and this is that assertion. If
					// this ever reads 0, the server has changed behaviour and
					// `attributes` no longer needs to be Computed.
					resource.TestCheckResourceAttr(privateDNS, "attributes.#", "1"),
					resource.TestCheckResourceAttr(privateDNS, "attributes.0.servers.#", "0"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.search_domains.#", "0"),
				),
			},
			// 2. The same configuration re-planned, immediately after step 1.
			//    With `attributes` Optional-only this is a permanent diff.
			{
				Config:   testAccEnhancedNetworkPrivateDNSConfigDisabled(),
				PlanOnly: true,
			},
			// 3. The dns_policy shape -- unmeasured, see the doc comment.
			{
				Config: testAccEnhancedNetworkPrivateDNSConfigWithPolicy(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(privateDNS, "enabled", "true"),
					resource.TestCheckResourceAttr(privateDNS, "attributes.0.servers.#", "1"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.dns_policy.#", "1"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.dns_policy.0.public.0.domains.#", "2"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.dns_policy.0.public.0.domains.0", "public-b.example.com"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.dns_policy.0.public.0.domains.1", "public-a.example.com"),
					// mode is asserted with its exact casing. The API does not
					// fold case on this enum, which is why the schema validates
					// case-sensitively; a server that echoed "matchpattern" would
					// diff forever and this is where that shows.
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.dns_policy.0.private.0.mode", "matchPattern"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.dns_policy.0.private.0.public_fallback", "true"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.dns_policy.0.private.0.domains.#", "1"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.dns_policy.0.private.0.domains.0", "private.example.com"),
				),
			},
			// 4. The dns_policy shape must also re-plan empty.
			{
				Config:   testAccEnhancedNetworkPrivateDNSConfigWithPolicy(),
				PlanOnly: true,
			},
			// 5. EPD-I01: import by network id.
			{
				ResourceName:      privateDNS,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// 6. EPD-01/EPD-03: the measured shape, and dns_policy cleared by
			//    omission.
			{
				Config: testAccEnhancedNetworkPrivateDNSConfigMeasured(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(privateDNS, "enabled", "true"),
					// The id must NOT have changed across any of these steps:
					// there is no ForceNew candidate on a singleton bar its
					// address, and network_id never changed.
					resource.TestCheckResourceAttrPair(privateDNS, "id", network, "id"),
					resource.TestCheckResourceAttr(privateDNS, "attributes.0.servers.#", "2"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.servers.0.address", testAccEnhancedNetworkPrivateDNSServer),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.servers.0.is_tls", "false"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.servers.1.address", testAccEnhancedNetworkPrivateDNSTLSSrv),
					// is_tls true on the SECOND entry only: a flattener that
					// dropped the field would still pass on the first.
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.servers.1.is_tls", "true"),
					// Non-alphabetical, and asserted BY INDEX. This is what a
					// TypeSet would break.
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.search_domains.#", "2"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.search_domains.0", "b.example.com"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.search_domains.1", "a.example.com"),
					// dns_policy was in the configuration at step 3 and is not in
					// this one, so the full replacement must have CLEARED it.
					// This is the check that `attributes` being Computed did not
					// leak into the nested blocks.
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.dns_policy.#", "0"),
				),
			},
			// 7. EPD-01: the second plan over the measured shape must be empty.
			{
				Config:   testAccEnhancedNetworkPrivateDNSConfigMeasured(),
				PlanOnly: true,
			},
			// 8. The live half of D9: remove the resource, keep the network.
			{
				Config: testAccEnhancedNetworkPrivateDNSConfigNetworkOnly(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedNetworkPrivateDNSGone(privateDNS),
					testAccCheckEnhancedNetworkPrivateDNSSurvived(network),
				),
			},
		},
	})
}

/*
testAccCheckEnhancedNetworkPrivateDNSGone asserts Terraform has stopped tracking
the private-DNS resource.

Paired with the check below rather than used alone: on its own it is satisfied by
a Delete that made no request AND by one that rewrote the network, because both
remove the resource from state. It is here so that a failure of the survival
check cannot be explained away as "the resource was never destroyed".
*/
func testAccCheckEnhancedNetworkPrivateDNSGone(address string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if _, ok := s.RootModule().Resources[address]; ok {
			return fmt.Errorf("%s is still in state after being removed from the configuration, "+
				"so this step did not exercise Delete at all", address)
		}
		return nil
	}
}

/*
testAccCheckEnhancedNetworkPrivateDNSSurvived is the live evidence for decision
D9: destroying the resource released Terraform's claim and left the network's
private DNS exactly as it was.

The offline test TestEnhancedNetworkPrivateDNSDeleteMakesNoRequest already pins
that Delete issues zero requests, by counting them against an httptest server.
What it cannot show is the CONSEQUENCE -- that a live network is still resolving
names the way the last apply configured it once Terraform has stopped managing
the setting. This reads the network directly and asserts exactly that.

It asserts on `enabled` AND on the servers, because "still enabled with no
servers" is not a state the API can hold (servers must be non-empty when enabled
is true) and would mean something else had happened.

  - @param networkAddress string - the enhanced network resource's address in state

@return resource.TestCheckFunc
*/
func testAccCheckEnhancedNetworkPrivateDNSSurvived(networkAddress string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[networkAddress]
		if !ok {
			return fmt.Errorf("%s is not in state, so there is no network to read", networkAddress)
		}
		networkId := rs.Primary.ID
		if networkId == "" {
			return fmt.Errorf("%s holds no id", networkAddress)
		}

		customDns, _, err := getEnhancedNetworkPrivateDNS(
			context.Background(), testAccEnvClient(), networkId)
		if err != nil {
			return fmt.Errorf("reading network %s private DNS after the resource was destroyed: %w",
				networkId, err)
		}

		if !customDns.GetEnabled() {
			return fmt.Errorf("network %s has private DNS DISABLED after the Terraform resource "+
				"was destroyed, and it was enabled before. Destroy must make NO API call at all "+
				"(D9): turning off a live network's private DNS because somebody removed a "+
				"Terraform resource is exactly the outcome that decision exists to prevent",
				networkId)
		}
		attributes := customDns.Attributes
		if attributes == nil || len(attributes.Servers) != 2 {
			return fmt.Errorf("network %s no longer holds the two DNS servers the last apply "+
				"wrote (attributes = %+v). Destroy must leave the configuration untouched",
				networkId, attributes)
		}
		if got := attributes.Servers[0].GetAddress(); got != testAccEnhancedNetworkPrivateDNSServer {
			return fmt.Errorf("network %s servers[0].address is %q after destroy, want %q -- "+
				"something rewrote the configuration", networkId, got,
				testAccEnhancedNetworkPrivateDNSServer)
		}
		return nil
	}
}

/*
testAccCheckEnhancedNetworkPrivateDNSDestroyRemovedTheResource is all CheckDestroy
can honestly assert here, and the limitation is worth stating rather than working
around.

The full destroy removes the enhanced network as well, and Terraform destroys in
reverse dependency order -- private DNS first, then its parent -- so by the time
this runs the network is gone and a GET on its private DNS is a 404 whatever
Delete did. Asserting "the setting survived" here would therefore be asserting
nothing, or worse, would fail for the right reason and be silenced by somebody.
Step 8 of the test is where that assertion lives instead.
*/
func testAccCheckEnhancedNetworkPrivateDNSDestroyRemovedTheResource(s *terraform.State) error {
	for address, rs := range s.RootModule().Resources {
		if rs.Type == "checkpointsase_enhanced_network_private_dns" {
			return fmt.Errorf("%s is still in state after destroy", address)
		}
	}
	return nil
}

/*
testAccEnhancedNetworkPrivateDNSNetwork is the one enhanced network every step
shares, and it is the only thing this test creates.

The region is taken from the checkpointsase_enhanced_regions catalogue rather than
from CHECKPOINT_SASE_TEST_REGION_ID, because enhanced networks and standard
networks draw from different catalogues on this tenant -- the standard region id
is not a valid harmony_sase_region_id here. Same reasoning, same shape, as
testAccDataSourceEnhancedNetworkScopedConfig.
*/
func testAccEnhancedNetworkPrivateDNSNetwork() string {
	return fmt.Sprintf(`
data "checkpointsase_enhanced_regions" "pdns" {}

locals {
  pdns_region = data.checkpointsase_enhanced_regions.pdns.regions[0]
}

resource "checkpointsase_enhanced_network" "pdns" {
  name   = "qa-pdns-enh-net-%[1]s"
  subnet = "%[2]s"
  tags   = ["qa-pdns"]

  region {
    harmony_sase_region_id = local.pdns_region.id
    scale_units            = 1
    idle                   = true
  }
}
`, randNameEnhancedNetworkPrivateDNS, testAccEnhancedNetworkPrivateDNSSubnet)
}

// testAccEnhancedNetworkPrivateDNSConfigNetworkOnly is the network with NO
// private-DNS resource, used by the last step to destroy the resource alone.
func testAccEnhancedNetworkPrivateDNSConfigNetworkOnly() string {
	return testAccEnhancedNetworkPrivateDNSNetwork()
}

/*
testAccEnhancedNetworkPrivateDNSConfigMeasured is the shape API-FINDINGS.md 1.31
measured round-tripping byte-exactly.

The two search domains are in deliberately NON-ALPHABETICAL order, matching the
probe: b before a. That is the point of them, not an accident -- the finding is
that the API returned them in the order sent, which is why these are TypeList and
why the assertions in step 1 are by index.

The two servers carry DIFFERENT is_tls values, so a flattener that dropped the
field cannot pass by accident on a single row.

It carries NO dns_policy, which step 6 asserts cleared the one step 3 wrote.
*/
func testAccEnhancedNetworkPrivateDNSConfigMeasured() string {
	return testAccEnhancedNetworkPrivateDNSNetwork() + fmt.Sprintf(`
resource "checkpointsase_enhanced_network_private_dns" "pdns" {
  network_id = checkpointsase_enhanced_network.pdns.id
  enabled    = true

  attributes {
    servers {
      address = %[1]q
      is_tls  = false
    }
    servers {
      address = %[2]q
      is_tls  = true
    }

    search_domains = ["b.example.com", "a.example.com"]
  }
}
`, testAccEnhancedNetworkPrivateDNSServer, testAccEnhancedNetworkPrivateDNSTLSSrv)
}

/*
testAccEnhancedNetworkPrivateDNSConfigWithPolicy adds a dns_policy and DROPS
search_domains.

A dns_policy HAS now been measured on this endpoint. P8 and P8b carried `servers`
and `searchDomains` only, but API-FINDINGS.md 1.34 (2026-08-26) PUT a full policy
and read it back intact -- `public.domains` and `private.{mode, publicFallback,
domains}`, with `publicFallback` present and explicitly `false` -- and both
CustomDns and CustomDnsResponse decoded it through the real generated types. So
this step is no longer the first exercise of the shape; it is the first exercise
of it THROUGH THE PROVIDER, which is still worth having because the flattener and
the expander sit between the operator and that body.

It drops search_domains, which step 6 then adds back while dropping dns_policy.
Between them the two steps show the full replacement working in both directions on
the nested blocks -- which is the part `attributes` being Computed must NOT have
changed, and step 6 is where that is asserted.
*/
func testAccEnhancedNetworkPrivateDNSConfigWithPolicy() string {
	return testAccEnhancedNetworkPrivateDNSNetwork() + fmt.Sprintf(`
resource "checkpointsase_enhanced_network_private_dns" "pdns" {
  network_id = checkpointsase_enhanced_network.pdns.id
  enabled    = true

  attributes {
    servers {
      address = %[1]q
      is_tls  = false
    }

    dns_policy {
      public {
        domains = ["public-b.example.com", "public-a.example.com"]
      }
      private {
        mode            = "matchPattern"
        public_fallback = true
        domains         = ["private.example.com"]
      }
    }
  }
}
`, testAccEnhancedNetworkPrivateDNSServer)
}

/*
testAccEnhancedNetworkPrivateDNSConfigDisabled is the "off" configuration, written
the way an operator would: enabled = false and no attributes block at all.

IT IS STEP 1 ON PURPOSE, and moving it later would quietly stop it testing
anything. It is the only step that reaches the expander's synthesised empty
arrays, and it reaches them only while `attributes` is empty in BOTH the
configuration and the state -- which is true of the first write to a fresh network
and of nothing else. Once anything has been written, `attributes` is Computed and
carries the previous value forward, so a later `enabled = false` step would send
the servers it inherited rather than `[]`.

What it catches there: the read of a never-configured network is {"enabled": false}
and PUTting that same body back is a 422 (API-FINDINGS.md 1.31), so the provider
must synthesise {"servers": [], "searchDomains": []} for a configuration that names
neither. If it ever stopped, this step is the 422.
*/
func testAccEnhancedNetworkPrivateDNSConfigDisabled() string {
	return testAccEnhancedNetworkPrivateDNSNetwork() + `
resource "checkpointsase_enhanced_network_private_dns" "pdns" {
  network_id = checkpointsase_enhanced_network.pdns.id
  enabled    = false
}
`
}
