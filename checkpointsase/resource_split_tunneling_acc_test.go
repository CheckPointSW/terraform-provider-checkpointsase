package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
The one ACCEPTANCE test for checkpointsase_split_tunneling.

This file holds the only TestAcc-prefixed name for this resource, and it is
genuinely an acceptance test: resource.Test skips it unless TF_ACC=1, and it
creates and destroys a real network. Every other test for this resource is offline
and lives in resource_split_tunneling_test.go under a name that says what it does.
Phase 4 shipped 21 offline tests wearing the TestAcc prefix, which reads in the
summary as 21 skipped acceptance tests and as zero offline coverage.
*/

// The exception CIDRs this test writes. They are destinations in a split-tunnelling
// exception list, not network subnets, so they cannot collide with another
// acceptance test's network -- but they are deliberately NOT 10.99.0.0/16, which
// is what the leftover probe network's configuration holds (LEFTOVERS.md L33), so
// that nothing here can be confused with that state while reading a failure.
const (
	testAccSplitTunnelingCidr      = "10.97.0.0/24"
	testAccSplitTunnelingCidrExtra = "10.97.1.0/24"
)

var randNameSplitTunneling = randStringBytesRmndr()

/*
TestAccSplitTunneling_basic covers test-plan rows SPT-01 (apply, then an empty
re-plan), SPT-02 (the re-plan itself), SPT-I01 (import by network id) and the LIVE
half of decision D9 (destroy leaves the setting in force).

WHICH NETWORK IT USES, AND WHY IT IS A STANDARD ONE. Probe P1 measured this
endpoint on 2026-08-26 against BOTH families and got byte-identical bodies and
accepted writes on each, so the resource is family-agnostic and the test does not
have to pick a family to prove anything. It therefore builds the STANDARD network
fixture the suite already uses in ten other acceptance tests
(`checkpointsase_network` with one region from CHECKPOINT_SASE_TEST_REGION_ID)
rather than an enhanced one, because a standard network is the cheaper of the two
to create and this test is not about networks. No subnet is named, so the server
assigns one and no acceptance test can collide with another over it.

IT DOES NOT ASSUME A CLEAN TENANT, and that is a deliberate constraint rather than
a nicety. The test tenant holds two probe networks left over from Phase 5's
measurement run, and the STANDARD one is in `out_of_tunnel` HOLDING A SAVED
EXCEPTION THAT CANNOT BE DELETED through the v3 API (API-FINDINGS.md 1.29,
LEFTOVERS.md L33). So:

  - this test creates its OWN network and touches nothing else, which is what makes
    the starting state knowable;
  - nothing here asserts a tenant-wide count, lists networks, or reads a network it
    did not create. An assertion of the form "no network has an exception" would
    fail on this tenant today and would be measuring the tenant rather than the
    provider;
  - the `exceptions.# = 0` assertions below are about THIS network only, and they
    are meaningful precisely because `exceptions` is Computed-only: the resource
    cannot create one, so a network it built can never have one.

WHAT EACH STEP IS FOR. THE ORDER IS LOAD-BEARING for steps 1 and 2.

 1. SPT-01: `out_of_tunnel` with one `cidr` entry, applied to a network that has
    never had its split tunnelling written. The API answers 202 and the provider
    polls to completion before reading back, so a read-back that ran early would
    store the network's ORIGINAL mode here.
 2. SPT-02: the SAME configuration, re-planned. This is the live twin of
    TestSplitTunnelingDoesNotDiffForever, and it only works directly after step 1 --
    it is the first plan after the first apply, which is the only place a
    canonicalisation or read-shape mismatch shows.
 3. Flip to `via_tunnel` with `except_data {}`. Two things at once: the mode change
    is a real update through the same async path, and the empty block must CLEAR
    the `cidr` step 1 wrote, because those three lists are a full replacement.
 4. An empty re-plan over the via_tunnel shape.
 5. Back to `out_of_tunnel` with TWO cidr entries, asserted BY INDEX in the order
    written. That assertion is now backed by a measurement rather than by caution:
    API-FINDINGS.md 1.31 sent three cidr entries deliberately non-ascending and got
    them back in the order sent, so `cidr` is known to preserve order on an
    ENHANCED network. This step is the STANDARD-family half of the same question,
    which that probe did not cover -- so it is still the place a sorting or
    deduplicating server surfaces, rather than a customer's plan.
 6. An empty re-plan over that shape.
 7. SPT-I01: import by network id, verified against the state the apply produced.
    Both sides come from the same Read, so any difference is an importer defect.
 8. THE LIVE HALF OF D9. The split-tunnelling resource is removed from the
    configuration while the network stays, so Terraform destroys the resource alone
    and the network is still there to be read. The check then GETs the network's
    split tunnelling directly and asserts it is STILL `out_of_tunnel` with the two
    CIDRs step 5 wrote.

Step 8 exists because CheckDestroy cannot do this job here. A full destroy removes
the network too, and Terraform destroys in reverse dependency order -- split
tunnelling first, then its parent -- so by the time CheckDestroy runs the network
is gone and the GET is a 404 no matter what Delete did. Removing only the resource
from the configuration is the only way to observe "the claim was released and the
setting stayed", which is the entire content of D9.

WHAT THIS TEST CANNOT COVER, and it is not an oversight. `except_data.exceptions`
is Computed-only (D5), so no configuration here can create an exception, and there
is no v3 call that removes one -- so the exception lifecycle is unreachable from
Terraform in both directions and there is nothing for an acceptance step to
exercise. Every assertion on it below is therefore `0`. If L33 is ever resolved,
this is the test that grows a step.
*/
func TestAccSplitTunneling_basic(t *testing.T) {
	t.Parallel()

	const (
		network        = "checkpointsase_network.spt"
		splitTunneling = "checkpointsase_split_tunneling.spt"
	)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t); testAccPreCheckRegion(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckSplitTunnelingDestroyRemovedTheResource,
		Steps: []resource.TestStep{
			// 1. SPT-01: the first split-tunnelling write this network receives.
			{
				Config: testAccSplitTunnelingConfigOutOfTunnel(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(splitTunneling, "network_id", network, "id"),
					// The id IS the network id -- no digest, no separator, no
					// timestamp.
					resource.TestCheckResourceAttrPair(splitTunneling, "id", network, "id"),
					resource.TestCheckResourceAttr(splitTunneling,
						"default_tunneling_mode", "out_of_tunnel"),
					resource.TestCheckResourceAttr(splitTunneling, "except_data.#", "1"),
					resource.TestCheckResourceAttr(splitTunneling,
						"except_data.0.cidr.#", "1"),
					resource.TestCheckResourceAttr(splitTunneling,
						"except_data.0.cidr.0", testAccSplitTunnelingCidr),
					resource.TestCheckResourceAttr(splitTunneling,
						"except_data.0.address_object_ids.#", "0"),
					resource.TestCheckResourceAttr(splitTunneling,
						"except_data.0.updatable_object_ids.#", "0"),
					// This network cannot have an exception: the resource cannot
					// create one and nothing else has touched it.
					resource.TestCheckResourceAttr(splitTunneling,
						"except_data.0.exceptions.#", "0"),
				),
			},
			// 2. SPT-02: the same configuration re-planned, immediately after
			//    step 1. The first plan after the first apply.
			{
				Config:   testAccSplitTunnelingConfigOutOfTunnel(),
				PlanOnly: true,
			},
			// 3. Flip the mode, and clear the cidr list by writing the block
			//    empty.
			{
				Config: testAccSplitTunnelingConfigViaTunnel(),
				Check: resource.ComposeTestCheckFunc(
					// The id must NOT have changed: network_id is the only
					// ForceNew attribute and it did not change.
					resource.TestCheckResourceAttrPair(splitTunneling, "id", network, "id"),
					resource.TestCheckResourceAttr(splitTunneling,
						"default_tunneling_mode", "via_tunnel"),
					// The full replacement must have cleared what step 1 wrote.
					resource.TestCheckResourceAttr(splitTunneling,
						"except_data.0.cidr.#", "0"),
					resource.TestCheckResourceAttr(splitTunneling,
						"except_data.0.exceptions.#", "0"),
				),
			},
			// 4. An empty re-plan over the via_tunnel shape.
			{
				Config:   testAccSplitTunnelingConfigViaTunnel(),
				PlanOnly: true,
			},
			// 5. Two destinations, asserted BY INDEX. See the doc comment: this
			//    is where a server that sorts or deduplicates would show.
			{
				Config: testAccSplitTunnelingConfigTwoDestinations(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(splitTunneling,
						"default_tunneling_mode", "out_of_tunnel"),
					resource.TestCheckResourceAttr(splitTunneling,
						"except_data.0.cidr.#", "2"),
					resource.TestCheckResourceAttr(splitTunneling,
						"except_data.0.cidr.0", testAccSplitTunnelingCidr),
					resource.TestCheckResourceAttr(splitTunneling,
						"except_data.0.cidr.1", testAccSplitTunnelingCidrExtra),
				),
			},
			// 6. An empty re-plan over that shape.
			{
				Config:   testAccSplitTunnelingConfigTwoDestinations(),
				PlanOnly: true,
			},
			// 7. SPT-I01: import by network id.
			{
				ResourceName:      splitTunneling,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// 8. The live half of D9: remove the resource, keep the network.
			{
				Config: testAccSplitTunnelingConfigNetworkOnly(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSplitTunnelingGone(splitTunneling),
					testAccCheckSplitTunnelingSurvived(network),
				),
			},
		},
	})
}

/*
testAccCheckSplitTunnelingGone asserts Terraform has stopped tracking the
split-tunnelling resource.

Paired with the check below rather than used alone: on its own it is satisfied by
a Delete that made no request AND by one that rewrote the network, because both
remove the resource from state. It is here so that a failure of the survival check
cannot be explained away as "the resource was never destroyed".
*/
func testAccCheckSplitTunnelingGone(address string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if _, ok := s.RootModule().Resources[address]; ok {
			return fmt.Errorf("%s is still in state after being removed from the configuration, "+
				"so this step did not exercise Delete at all", address)
		}
		return nil
	}
}

/*
testAccCheckSplitTunnelingSurvived is the live evidence for decision D9:
destroying the resource released Terraform's claim and left the network's split
tunnelling exactly as it was.

The offline test TestSplitTunnelingDeleteMakesNoRequest already pins that Delete
issues zero requests, by counting them against an httptest server. What it cannot
show is the CONSEQUENCE -- that a live network is still routing traffic the way the
last apply configured it once Terraform has stopped managing the setting. This
reads the network directly and asserts exactly that.

It asserts on the MODE AND on the destinations. Mode alone is not enough: a Delete
that wrote `out_of_tunnel` with three empty arrays would leave the mode intact and
silently pull every excepted destination back into the tunnel, which is the same
class of silent traffic change D9 exists to prevent.

  - @param networkAddress string - the network resource's address in state

@return resource.TestCheckFunc
*/
func testAccCheckSplitTunnelingSurvived(networkAddress string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[networkAddress]
		if !ok {
			return fmt.Errorf("%s is not in state, so there is no network to read", networkAddress)
		}
		networkId := rs.Primary.ID
		if networkId == "" {
			return fmt.Errorf("%s holds no id", networkAddress)
		}

		splitTunneling, _, err := getSplitTunneling(
			context.Background(), testAccEnvClient(), networkId)
		if err != nil {
			return fmt.Errorf("reading network %s split tunnelling after the resource was "+
				"destroyed: %w", networkId, err)
		}

		if got := splitTunneling.GetDefaultTunnelingMode(); got != "out_of_tunnel" {
			return fmt.Errorf("network %s is in %q after the Terraform resource was destroyed, "+
				"and it was out_of_tunnel before. Destroy must make NO API call at all (D9): "+
				"changing which of a live network's traffic bypasses the tunnel because somebody "+
				"removed a Terraform resource is exactly the outcome that decision exists to "+
				"prevent", networkId, got)
		}
		cidr := splitTunneling.ExceptData.GetCidr()
		if len(cidr) != 2 {
			return fmt.Errorf("network %s holds %v after destroy, want the two destinations the "+
				"last apply wrote. A destroy that emptied the lists would leave the MODE intact "+
				"and still pull every excepted destination back into the tunnel", networkId, cidr)
		}
		if cidr[0] != testAccSplitTunnelingCidr || cidr[1] != testAccSplitTunnelingCidrExtra {
			return fmt.Errorf("network %s holds %v after destroy, want [%s %s] -- something "+
				"rewrote the configuration", networkId, cidr,
				testAccSplitTunnelingCidr, testAccSplitTunnelingCidrExtra)
		}
		return nil
	}
}

/*
testAccCheckSplitTunnelingDestroyRemovedTheResource is all CheckDestroy can
honestly assert here, and the limitation is worth stating rather than working
around.

The full destroy removes the network as well, and Terraform destroys in reverse
dependency order -- split tunnelling first, then its parent -- so by the time this
runs the network is gone and a GET on its split tunnelling is a 404 whatever Delete
did. Asserting "the setting survived" here would therefore be asserting nothing,
or worse, would fail for the right reason and be silenced by somebody. Step 8 of
the test is where that assertion lives instead.
*/
func testAccCheckSplitTunnelingDestroyRemovedTheResource(s *terraform.State) error {
	for address, rs := range s.RootModule().Resources {
		if rs.Type == "checkpointsase_split_tunneling" {
			return fmt.Errorf("%s is still in state after destroy", address)
		}
	}
	return nil
}

/*
testAccSplitTunnelingNetwork is the one network every step shares, and it is the
only thing this test creates.

It is the STANDARD network fixture the suite already uses -- the same shape as
testAccNetworkConfig, region from CHECKPOINT_SASE_TEST_REGION_ID -- because probe
P1 showed this endpoint behaves identically on both families, so the cheaper one is
the right one. NO SUBNET IS NAMED: `network.subnet` is Optional+Computed and the
server assigns one when it is omitted, which is what keeps this test from being
able to collide with another acceptance test's subnet.

The region is left `idle = true`, matching every other network fixture here: this
test never sends traffic, and an active region costs scale units.
*/
func testAccSplitTunnelingNetwork() string {
	return fmt.Sprintf(`
resource "checkpointsase_network" "spt" {
  network {
    name = "qa-spt-%[1]s"
    tags = ["qa-spt"]
  }

  region {
    cpregion_id = %[2]q
    idle        = true
  }
}
`, randNameSplitTunneling, testAccRegionID())
}

// testAccSplitTunnelingConfigNetworkOnly is the network with NO split-tunnelling
// resource, used by the last step to destroy the resource alone.
func testAccSplitTunnelingConfigNetworkOnly() string {
	return testAccSplitTunnelingNetwork()
}

/*
testAccSplitTunnelingConfigOutOfTunnel is SPT-01's configuration: only the named
destination is tunnelled.

`address_object_ids` and `updatable_object_ids` are deliberately OMITTED rather
than written as `[]`. That is the interesting half: the API requires all three keys
on the wire even when empty (API-FINDINGS.md 1.31), so this configuration is a live
exercise of the arrays the provider synthesises. If expandSplitTunneling ever
stopped sending them, this step is the 400.
*/
func testAccSplitTunnelingConfigOutOfTunnel() string {
	return testAccSplitTunnelingNetwork() + fmt.Sprintf(`
resource "checkpointsase_split_tunneling" "spt" {
  network_id             = checkpointsase_network.spt.id
  default_tunneling_mode = "out_of_tunnel"

  except_data {
    cidr = [%[1]q]
  }
}
`, testAccSplitTunnelingCidr)
}

/*
testAccSplitTunnelingConfigViaTunnel flips the mode and writes `except_data`
EMPTY.

`except_data {}` rather than no block at all, because the block is Required -- and
the empty block is the shape that has to clear the `cidr` step 1 wrote. Every
internet destination goes through the tunnel in this configuration.
*/
func testAccSplitTunnelingConfigViaTunnel() string {
	return testAccSplitTunnelingNetwork() + `
resource "checkpointsase_split_tunneling" "spt" {
  network_id             = checkpointsase_network.spt.id
  default_tunneling_mode = "via_tunnel"

  except_data {}
}
`
}

/*
testAccSplitTunnelingConfigTwoDestinations writes two destinations, and their ORDER
is the point.

MEASURED, AND NARROWLY. API-FINDINGS.md 1.31 sent three cidr entries in
deliberately non-ascending order -- "10.80.0.0/16", "10.10.0.0/16", "10.50.0.0/16"
-- and read them back unchanged, so a sorting server would have put 10.80 last and
did not. That settles `cidr` on an ENHANCED network and nothing else: the other two
exceptData arrays were sent EMPTY in that probe, and the STANDARD family -- which
is what this test builds -- was not covered at all.

So the index assertions in step 5 do two jobs at once. For `cidr` they are a
regression check on behaviour that has been measured. For the standard family they
are still the open question, and if the API sorts or deduplicates here, this is the
step that fails and the answer is a finding rather than a code change. TypeList is
right under either outcome, which is why it did not wait for the probe.
*/
func testAccSplitTunnelingConfigTwoDestinations() string {
	return testAccSplitTunnelingNetwork() + fmt.Sprintf(`
resource "checkpointsase_split_tunneling" "spt" {
  network_id             = checkpointsase_network.spt.id
  default_tunneling_mode = "out_of_tunnel"

  except_data {
    cidr = [%[1]q, %[2]q]
  }
}
`, testAccSplitTunnelingCidr, testAccSplitTunnelingCidrExtra)
}
