package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
The one ACCEPTANCE test for checkpointsase_enhanced_region_private_dns.

This file holds the only TestAcc-prefixed name for this resource, and it is
genuinely an acceptance test: resource.Test skips it unless TF_ACC=1, and it
creates and destroys a real enhanced network. Every other test for this resource
is offline and lives in resource_enhanced_region_private_dns_test.go under a name
that says what it does. Phase 4 shipped 21 offline tests wearing the TestAcc
prefix, which reads in the summary as 21 skipped acceptance tests and as zero
offline coverage.

THIS IS THE FIRST THING THAT WILL EVER TOUCH THE REGION PRIVATE-DNS ENDPOINT. No
probe in Phase 5's measurement run, or any run before it, has issued a single
request to /v3/networks/enhanced/{networkId}/regions/{regionId}/privateDNS. Every
offline test for this resource drives the shape the SPEC declares, using bodies
measured against the NETWORK path. So a failure here is INFORMATION FIRST and a
provider defect second -- read what the server actually said before changing any
code, and record it in API-FINDINGS.md 1.31, which currently describes the network
endpoint alone.
*/

// The network this test builds. 10.97.0.0/22 is chosen to avoid every subnet
// already used by an acceptance test in this package (10.90-10.96 are taken,
// 10.96.0.0/22 by TestAccEnhancedNetworkPrivateDNS_basic), because two networks
// with overlapping subnets are refused and a collision would fail whichever test
// ran second for a reason that has nothing to do with private DNS.
const (
	testAccEnhancedRegionPrivateDNSSubnet = "10.97.0.0/22"
	testAccEnhancedRegionPrivateDNSServer = "10.97.0.53"
	testAccEnhancedRegionPrivateDNSTLSSrv = "10.97.1.53"
)

var randNameEnhancedRegionPrivateDNS = randStringBytesRmndr()

/*
TestAccEnhancedRegionPrivateDNS_basic covers test-plan rows EPD-02 (apply, then an
empty re-plan), EPD-03 (flip `enabled` in place), EPD-D01 (the vanished parent, in
its live half) and EPD-I01 (import by the composite id), plus the LIVE half of
decision D9 (destroy leaves the setting in force).

THE REGION ID COMES FROM THE NETWORK'S OWN INLINE `region` BLOCK, and that is not
interchangeable with the catalogue id it was created from.
`checkpointsase_enhanced_network` takes a `harmony_sase_region_id` out of
checkpointsase_enhanced_regions and the server assigns the region its OWN id,
which is what this endpoint's path wants. `one(...region[*].id)` is how
data_source_enhanced_network_scoped_test.go already reads it, and `one` rather
than `[0]` because the region block is a set-like list of one -- `one` fails loudly
if a future change makes it two, where `[0]` would silently pick whichever came
back first.

IT CREATES ONE NETWORK, NOT TWO. The Phase 5 plan pairs EPD-01 and EPD-02 on a
single create for a reason: an enhanced network takes 10 to 15 minutes to come up,
and this fixture is the same shape as
TestAccEnhancedNetworkPrivateDNS_basic's. They are separate networks because the
two tests run in parallel (t.Parallel) and a shared one would make each depend on
the other's ordering; within THIS test, one network serves every step.

IT DOES NOT ASSUME A CLEAN TENANT, and that is a deliberate constraint rather than
a nicety. The test tenant currently holds two probe networks left over from Phase
5's measurement run, and ONE OF THEM ALREADY HAS PRIVATE DNS ENABLED. So:

  - it creates its OWN enhanced network and touches nothing else, which is what
    makes the starting state known;
  - nothing here asserts a tenant-wide count, lists networks, or reads a network
    it did not create. An assertion of the form "no region has private DNS" would
    fail on this tenant today and would be measuring the tenant rather than the
    provider.

The region comes from the checkpointsase_enhanced_regions data source rather than
from CHECKPOINT_SASE_TEST_REGION_ID, and testAccPreCheckRegion is deliberately NOT
called: enhanced networks draw from a different region catalogue from the standard
resources, so the standard region id is not a valid harmony_sase_region_id here.

WHAT EACH STEP IS FOR. THE ORDER IS LOAD-BEARING: step 1 has to be the first write
this region ever receives, and step 2 has to follow it immediately, or neither
proves what it is here to prove.

 1. `enabled = false` with NO attributes block, as the FIRST apply on a fresh
    region. This is the only place the provider's synthesised empty arrays are
    exercised: on the network path, PUTting back the {"enabled": false} that a
    never-configured object reads as is a 422, so the provider has to send
    {"servers": [], "searchDomains": []} for a configuration that names neither.
    Whether the region path agrees is UNMEASURED; if this step is a 422, that is
    the answer and it belongs in the findings. It also asserts `attributes.# = 1`
    afterwards -- the live half of the two-shapes finding, again on a path where
    only the network's behaviour has been observed.
 2. The SAME configuration, re-planned. This is the live twin of
    TestEnhancedRegionPrivateDNSDisablingDoesNotDiffForever, and it only works
    directly after step 1: step 1 changes what step 2 sees, because the API returns
    `attributes` once anything has been written. With `attributes` Optional-only
    this step is a permanent diff.
 3. The measured-on-the-network shape: two servers with different is_tls, two
    search domains in deliberately non-alphabetical order. The order assertions are
    the live proof that TypeList (not TypeSet) is right; a set would sort
    b.example.com after a.example.com.
 4. An empty re-plan over that shape.
 5. Import by the COMPOSITE id, "<network_id>:<region_id>", built in the test with
    the same separator the resource uses. ImportStateIdFunc rather than the default,
    because the default passes the resource's own id -- which would pass even if
    Create wrote an id the importer cannot parse. Building it here from the two
    state attributes is what makes this an assertion about the FORMAT.
 6. The dns_policy shape. NOTHING HAS MEASURED EITHER PRIVATE-DNS ENDPOINT WITH A
    dns_policy: P8/P8b sent servers and searchDomains only. Dropping search_domains
    at the same time means step 6 also proves the full replacement CLEARS an
    omitted nested block -- the check that `attributes` being Computed did not leak
    into the blocks nested inside it, which are still Optional-only.
 7. An empty re-plan over the dns_policy shape, for exactly that reason.
 8. THE LIVE HALF OF D9. The private-DNS resource is removed from the configuration
    while the network stays, so Terraform destroys the resource alone and the
    region is still there to be read. The check then GETs the region's private DNS
    directly and asserts it is STILL configured the way step 6 left it.

Step 8 exists because CheckDestroy cannot do this job here. A full destroy removes
the network too, and Terraform destroys in reverse dependency order -- private DNS
first, then its parent -- so by the time CheckDestroy runs the network is gone and
the GET is a 404 no matter what Delete did. Removing only the resource from the
configuration is the only way to observe "the claim was released and the setting
stayed", which is the entire content of D9.
*/
func TestAccEnhancedRegionPrivateDNS_basic(t *testing.T) {
	t.Parallel()

	const (
		network    = "checkpointsase_enhanced_network.rpdns"
		privateDNS = "checkpointsase_enhanced_region_private_dns.rpdns"
	)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckEnhancedRegionPrivateDNSDestroyRemovedTheResource,
		Steps: []resource.TestStep{
			// 1. The first write this region ever receives: enabled = false with
			//    no attributes block. See the doc comment -- this is the only step
			//    that exercises the synthesised empty arrays.
			{
				Config: testAccEnhancedRegionPrivateDNSConfigDisabled(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(privateDNS, "network_id", network, "id"),
					// The id is the COMPOSITE. Asserted as network_id + ":" +
					// region_id read back out of state, so it fails for a
					// different separator as well as for a missing half.
					testAccCheckEnhancedRegionPrivateDNSIDIsComposite(privateDNS),
					resource.TestCheckResourceAttr(privateDNS, "enabled", "false"),
					// THE LIVE HALF OF THE TWO-SHAPES FINDING, on a path where
					// only the network's behaviour has been observed. If this
					// reads 0, the region endpoint does NOT return `attributes`
					// after a write and the finding needs a region row.
					resource.TestCheckResourceAttr(privateDNS, "attributes.#", "1"),
					resource.TestCheckResourceAttr(privateDNS, "attributes.0.servers.#", "0"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.search_domains.#", "0"),
				),
			},
			// 2. The same configuration re-planned, immediately after step 1.
			//    With `attributes` Optional-only this is a permanent diff.
			{
				Config:   testAccEnhancedRegionPrivateDNSConfigDisabled(),
				PlanOnly: true,
			},
			// 3. EPD-02/EPD-03: the shape measured on the network path, and the
			//    flip of `enabled` in place.
			{
				Config: testAccEnhancedRegionPrivateDNSConfigMeasured(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(privateDNS, "enabled", "true"),
					// The id must NOT have changed across these steps: there is no
					// ForceNew candidate on a singleton bar its address, and
					// neither id changed.
					testAccCheckEnhancedRegionPrivateDNSIDIsComposite(privateDNS),
					resource.TestCheckResourceAttr(privateDNS, "attributes.0.servers.#", "2"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.servers.0.address", testAccEnhancedRegionPrivateDNSServer),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.servers.0.is_tls", "false"),
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.servers.1.address", testAccEnhancedRegionPrivateDNSTLSSrv),
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
				),
			},
			// 4. EPD-02: the second plan over that shape must be empty.
			{
				Config:   testAccEnhancedRegionPrivateDNSConfigMeasured(),
				PlanOnly: true,
			},
			// 5. EPD-I01: import by the composite id. ImportStateIdFunc builds it
			//    from state rather than reusing the resource's own id, so this is
			//    an assertion about the FORMAT and not just about the round trip.
			{
				ResourceName:      privateDNS,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccEnhancedRegionPrivateDNSImportID(privateDNS),
			},
			// 6. The dns_policy shape -- unmeasured on either endpoint -- and
			//    search_domains dropped, which the full replacement must clear.
			{
				Config: testAccEnhancedRegionPrivateDNSConfigWithPolicy(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(privateDNS, "enabled", "true"),
					resource.TestCheckResourceAttr(privateDNS, "attributes.0.servers.#", "1"),
					// search_domains was in the configuration at step 3 and is not
					// in this one, so the full replacement must have CLEARED it.
					// This is the check that `attributes` being Computed did not
					// leak into the blocks nested inside it.
					resource.TestCheckResourceAttr(privateDNS,
						"attributes.0.search_domains.#", "0"),
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
			// 7. The dns_policy shape must also re-plan empty.
			{
				Config:   testAccEnhancedRegionPrivateDNSConfigWithPolicy(),
				PlanOnly: true,
			},
			// 8. The live half of D9: remove the resource, keep the network.
			{
				Config: testAccEnhancedRegionPrivateDNSConfigNetworkOnly(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedRegionPrivateDNSGone(privateDNS),
					testAccCheckEnhancedRegionPrivateDNSSurvived(network),
				),
			},
		},
	})
}

/*
testAccCheckEnhancedRegionPrivateDNSIDIsComposite asserts the resource id is the
two address attributes joined by the separator, read back out of state.

It is not the same assertion as TestCheckResourceAttrPair against the network's
id, which is what the sibling resource can use: a region's id is a JOIN, and the
two failures that matter are a half missing and a different separator. Both are
invisible until somebody tries to import.
*/
func testAccCheckEnhancedRegionPrivateDNSIDIsComposite(address string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[address]
		if !ok {
			return fmt.Errorf("%s is not in state", address)
		}
		networkId := rs.Primary.Attributes[privateDNSAttrNetworkID]
		regionId := rs.Primary.Attributes[privateDNSAttrRegionID]
		if networkId == "" || regionId == "" {
			return fmt.Errorf("%s holds network_id=%q region_id=%q; both must be set",
				address, networkId, regionId)
		}
		want := enhancedRegionPrivateDNSID(networkId, regionId)
		if rs.Primary.ID != want {
			return fmt.Errorf("%s has id %q, want %q. The id is the two ids joined by %q -- a "+
				"different separator, or a missing half, only shows up when somebody imports",
				address, rs.Primary.ID, want, privateDNSRegionIDSeparator)
		}
		return nil
	}
}

/*
testAccEnhancedRegionPrivateDNSImportID builds the import id from the two address
attributes in state.

Not the default (which passes the resource's own id): the default would pass even
if Create wrote an id parseEnhancedRegionPrivateDNSID cannot read, because the
same wrong string would go in and come back. Building it independently here is
what makes step 5 an assertion about the id FORMAT rather than about round
tripping whatever Create happened to produce.
*/
func testAccEnhancedRegionPrivateDNSImportID(address string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[address]
		if !ok {
			return "", fmt.Errorf("%s is not in state", address)
		}
		networkId := rs.Primary.Attributes[privateDNSAttrNetworkID]
		regionId := rs.Primary.Attributes[privateDNSAttrRegionID]
		if networkId == "" || regionId == "" {
			return "", fmt.Errorf("%s holds network_id=%q region_id=%q; both are needed to build "+
				"an import id", address, networkId, regionId)
		}
		return enhancedRegionPrivateDNSID(networkId, regionId), nil
	}
}

/*
testAccCheckEnhancedRegionPrivateDNSGone asserts Terraform has stopped tracking
the private-DNS resource.

Paired with the check below rather than used alone: on its own it is satisfied by
a Delete that made no request AND by one that rewrote the region, because both
remove the resource from state. It is here so that a failure of the survival check
cannot be explained away as "the resource was never destroyed".
*/
func testAccCheckEnhancedRegionPrivateDNSGone(address string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if _, ok := s.RootModule().Resources[address]; ok {
			return fmt.Errorf("%s is still in state after being removed from the configuration, "+
				"so this step did not exercise Delete at all", address)
		}
		return nil
	}
}

/*
testAccCheckEnhancedRegionPrivateDNSSurvived is the live evidence for decision D9:
destroying the resource released Terraform's claim and left the region's private
DNS exactly as it was.

The offline test TestEnhancedRegionPrivateDNSDeleteMakesNoRequest already pins that
Delete issues zero requests, by counting them against an httptest server. What it
cannot show is the CONSEQUENCE -- that a live region is still resolving names the
way the last apply configured it once Terraform has stopped managing the setting.
This reads the region directly and asserts exactly that.

It asserts on `enabled` AND on the dns_policy step 6 wrote, because "still enabled
with nothing configured" is not a state the API can hold (servers must be non-empty
when enabled is true) and would mean something else had happened.

THE REGION ID IS TAKEN FROM THE NETWORK RESOURCE'S OWN STATE, not from the
destroyed private-DNS resource -- which is gone by the time this runs, which is
the whole point of the step. `region.0.id` is the same value
one(...region[*].id) resolves to in the configuration.
*/
func testAccCheckEnhancedRegionPrivateDNSSurvived(networkAddress string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[networkAddress]
		if !ok {
			return fmt.Errorf("%s is not in state, so there is no network to read", networkAddress)
		}
		networkId := rs.Primary.ID
		regionId := rs.Primary.Attributes["region.0.id"]
		if networkId == "" || regionId == "" {
			return fmt.Errorf("%s holds id=%q region.0.id=%q; both are needed to read the "+
				"region's private DNS", networkAddress, networkId, regionId)
		}

		customDns, _, err := getEnhancedRegionPrivateDNS(
			context.Background(), testAccEnvClient(), networkId, regionId)
		if err != nil {
			return fmt.Errorf("reading region %s of network %s private DNS after the resource "+
				"was destroyed: %w", regionId, networkId, err)
		}

		if !customDns.GetEnabled() {
			return fmt.Errorf("region %s of network %s has private DNS DISABLED after the "+
				"Terraform resource was destroyed, and it was enabled before. Destroy must make "+
				"NO API call at all (D9): turning off a live region's private DNS because "+
				"somebody removed a Terraform resource is exactly the outcome that decision "+
				"exists to prevent", regionId, networkId)
		}
		attributes := customDns.Attributes
		if attributes == nil || len(attributes.Servers) != 1 {
			return fmt.Errorf("region %s of network %s no longer holds the DNS server the last "+
				"apply wrote (attributes = %+v). Destroy must leave the configuration untouched",
				regionId, networkId, attributes)
		}
		if got := attributes.Servers[0].GetAddress(); got != testAccEnhancedRegionPrivateDNSServer {
			return fmt.Errorf("region %s servers[0].address is %q after destroy, want %q -- "+
				"something rewrote the configuration", regionId, got,
				testAccEnhancedRegionPrivateDNSServer)
		}
		return nil
	}
}

/*
testAccCheckEnhancedRegionPrivateDNSDestroyRemovedTheResource is all CheckDestroy
can honestly assert here, and the limitation is worth stating rather than working
around.

The full destroy removes the enhanced network as well, and Terraform destroys in
reverse dependency order -- private DNS first, then its parent -- so by the time
this runs the network is gone and a GET on its region's private DNS is a 404
whatever Delete did. Asserting "the setting survived" here would therefore be
asserting nothing, or worse, would fail for the right reason and be silenced by
somebody. Step 8 of the test is where that assertion lives instead.
*/
func testAccCheckEnhancedRegionPrivateDNSDestroyRemovedTheResource(s *terraform.State) error {
	for address, rs := range s.RootModule().Resources {
		if rs.Type == "checkpointsase_enhanced_region_private_dns" {
			return fmt.Errorf("%s is still in state after destroy", address)
		}
	}
	return nil
}

/*
testAccEnhancedRegionPrivateDNSNetwork is the one enhanced network every step
shares, and it is the only thing this test creates.

The region is taken from the checkpointsase_enhanced_regions catalogue rather than
from CHECKPOINT_SASE_TEST_REGION_ID, because enhanced networks and standard
networks draw from different catalogues on this tenant -- the standard region id
is not a valid harmony_sase_region_id here. Same reasoning, same shape, as
testAccDataSourceEnhancedNetworkScopedConfig.
*/
func testAccEnhancedRegionPrivateDNSNetwork() string {
	return fmt.Sprintf(`
data "checkpointsase_enhanced_regions" "rpdns" {}

locals {
  rpdns_region = data.checkpointsase_enhanced_regions.rpdns.regions[0]
}

resource "checkpointsase_enhanced_network" "rpdns" {
  name   = "qa-rpdns-enh-net-%[1]s"
  subnet = "%[2]s"
  tags   = ["qa-rpdns"]

  region {
    harmony_sase_region_id = local.rpdns_region.id
    scale_units            = 1
    idle                   = true
  }
}
`, randNameEnhancedRegionPrivateDNS, testAccEnhancedRegionPrivateDNSSubnet)
}

// testAccEnhancedRegionPrivateDNSConfigNetworkOnly is the network with NO
// private-DNS resource, used by the last step to destroy the resource alone.
func testAccEnhancedRegionPrivateDNSConfigNetworkOnly() string {
	return testAccEnhancedRegionPrivateDNSNetwork()
}

/*
testAccEnhancedRegionPrivateDNSConfigDisabled is the "off" configuration, written
the way an operator would: enabled = false and no attributes block at all.

IT IS STEP 1 ON PURPOSE, and moving it later would quietly stop it testing
anything. It is the only step that reaches the expander's synthesised empty
arrays, and it reaches them only while `attributes` is empty in BOTH the
configuration and the state -- which is true of the first write to a fresh region
and of nothing else. Once anything has been written, `attributes` is Computed and
carries the previous value forward, so a later `enabled = false` step would send
the servers it inherited rather than `[]`.

What it catches there, ON THE NETWORK PATH where it was measured: the read of a
never-configured object is {"enabled": false} and PUTting that same body back is a
422 (API-FINDINGS.md 1.31), so the provider must synthesise
{"servers": [], "searchDomains": []} for a configuration that names neither. The
region path has never been probed; if this step is a 422 that IS the measurement
and it belongs in the findings.
*/
func testAccEnhancedRegionPrivateDNSConfigDisabled() string {
	return testAccEnhancedRegionPrivateDNSNetwork() + `
resource "checkpointsase_enhanced_region_private_dns" "rpdns" {
  network_id = checkpointsase_enhanced_network.rpdns.id
  region_id  = one(checkpointsase_enhanced_network.rpdns.region[*].id)
  enabled    = false
}
`
}

/*
testAccEnhancedRegionPrivateDNSConfigMeasured is the shape API-FINDINGS.md 1.31
measured round-tripping byte-exactly ON THE NETWORK PATH.

The two search domains are in deliberately NON-ALPHABETICAL order, matching the
probe: b before a. That is the point of them, not an accident -- the finding is
that the API returned them in the order sent, which is why these are TypeList and
why the assertions in step 3 are by index. Whether the region endpoint preserves
order too is what this step finds out.

The two servers carry DIFFERENT is_tls values, so a flattener that dropped the
field cannot pass by accident on a single row.

It carries NO dns_policy; step 6 adds one and drops search_domains, and asserts
both directions of the full replacement on the nested blocks.
*/
func testAccEnhancedRegionPrivateDNSConfigMeasured() string {
	return testAccEnhancedRegionPrivateDNSNetwork() + fmt.Sprintf(`
resource "checkpointsase_enhanced_region_private_dns" "rpdns" {
  network_id = checkpointsase_enhanced_network.rpdns.id
  region_id  = one(checkpointsase_enhanced_network.rpdns.region[*].id)
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
`, testAccEnhancedRegionPrivateDNSServer, testAccEnhancedRegionPrivateDNSTLSSrv)
}

/*
testAccEnhancedRegionPrivateDNSConfigWithPolicy adds a dns_policy and DROPS
search_domains.

No probe has ever sent a dns_policy to EITHER private-DNS endpoint -- P8 and P8b
carried `servers` and `searchDomains` only. See the test's doc comment: this is
among the first live exercises of it, and a failure here is information about the
API rather than automatically a provider defect.

It drops search_domains, which step 3 wrote. Between them the two steps show the
full replacement working in both directions on the nested blocks -- which is the
part `attributes` being Computed must NOT have changed, and step 6 is where that
is asserted.

It is also what step 8 reads back after the destroy, which is why it leaves
exactly one server: that count is the assertion there.
*/
func testAccEnhancedRegionPrivateDNSConfigWithPolicy() string {
	return testAccEnhancedRegionPrivateDNSNetwork() + fmt.Sprintf(`
resource "checkpointsase_enhanced_region_private_dns" "rpdns" {
  network_id = checkpointsase_enhanced_network.rpdns.id
  region_id  = one(checkpointsase_enhanced_network.rpdns.region[*].id)
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
`, testAccEnhancedRegionPrivateDNSServer)
}
