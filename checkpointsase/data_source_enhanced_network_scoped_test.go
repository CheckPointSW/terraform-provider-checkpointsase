package checkpointsase

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

var randNameDataSourceEnhancedNetwork string = randStringBytesRmndr()

// The remote peer is fake (RFC 5737 TEST-NET-3). This test is about what the
// data sources report, not about a working IKE session.
//
// remote_gateway_subnets must not be the default route: a static tunnel created
// with 0.0.0.0/0 there can never be updated (measured 2026-08-17, recorded in
// resource_enhanced_static_tunnel_test.go). p81_gateway_subnets must be the
// default route or the network subnet, or create answers 409. This value is
// also the assertion target for the route table below, because the API creates
// the tunnel's route entry from exactly this list.
const (
	testAccDataSourceEnhancedTunnelName    = "EnhDsTun1"
	testAccDataSourceEnhancedRemoteIP      = "203.0.113.57"
	testAccDataSourceEnhancedRemoteSubnet  = "172.31.252.0/24"
	testAccDataSourceEnhancedNetworkSubnet = "10.95.0.0/22"
)

// TestAccDataSourceEnhancedNetworkScoped_basic is the first live exercise of
// checkpointsase_enhanced_route_table, checkpointsase_enhanced_network_health
// and checkpointsase_enhanced_tunnels — the three data sources that require an
// enhanced network_id.
//
// One enhanced network, shared by all three, for the same reason Test B builds
// one standard network: creation is the expensive part and none of these reads
// needs a network to itself.
//
// Why this test also builds a tunnel (a deliberate deviation from the brief)
//
// The brief asked for an enhanced network only. Measured against this tenant
// that would make all three data sources return empty lists, and the test would
// assert nothing beyond "the read did not error":
//
//   - enhanced_tunnels lists the network's tunnels. A new network has none.
//   - enhanced_network_health covers tunnels only for enhanced networks (see
//     EnhancedHealthResponse: "List of health checks for enhanced networks
//     (tunnels only)"). No tunnels, no rows.
//   - enhanced_route_table is per-tunnel. LEFTOVERS L11 measured this directly:
//     a route entry is not a separate object, it is "for this tunnel, these
//     subnets", and every tunnel is created with its entry already present. No
//     tunnels, no routes.
//
// One checkpointsase_enhanced_static_tunnel on the already-created network
// turns all three into guaranteed content, and it creates no additional
// network — which is the constraint the brief said was real. The resource has
// no deferred items against it (LEFTOVERS, P81-115711) and
// TestAccEnhancedStaticTunnel_basic already creates and destroys one, so this
// adds a known-good resource rather than new risk.
//
// checkpointsase_enhanced_networks rides along for the same reason
// checkpointsase_standard_networks rides along in Test B: the tenant holds zero
// enhanced networks, so Test A can only assert its shape, while here the
// network just created is guaranteed to be in the list.
func TestAccDataSourceEnhancedNetworkScoped_basic(t *testing.T) {
	t.Parallel()

	const (
		network    = "checkpointsase_enhanced_network.ds"
		tunnel     = "checkpointsase_enhanced_static_tunnel.ds"
		tunnels    = "data.checkpointsase_enhanced_tunnels.ds"
		routeTable = "data.checkpointsase_enhanced_route_table.ds"
		health     = "data.checkpointsase_enhanced_network_health.ds"
		enhanced   = "data.checkpointsase_enhanced_networks.ds"
	)

	wantNetworkName := fmt.Sprintf("qa-ds-enh-net-%s", randNameDataSourceEnhancedNetwork)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceEnhancedNetworkScopedConfig(),
				Check: resource.ComposeTestCheckFunc(
					// checkpointsase_enhanced_tunnels.
					//
					// The pagination metadata is asserted present rather than
					// equal to a literal. items_total/page/total_page are
					// TypeFloat, so a zero renders as "0" in state and
					// TestCheckResourceAttrSet still passes — the assertion
					// proves the provider wrote all three, which is the part
					// that could regress. items_total is then cross-checked
					// against the list length, which is the assertion that
					// actually has teeth: it fails if the provider reports a
					// total that disagrees with the rows it returned.
					resource.TestCheckResourceAttrPair(tunnels, "network_id", network, "id"),
					resource.TestCheckResourceAttrSet(tunnels, "items_total"),
					resource.TestCheckResourceAttrSet(tunnels, "page"),
					resource.TestCheckResourceAttrSet(tunnels, "total_page"),
					resource.TestCheckResourceAttr(tunnels, "tunnels.#", "1"),
					testAccCheckDataSourceListMinLen(tunnels, "tunnels", 1),
					testAccCheckDataSourceListLenMatchesTotal(tunnels, "tunnels", "items_total"),

					// The tunnel this test created, located by the ID
					// Terraform recorded rather than by index.
					//
					// Every field named here is one a live GET was confirmed
					// to return: the non-pointer required fields of
					// EnhancedTunnel (id, tunnelName, regionID, haTunnelID,
					// authType, keyExchange), plus the six that SDK overlay
					// A19 corrected after a 2026-08-16 capture showed the
					// server sends them at the top level rather than nested
					// under advancedSettings (the timing fields, remotePublicIP
					// and remoteID). Before A19 this data source reported ""
					// for those six on every call, so these are regression
					// assertions, not decoration.
					//
					// Three attributes are deliberately NOT asserted:
					// description (never configured here, so legitimately
					// empty), routing_type (*RoutingType in the model, no
					// captured evidence the server sends it for a static
					// tunnel) and dpd_action (declared non-pointer but
					// likewise unconfirmed). Asserting an unverified field
					// would produce a failure that says nothing about the
					// provider.
					testAccCheckDataSourceMemberByResourceID(
						tunnels, "tunnels", "id", tunnel,
						[]string{"tunnel_name", "region_id", "ha_tunnel_id", "auth_type",
							"key_exchange", "ike_life_time", "lifetime", "dpd_delay",
							"dpd_timeout", "remote_public_ip", "remote_id"},
						map[string]string{
							"tunnel_name":              testAccDataSourceEnhancedTunnelName,
							"auth_type":                "psk",
							"key_exchange":             "ikev1",
							"ike_life_time":            "9h",
							"lifetime":                 "2h",
							"dpd_delay":                "20s",
							"dpd_timeout":              "40s",
							"remote_public_ip":         testAccDataSourceEnhancedRemoteIP,
							"remote_id":                testAccDataSourceEnhancedRemoteIP,
							"peak_bandwidth":           "1000",
							"p81_gateway_subnets.#":    "1",
							"p81_gateway_subnets.0":    "0.0.0.0/0",
							"remote_gateway_subnets.#": "1",
							"remote_gateway_subnets.0": testAccDataSourceEnhancedRemoteSubnet,
						},
					),
					// region_id is compared against the tunnel resource's own
					// region_id attribute rather than asserted "set": that is
					// the check testAccCheckEnhancedStaticTunnelRegionID makes
					// against a direct GET, made here against what the data
					// source reports. Index 0 is safe because tunnels.# is
					// asserted to be exactly 1 above.
					resource.TestCheckResourceAttrPair(
						tunnels, "tunnels.0.region_id", tunnel, "region_id"),

					// checkpointsase_enhanced_route_table.
					//
					// Asserted non-empty, and asserted to contain the tunnel's
					// own auto-created entry. Both halves rest on the same
					// measured fact from LEFTOVERS L11: the API creates a
					// static tunnel's route entry with the tunnel, carrying
					// that tunnel's remote_gateway_subnets. This test's tunnel
					// is the only one on the network, so there is exactly one
					// route and its subnets are known exactly.
					//
					// The element is located by tunnel_ids.0, which is a
					// nested list inside a list element — L9 established that
					// the GET response collapses both static and dynamic
					// routes to a tunnelIds array, one element for a static
					// tunnel.
					//
					// propagated is not asserted: nothing measured pins its
					// value for an auto-created route.
					//
					// The count is asserted as "at least 1", not "exactly 1".
					// One tunnel means one route today, but if the server ever
					// adds an entry of its own the member assertion below is
					// still the one that matters, and an exact count would turn
					// that addition into a failure that says nothing about the
					// provider.
					resource.TestCheckResourceAttrPair(routeTable, "network_id", network, "id"),
					testAccCheckDataSourceListMinLen(routeTable, "routes", 1),
					testAccCheckDataSourceMemberByResourceID(
						routeTable, "routes", "tunnel_ids.0", tunnel,
						[]string{"id"},
						map[string]string{
							"tunnel_ids.#": "1",
							"subnets.#":    "1",
							"subnets.0":    testAccDataSourceEnhancedRemoteSubnet,
						},
					),

					// checkpointsase_enhanced_network_health.
					//
					// Shape, not count. The network does have a tunnel, so a
					// row is expected — but enhanced health is a monitoring
					// read, and unlike Test B's gateway (which has been up for
					// the 10-15 minutes the network took to create) this tunnel
					// is seconds old and, pointed at a fake peer, will never
					// establish. Asserting `> 0` here would be asserting how
					// fast an eventually-consistent subsystem registers a new
					// tunnel, and a failure would not be a provider defect.
					//
					// The value assertions still bite whenever a row is
					// present: every row must carry this network's ID, every
					// type must be "tunnel" (the response is documented as
					// tunnels-only for enhanced networks), and every status
					// must be one of the three documented values. Those catch
					// a wrong meta mapping without depending on the row count.
					resource.TestCheckResourceAttrPair(health, "network_id", network, "id"),
					testAccCheckDataSourceListPresent(health, "health_checks"),
					testAccCheckDataSourceEveryElemFieldEqualsResourceID(
						health, "health_checks", "network_id", network),
					testAccCheckDataSourceEveryElemFieldIn(health, "health_checks", "type",
						"tunnel"),
					testAccCheckDataSourceEveryElemFieldIn(health, "health_checks", "status",
						"passing", "critical", "unknown"),
					testAccCheckDataSourceFirstElemFieldsSetIfAny(health, "health_checks",
						"type", "status", "network_id", "tunnel_id", "tunnel_name", "region_id"),

					// checkpointsase_enhanced_networks — content assertion
					// against the network this test created.
					//
					// created_at is not asserted for the same reason as in
					// Test B: flattenEnhancedNetworksData renders it with
					// time.Time.String(), so it can never be empty.
					testAccCheckDataSourceListMinLen(enhanced, "networks", 1),
					testAccCheckDataSourceMemberByResourceID(
						enhanced, "networks", "id", network,
						[]string{"name", "subnet", "dns", "access_type", "tenant_id"},
						map[string]string{
							"name":   wantNetworkName,
							"subnet": testAccDataSourceEnhancedNetworkSubnet,
							"tags.#": "1",
							"tags.0": "qa-ds",
						},
					),
				),
			},
		},
	})
}

// testAccDataSourceEnhancedNetworkScopedConfig builds one enhanced network and
// one static tunnel on it, then points the three network-scoped data sources at
// the network.
//
// The region comes from checkpointsase_enhanced_regions rather than
// testAccRegionID(): enhanced networks draw from a different region catalogue
// from the standard checkpointsase_network resource (13 standard entries vs 4
// enhanced on this tenant), so CHECKPOINT_SASE_TEST_REGION_ID is not a valid
// harmony_sase_region_id. This mirrors testAccEnhancedNetworkConfig.
//
// Every data source carries depends_on the tunnel, not just the network. The
// three scoped reads reference the network's id, which orders them after the
// network but says nothing about the tunnel — without the explicit dependency
// Terraform could read an empty tunnel list, an empty route table and an empty
// health list while the tunnel is still being created, and every content
// assertion above would fail.
func testAccDataSourceEnhancedNetworkScopedConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  selected_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
}

resource "checkpointsase_enhanced_network" "ds" {
  name   = "qa-ds-enh-net-%[1]s"
  subnet = "%[2]s"
  tags   = ["qa-ds"]

  region {
    harmony_sase_region_id = local.selected_region.id
    scale_units            = 1
    idle                   = true
  }
}

resource "checkpointsase_enhanced_static_tunnel" "ds" {
  network_id  = checkpointsase_enhanced_network.ds.id
  region_id   = one(checkpointsase_enhanced_network.ds.region[*].id)
  tunnel_name = "%[3]s"

  auth_type        = "psk"
  passphrase       = "CHANGEMEenhDsTun1"
  remote_public_ip = "%[4]s"
  remote_id        = "%[4]s"

  key_exchange  = "ikev1"
  ike_life_time = "9h"
  lifetime      = "2h"
  dpd_delay     = "20s"
  dpd_timeout   = "40s"

  p81_gateway_subnets    = ["0.0.0.0/0"]
  remote_gateway_subnets = ["%[5]s"]

  phase1 {
    auth                = ["sha256"]
    encryption          = ["3des"]
    key_exchange_method = ["modp2048"]
  }
  phase2 {
    auth                = ["sha256"]
    encryption          = ["3des"]
    key_exchange_method = ["modp2048"]
  }
}

data "checkpointsase_enhanced_tunnels" "ds" {
  network_id = checkpointsase_enhanced_network.ds.id

  depends_on = [
    checkpointsase_enhanced_static_tunnel.ds
  ]
}

data "checkpointsase_enhanced_route_table" "ds" {
  network_id = checkpointsase_enhanced_network.ds.id

  depends_on = [
    checkpointsase_enhanced_static_tunnel.ds
  ]
}

data "checkpointsase_enhanced_network_health" "ds" {
  network_id = checkpointsase_enhanced_network.ds.id

  depends_on = [
    checkpointsase_enhanced_static_tunnel.ds
  ]
}

data "checkpointsase_enhanced_networks" "ds" {
  depends_on = [
    checkpointsase_enhanced_network.ds
  ]
}
  `
	return fmt.Sprintf(config,
		randNameDataSourceEnhancedNetwork,
		testAccDataSourceEnhancedNetworkSubnet,
		testAccDataSourceEnhancedTunnelName,
		testAccDataSourceEnhancedRemoteIP,
		testAccDataSourceEnhancedRemoteSubnet,
	)
}
