package checkpointsase

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

var randNameDataSourceNetwork string = randStringBytesRmndr()

// TestAccDataSourceStandardNetworkScoped_basic is the first live exercise of
// checkpointsase_route_table and checkpointsase_network_health, the two data
// sources that require a standard network_id.
//
// It builds exactly one checkpointsase_network and points both at it. One
// network, not two: a standard network takes 10-15 minutes to create on this
// API, and nothing about either data source needs a network of its own.
//
// checkpointsase_standard_networks rides along on the same network. Test A can
// only assert shape for it — the tenant holds zero standard networks — but here
// the network Terraform just created is guaranteed to be in the list, so this
// step carries the real content assertion for that data source: the created
// network is present, and the fields flattenStandardNetworks claims to map are
// actually populated on it.
//
// The `depends_on` on the standard_networks read is required. Without a
// reference to the resource, Terraform is free to read a no-argument data
// source before the network exists, and the membership assertion would fail on
// an empty list. The route_table and network_health reads need no depends_on:
// they reference the network's computed id, which is an implicit dependency.
// (checkpointsase_networks in testAccGatewaysConfig already uses the same
// depends_on pattern inside a resource.Test config.)
func TestAccDataSourceStandardNetworkScoped_basic(t *testing.T) {
	t.Parallel()

	const (
		network       = "checkpointsase_network.ds"
		routeTable    = "data.checkpointsase_route_table.ds"
		networkHealth = "data.checkpointsase_network_health.ds"
		standard      = "data.checkpointsase_standard_networks.ds"
	)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t); testAccPreCheckRegion(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceStandardNetworkScopedConfig(),
				Check: resource.ComposeTestCheckFunc(
					// checkpointsase_route_table.
					//
					// The route list is shape-only. A standard network's route
					// entries are per-interface and there is no documented,
					// measured guarantee that a freshly created network with one
					// idle region and no IPsec tunnels has any: asserting `> 0`
					// would be asserting an unverified server behaviour, and a
					// failure would tell the reader nothing about the provider.
					// The conditional element check still covers the flatten
					// function the moment the tenant does return a route.
					//
					// propagated is excluded from the field check on purpose: it
					// is a bool, so "false" is a legitimate value that a
					// non-empty assertion would wrongly accept anyway.
					resource.TestCheckResourceAttrPair(routeTable, "network_id", network, "id"),
					testAccCheckDataSourceListPresent(routeTable, "routes"),
					testAccCheckDataSourceFirstElemFieldsSetIfAny(routeTable, "routes",
						"id", "interface_name"),

					// checkpointsase_network_health.
					//
					// This is asserted non-empty. A standard network is created
					// with one region, and a region is provisioned with a
					// default gateway before Create returns (region.
					// default_gateway_ip is a computed attribute of it, and
					// testAccCheckGatewaysCount in resource_gateway_test.go
					// counts region instances that exist without any
					// checkpointsase_gateway resource). The provider's own
					// create wait is what makes this safe: by the time these
					// data sources are read, the network has been up for the
					// 10-15 minutes creation took, so the health subsystem has
					// had time to register the gateway.
					//
					// The stronger assertion is the second one: every row a
					// network-scoped read returns must carry the network_id
					// that was asked for. That is what separates a correct
					// meta mapping from a plausible-looking wrong one — the
					// class of bug already found in the enhanced tunnel read
					// and the firewall policy oneOf.
					//
					// tunnel_name is excluded from the field check: it is
					// documented as populated for tunnel-type checks only, so
					// it is legitimately empty for the gateway rows this
					// network produces.
					resource.TestCheckResourceAttrPair(networkHealth, "network_id", network, "id"),
					testAccCheckDataSourceListMinLen(networkHealth, "health_checks", 1),
					testAccCheckDataSourceEveryElemFieldEqualsResourceID(
						networkHealth, "health_checks", "network_id", network),
					testAccCheckDataSourceEveryElemFieldIn(networkHealth, "health_checks", "type",
						"gateway", "tunnel"),
					testAccCheckDataSourceEveryElemFieldIn(networkHealth, "health_checks", "status",
						"passing", "critical", "unknown"),
					testAccCheckDataSourceElemFieldsSet(networkHealth, "health_checks", 0,
						"type", "status", "network_id", "instance_id"),

					// checkpointsase_standard_networks — content assertion
					// against the network this test created.
					//
					// created_at and updated_at are deliberately not asserted
					// non-empty: dataSourceStandardNetworksRead renders them
					// with time.Time.String(), which produces the zero time
					// rather than an empty string when the server omits the
					// field, so the assertion could never fail and would be
					// noise.
					testAccCheckDataSourceListMinLen(standard, "networks", 1),
					testAccCheckDataSourceMemberByResourceID(
						standard, "networks", "id", network,
						[]string{"name", "subnet", "dns", "access_type", "tenant_id"},
						map[string]string{
							"name":   randNameDataSourceNetwork,
							"tags.#": "1",
							"tags.0": "qa-ds",
						},
					),
				),
			},
		},
	})
}

func testAccDataSourceStandardNetworkScopedConfig() string {
	config := `
resource "checkpointsase_network" "ds" {
  network {
    name = "%s"
    tags = ["qa-ds"]
  }
  region {
    cpregion_id = "%s"
    idle        = true
  }
}

data "checkpointsase_route_table" "ds" {
  network_id = checkpointsase_network.ds.id
}

data "checkpointsase_network_health" "ds" {
  network_id = checkpointsase_network.ds.id
}

data "checkpointsase_standard_networks" "ds" {
  depends_on = [
    checkpointsase_network.ds
  ]
}
  `
	return fmt.Sprintf(config, randNameDataSourceNetwork, testAccRegionID())
}
