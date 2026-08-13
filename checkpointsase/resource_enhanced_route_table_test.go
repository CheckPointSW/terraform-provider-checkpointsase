package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var randNameEnhancedRouteTable string = randStringBytesRmndr()

// TestAccEnhancedRouteTable_basic is the first live exercise of
// checkpointsase_enhanced_route_table. It builds its own enhanced network
// and static tunnel (rather than depending on the enhanced_static_tunnel
// test file, so this test stays independently runnable — the same
// independence the validated demo/enhanced_route_table/main.tf documents),
// attaches a static route table entry to that tunnel, confirms it exists
// server-side with the configured subnets and is attached to the right
// tunnel, then exercises the Update path by adding a second subnet CIDR
// (network_id, type, and the tunnel reference are all ForceNew — subnets is
// the only in-place-mutable attribute) and confirms the change round-trips.
func TestAccEnhancedRouteTable_basic(t *testing.T) {
	t.Parallel()
	var route perimeter81Sdk.EnhancedRouteTable

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccEnhancedRouteTableConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedRouteTableExists("checkpointsase_enhanced_route_table.demo", &route),
					testAccCheckEnhancedRouteTableSubnets(&route, []string{"192.0.2.0/24"}),
					testAccCheckEnhancedRouteTableTunnelID("checkpointsase_enhanced_route_table.demo", "checkpointsase_enhanced_static_tunnel.demo", &route),
				),
			},
			{
				Config: testAccEnhancedRouteTableUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedRouteTableExists("checkpointsase_enhanced_route_table.demo", &route),
					testAccCheckEnhancedRouteTableSubnets(&route, []string{"192.0.2.0/24", "203.0.113.0/24"}),
					testAccCheckEnhancedRouteTableTunnelID("checkpointsase_enhanced_route_table.demo", "checkpointsase_enhanced_static_tunnel.demo", &route),
				),
			},
		},
	})
}

// testAccCheckEnhancedRouteTableExists fetches the route table entry
// directly from the API by network_id + route id from state, so this fails
// if Create never actually produced a server-side route.
func testAccCheckEnhancedRouteTableExists(n string, route *perimeter81Sdk.EnhancedRouteTable) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}

		routeId := rs.Primary.ID
		if routeId == "" {
			return fmt.Errorf("No route table id is set")
		}
		networkId := rs.Primary.Attributes["network_id"]
		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		ctx := context.Background()
		got, _, err := conn.EnhancedRouteTablesAPI.GetRouteEntry(ctx, networkId, routeId).Execute()
		if err != nil {
			return err
		}
		*route = *got
		return nil
	}
}

// testAccCheckEnhancedRouteTableSubnets compares the API's subnets (which
// resourceEnhancedRouteTableRead sets directly from the same GetRouteEntry
// response) against what was configured.
func testAccCheckEnhancedRouteTableSubnets(route *perimeter81Sdk.EnhancedRouteTable, want []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if !testComparableArraiesEq(route.Subnets, want) {
			return fmt.Errorf("got subnets %q; want %q", route.Subnets, want)
		}
		return nil
	}
}

// testAccCheckEnhancedRouteTableTunnelID confirms the route was actually
// attached to the static tunnel this test created — not merely that some
// route object exists with no error. tunnelResource's ID (the static
// tunnel's server-assigned ID) is read from state rather than hardcoded, so
// this works across reruns.
func testAccCheckEnhancedRouteTableTunnelID(routeResource, tunnelResource string, route *perimeter81Sdk.EnhancedRouteTable) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		trs, ok := s.RootModule().Resources[tunnelResource]
		if !ok {
			return fmt.Errorf("Not Found: %s", tunnelResource)
		}
		tunnelId := trs.Primary.ID
		if tunnelId == "" {
			return fmt.Errorf("No tunnel id is set on %s", tunnelResource)
		}
		if !testComparableArraiesEq(route.TunnelIds, []string{tunnelId}) {
			return fmt.Errorf("got tunnel_ids %q; want [%q]", route.TunnelIds, tunnelId)
		}
		return nil
	}
}

func testAccEnhancedRouteTableConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  selected_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
}

resource "checkpointsase_enhanced_network" "demo" {
  name   = "qa-enh-route-%s"
  subnet = "10.92.0.0/22"
  tags   = ["qa-demo"]

  region {
    harmony_sase_region_id = local.selected_region.id
    scale_units            = 1
    idle                   = true
  }
}

resource "checkpointsase_enhanced_static_tunnel" "demo" {
  network_id  = checkpointsase_enhanced_network.demo.id
  region_id   = one(checkpointsase_enhanced_network.demo.region[*].id)
  tunnel_name = "EnhancedRouteTableTunnel1"

  auth_type        = "psk"
  passphrase       = "CHANGE-ME-enhRoute1"
  remote_public_ip = "198.51.100.44"

  key_exchange  = "ikev1"
  ike_life_time = "9h"
  lifetime      = "2h"
  dpd_delay     = "20s"
  dpd_timeout   = "40s"

  p81_gateway_subnets    = ["0.0.0.0/0"]
  remote_gateway_subnets = ["0.0.0.0/0"]

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

resource "checkpointsase_enhanced_route_table" "demo" {
  network_id = checkpointsase_enhanced_network.demo.id
  type       = "static"
  tunnel_id  = checkpointsase_enhanced_static_tunnel.demo.id
  subnets    = ["192.0.2.0/24"]
}
  `
	return fmt.Sprintf(config, randNameEnhancedRouteTable)
}

func testAccEnhancedRouteTableUpdateConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  selected_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
}

resource "checkpointsase_enhanced_network" "demo" {
  name   = "qa-enh-route-%s"
  subnet = "10.92.0.0/22"
  tags   = ["qa-demo"]

  region {
    harmony_sase_region_id = local.selected_region.id
    scale_units            = 1
    idle                   = true
  }
}

resource "checkpointsase_enhanced_static_tunnel" "demo" {
  network_id  = checkpointsase_enhanced_network.demo.id
  region_id   = one(checkpointsase_enhanced_network.demo.region[*].id)
  tunnel_name = "EnhancedRouteTableTunnel1"

  auth_type        = "psk"
  passphrase       = "CHANGE-ME-enhRoute1"
  remote_public_ip = "198.51.100.44"

  key_exchange  = "ikev1"
  ike_life_time = "9h"
  lifetime      = "2h"
  dpd_delay     = "20s"
  dpd_timeout   = "40s"

  p81_gateway_subnets    = ["0.0.0.0/0"]
  remote_gateway_subnets = ["0.0.0.0/0"]

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

resource "checkpointsase_enhanced_route_table" "demo" {
  network_id = checkpointsase_enhanced_network.demo.id
  type       = "static"
  tunnel_id  = checkpointsase_enhanced_static_tunnel.demo.id
  subnets    = ["192.0.2.0/24", "203.0.113.0/24"]
}
  `
	return fmt.Sprintf(config, randNameEnhancedRouteTable)
}
