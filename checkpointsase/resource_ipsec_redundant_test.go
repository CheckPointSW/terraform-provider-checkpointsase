package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccIpsecRedundant_basic(t *testing.T) {
	t.Parallel()
	// This fixture costs two gateways in one region and takes ~26 minutes. It was
	// skipped while Create stored a member id instead of the pair id, which made
	// the post-create read 404; Create now takes the pair id from the async
	// status, so it runs again.
	var tunnel perimeter81Sdk.IPSecRedundantTunnels
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t); testAccPreCheckRegion(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccIpsecRedundantConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckIpsecRedundantExists("checkpointsase_ipsec_redundant.ipsr1", &tunnel),
					testAccCheckIpsecRedundantAttributes(&tunnel, &perimeter81Sdk.IPSecRedundantTunnels{
						SharedSettings: &perimeter81Sdk.IPSecSharedSettings{
							P81GatewaySubnets:    []string{"0.0.0.0/0"},
							RemoteGatewaySubnets: []string{"0.0.0.0/0"},
						},
						AdvancedSettings: &perimeter81Sdk.IPSecAdvancedSettings{
							KeyExchange: "ikev2",
							IkeLifeTime: "8h",
							Lifetime:    "1h",
							DpdDelay:    "10s",
							DpdTimeout:  "30s",
							Phase1: perimeter81Sdk.IPSecPhaseConfig{
								Auth:       []string{"sha256"},
								Encryption: []string{"3des"},
								Dh:         []int32{14},
							},
							Phase2: perimeter81Sdk.IPSecPhaseConfig{
								Auth:       []string{"sha256"},
								Encryption: []string{"3des"},
								Dh:         []int32{14},
							},
						},
					}),
				),
			},
		},
	})
}

func testAccCheckIpsecRedundantExists(n string, tunnel *perimeter81Sdk.IPSecRedundantTunnels) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}

		tunnelId := rs.Primary.ID
		if tunnelId == "" {
			return fmt.Errorf("No tunnel id is set")
		}
		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		ctx := context.Background()
		networkId := rs.Primary.Attributes["network_id"]
		gotIpsecRedundant, _, err := conn.StandardTunnelsAPI.StandardGetIPSecRedundantTunnel(ctx, networkId, tunnelId).Execute()
		if err != nil {
			return err
		}

		*tunnel = *gotIpsecRedundant
		return nil
	}
}

func testAccCheckIpsecRedundantAttributes(tunnel *perimeter81Sdk.IPSecRedundantTunnels, want *perimeter81Sdk.IPSecRedundantTunnels) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if tunnel.SharedSettings == nil {
			return fmt.Errorf("got nil shared settings")
		}
		if !testComparableArraiesEq(tunnel.SharedSettings.P81GatewaySubnets, want.SharedSettings.P81GatewaySubnets) {
			return fmt.Errorf("got p81 gateway subnets %q; want %q", tunnel.SharedSettings.P81GatewaySubnets, want.SharedSettings.P81GatewaySubnets)
		}
		if !testComparableArraiesEq(tunnel.SharedSettings.RemoteGatewaySubnets, want.SharedSettings.RemoteGatewaySubnets) {
			return fmt.Errorf("got remote gateway subnets %q; want %q", tunnel.SharedSettings.RemoteGatewaySubnets, want.SharedSettings.RemoteGatewaySubnets)
		}
		if tunnel.AdvancedSettings == nil {
			return fmt.Errorf("got nil advanced settings")
		}
		if tunnel.AdvancedSettings.IkeLifeTime != want.AdvancedSettings.IkeLifeTime {
			return fmt.Errorf("got ike life time %q; want %q", tunnel.AdvancedSettings.IkeLifeTime, want.AdvancedSettings.IkeLifeTime)
		}
		if tunnel.AdvancedSettings.DpdDelay != want.AdvancedSettings.DpdDelay {
			return fmt.Errorf("got dpd delay %q; want %q", tunnel.AdvancedSettings.DpdDelay, want.AdvancedSettings.DpdDelay)
		}
		if tunnel.AdvancedSettings.DpdTimeout != want.AdvancedSettings.DpdTimeout {
			return fmt.Errorf("got dpd timeout %q; want %q", tunnel.AdvancedSettings.DpdTimeout, want.AdvancedSettings.DpdTimeout)
		}
		if tunnel.Tunnel1 == nil {
			return fmt.Errorf("got nil tunnel1")
		}
		if tunnel.Tunnel1.GatewayID == "" {
			return fmt.Errorf("got Gateway id empty for tunnel 1")
		}
		if tunnel.Tunnel2 == nil {
			return fmt.Errorf("got nil tunnel2")
		}
		if tunnel.Tunnel2.GatewayID == "" {
			return fmt.Errorf("got Gateway id empty for tunnel 2")
		}
		if tunnel.Tunnel1.GetTunnelID() == "" {
			return fmt.Errorf("got Tunnel id empty for tunnel 1")
		}
		if tunnel.Tunnel2.GetTunnelID() == "" {
			return fmt.Errorf("got Tunnel id empty for tunnel 2")
		}
		if !testComparableArraiesEq(tunnel.AdvancedSettings.Phase1.Auth, want.AdvancedSettings.Phase1.Auth) {
			return fmt.Errorf("got phase1 auth %q; want %q", tunnel.AdvancedSettings.Phase1.Auth, want.AdvancedSettings.Phase1.Auth)
		}
		if !testComparableArraiesEq(tunnel.AdvancedSettings.Phase1.Encryption, want.AdvancedSettings.Phase1.Encryption) {
			return fmt.Errorf("got phase1 encryption %q; want %q", tunnel.AdvancedSettings.Phase1.Encryption, want.AdvancedSettings.Phase1.Encryption)
		}
		if !testComparableArraiesEq(tunnel.AdvancedSettings.Phase1.Dh, want.AdvancedSettings.Phase1.Dh) {
			return fmt.Errorf("got phase1 dh %q; want %q", tunnel.AdvancedSettings.Phase1.Dh, want.AdvancedSettings.Phase1.Dh)
		}
		if !testComparableArraiesEq(tunnel.AdvancedSettings.Phase2.Auth, want.AdvancedSettings.Phase2.Auth) {
			return fmt.Errorf("got phase2 auth %q; want %q", tunnel.AdvancedSettings.Phase2.Auth, want.AdvancedSettings.Phase2.Auth)
		}
		if !testComparableArraiesEq(tunnel.AdvancedSettings.Phase2.Encryption, want.AdvancedSettings.Phase2.Encryption) {
			return fmt.Errorf("got phase2 encryption %q; want %q", tunnel.AdvancedSettings.Phase2.Encryption, want.AdvancedSettings.Phase2.Encryption)
		}
		if !testComparableArraiesEq(tunnel.AdvancedSettings.Phase2.Dh, want.AdvancedSettings.Phase2.Dh) {
			return fmt.Errorf("got phase2 dh %q; want %q", tunnel.AdvancedSettings.Phase2.Dh, want.AdvancedSettings.Phase2.Dh)
		}

		return nil
	}
}

func testAccIpsecRedundantConfig() string {
	config := `

resource "checkpointsase_network" "n4" {
  network {
    name = "%s"
    tags = ["test"]
  }
  region {
    cpregion_id = "%s"
    idle = true
  }
}
resource "checkpointsase_gateway"  "g2"{

  network_id = checkpointsase_network.n4.id
  region_id = checkpointsase_network.n4.region[0].region_id
   gateways {
      name = "perimeter81"
      idle = true
  }
  	depends_on = [
    	checkpointsase_network.n4
  	]
}

data "checkpointsase_networks" "all4" {
	depends_on = [
    	checkpointsase_network.n4,
		checkpointsase_gateway.g2
  	]
}
resource "checkpointsase_ipsec_redundant" "ipsr1" {
  region_id = checkpointsase_network.n4.region[0].region_id
  network_id = checkpointsase_network.n4.id
  tunnel_name = "ipseed"
  tunnel1 {
      passphrase = "aXvgHEYt"
      p81_gwinternal_ip = "169.254.100.19"
      remote_gwinternal_ip = "169.254.100.5"
      remote_public_ip = "169.254.100.7"
      remote_asn = "65323"
      remote_id = "tunnelOneRemoteId"
      gateway_id = {
		for network in data.checkpointsase_networks.all4.networks :
		network.id => network.regions[0].instances[0].id
		if network.id == checkpointsase_network.n4.id
	  }[checkpointsase_network.n4.id]
  }
  tunnel2 {
      passphrase = "Sg4gKHtT"
      p81_gwinternal_ip = "169.254.100.10"
      remote_gwinternal_ip = "169.254.100.14"
      remote_public_ip = "169.254.100.16"
      remote_asn = "65324"
      remote_id = "tunnelTwoRemoteId"
      gateway_id = {
		for network in data.checkpointsase_networks.all4.networks :
		network.id => network.regions[0].instances[1].id
		if network.id == checkpointsase_network.n4.id
	  }[checkpointsase_network.n4.id]
  }
  shared_settings {
    p81_gateway_subnets = ["0.0.0.0/0"]
    remote_gateway_subnets = ["0.0.0.0/0"]
  }
  advanced_settings {
    key_exchange = "ikev2"
    ike_life_time = "8h"
    lifetime = "1h"
    dpd_delay = "10s"
    dpd_timeout = "30s"
    phase1 {
      auth = ["sha256"]
      encryption = ["3des"]
      dh = [14]
    }
    phase2 {
      auth = ["sha256"]
      encryption = ["3des"]
      dh = [14]
    }
  }
}
  `
	return fmt.Sprintf(config, randStringBytesRmndr(), testAccRegionID())
}

/*
TestIpsecRedundantIsManageable pins the shape that makes this resource work.

It replaces a test that asserted the opposite. The resource used to refuse every
configuration in CustomizeDiff, because Create guessed the pair id by searching
network-find and could only ever find a MEMBER id, which every later read,
update and delete then 404'd on. Create now takes the pair id from the async
create status instead, so the refusal is gone on purpose -- if it comes back,
this test says so rather than silently passing.

The ForceNew assertions are the other half. helper/schema propagates a list's
ForceNew only for `Elem: *Schema`, never for `Elem: *Resource`, so a nested edit
inside these four blocks has always planned an in-place update. Marking the
blocks ForceNew therefore never prevented anything; it only made the plan lie.
Update is wired to PUT now, so they are deliberately not ForceNew.
*/
func TestIpsecRedundantIsManageable(t *testing.T) {
	r := resourceIpsecRedundant()

	if r.CustomizeDiff != nil {
		t.Error("CustomizeDiff is registered again; the plan-time refusal was removed " +
			"because the pair id is available from the create status")
	}
	if r.UpdateContext == nil {
		t.Error("UpdateContext is not registered, so nested edits cannot be applied")
	}

	for _, name := range []string{"region_id", "network_id", "tunnel_name"} {
		if s := r.Schema[name]; s == nil {
			t.Errorf("%s is missing from the schema", name)
		} else if !s.ForceNew {
			t.Errorf("%s must stay ForceNew: the pair cannot be moved between "+
				"networks, regions or names in place", name)
		}
	}

	for _, name := range []string{"tunnel1", "tunnel2", "shared_settings", "advanced_settings"} {
		if s := r.Schema[name]; s == nil {
			t.Errorf("%s is missing from the schema", name)
		} else if s.ForceNew {
			t.Errorf("%s must not be ForceNew: the SDK never propagated it into the "+
				"element schema, so it only made the plan disagree with the apply", name)
		}
	}

	// Update sends each member's own id, and it exists nowhere in the config --
	// Read is what puts it into state.
	for _, name := range []string{"tunnel1", "tunnel2"} {
		elem, ok := r.Schema[name].Elem.(*schema.Resource)
		if !ok {
			t.Fatalf("%s.Elem is not a *schema.Resource", name)
		}
		tunnelId := elem.Schema["tunnel_id"]
		if tunnelId == nil {
			t.Errorf("%s.tunnel_id is missing; Update cannot address the member without it", name)
			continue
		}
		if !tunnelId.Computed {
			t.Errorf("%s.tunnel_id must be Computed: the server assigns it and Update reads it back from state", name)
		}
	}
}
