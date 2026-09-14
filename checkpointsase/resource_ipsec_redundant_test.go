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
	const resourceName = "checkpointsase_ipsec_redundant.ipsr1"
	networkName := randStringBytesRmndr()
	var pairId string

	want := func(ikeLifeTime string) *perimeter81Sdk.IPSecRedundantTunnels {
		return &perimeter81Sdk.IPSecRedundantTunnels{
			SharedSettings: &perimeter81Sdk.IPSecSharedSettings{
				P81GatewaySubnets:    []string{"0.0.0.0/0"},
				RemoteGatewaySubnets: []string{"0.0.0.0/0"},
			},
			AdvancedSettings: &perimeter81Sdk.IPSecAdvancedSettings{
				KeyExchange: "ikev2",
				IkeLifeTime: ikeLifeTime,
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
		}
	}

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t); testAccPreCheckRegion(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccIpsecRedundantConfig(networkName, "8h", "aXvgHEYt"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckIpsecRedundantExists(resourceName, &tunnel),
					testAccCheckIpsecRedundantAttributes(&tunnel, want("8h")),
					testAccRecordIpsecRedundantId(resourceName, &pairId),
				),
			},
			{
				// Changes one field inside advanced_settings and one inside
				// tunnel1, so both expansions are exercised. Neither is ForceNew,
				// so this plans an in-place update and goes through PUT.
				//
				// The id assertion is the point of the step: a destroy+recreate
				// would satisfy the value checks just as well while silently
				// rebuilding both tunnels, and only the id tells them apart.
				Config: testAccIpsecRedundantConfig(networkName, "4h", "bXvgHEYtZ"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckIpsecRedundantExists(resourceName, &tunnel),
					testAccCheckIpsecRedundantAttributes(&tunnel, want("4h")),
					testAccCheckIpsecRedundantIdUnchanged(resourceName, &pairId),
					resource.TestCheckResourceAttr(resourceName, "advanced_settings.0.ike_life_time", "4h"),
					resource.TestCheckResourceAttr(resourceName, "tunnel1.0.passphrase", "bXvgHEYtZ"),
					// Read must keep populating the member ids the PUT addresses.
					resource.TestCheckResourceAttrSet(resourceName, "tunnel1.0.tunnel_id"),
					resource.TestCheckResourceAttrSet(resourceName, "tunnel2.0.tunnel_id"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: false,
				// passphrase is write-only on the pair read for import purposes,
				// so a full ImportStateVerify would diff on it.
				ImportStateIdFunc: testAccIpsecRedundantImportId(resourceName),
			},
		},
	})
}

/*
testAccRecordIpsecRedundantId stores the resource id so a later step can assert
the pair was updated in place rather than replaced.
*/
func testAccRecordIpsecRedundantId(n string, into *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}
		*into = rs.Primary.ID
		return nil
	}
}

func testAccCheckIpsecRedundantIdUnchanged(n string, want *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}
		if *want == "" {
			return fmt.Errorf("no id was recorded by the earlier step")
		}
		if rs.Primary.ID != *want {
			return fmt.Errorf("pair id changed from %s to %s, so the nested edit replaced the pair instead of updating it through PUT",
				*want, rs.Primary.ID)
		}
		return nil
	}
}

/*
testAccIpsecRedundantImportId builds the composite id import expects, which is
"<network_id>-<ha_tunnel_id>" rather than the bare id held in state.
*/
func testAccIpsecRedundantImportId(n string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return "", fmt.Errorf("Not Found: %s", n)
		}
		return fmt.Sprintf("%s-%s", rs.Primary.Attributes["network_id"], rs.Primary.ID), nil
	}
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

/*
testAccIpsecRedundantConfig takes the network name so two steps can share one
network, and the two values the update step changes.

The name has to be passed in rather than generated here: a fresh name on the
second call would replace the network and the pair with it, which is exactly the
thing the update step is trying to prove does NOT happen.
*/
func testAccIpsecRedundantConfig(networkName string, ikeLifeTime string, tunnel1Passphrase string) string {
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
      passphrase = "%s"
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
    ike_life_time = "%s"
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
	return fmt.Sprintf(config, networkName, testAccRegionID(), tunnel1Passphrase, ikeLifeTime)
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
