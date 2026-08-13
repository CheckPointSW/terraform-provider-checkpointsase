package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var randNameEnhancedDynamicTunnel string = randStringBytesRmndr()

// TestAccEnhancedDynamicTunnel_basic is the first live exercise of
// checkpointsase_enhanced_dynamic_tunnel. It builds an enhanced network with
// one region, attaches a BGP-routed dynamic tunnel with a single endpoint
// against a fake remote peer (TEST-NET-2, RFC 5737 + placeholder ASNs — BGP
// will never actually come up; this is about the Terraform lifecycle, not a
// working session), and confirms the tunnel exists server-side with the
// configured shared/advanced settings.
//
// Step 2 deliberately changes only dpd_delay/dpd_timeout — fields that
// resourceEnhancedDynamicTunnelUpdate (resource_enhanced_dynamic_tunnel.go)
// never sends to the server: its update payload carries only TunnelName and
// description, nothing from AdvancedSettings/SharedSettings/tunnel details.
// That means after this update, Read re-fetches the *unchanged* server
// value and overwrites it into state, which contradicts the new config on
// two fronts: the framework's automatic post-apply "second plan should be
// empty" check (ExpectNonEmptyPlan is deliberately left unset) and the
// explicit dpd_delay/dpd_timeout assertion in
// testAccCheckEnhancedDynamicTunnelAttributes. Both are expected to fail
// live — this test exists to expose that regression, not to hide it; see
// the task-32 report.
//
// tunnel_name, left_asn, passphrase, p81_gw_internal_ip/remote_gw_internal_ip
// etc. are lifted from demo/enhanced_dynamic_tunnel/main.tf. passphrase must
// avoid hyphens per the public-api regex (see the schema description on the
// tunnel.passphrase attribute) and is an obviously fake placeholder.
func TestAccEnhancedDynamicTunnel_basic(t *testing.T) {
	var tunnel perimeter81Sdk.EnhancedTunnel

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccEnhancedDynamicTunnelConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedDynamicTunnelExists("checkpointsase_enhanced_dynamic_tunnel.demo", &tunnel),
					testAccCheckEnhancedDynamicTunnelAttributes(&tunnel, &testAccEnhancedDynamicTunnelExpectedAttributes{
						TunnelNameBase:       "EnhDynTun1",
						KeyExchange:          "ikev1",
						IkeLifeTime:          "9h",
						Lifetime:             "2h",
						DpdDelay:             "20s",
						DpdTimeout:           "40s",
						P81GatewaySubnets:    []string{"0.0.0.0/0"},
						RemoteGatewaySubnets: []string{"0.0.0.0/0"},
						Phase1: perimeter81Sdk.IPSecPhaseConfigV23{
							Auth:              []string{"sha256"},
							Encryption:        []string{"3des"},
							KeyExchangeMethod: []string{"modp2048"},
						},
						Phase2: perimeter81Sdk.IPSecPhaseConfigV23{
							Auth:              []string{"sha256"},
							Encryption:        []string{"3des"},
							KeyExchangeMethod: []string{"modp2048"},
						},
					}),
					testAccCheckEnhancedDynamicTunnelRegionID("checkpointsase_enhanced_dynamic_tunnel.demo", &tunnel),
				),
			},
			{
				Config: testAccEnhancedDynamicTunnelUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedDynamicTunnelExists("checkpointsase_enhanced_dynamic_tunnel.demo", &tunnel),
					testAccCheckEnhancedDynamicTunnelAttributes(&tunnel, &testAccEnhancedDynamicTunnelExpectedAttributes{
						TunnelNameBase:       "EnhDynTun1",
						KeyExchange:          "ikev1",
						IkeLifeTime:          "9h",
						Lifetime:             "2h",
						DpdDelay:             "35s",
						DpdTimeout:           "45s",
						P81GatewaySubnets:    []string{"0.0.0.0/0"},
						RemoteGatewaySubnets: []string{"0.0.0.0/0"},
						Phase1: perimeter81Sdk.IPSecPhaseConfigV23{
							Auth:              []string{"sha256"},
							Encryption:        []string{"3des"},
							KeyExchangeMethod: []string{"modp2048"},
						},
						Phase2: perimeter81Sdk.IPSecPhaseConfigV23{
							Auth:              []string{"sha256"},
							Encryption:        []string{"3des"},
							KeyExchangeMethod: []string{"modp2048"},
						},
					}),
				),
			},
		},
	})
}

// testAccCheckEnhancedDynamicTunnelExists fetches the tunnel directly from
// the API by network_id + tunnel id from state, so this fails if Create
// never actually produced a server-side tunnel. GetDynamicTunnel returns one
// EnhancedTunnel per endpoint; this test's config declares exactly one
// `tunnel` block, so index 0 is the endpoint under test.
func testAccCheckEnhancedDynamicTunnelExists(n string, tunnel *perimeter81Sdk.EnhancedTunnel) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}

		tunnelId := rs.Primary.ID
		if tunnelId == "" {
			return fmt.Errorf("No tunnel id is set")
		}
		networkId := rs.Primary.Attributes["network_id"]
		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		ctx := context.Background()
		got, _, err := conn.EnhancedTunnelsAPI.GetDynamicTunnel(ctx, networkId, tunnelId).Execute()
		if err != nil {
			return err
		}
		if len(got) == 0 {
			return fmt.Errorf("GetDynamicTunnel returned no tunnel data for id %s", tunnelId)
		}
		*tunnel = got[0]
		return nil
	}
}

type testAccEnhancedDynamicTunnelExpectedAttributes struct {
	TunnelNameBase       string
	KeyExchange          string
	IkeLifeTime          string
	Lifetime             string
	DpdDelay             string
	DpdTimeout           string
	P81GatewaySubnets    []string
	RemoteGatewaySubnets []string
	Phase1               perimeter81Sdk.IPSecPhaseConfigV23
	Phase2               perimeter81Sdk.IPSecPhaseConfigV23
}

// testAccCheckEnhancedDynamicTunnelAttributes only compares fields the read
// path actually populates or that the shared EnhancedTunnel read-shape
// carries regardless of whether resourceEnhancedDynamicTunnelRead wires them
// into state (P81GatewaySubnets/RemoteGatewaySubnets are present on the API
// response but never d.Set by Read for this resource — an omission worth
// flagging on its own, since it means Terraform can never detect drift on
// those two attributes after create).
func testAccCheckEnhancedDynamicTunnelAttributes(tunnel *perimeter81Sdk.EnhancedTunnel, want *testAccEnhancedDynamicTunnelExpectedAttributes) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// The upstream model auto-suffixes the tunnel name with "01" (see the
		// tunnel_name DiffSuppressFunc in resource_enhanced_dynamic_tunnel.go);
		// accept either form rather than hardcoding the suffix as fact.
		if tunnel.TunnelName != want.TunnelNameBase && tunnel.TunnelName != want.TunnelNameBase+"01" {
			return fmt.Errorf("got tunnel_name %q; want %q (optionally with a server-appended \"01\" suffix)", tunnel.TunnelName, want.TunnelNameBase)
		}
		if tunnel.KeyExchange != want.KeyExchange {
			return fmt.Errorf("got key_exchange %q; want %q", tunnel.KeyExchange, want.KeyExchange)
		}
		if got := tunnel.AdvancedSettings.GetIkeLifeTime(); got != want.IkeLifeTime {
			return fmt.Errorf("got ike_life_time %q; want %q", got, want.IkeLifeTime)
		}
		if got := tunnel.AdvancedSettings.GetLifetime(); got != want.Lifetime {
			return fmt.Errorf("got lifetime %q; want %q", got, want.Lifetime)
		}
		if got := tunnel.AdvancedSettings.GetDpdDelay(); got != want.DpdDelay {
			return fmt.Errorf("got dpd_delay %q; want %q — if this fails after an update-only step, "+
				"resourceEnhancedDynamicTunnelUpdate's payload does not include AdvancedSettings, so "+
				"the change never reached the server (suspected bug, see task-32 report)", got, want.DpdDelay)
		}
		if got := tunnel.AdvancedSettings.GetDpdTimeout(); got != want.DpdTimeout {
			return fmt.Errorf("got dpd_timeout %q; want %q — see the dpd_delay note above", got, want.DpdTimeout)
		}
		if !testComparableArraiesEq(tunnel.P81GatewaySubnets, want.P81GatewaySubnets) {
			return fmt.Errorf("got p81_gateway_subnets %q; want %q", tunnel.P81GatewaySubnets, want.P81GatewaySubnets)
		}
		if !testComparableArraiesEq(tunnel.RemoteGatewaySubnets, want.RemoteGatewaySubnets) {
			return fmt.Errorf("got remote_gateway_subnets %q; want %q", tunnel.RemoteGatewaySubnets, want.RemoteGatewaySubnets)
		}
		phase1 := tunnel.AdvancedSettings.GetPhase1()
		if !testComparableArraiesEq(phase1.Auth, want.Phase1.Auth) {
			return fmt.Errorf("got phase1 auth %q; want %q", phase1.Auth, want.Phase1.Auth)
		}
		if !testComparableArraiesEq(phase1.Encryption, want.Phase1.Encryption) {
			return fmt.Errorf("got phase1 encryption %q; want %q", phase1.Encryption, want.Phase1.Encryption)
		}
		if !testComparableArraiesEq(phase1.KeyExchangeMethod, want.Phase1.KeyExchangeMethod) {
			return fmt.Errorf("got phase1 key_exchange_method %q; want %q", phase1.KeyExchangeMethod, want.Phase1.KeyExchangeMethod)
		}
		phase2 := tunnel.AdvancedSettings.GetPhase2()
		if !testComparableArraiesEq(phase2.Auth, want.Phase2.Auth) {
			return fmt.Errorf("got phase2 auth %q; want %q", phase2.Auth, want.Phase2.Auth)
		}
		if !testComparableArraiesEq(phase2.Encryption, want.Phase2.Encryption) {
			return fmt.Errorf("got phase2 encryption %q; want %q", phase2.Encryption, want.Phase2.Encryption)
		}
		if !testComparableArraiesEq(phase2.KeyExchangeMethod, want.Phase2.KeyExchangeMethod) {
			return fmt.Errorf("got phase2 key_exchange_method %q; want %q", phase2.KeyExchangeMethod, want.Phase2.KeyExchangeMethod)
		}
		return nil
	}
}

// testAccCheckEnhancedDynamicTunnelRegionID cross-checks the API's RegionID
// for the first (only) tunnel endpoint against tunnel.0.region_id in
// Terraform state, without hardcoding a tenant-specific region ID.
func testAccCheckEnhancedDynamicTunnelRegionID(n string, tunnel *perimeter81Sdk.EnhancedTunnel) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}
		wantRegionID := rs.Primary.Attributes["tunnel.0.region_id"]
		if wantRegionID == "" {
			return fmt.Errorf("tunnel.0.region_id is empty in state")
		}
		if tunnel.RegionID != wantRegionID {
			return fmt.Errorf("got region_id %q; want %q", tunnel.RegionID, wantRegionID)
		}
		return nil
	}
}

func testAccEnhancedDynamicTunnelConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  selected_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
}

resource "checkpointsase_enhanced_network" "demo" {
  name   = "qa-enh-dyn-tun-%s"
  subnet = "10.94.0.0/22"
  tags   = ["qa-demo"]

  region {
    harmony_sase_region_id = local.selected_region.id
    scale_units            = 1
    idle                   = true
  }
}

resource "checkpointsase_enhanced_dynamic_tunnel" "demo" {
  network_id  = checkpointsase_enhanced_network.demo.id
  tunnel_name = "EnhDynTun1"
  left_asn    = 65000

  tunnel {
    region_id             = one(checkpointsase_enhanced_network.demo.region[*].id)
    auth_type             = "psk"
    passphrase            = "CHANGEMEenhDynamic1"
    remote_public_ip      = "198.51.100.45"
    remote_asn            = 65001
    p81_gw_internal_ip    = "169.254.100.1"
    remote_gw_internal_ip = "169.254.100.2"
  }

  p81_gateway_subnets    = ["0.0.0.0/0"]
  remote_gateway_subnets = ["0.0.0.0/0"]

  key_exchange  = "ikev1"
  ike_life_time = "9h"
  lifetime      = "2h"
  dpd_delay     = "20s"
  dpd_timeout   = "40s"

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
  `
	return fmt.Sprintf(config, randNameEnhancedDynamicTunnel)
}

func testAccEnhancedDynamicTunnelUpdateConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  selected_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
}

resource "checkpointsase_enhanced_network" "demo" {
  name   = "qa-enh-dyn-tun-%s"
  subnet = "10.94.0.0/22"
  tags   = ["qa-demo"]

  region {
    harmony_sase_region_id = local.selected_region.id
    scale_units            = 1
    idle                   = true
  }
}

resource "checkpointsase_enhanced_dynamic_tunnel" "demo" {
  network_id  = checkpointsase_enhanced_network.demo.id
  tunnel_name = "EnhDynTun1"
  left_asn    = 65000

  tunnel {
    region_id             = one(checkpointsase_enhanced_network.demo.region[*].id)
    auth_type             = "psk"
    passphrase            = "CHANGEMEenhDynamic1"
    remote_public_ip      = "198.51.100.45"
    remote_asn            = 65001
    p81_gw_internal_ip    = "169.254.100.1"
    remote_gw_internal_ip = "169.254.100.2"
  }

  p81_gateway_subnets    = ["0.0.0.0/0"]
  remote_gateway_subnets = ["0.0.0.0/0"]

  key_exchange  = "ikev1"
  ike_life_time = "9h"
  lifetime      = "2h"
  dpd_delay     = "35s"
  dpd_timeout   = "45s"

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
  `
	return fmt.Sprintf(config, randNameEnhancedDynamicTunnel)
}
