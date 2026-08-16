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
// Step 2 changes only dpd_delay/dpd_timeout. It was written to expose the
// defect that resourceEnhancedDynamicTunnelUpdate sent only TunnelName and
// description, so neither field ever reached the server and both the
// framework's automatic post-apply "second plan should be empty" check
// (ExpectNonEmptyPlan is deliberately left unset) and the explicit
// dpd_delay/dpd_timeout assertion in
// testAccCheckEnhancedDynamicTunnelAttributes were expected to fail live
// (task-32 report). The update path now sends both fields, nested under
// `advancedSettings`, and waits for the async operation to complete before
// re-reading — so this step is expected to PASS. If it fails on dpd_delay or
// dpd_timeout, the first thing to check is whether the server actually wants
// those fields nested there: that nesting comes from the generated model and
// has never been confirmed against a live response, and the sibling READ
// shape was wrong in exactly this way until SDK overlay A19. See the task-35
// report.
//
// Step 2 is also what found the compounding-name defect on 2026-08-16: the
// tunnel_name assertion came back "EnhDynTun10101" where "EnhDynTun1" or
// "EnhDynTun101" was expected. Read had been storing the server's decorated
// name and a DiffSuppressFunc hid the difference, which left the decorated name
// in place for the apply, so Update sent it and the server decorated it again —
// two characters per apply against a 15-character cap. Fixed by reconciling in
// Read; see dynamicTunnelNameForState and the offline lifecycle tests in
// resource_enhanced_dynamic_tunnel_name_test.go.
//
// Note that step 2 leaves the `tunnel` block untouched. That is not
// incidental: changing an existing endpoint is refused by the provider (no
// server-side endpoint id is obtainable — see planDynamicTunnelEndpointChanges),
// so a step that edited one would fail by design.
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
					// State must hold the name the config asked for, not the
					// decorated one the server reports. This is the other half
					// of the check above: the server-side assertion catches the
					// name growing, this catches the reason it grew.
					resource.TestCheckResourceAttr("checkpointsase_enhanced_dynamic_tunnel.demo", "tunnel_name", "EnhDynTun1"),
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
					resource.TestCheckResourceAttr("checkpointsase_enhanced_dynamic_tunnel.demo", "tunnel_name", "EnhDynTun1"),
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

// testAccCheckEnhancedDynamicTunnelAttributes compares the server's view of
// the tunnel against what the configuration asked for. Every field it checks
// is now also wired into state by resourceEnhancedDynamicTunnelRead —
// P81GatewaySubnets/RemoteGatewaySubnets used to be present on the API
// response but never d.Set by this resource's Read, so Terraform could not
// detect drift on either after create; both now go through
// setEnhancedTunnelSharedSubnetState.
func testAccCheckEnhancedDynamicTunnelAttributes(tunnel *perimeter81Sdk.EnhancedTunnel, want *testAccEnhancedDynamicTunnelExpectedAttributes) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// The upstream model derives the endpoint's interface name by appending
		// "01" to the tunnel name (see dynamicTunnelNameForState in
		// resource_enhanced_dynamic_tunnel.go); accept either form rather than
		// hardcoding the suffix as fact.
		//
		// This assertion is what caught the compounding-name defect live: after
		// one update the server held "EnhDynTun10101", because Read had stored
		// the decorated name and Update sent it back to be decorated again.
		// Nothing weaker than "exactly the base name, or exactly the base name
		// plus one suffix" would have noticed.
		if !dynamicTunnelNameIsDerivedFrom(tunnel.TunnelName, want.TunnelNameBase) {
			return fmt.Errorf("got tunnel_name %q; want %q (optionally with a server-appended \"01\" suffix). "+
				"A name with more than one suffix means the provider sent the server's decorated name back to it — "+
				"see dynamicTunnelNameForState", tunnel.TunnelName, want.TunnelNameBase)
		}
		if tunnel.KeyExchange != want.KeyExchange {
			return fmt.Errorf("got key_exchange %q; want %q", tunnel.KeyExchange, want.KeyExchange)
		}
		if got := tunnel.GetIkeLifeTime(); got != want.IkeLifeTime {
			return fmt.Errorf("got ike_life_time %q; want %q", got, want.IkeLifeTime)
		}
		if got := tunnel.GetLifetime(); got != want.Lifetime {
			return fmt.Errorf("got lifetime %q; want %q", got, want.Lifetime)
		}
		if got := tunnel.GetDpdDelay(); got != want.DpdDelay {
			return fmt.Errorf("got dpd_delay %q; want %q — if this fails after an update-only step, the update body's "+
				"`advancedSettings` nesting is the first suspect: it comes from the generated model and has not been "+
				"confirmed against a live response (see the task-35 report)", got, want.DpdDelay)
		}
		if got := tunnel.GetDpdTimeout(); got != want.DpdTimeout {
			return fmt.Errorf("got dpd_timeout %q; want %q — see the dpd_delay note above", got, want.DpdTimeout)
		}
		if !testComparableArraiesEq(tunnel.P81GatewaySubnets, want.P81GatewaySubnets) {
			return fmt.Errorf("got p81_gateway_subnets %q; want %q", tunnel.P81GatewaySubnets, want.P81GatewaySubnets)
		}
		if !testComparableArraiesEq(tunnel.RemoteGatewaySubnets, want.RemoteGatewaySubnets) {
			return fmt.Errorf("got remote_gateway_subnets %q; want %q", tunnel.RemoteGatewaySubnets, want.RemoteGatewaySubnets)
		}
		phase1 := tunnel.GetPhase1()
		if !testComparableArraiesEq(phase1.Auth, want.Phase1.Auth) {
			return fmt.Errorf("got phase1 auth %q; want %q", phase1.Auth, want.Phase1.Auth)
		}
		if !testComparableArraiesEq(phase1.Encryption, want.Phase1.Encryption) {
			return fmt.Errorf("got phase1 encryption %q; want %q", phase1.Encryption, want.Phase1.Encryption)
		}
		if !testComparableArraiesEq(phase1.KeyExchangeMethod, want.Phase1.KeyExchangeMethod) {
			return fmt.Errorf("got phase1 key_exchange_method %q; want %q", phase1.KeyExchangeMethod, want.Phase1.KeyExchangeMethod)
		}
		phase2 := tunnel.GetPhase2()
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
