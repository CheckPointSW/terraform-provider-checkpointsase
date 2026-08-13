package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var randNameEnhancedStaticTunnel string = randStringBytesRmndr()

// TestAccEnhancedStaticTunnel_basic is the first live exercise of
// checkpointsase_enhanced_static_tunnel. It builds an enhanced network with
// one region, attaches a static IPsec tunnel against a fake remote peer
// (TEST-NET-2, RFC 5737 — this test is about the Terraform lifecycle, not a
// working IKE session), confirms the tunnel exists server-side with the
// configured settings, then updates the timing knobs (ike_life_time,
// lifetime, dpd_delay, dpd_timeout) and tunnel_name in place and confirms
// they round-trip through a fresh GET.
//
// passphrase is an obviously fake placeholder, lifted from the validated
// demo/enhanced_static_tunnel/main.tf config along with the rest of the HCL.
// It is intentionally excluded from the attribute assertions below:
// resourceEnhancedStaticTunnelRead never calls d.Set for passphrase (the
// same write-only treatment resource_openvpn.go gives secret_access_key),
// so asserting on it here would risk repeating the exact mistake flagged in
// TestAccOpenvpn_basic's history — a check that could never pass because
// the value it compares against was never actually populated by the read
// path being tested.
func TestAccEnhancedStaticTunnel_basic(t *testing.T) {
	var tunnel perimeter81Sdk.EnhancedTunnel

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccEnhancedStaticTunnelConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedStaticTunnelExists("checkpointsase_enhanced_static_tunnel.demo", &tunnel),
					testAccCheckEnhancedStaticTunnelAttributes(&tunnel, &testAccEnhancedStaticTunnelExpectedAttributes{
						TunnelName:           "EnhStaticTun1",
						AuthType:             "psk",
						KeyExchange:          "ikev1",
						IkeLifeTime:          "9h",
						Lifetime:             "2h",
						DpdDelay:             "20s",
						DpdTimeout:           "40s",
						P81GatewaySubnets:    []string{"0.0.0.0/0"},
						RemoteGatewaySubnets: []string{"0.0.0.0/0"},
						PeakBandwidthMbps:    1000,
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
					testAccCheckEnhancedStaticTunnelRegionID("checkpointsase_enhanced_static_tunnel.demo", &tunnel),
					// remote_id is documented ("The remote gateway ID. When
					// omitted, the server defaults this to remote_public_ip;
					// the provider reads the server-assigned value back into
					// state.") but resourceEnhancedStaticTunnelRead never
					// calls d.Set for remote_id, and EnhancedTunnel (the v3
					// read shape) has no RemoteID field to read it from at
					// all. This assertion is expected to fail live —
					// suspected bug, see task-32 report.
					testAccCheckEnhancedStaticTunnelRemoteIDInState("checkpointsase_enhanced_static_tunnel.demo"),
				),
			},
			{
				Config: testAccEnhancedStaticTunnelUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedStaticTunnelExists("checkpointsase_enhanced_static_tunnel.demo", &tunnel),
					testAccCheckEnhancedStaticTunnelAttributes(&tunnel, &testAccEnhancedStaticTunnelExpectedAttributes{
						TunnelName:           "EnhStaticTun2",
						AuthType:             "psk",
						KeyExchange:          "ikev1",
						IkeLifeTime:          "10h",
						Lifetime:             "3h",
						DpdDelay:             "30s",
						DpdTimeout:           "50s",
						P81GatewaySubnets:    []string{"0.0.0.0/0"},
						RemoteGatewaySubnets: []string{"0.0.0.0/0"},
						PeakBandwidthMbps:    1000,
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

// testAccCheckEnhancedStaticTunnelExists fetches the tunnel directly from
// the API by network_id + tunnel id from state, so this fails if Create
// never actually produced a server-side tunnel.
func testAccCheckEnhancedStaticTunnelExists(n string, tunnel *perimeter81Sdk.EnhancedTunnel) resource.TestCheckFunc {
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
		got, _, err := conn.EnhancedTunnelsAPI.GetStaticTunnel(ctx, networkId, tunnelId).Execute()
		if err != nil {
			return err
		}
		*tunnel = *got
		return nil
	}
}

type testAccEnhancedStaticTunnelExpectedAttributes struct {
	TunnelName           string
	AuthType             string
	KeyExchange          string
	IkeLifeTime          string
	Lifetime             string
	DpdDelay             string
	DpdTimeout           string
	P81GatewaySubnets    []string
	RemoteGatewaySubnets []string
	PeakBandwidthMbps    int32
	Phase1               perimeter81Sdk.IPSecPhaseConfigV23
	Phase2               perimeter81Sdk.IPSecPhaseConfigV23
}

// testAccCheckEnhancedStaticTunnelAttributes only compares fields the read
// path actually populates (resourceEnhancedStaticTunnelRead sets all of
// these from GetStaticTunnel's response) against what was configured.
func testAccCheckEnhancedStaticTunnelAttributes(tunnel *perimeter81Sdk.EnhancedTunnel, want *testAccEnhancedStaticTunnelExpectedAttributes) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if tunnel.TunnelName != want.TunnelName {
			return fmt.Errorf("got tunnel_name %q; want %q", tunnel.TunnelName, want.TunnelName)
		}
		if tunnel.AuthType != want.AuthType {
			return fmt.Errorf("got auth_type %q; want %q", tunnel.AuthType, want.AuthType)
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
			return fmt.Errorf("got dpd_delay %q; want %q", got, want.DpdDelay)
		}
		if got := tunnel.AdvancedSettings.GetDpdTimeout(); got != want.DpdTimeout {
			return fmt.Errorf("got dpd_timeout %q; want %q", got, want.DpdTimeout)
		}
		if !testComparableArraiesEq(tunnel.P81GatewaySubnets, want.P81GatewaySubnets) {
			return fmt.Errorf("got p81_gateway_subnets %q; want %q", tunnel.P81GatewaySubnets, want.P81GatewaySubnets)
		}
		if !testComparableArraiesEq(tunnel.RemoteGatewaySubnets, want.RemoteGatewaySubnets) {
			return fmt.Errorf("got remote_gateway_subnets %q; want %q", tunnel.RemoteGatewaySubnets, want.RemoteGatewaySubnets)
		}
		if tunnel.PeakBandwidthMbps == nil || *tunnel.PeakBandwidthMbps != want.PeakBandwidthMbps {
			return fmt.Errorf("got peak_bandwidth %v; want %d", tunnel.PeakBandwidthMbps, want.PeakBandwidthMbps)
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

// testAccCheckEnhancedStaticTunnelRegionID cross-checks the API's RegionID
// against the region_id Terraform recorded in state, without hardcoding a
// tenant-specific region ID: the enhanced network's region ID is
// server-assigned at create time, so the only stable expectation is that it
// matches what the tunnel resource itself was configured with.
func testAccCheckEnhancedStaticTunnelRegionID(n string, tunnel *perimeter81Sdk.EnhancedTunnel) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}
		wantRegionID := rs.Primary.Attributes["region_id"]
		if wantRegionID == "" {
			return fmt.Errorf("region_id is empty in state")
		}
		if tunnel.RegionID != wantRegionID {
			return fmt.Errorf("got region_id %q; want %q", tunnel.RegionID, wantRegionID)
		}
		return nil
	}
}

// testAccCheckEnhancedStaticTunnelRemoteIDInState reads remote_id from
// Terraform STATE rather than the API — per the assertion rules, a value
// only available at create/read time must be checked against state, not
// re-derived from a live API call the schema doesn't actually guarantee
// returns it. See the TestAccEnhancedStaticTunnel_basic doc comment for why
// this is expected to fail live.
func testAccCheckEnhancedStaticTunnelRemoteIDInState(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}
		remoteID := rs.Primary.Attributes["remote_id"]
		if remoteID == "" {
			return fmt.Errorf("remote_id is empty in state; the schema documents that the server " +
				"defaults remote_id to remote_public_ip and the provider reads the assigned value " +
				"back, but resourceEnhancedStaticTunnelRead never sets remote_id and EnhancedTunnel " +
				"(the v3 read shape) has no RemoteID field to read it from")
		}
		return nil
	}
}

func testAccEnhancedStaticTunnelConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  selected_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
}

resource "checkpointsase_enhanced_network" "demo" {
  name   = "qa-enh-static-tun-%s"
  subnet = "10.93.0.0/22"
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
  tunnel_name = "EnhStaticTun1"

  auth_type        = "psk"
  passphrase       = "CHANGEMEenhStatic1"
  remote_public_ip = "198.51.100.43"
  remote_id        = "198.51.100.43"

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
  `
	return fmt.Sprintf(config, randNameEnhancedStaticTunnel)
}

func testAccEnhancedStaticTunnelUpdateConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  selected_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
}

resource "checkpointsase_enhanced_network" "demo" {
  name   = "qa-enh-static-tun-%s"
  subnet = "10.93.0.0/22"
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
  tunnel_name = "EnhStaticTun2"

  auth_type        = "psk"
  passphrase       = "CHANGEMEenhStatic1"
  remote_public_ip = "198.51.100.43"
  remote_id        = "198.51.100.43"

  key_exchange  = "ikev1"
  ike_life_time = "10h"
  lifetime      = "3h"
  dpd_delay     = "30s"
  dpd_timeout   = "50s"

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
  `
	return fmt.Sprintf(config, randNameEnhancedStaticTunnel)
}
