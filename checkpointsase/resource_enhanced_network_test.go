package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var randNameEnhancedNetwork string = randStringBytesRmndr()

// TestAccEnhancedNetwork_basic is the first live exercise of
// checkpointsase_enhanced_network — it has shipped since v3.0.0 but has
// never run against a real tenant. It creates a single-region enhanced
// network, confirms the object exists server-side with the name/subnet/tags
// it was given, then updates name+tags in place (subnet is ForceNew and is
// deliberately left unchanged across steps) and confirms the update
// round-trips through a fresh GET.
//
// harmony_sase_region_id comes from the checkpointsase_enhanced_regions data
// source rather than testAccRegionID(): enhanced networks draw from a
// distinct region catalogue from checkpointsase_regions (used by the
// standard checkpointsase_network resource) — see the validated config at
// demo/enhanced_network/main.tf, which this test's HCL is lifted from.
func TestAccEnhancedNetwork_basic(t *testing.T) {
	var network perimeter81Sdk.EnhancedNetwork

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccEnhancedNetworkConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedNetworkExists("checkpointsase_enhanced_network.demo", &network),
					testAccCheckEnhancedNetworkAttributes(&network, &testAccEnhancedNetworkExpectedAttributes{
						Name:   fmt.Sprintf("qa-enh-net-%s", randNameEnhancedNetwork),
						Subnet: "10.90.0.0/22",
						Tags:   []string{"qa-demo"},
					}),
				),
			},
			{
				Config: testAccEnhancedNetworkUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedNetworkExists("checkpointsase_enhanced_network.demo", &network),
					testAccCheckEnhancedNetworkAttributes(&network, &testAccEnhancedNetworkExpectedAttributes{
						Name:   fmt.Sprintf("qa-enh-net-%s-upd", randNameEnhancedNetwork),
						Subnet: "10.90.0.0/22",
						Tags:   []string{"qa-demo", "updated"},
					}),
				),
			},
		},
	})
}

// testAccCheckEnhancedNetworkExists fetches the network directly from the
// API by the ID Terraform recorded, so this fails if Create never actually
// produced a server-side object (as opposed to merely not erroring).
func testAccCheckEnhancedNetworkExists(n string, network *perimeter81Sdk.EnhancedNetwork) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}

		networkId := rs.Primary.ID
		if networkId == "" {
			return fmt.Errorf("No enhanced network id is set")
		}
		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		ctx := context.Background()
		got, _, err := conn.EnhancedNetworksAPI.GetEnhancedNetwork(ctx, networkId).Execute()
		if err != nil {
			return err
		}
		*network = *got
		return nil
	}
}

type testAccEnhancedNetworkExpectedAttributes struct {
	Name   string
	Subnet string
	Tags   []string
}

// testAccCheckEnhancedNetworkAttributes compares fields the read path
// actually populates (resourceEnhancedNetworkRead sets name, subnet, and
// tags straight from GetEnhancedNetwork) against what was configured, so a
// resource that silently drops one of these on create or update fails here.
func testAccCheckEnhancedNetworkAttributes(network *perimeter81Sdk.EnhancedNetwork, want *testAccEnhancedNetworkExpectedAttributes) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if network.Name != want.Name {
			return fmt.Errorf("got name %q; want %q", network.Name, want.Name)
		}
		if network.Subnet != want.Subnet {
			return fmt.Errorf("got subnet %q; want %q", network.Subnet, want.Subnet)
		}
		if !testComparableArraiesEq(network.Tags, want.Tags) {
			return fmt.Errorf("got tags %q; want %q", network.Tags, want.Tags)
		}
		return nil
	}
}

func testAccEnhancedNetworkConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  selected_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
}

resource "checkpointsase_enhanced_network" "demo" {
  name   = "qa-enh-net-%s"
  subnet = "10.90.0.0/22"
  tags   = ["qa-demo"]

  region {
    harmony_sase_region_id = local.selected_region.id
    scale_units            = 1
    idle                   = true
  }
}
  `
	return fmt.Sprintf(config, randNameEnhancedNetwork)
}

func testAccEnhancedNetworkUpdateConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  selected_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
}

resource "checkpointsase_enhanced_network" "demo" {
  name   = "qa-enh-net-%s-upd"
  subnet = "10.90.0.0/22"
  tags   = ["qa-demo", "updated"]

  region {
    harmony_sase_region_id = local.selected_region.id
    scale_units            = 1
    idle                   = true
  }
}
  `
	return fmt.Sprintf(config, randNameEnhancedNetwork)
}
