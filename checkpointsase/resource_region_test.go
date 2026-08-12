package checkpointsase

import (
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var randNameRegion string = randStringBytesRmndr()

func TestAccRegion_basic(t *testing.T) {
	t.Parallel()
	var network perimeter81Sdk.Network

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccPreCheckSecondaryRegion(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccRegionsConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNetworkExists("checkpointsase_network.n5", &network),
					testAccCheckRegionsCount(&network, 1),
				),
			},
			{
				Config: testAccRegionsUpdate1Config(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNetworkExists("checkpointsase_network.n5", &network),
					testAccCheckRegionsCount(&network, 2),
				),
			},
			{
				Config: testAccRegionsUpdate2Config(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNetworkExists("checkpointsase_network.n5", &network),
					testAccCheckRegionsCount(&network, 1),
				),
			},
		},
	})
}

func testAccCheckRegionsCount(network *perimeter81Sdk.Network, want int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if len(network.Regions) != want {
			return fmt.Errorf("got region count %d; want %d", len(network.Regions), want)
		}

		return nil
	}
}

func testAccRegionsConfig() string {
	config := `
resource "checkpointsase_network" "n5" {
	network {
		name = "%s"
		tags = ["test"]
	}
	region {
		cpregion_id = "%s"
		idle = true
	}
}
  `
	return fmt.Sprintf(config, randNameNetwork, testAccRegionID())
}

func testAccRegionsUpdate1Config() string {
	config := `
resource "checkpointsase_network" "n5" {
	network {
		name = "%s"
		tags = ["test"]
	}
	region {
		cpregion_id = "%s"
		idle = true
	}
	region {
    	cpregion_id = "%s"
    	idle = true
  	}
}
  `
	return fmt.Sprintf(config, randNameRegion, testAccRegionID(), testAccRegionID2())
}
func testAccRegionsUpdate2Config() string {
	config := `
resource "checkpointsase_network" "n5" {
	network {
		name = "%s"
		tags = ["test"]
	}
	region {
		cpregion_id = "%s"
		idle = true
	}
}
  `
	return fmt.Sprintf(config, randNameRegion, testAccRegionID())
}
