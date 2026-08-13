package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var randNameEnhancedRegion string = randStringBytesRmndr()

// TestAccEnhancedRegion_basic is the first live exercise of
// checkpointsase_enhanced_region. It builds an enhanced network with its
// first region declared inline, adds a second region via
// checkpointsase_enhanced_region, confirms it exists server-side with the
// configured scale_units/idle, then exercises the Update path by bumping
// scale_units (the only in-place-mutable attribute — network_id,
// harmony_sase_region_id, and idle are all ForceNew) and confirms the
// increase round-trips through a fresh GET.
//
// The second region ID comes from the checkpointsase_enhanced_regions data
// source's catalogue (falling back to the same region if the tenant only
// has one, which may be rejected server-side as a duplicate) — this
// fallback logic is lifted verbatim from the validated
// demo/enhanced_region/main.tf config, which explicitly documents the same
// risk given this resource has never been run live before.
func TestAccEnhancedRegion_basic(t *testing.T) {
	var region perimeter81Sdk.EnhancedRegion

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccEnhancedRegionConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedRegionExists("checkpointsase_enhanced_region.second", &region),
					testAccCheckEnhancedRegionAttributes(&region, &testAccEnhancedRegionExpectedAttributes{
						ScaleUnits: 1,
						Idle:       true,
					}),
				),
			},
			{
				Config: testAccEnhancedRegionUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEnhancedRegionExists("checkpointsase_enhanced_region.second", &region),
					testAccCheckEnhancedRegionAttributes(&region, &testAccEnhancedRegionExpectedAttributes{
						ScaleUnits: 2,
						Idle:       true,
					}),
				),
			},
		},
	})
}

// testAccCheckEnhancedRegionExists fetches the region directly from the API
// using both network_id and the region's own ID from state, so this fails
// if CreateEnhancedRegion never actually produced a server-side region.
func testAccCheckEnhancedRegionExists(n string, region *perimeter81Sdk.EnhancedRegion) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}

		regionId := rs.Primary.ID
		if regionId == "" {
			return fmt.Errorf("No enhanced region id is set")
		}
		networkId := rs.Primary.Attributes["network_id"]
		if networkId == "" {
			return fmt.Errorf("No network_id is set on %s", n)
		}
		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		ctx := context.Background()
		got, _, err := conn.EnhancedRegionsAPI.GetEnhancedRegion(ctx, networkId, regionId).Execute()
		if err != nil {
			return err
		}
		*region = *got
		return nil
	}
}

type testAccEnhancedRegionExpectedAttributes struct {
	ScaleUnits int32
	Idle       bool
}

// testAccCheckEnhancedRegionAttributes checks fields the read path actually
// populates: resourceEnhancedRegionRead sets scale_units unconditionally and
// idle whenever the server includes RunningMode. A missing RunningMode is
// treated as a failure here (rather than silently skipped) because we
// explicitly configured idle and expect the server to confirm it.
func testAccCheckEnhancedRegionAttributes(region *perimeter81Sdk.EnhancedRegion, want *testAccEnhancedRegionExpectedAttributes) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if region.ScaleUnits != want.ScaleUnits {
			return fmt.Errorf("got scale_units %d; want %d", region.ScaleUnits, want.ScaleUnits)
		}
		if region.Attributes.RunningMode == nil {
			return fmt.Errorf("got nil running_mode attributes; cannot verify idle")
		}
		if region.Attributes.RunningMode.Idle != want.Idle {
			return fmt.Errorf("got idle %v; want %v", region.Attributes.RunningMode.Idle, want.Idle)
		}
		return nil
	}
}

func testAccEnhancedRegionConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  first_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
  # Prefer a second, distinct region if the tenant's catalogue offers one, so
  # this test actually exercises "add a region to an existing network"
  # rather than colliding with the first region. Falls back to the same
  # region if the tenant only has one — that may be rejected server-side as
  # a duplicate, which is plausible given this resource has never been run
  # against a live tenant.
  second_region = length(data.checkpointsase_enhanced_regions.catalog.regions) > 1 ? (
    data.checkpointsase_enhanced_regions.catalog.regions[1]
  ) : local.first_region
}

resource "checkpointsase_enhanced_network" "demo" {
  name   = "qa-enh-region-%s"
  subnet = "10.91.0.0/22"
  tags   = ["qa-demo"]

  region {
    harmony_sase_region_id = local.first_region.id
    scale_units            = 1
    idle                   = true
  }
}

resource "checkpointsase_enhanced_region" "second" {
  network_id             = checkpointsase_enhanced_network.demo.id
  harmony_sase_region_id = local.second_region.id
  scale_units            = 1
  idle                   = true
}
  `
	return fmt.Sprintf(config, randNameEnhancedRegion)
}

func testAccEnhancedRegionUpdateConfig() string {
	config := `
data "checkpointsase_enhanced_regions" "catalog" {}

locals {
  first_region = data.checkpointsase_enhanced_regions.catalog.regions[0]
  second_region = length(data.checkpointsase_enhanced_regions.catalog.regions) > 1 ? (
    data.checkpointsase_enhanced_regions.catalog.regions[1]
  ) : local.first_region
}

resource "checkpointsase_enhanced_network" "demo" {
  name   = "qa-enh-region-%s"
  subnet = "10.91.0.0/22"
  tags   = ["qa-demo"]

  region {
    harmony_sase_region_id = local.first_region.id
    scale_units            = 1
    idle                   = true
  }
}

resource "checkpointsase_enhanced_region" "second" {
  network_id             = checkpointsase_enhanced_network.demo.id
  harmony_sase_region_id = local.second_region.id
  scale_units            = 2
  idle                   = true
}
  `
	return fmt.Sprintf(config, randNameEnhancedRegion)
}
