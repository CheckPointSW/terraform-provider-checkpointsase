package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var randNameGateway string = randStringBytesRmndr()

func TestAccGateway_basic(t *testing.T) {
	t.Parallel()
	var network perimeter81Sdk.Network

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t); testAccPreCheckRegion(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccGatewaysConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNetworkExists("checkpointsase_network.n6", &network),
					testAccCheckGatewaysCount(&network, 2),
				),
			},
			{
				Config: testAccGatewaysUpdate1Config(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNetworkExists("checkpointsase_network.n6", &network),
					testAccCheckGatewaysCount(&network, 1),
				),
			},
			{
				Config: testAccGatewaysUpdate2Config(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNetworkExists("checkpointsase_network.n6", &network),
					testAccCheckGatewaysCount(&network, 2),
				),
			},
		},
	})
}

func testAccCheckGatewaysCount(network *perimeter81Sdk.Network, want int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if len(network.Regions[0].Instances) != want {
			return fmt.Errorf("got gateway count %d; want %d", len(network.Regions[0].Instances), want)
		}

		return nil
	}
}

func testAccGatewaysConfig() string {
	config := `
resource "checkpointsase_network" "n6" {
	network {
		name = "%s"
		tags = ["test"]
	}
	region {
		cpregion_id = "%s"
		idle = true
	}
}

data "checkpointsase_networks" "all5" {
	depends_on = [
    	checkpointsase_network.n6
  	]
}

resource "checkpointsase_gateway"  "g1"{

  gateways {
      name = "%s"
      idle = true
  }

  network_id = checkpointsase_network.n6.id
  region_id = {
    for network in data.checkpointsase_networks.all5.networks :
    network.id => network.regions[0].id
    if network.id == checkpointsase_network.n6.id
  }[checkpointsase_network.n6.id]
}
  `
	return fmt.Sprintf(config, randNameGateway, testAccRegionID(), randNameGateway)
}

func testAccGatewaysUpdate1Config() string {
	config := `
resource "checkpointsase_network" "n6" {
	network {
		name = "%s"
		tags = ["test"]
	}
	region {
		cpregion_id = "%s"
		idle = true
	}
}

data "checkpointsase_networks" "all5" {
	depends_on = [
    	checkpointsase_network.n6
  	]
}

resource "checkpointsase_gateway"  "g1"{

  network_id = checkpointsase_network.n6.id
  region_id = {
    for network in data.checkpointsase_networks.all5.networks :
    network.id => network.regions[0].id
    if network.id == checkpointsase_network.n6.id
  }[checkpointsase_network.n6.id]
}
  `
	return fmt.Sprintf(config, randNameGateway, testAccRegionID())
}
func testAccGatewaysUpdate2Config() string {
	config := `
resource "checkpointsase_network" "n6" {
	network {
		name = "%s"
		tags = ["test"]
	}
	region {
		cpregion_id = "%s"
		idle = true
	}
}

data "checkpointsase_networks" "all5" {
	depends_on = [
    	checkpointsase_network.n6
  	]
}

resource "checkpointsase_gateway"  "g1"{

 gateways {
      name = "%s"
      idle = true
  }

  network_id = checkpointsase_network.n6.id
  region_id = {
    for network in data.checkpointsase_networks.all5.networks :
    network.id => network.regions[0].id
    if network.id == checkpointsase_network.n6.id
  }[checkpointsase_network.n6.id]
}
  `
	return fmt.Sprintf(config, randNameGateway, testAccRegionID(), randNameGateway)
}

/*
TestGatewayReadTreatsAVanishedParentNetworkAsDrift is the gate on SI-D02.

Before Phase 6, Read returned an error when the parent network lookup failed, so
deleting the network out of band left every gateway under it UNREADABLE. `plan`
could not even report that the gateway was gone, and recovering meant a manual
`terraform state rm` per gateway.

The 500 row is the necessary other half. A 404 on this request means the named
network is absent, because the request addresses ONE network by id. A 500 means
the server broke, the network may well still exist, and clearing the id would
tell Terraform to recreate a gateway that is already there. The distinction
between "absent" and "could not tell" is the whole point, and this project
shipped the wrong side of it three times on collection endpoints before naming
it.
*/
func TestGatewayReadTreatsAVanishedParentNetworkAsDrift(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantErr    bool
		wantIDGone bool
	}{
		{"404 means the parent network is gone", http.StatusNotFound,
			`{"message":"Network doesn't exist.","messageCode":"NOT_FOUND","status":404}`, false, true},
		{"500 must not be read as absence", http.StatusInternalServerError,
			`{"message":"boom"}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceGateway().Schema, map[string]interface{}{
				"network_id": "net-gone",
				"region_id":  "reg-1",
			})
			d.SetId("gw-1")

			diags := resourceGatewayRead(context.Background(), d, newTestUserAPIClient(srv.URL))

			if diags.HasError() != tc.wantErr {
				t.Errorf("HasError = %v, want %v: %v", diags.HasError(), tc.wantErr, diags)
			}
			if gone := d.Id() == ""; gone != tc.wantIDGone {
				t.Errorf("id cleared = %v, want %v (id is %q)", gone, tc.wantIDGone, d.Id())
			}
		})
	}
}
