package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var randNameNetwork string = randStringBytesRmndr()
var randNameNetworkUpdated string = randStringBytesRmndr()

func TestAccNetwork_basic(t *testing.T) {
	t.Parallel()
	var network perimeter81Sdk.Network

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t); testAccPreCheckRegion(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccNetworkConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNetworkExists("checkpointsase_network.n", &network),
					testAccCheckNetworkAttributes(&network, &testAccNetworkExpectedAttributes{
						Name: randNameNetwork,
						Tags: []string{"test"},
					}),
				),
			},
			{
				Config: testAccNetworkUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckNetworkExists("checkpointsase_network.n", &network),
					testAccCheckNetworkAttributes(&network, &testAccNetworkExpectedAttributes{
						Name: randNameNetworkUpdated,
						Tags: []string{"test", "updated"},
					}),
				),
			},
		},
	})
}

func testAccCheckNetworkExists(n string, network *perimeter81Sdk.Network) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}

		networkID := rs.Primary.ID
		if networkID == "" {
			return fmt.Errorf("No network ID is set")
		}
		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		ctx := context.Background()
		gotNetwork, _, err := conn.StandardNetworksAPI.StandardNetworksControllerV2NetworkFind(ctx, networkID).Execute()
		if err != nil {
			return err
		}
		*network = *gotNetwork
		return nil
	}
}

type testAccNetworkExpectedAttributes struct {
	Name string
	Tags []string
}

func testAccCheckNetworkAttributes(network *perimeter81Sdk.Network, want *testAccNetworkExpectedAttributes) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if network.Name != want.Name {
			return fmt.Errorf("got name %q; want %q", network.Name, want.Name)
		}

		if !testComparableArraiesEq(network.Tags, want.Tags) {
			return fmt.Errorf("got tags %q; want %q", network.Tags, want.Tags)
		}

		return nil
	}
}

func testAccNetworkConfig() string {
	config := `
resource "checkpointsase_network" "n" {
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

func testAccNetworkUpdateConfig() string {
	config := `
resource "checkpointsase_network" "n" {
	network {
		name = "%s"
		tags = ["test", "updated"]
	}
	region {
		cpregion_id = "%s"
		idle = true
	}
}
  `
	return fmt.Sprintf(config, randNameNetworkUpdated, testAccRegionID())
}

// standardNetworkFixture renders one GET /v3/networks/standard/{networkId}
// body. Every field here is required by Network's requiredProperties loop, so
// a fixture missing any of them fails to decode and the test would be
// measuring the fixture rather than the provider.
func standardNetworkFixture(networkId string) string {
	return fmt.Sprintf(`{
		"createdAt":"2026-09-12T10:00:00.000Z",
		"dns":"net.example.test",
		"subnet":"10.0.0.0/16",
		"accessType":"standard",
		"applications":[],
		"tags":[],
		"name":"net-under-test",
		"isDefault":false,
		"id":%q,
		"tenantId":"tenant-1",
		"regions":[]
	}`, networkId)
}

/*
TestNetworkDeleteWaitsForTheNetworkToActuallyGo is the regression gate on
P81-145380.

WHAT THE BUG WAS. DELETE /v3/networks/standard/{id} answers 202 with its
AsyncOperationResult INLINE -- the deletion is accepted, not done. Delete
discarded that response entirely (`_, _, err :=`), cleared the id and
returned. Two separate failures came out of that one line:

  - A destroy that exits 0 while the network is still on the tenant, so
    re-applying the same configuration collides on the name and fails 409.
    Measured at over seven minutes in the ticket.
  - A deletion the backend COMPLETES WITH A NON-2XX statusCode is reported to
    Terraform as a successful destroy, because nobody looked at the field.
    resourceGatewayDelete and resourceRegionDelete both check it; this did
    not.

WHY NOT POLL A STATUS URL. There isn't one. This endpoint returns
AsyncOperationResult ({resource, statusCode, reason}), not the
AsyncOperationResponse ({statusUrl}) the create and the tunnel deletes return.
Completion can only be observed by re-reading the network until it is absent.

WHY THE LAST CASE MATTERS MOST. A wait that gives up must NOT clear the id.
Clearing it strands the network exactly the way the un-waited delete did,
while reporting success. Keeping the resource in state is what lets a re-run
finish the job.
*/
func TestNetworkDeleteWaitsForTheNetworkToActuallyGo(t *testing.T) {
	t.Run("returns only once the network is absent", func(t *testing.T) {
		var deletes, gets int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodDelete {
				deletes++
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"statusCode":202,"reason":[]}`))
				return
			}
			gets++
			// Still on the tenant on the first read back -- the window the
			// ticket measured at over seven minutes.
			if gets == 1 {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(standardNetworkFixture("net-1")))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Network doesn't exist.","messageCode":"NOT_FOUND","status":404}`))
		}))
		defer srv.Close()

		d := schema.TestResourceDataRaw(t, resourceNetwork().Schema, map[string]interface{}{})
		d.SetId("net-1")

		diags := resourceNetworkDelete(context.Background(), d, newTestUserAPIClient(srv.URL))

		if diags.HasError() {
			t.Fatalf("delete reported an error: %v", diags)
		}
		if deletes != 1 {
			t.Errorf("DELETE called %d times, want exactly 1", deletes)
		}
		// One read would mean the delete returned on the accepted response
		// without ever checking, which is the bug.
		if gets < 2 {
			t.Errorf("network was read back %d time(s); the delete did not wait for it to go", gets)
		}
		if d.Id() != "" {
			t.Errorf("id = %q, want cleared once the network is confirmed gone", d.Id())
		}
	})

	t.Run("a retry after a timed-out wait is not an error", func(t *testing.T) {
		// The sequel to the timeout case below. The first destroy gave up
		// waiting and deliberately kept the id; the backend then finished the
		// deletion, so the retry's DELETE answers 404. If that is reported as
		// an error the resource is wedged in state forever -- the exact thing
		// keeping the id was meant to prevent.
		var gets int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method != http.MethodDelete {
				gets++
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Network doesn't exist.","messageCode":"NOT_FOUND","status":404}`))
		}))
		defer srv.Close()

		d := schema.TestResourceDataRaw(t, resourceNetwork().Schema, map[string]interface{}{})
		d.SetId("net-1")

		diags := resourceNetworkDelete(context.Background(), d, newTestUserAPIClient(srv.URL))

		if diags.HasError() {
			t.Fatalf("a 404 on an already-deleted network was reported as a failure: %v", diags)
		}
		if d.Id() != "" {
			t.Errorf("id = %q, want cleared; the network is gone, which is the goal state", d.Id())
		}
		if gets != 0 {
			t.Errorf("polled %d time(s) for a network the DELETE already said was absent", gets)
		}
	})

	t.Run("a completed-but-rejected delete is not success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodDelete {
				// A 2xx TRANSPORT status carrying a failed operation in the
				// body. Checking only `err` sails straight past this.
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"statusCode":409,"reason":["network has attached tunnels"]}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(standardNetworkFixture("net-1")))
		}))
		defer srv.Close()

		d := schema.TestResourceDataRaw(t, resourceNetwork().Schema, map[string]interface{}{})
		d.SetId("net-1")

		diags := resourceNetworkDelete(context.Background(), d, newTestUserAPIClient(srv.URL))

		if !diags.HasError() {
			t.Fatal("a 409 completion was reported to Terraform as a successful destroy")
		}
		if d.Id() == "" {
			t.Error("id was cleared on a rejected delete; the network is now orphaned with nothing to reconcile it")
		}
		if !strings.Contains(diags[0].Detail, "network has attached tunnels") {
			t.Errorf("diagnostic %q drops the reason the server gave", diags[0].Detail)
		}
	})

	t.Run("a network that never goes is an error, and stays in state", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"statusCode":202,"reason":[]}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(standardNetworkFixture("net-1")))
		}))
		defer srv.Close()

		d := schema.TestResourceDataRaw(t, resourceNetwork().Schema, map[string]interface{}{})
		d.SetId("net-1")

		// Stands in for the Delete timeout Terraform puts on the context.
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		diags := resourceNetworkDelete(ctx, d, newTestUserAPIClient(srv.URL))

		if !diags.HasError() {
			t.Fatal("delete reported success while the network was still on the tenant")
		}
		if d.Id() == "" {
			t.Error("id was cleared on a failed wait; the network is now orphaned with nothing to reconcile it")
		}
		if !strings.Contains(diags[0].Detail, "net-1") {
			t.Errorf("diagnostic %q does not name the network it gave up on", diags[0].Detail)
		}
	})
}

/*
TestNetworkImportStateErrorsOnMissingId pins P81-145138 for the direct-GET
import path: importing an id the server 404s on must fail with an error
naming the id, not silently produce a zero-value resource via d.SetId("").
*/
func TestNetworkImportStateErrorsOnMissingId(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Network doesn't exist.","messageCode":"NOT_FOUND","status":404}`))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceNetwork().Schema, map[string]interface{}{})
	d.SetId("net-missing")

	_, err := ResourceNetworkImportState(context.Background(), d, newTestUserAPIClient(srv.URL))

	if err == nil {
		t.Fatal("expected an error importing a nonexistent id, got nil")
	}
	if !strings.Contains(err.Error(), "net-missing") {
		t.Errorf("error %q does not name the missing id", err.Error())
	}
	if d.Id() != "" {
		t.Errorf("id = %q, want empty: a failed import must not leave a partial resource behind", d.Id())
	}
}
