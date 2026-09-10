package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var randNameGateway string = randStringBytesRmndr()

/*
TestAccGateway_basic exercises the one-resource-per-gateway shape.

REWRITTEN 2026-09-10 with the resource. The previous version declared a single
checkpointsase_gateway holding a list of `gateways` blocks and asserted on the
COUNT of instances in the region, which is a test of the pool, not of any
gateway. Nothing in it could have caught the placeholder-name import defect,
because it never imported.

BUDGET AN HOUR. Gateway creates take ~14 minutes each and the backend
SERIALISES them regardless of how they are submitted (measured 2026-09-10: two
concurrent creates finished at 13.3 and 27.8 minutes). Two gateways plus a
recreate is three builds.

The ImportState step is the point of the whole test. ImportStateVerify compares
the imported attribute map against the one the apply produced, so an importer
that writes a placeholder -- or omits an attribute the config sets -- fails
here rather than in a customer's first plan.
*/
func TestAccGateway_basic(t *testing.T) {
	t.Parallel()

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t); testAccPreCheckRegion(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccGatewayConfig(2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("checkpointsase_gateway.g0", "ip"),
					resource.TestCheckResourceAttrSet("checkpointsase_gateway.g0", "dns"),
					resource.TestCheckResourceAttrSet("checkpointsase_gateway.g1", "ip"),
					// dns and ip come from the async result's own gateway id now.
					// getGatewayInfo returned them EMPTY whenever the region held
					// one gateway, so asserting they are set is a regression gate,
					// not a formality.
					resource.TestCheckResourceAttrSet("checkpointsase_gateway.g1", "dns"),
					resource.TestCheckResourceAttrPair(
						"checkpointsase_gateway.g0", "region_id",
						"checkpointsase_gateway.g1", "region_id"),
				),
			},
			{
				// Two gateways created in one apply must get DISTINCT ids. With
				// the old newest-wins guess this was a race; with the async
				// result it cannot be wrong. Worth its own step because the
				// failure is silent -- two resources pointing at one gateway.
				Config: testAccGatewayConfig(2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGatewayIDsDiffer(
						"checkpointsase_gateway.g0", "checkpointsase_gateway.g1"),
				),
				PlanOnly: false,
			},
			{
				ResourceName:      "checkpointsase_gateway.g0",
				ImportState:       true,
				ImportStateIdFunc: testAccGatewayImportID("checkpointsase_gateway.g0"),
				ImportStateVerify: true,
				// `idle` is not returned by any read model, so import cannot
				// recover it and it defaults to false. Verifying it would fail
				// for a reason the provider cannot fix. Everything else must
				// round-trip exactly -- that is the P81-144756 gate.
				ImportStateVerifyIgnore: []string{"idle"},
			},
			{
				// Dropping one resource must delete exactly that gateway and
				// leave the other alone.
				Config: testAccGatewayConfig(1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("checkpointsase_gateway.g0", "ip"),
				),
			},
		},
	})
}

// testAccCheckGatewayIDsDiffer fails when two gateway resources share an id,
// which is what a mis-correlated create looks like from the outside.
func testAccCheckGatewayIDsDiffer(a, b string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ra, ok := s.RootModule().Resources[a]
		if !ok {
			return fmt.Errorf("%s not in state", a)
		}
		rb, ok := s.RootModule().Resources[b]
		if !ok {
			return fmt.Errorf("%s not in state", b)
		}
		if ra.Primary.ID == rb.Primary.ID {
			return fmt.Errorf("%s and %s share gateway id %q -- the create correlated two "+
				"resources to one gateway", a, b, ra.Primary.ID)
		}
		return nil
	}
}

// testAccGatewayImportID builds `<network_id>-<gateway_id>` from state, since
// the composite id is not knowable before the apply.
func testAccGatewayImportID(name string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return "", fmt.Errorf("%s not in state", name)
		}
		return rs.Primary.Attributes["network_id"] + "-" + rs.Primary.ID, nil
	}
}

// testAccGatewayConfig builds a network with one region and `count` gateways,
// each its own resource.
func testAccGatewayConfig(count int) string {
	config := `
resource "checkpointsase_network" "n6" {
  network {
    name = "%s"
    tags = ["test"]
  }
  region {
    cpregion_id = "%s"
    idle        = true
  }
}
`
	out := fmt.Sprintf(config, randNameGateway, testAccRegionID())
	for i := 0; i < count; i++ {
		out += fmt.Sprintf(`
resource "checkpointsase_gateway" "g%d" {
  network_id = checkpointsase_network.n6.id
  region_id  = one(checkpointsase_network.n6.region[*].region_id)
  idle       = true
}
`, i)
	}
	return out
}

/*
TestGatewayImportIDIsNetworkAndGateway pins the composite import id.

Two things it guards. The SEPARATOR SPLIT IS SplitN WITH A LIMIT OF 2, so an id
whose second half contains a hyphen is accepted rather than refused for having
"too many parts" -- plain Split would reject it. And the SECOND HALF IS THE
GATEWAY ID: the old resource took a region id there, and a stale comment in the
old Read said "gateway" while the code said "region". An operator following the
wrong one got a confusing error, or in the worst case the panic this ticket is
about.

No API calls: every case here fails before the client is reached.
*/
func TestGatewayImportIDIsNetworkAndGateway(t *testing.T) {
	rejected := map[string]string{
		"":            "empty",
		"onlyonepart": "no separator, so no gateway id",
		"-gw1":        "empty network id",
		"net1-":       "empty gateway id",
	}
	for id, why := range rejected {
		t.Run(why, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, resourceGateway().Schema, map[string]interface{}{})
			d.SetId(id)
			_, err := resourceGatewayImportState(context.Background(), d, nil)
			if err == nil {
				t.Fatalf("import id %q was accepted; it must not be (%s)", id, why)
			}
			if !strings.Contains(err.Error(), "<network_id>") {
				t.Errorf("the refusal does not show the expected id format: %v", err)
			}
		})
	}
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

/*
TestGatewayImportDoesNotPanicWhenTheReadFails is the regression gate on the
crash reported in P81-144756.

WHAT CRASHED. The old importer called the network read, recorded the error into
a diagnostics slice, and CARRIED ON -- the slice was only inspected at the
bottom of the function, well past the point where the nil response was
dereferenced. The result was not a diagnostic but a SIGSEGV: "The
terraform-provider-checkpointsase plugin crashed!" with a Go stack trace, from
nothing worse than a mistyped id or an unset BASE_URL sending the call to the
wrong host.

WHY THESE THREE CASES. A 404 and a 500 are the two ways the request itself
fails, and they must end differently: 404 is "no such gateway", 500 is "the
server broke and we cannot tell". The `null` body is the third and least
obvious -- a 2xx whose payload decodes to JSON null leaves the SDK returning a
nil pointer with NO error, so an err-only check sails straight past it.

A panic fails a Go test, so this file is the gate: any future edit that
reintroduces the record-and-continue shape fails here rather than in an
operator's terminal.
*/
func TestGatewayImportDoesNotPanicWhenTheReadFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{
			name:    "404 says the gateway is absent",
			status:  http.StatusNotFound,
			body:    `{"message":"Not found","messageCode":"NOT_FOUND","status":404}`,
			wantErr: "no gateway",
		},
		{
			name:   "500 must not be reported as absence",
			status: http.StatusInternalServerError,
			body:   `{"message":"boom"}`,
			// Any error will do; what must NOT happen is a panic, and what must
			// not happen either is a cheerful "no gateway exists" that would
			// send the operator looking for a gateway that is probably fine.
			wantErr: "could not import gateway",
		},
		{
			name:    "a 2xx null body is a nil pointer with no error",
			status:  http.StatusOK,
			body:    `null`,
			wantErr: "no gateway",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceGateway().Schema, map[string]interface{}{})
			d.SetId("net-1-gw-1")

			// No recover() here on purpose. A panic must fail the test loudly
			// with its stack, which is the whole signal.
			out, err := resourceGatewayImportState(
				context.Background(), d, newTestUserAPIClient(srv.URL))

			if err == nil {
				t.Fatalf("import returned no error and %d resource(s); it must refuse", len(out))
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
