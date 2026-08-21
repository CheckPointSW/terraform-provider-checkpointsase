package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// randNameApplication is generated once per test binary and used for both the
// network name and the application name suffix. The API constrains application
// names to 5-32 characters drawn from a restricted set (test-plan rows APP-N05
// and APP-N06); the schema enforces neither, so the fixture has to. "tfacc" +
// 10 random letters is 15 characters, all alphabetic, and satisfies both.
var randNameApplication string = randStringBytesRmndr()

func testAccApplicationName() string { return "tfacc" + randNameApplication }

// TestAccApplication_basic is the first live exercise of
// checkpointsase_application.
//
// # Why one config step and not two
//
// checkpointsase_application registers no UpdateContext and marks every
// attribute ForceNew, so a second config step with different values would not
// exercise an update path — it would be a destroy-and-recreate (test-plan row
// APP-03). That is not merely uninformative here, it is destructive: the v2.3
// API exposes no delete endpoint for applications, so resourceApplicationDelete
// is a no-op that clears state and leaves the object on the tenant
// (APP-D02). A ForceNew step would therefore strand an orphan application that
// no Terraform run can ever clean up, on every execution of this test, in
// exchange for re-testing the create path that step 1 already covers. So:
// one config step.
//
// # The second step is an import, and it is the point of the test
//
// LEFTOVERS.md L1 says resourceApplicationRead repopulates only name and type.
// Read directly, that claim is now stale: the switch in resourceApplicationRead
// sets name, type, host, network, port and users for all three creatable
// types. The one field it genuinely never sets is groups — there is no
// d.Set("groups", ...) call anywhere in the function.
//
// A post-apply check cannot tell whether Read works, because after an apply the
// state already holds the configured values whether Read wrote them or not.
// Importing into a fresh state can: ImportStateVerify compares the imported
// state against the state step 1 produced, and any field Read fails to set is
// simply missing. That converts L1 from a code-reading claim into a measured
// one. It is set with no ImportStateVerifyIgnore — nothing is excluded.
//
// The import step reaches `groups` too, and that is new. terraform-plugin-sdk's
// ImportStateVerify drops flatmap container keys whose count is "0" from both
// sides before comparing, so while `groups` was unset in configuration the
// missing d.Set("groups", ...) was invisible — both sides were empty. Measuring
// the groups half of L1 needs a real group ID in the configuration, and the
// fixture now mints one instead of reading it from the environment: it declares
// a checkpointsase_group and grants the application access to it. Step 1's state
// therefore carries groups.# = "1", the imported state carries whatever Read
// writes, and APP-D03 is measured rather than assumed — it is expected to fail
// until Read sets groups (Phase 6).
func TestAccApplication_basic(t *testing.T) {
	t.Parallel()
	var application perimeter81Sdk.GetApplicationById200Response

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t); testAccPreCheckRegion(t) },
		Providers: testAccProviders,
		// No CheckDestroy: no other TestAcc test in this package defines one,
		// and for this resource none could assert anything true. Destroy
		// performs no API call at all, so the application is still there
		// afterwards by design (APP-D02); a CheckDestroy asserting its absence
		// would be a check written to fail, and one asserting its presence
		// would merely restate that Delete does nothing.
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckApplicationExists("checkpointsase_application.app", &application),
					testAccCheckApplicationAttributes(&application, &testAccApplicationExpectedAttributes{
						Name:       testAccApplicationName(),
						Type:       "https",
						Host:       "10.99.0.20",
						Port:       443,
						NetworkRef: "checkpointsase_network.n1",
						UserCount:  0,
						// One group, matching the fixture. The API refuses an
						// application that grants access to nobody, so this cannot
						// be 0 -- see the comment on `groups` in the config.
						GroupCount: 1,
					}),
					// State-side mirror of the same values. The API assertions
					// above prove Create sent the right thing; these prove the
					// values Terraform kept agree with it.
					resource.TestCheckResourceAttr("checkpointsase_application.app", "name", testAccApplicationName()),
					resource.TestCheckResourceAttr("checkpointsase_application.app", "type", "https"),
					resource.TestCheckResourceAttr("checkpointsase_application.app", "host", "10.99.0.20"),
					// The group Read writes back. L1 records that resourceApplicationRead
					// never calls d.Set("groups", ...) at all; if that is still true this
					// assertion fails, which is the point -- it was unmeasurable while the
					// fixture left groups unset.
					resource.TestCheckResourceAttr("checkpointsase_application.app", "groups.#", "1"),
					resource.TestCheckResourceAttrPair(
						"checkpointsase_application.app", "groups.0",
						"checkpointsase_group.app_access", "id"),
					resource.TestCheckResourceAttr("checkpointsase_application.app", "port", "443"),
					resource.TestCheckResourceAttrPair(
						"checkpointsase_application.app", "network",
						"checkpointsase_network.n1", "id"),
				),
			},
			{
				ResourceName:      "checkpointsase_application.app",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

/*
testAccCheckApplicationExists confirms the application exists server-side via
GetApplicationById — the same call resourceApplicationRead makes — so a
state-only assertion cannot pass against something that was never created.
*/
func testAccCheckApplicationExists(n string, application *perimeter81Sdk.GetApplicationById200Response) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}

		applicationId := rs.Primary.ID
		if applicationId == "" {
			return fmt.Errorf("No application id is set")
		}
		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		ctx := context.Background()
		gotApplication, _, err := conn.ApplicationsAPI.GetApplicationById(ctx, applicationId).Execute()
		if err != nil {
			return err
		}
		if gotApplication == nil {
			return fmt.Errorf("application %q read back as nil", applicationId)
		}
		*application = *gotApplication
		return nil
	}
}

// testAccApplicationView is the test's own normalisation of the five-variant
// GetApplicationById200Response oneOf.
//
// It handles all five variants, including ssh and vnc, on purpose. That is not
// compensating for the provider's gap — resourceApplicationRead has its own
// switch and this does not touch it. It exists so that if the server ever
// answers with a variant the provider drops, the failure message says which
// variant it was instead of reporting a wall of empty strings.
type testAccApplicationView struct {
	Name       string
	Type       string
	Host       string
	NetworkId  string
	PortInt    *int32
	PortString *string
	UserCount  int
	GroupCount int
}

/*
testAccFlattenApplicationResponse normalises the oneOf response. A nil return
means the response's `type` discriminator matched none of the SDK's five
variants, which leaves every field of resourceApplicationRead's switch at its
zero value and blanks the resource in state without raising an error.
*/
func testAccFlattenApplicationResponse(application *perimeter81Sdk.GetApplicationById200Response) *testAccApplicationView {
	switch {
	case application.HttpApplication != nil:
		a := application.HttpApplication
		return &testAccApplicationView{a.Name, a.Type, a.Host.Value, a.Network.Id, a.Port.Value.Int32, a.Port.Value.String, len(a.Users), len(a.Groups)}
	case application.HttpsApplication != nil:
		a := application.HttpsApplication
		return &testAccApplicationView{a.Name, a.Type, a.Host.Value, a.Network.Id, a.Port.Value.Int32, a.Port.Value.String, len(a.Users), len(a.Groups)}
	case application.RdpApplication != nil:
		a := application.RdpApplication
		return &testAccApplicationView{a.Name, a.Type, a.Host.Value, a.Network.Id, a.Port.Value.Int32, a.Port.Value.String, len(a.Users), len(a.Groups)}
	case application.SshApplication != nil:
		a := application.SshApplication
		return &testAccApplicationView{a.Name, a.Type, a.Host.Value, a.Network.Id, a.Port.Value.Int32, a.Port.Value.String, len(a.Users), len(a.Groups)}
	case application.VncApplication != nil:
		a := application.VncApplication
		return &testAccApplicationView{a.Name, a.Type, a.Host.Value, a.Network.Id, a.Port.Value.Int32, a.Port.Value.String, len(a.Users), len(a.Groups)}
	}
	return nil
}

type testAccApplicationExpectedAttributes struct {
	Name string
	Type string
	Host string
	Port int32
	// NetworkRef is a Terraform state address; the network ID is minted at
	// apply time and cannot be hardcoded.
	NetworkRef string
	UserCount  int
	GroupCount int
}

/*
testAccCheckApplicationAttributes compares the application the API holds
against what the configuration asked for, field by field.

host, port and network are asserted here even though LEFTOVERS.md L1 casts
doubt on them. These assertions describe the behaviour the resource is
documented to have; if any fails, the failure names the field and both values,
which is the useful outcome.
*/
func testAccCheckApplicationAttributes(application *perimeter81Sdk.GetApplicationById200Response, want *testAccApplicationExpectedAttributes) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		got := testAccFlattenApplicationResponse(application)
		if got == nil {
			return fmt.Errorf("GetApplicationById returned a response whose `type` discriminator matched none of the SDK's five variants (http/https/rdp/ssh/vnc); resourceApplicationRead's switch would fall through and blank every attribute without erroring")
		}

		if got.Name != want.Name {
			return fmt.Errorf("got name %q; want %q", got.Name, want.Name)
		}
		if got.Type != want.Type {
			return fmt.Errorf("got type %q; want %q", got.Type, want.Type)
		}
		if got.Host != want.Host {
			return fmt.Errorf("got host %q; want %q", got.Host, want.Host)
		}

		// resourceApplicationRead reads only the Int32 leg of the port union
		// and skips d.Set entirely when it resolves to 0, so a port returned
		// on the String leg would never reach state. Name that explicitly
		// rather than letting it read as a plain mismatch.
		switch {
		case got.PortInt != nil:
			if *got.PortInt != want.Port {
				return fmt.Errorf("got port %d; want %d", *got.PortInt, want.Port)
			}
		case got.PortString != nil:
			return fmt.Errorf("got port %q on the string leg of the port union; want %d on the int32 leg — resourceApplicationRead only reads Port.Value.Int32, so a string port never reaches state", *got.PortString, want.Port)
		default:
			return fmt.Errorf("got no port on either leg of the port union; want %d", want.Port)
		}

		wantNetworkIds, err := testAccResolveStateIDs(s, []string{want.NetworkRef})
		if err != nil {
			return err
		}
		if got.NetworkId != wantNetworkIds[0] {
			return fmt.Errorf("got network %q; want %q", got.NetworkId, wantNetworkIds[0])
		}

		if got.UserCount != want.UserCount {
			return fmt.Errorf("got %d users; want %d", got.UserCount, want.UserCount)
		}
		if got.GroupCount != want.GroupCount {
			return fmt.Errorf("got %d groups; want %d", got.GroupCount, want.GroupCount)
		}

		return nil
	}
}

/*
testAccApplicationConfig builds one network, one group and one HTTPS application
inside them. type is https because it is one of the three the schema's
ValidateFunc permits creating (APP-N02), and it exercises the HttpsApplication
leg of the response union. The host is an RFC 1918 placeholder — this test is
about the Terraform lifecycle, not a reachable service. users is omitted: it
takes tenant-specific directory IDs the harness cannot mint. groups is not, both
because the API refuses an application that grants access to nobody and because
checkpointsase_group can now mint the group in-band — which is why this fixture
no longer reads a tenant-specific group ID out of the environment.

CLEANUP: THIS FIXTURE STRANDS THREE OBJECTS, NOT TWO. LEFTOVERS.md L14 —
applications have no delete endpoint, so `terraform destroy` clears the
application from state, leaves it on the tenant, and then fails at the network
the surviving application pins. The group below joins that pile: destroy does
call DELETE /v3/groups for it, but the surviving application still grants access
to it, so the delete may be refused as well. Budget a manual sweep of one
application, one network and one group per run.

The group name carries the same randStringBytesRmndr() suffix as the network, so
a re-run cannot collide with a group a previous failed run left behind.
*/
func testAccApplicationConfig() string {
	config := `
resource "checkpointsase_network" "n1" {
  network {
    name = "%[1]s"
    tags = ["test"]
  }
  region {
    cpregion_id = "%[2]s"
    idle = true
  }
}

resource "checkpointsase_group" "app_access" {
  name        = "tf-acc-app-access-%[1]s"
  description = "Terraform acceptance test, safe to ignore."
}

resource "checkpointsase_application" "app" {
  name    = "%[3]s"
  type    = "https"
  network = checkpointsase_network.n1.id
  host    = "10.99.0.20"
  port    = 443

  # The API refuses an application that grants access to nobody: users carries a
  # cross-field @UsersMinSize(1) that fires whenever groups is empty, so one of
  # the two must be non-empty. Measured 2026-08-19 -- a config with neither is
  # now refused at plan time by the provider, which is why this is here.
  #
  # A group rather than a user, deliberately: it keeps a named person's identity
  # out of the fixture, and it also exercises the one field L1 records as never
  # being read back (there is no d.Set("groups", ...) anywhere in Read), which
  # was previously unmeasurable because ImportStateVerify drops empty
  # containers from both sides.
  groups = [checkpointsase_group.app_access.id]
}
  `
	return fmt.Sprintf(config, randNameApplication, testAccRegionID(), testAccApplicationName())
}
