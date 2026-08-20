package checkpointsase

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// TestUserResourceHasNoUpdate pins Pattern C. /v3/users has no PUT, so an
// UpdateContext could only re-POST -- creating a second user while Terraform
// believed it had updated one. Every attribute must be ForceNew so the plan is
// a replace (USR-02).
func TestUserResourceHasNoUpdate(t *testing.T) {
	r := resourceUser()
	if r.UpdateContext != nil {
		t.Error("resourceUser registers an UpdateContext, but /v3/users has no PUT: " +
			"an update could only re-POST and would create a second user")
	}
	for name, s := range r.Schema {
		if (s.Required || s.Optional) && !s.ForceNew {
			t.Errorf("%s is writable but not ForceNew; with no update endpoint every "+
				"writable attribute must force replacement", name)
		}
	}
}

// TestUserDecodesWithNothingButAnID is the provider-side pin on overlay entry
// A21b, which removes User.required ENTIRELY -- all eight fields it used to
// name, including email. The reason is that /v3/users is a LIST endpoint: one
// record missing one key fails the whole page, which is how the WebCategory
// defect (A20) presented. email is not exempt: an Active-Directory-synced
// account can have no `mail` attribute at all.
func TestUserDecodesWithNothingButAnID(t *testing.T) {
	// An id and nothing else. A21b removes User.required entirely, so this is
	// genuinely the minimum -- the point being that an Active-Directory-synced
	// account with no `mail` attribute must not fail the whole page.
	body := []byte(`{"data":[{"id":"u1"}],` +
		`"page":1,"totalPage":1,"itemsTotal":1}`)

	var list perimeter81Sdk.UserList
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("a user record carrying only id must decode; got %v. "+
			"If this fails, overlay entry A21b is not applied", err)
	}
	if len(list.Data) != 1 || list.Data[0].GetId() != "u1" {
		t.Fatalf("decoded %d records, want 1 with id u1: %+v", len(list.Data), list.Data)
	}
	if list.Data[0].Email != nil {
		t.Errorf("Email = %v, want nil: an absent key must read back as nil, not as \"\"",
			*list.Data[0].Email)
	}
}

// TestUserReadIsExactOnID pins that Read cannot adopt a different user's state.
// Two ids where one is a prefix of the other is the case that would slip
// through a strings.HasPrefix implementation.
func TestUserReadIsExactOnID(t *testing.T) {
	users := []perimeter81Sdk.User{}
	for _, id := range []string{"usr1", "usr12"} {
		u := perimeter81Sdk.User{}
		u.SetId(id)
		users = append(users, u)
	}
	got, found := readByIDFromList(users, "usr1", func(u perimeter81Sdk.User) string { return u.GetId() })
	if !found || got.GetId() != "usr1" {
		t.Errorf("got (%q, %v), want (usr1, true)", got.GetId(), found)
	}
}

// TestAccCheckpointsaseUser_basic covers USR-01 (apply, then an empty plan) and
// USR-03 (destroy, verified through the list endpoint since there is no
// GET-by-id).
func TestAccCheckpointsaseUser_basic(t *testing.T) {
	suffix := randStringBytesRmndr()
	email := "tf-acc-" + suffix + "@example.invalid"
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccUserConfigBasic(email),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("checkpointsase_user.test", "id"),
					resource.TestCheckResourceAttr("checkpointsase_user.test", "email", email),
					resource.TestCheckResourceAttr("checkpointsase_user.test", "terminated", "false"),
					resource.TestCheckResourceAttrSet("checkpointsase_user.test", "username"),
					resource.TestCheckResourceAttrSet("checkpointsase_user.test", "role_name"),
				),
			},
			// USR-01's second half: the same config must produce no diff.
			{
				Config:   testAccUserConfigBasic(email),
				PlanOnly: true,
			},
			// USR-I01: import, then no diff. invite_message is write-only, so
			// it cannot be verified from the imported object.
			{
				ResourceName:            "checkpointsase_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"invite_message"},
			},
		},
	})
}

// TestAccCheckpointsaseUser_replaceOnEmailChange covers USR-02: with no PUT on
// /v3/users, changing email must plan as -/+ and never as an in-place update.
// Asserted by capturing the id in step 1 and requiring a DIFFERENT id in step 2 --
// an in-place update would keep it, and no ComposeTestCheckFunc built-in can
// express "differs from the previous step".
func TestAccCheckpointsaseUser_replaceOnEmailChange(t *testing.T) {
	suffix := randStringBytesRmndr()
	first := "tf-acc-" + suffix + "-a@example.invalid"
	second := "tf-acc-" + suffix + "-b@example.invalid"
	var firstID string

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccUserConfigBasic(first),
				Check: func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources["checkpointsase_user.test"]
					if !ok {
						return fmt.Errorf("checkpointsase_user.test not in state")
					}
					firstID = rs.Primary.ID
					return nil
				},
			},
			{
				Config: testAccUserConfigBasic(second),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("checkpointsase_user.test", "email", second),
					func(s *terraform.State) error {
						rs := s.RootModule().Resources["checkpointsase_user.test"]
						if rs.Primary.ID == firstID {
							return fmt.Errorf("id is unchanged (%s) after an email change: the "+
								"resource was updated in place, but /v3/users has no PUT so it "+
								"must have been replaced", firstID)
						}
						return nil
					},
				),
			},
		},
	})
}

// TestAccCheckpointsaseUser_profileAndAccessGroups covers the optional block and
// the mayBeEmpty verdict on access_groups: an explicitly empty list must apply
// rather than being rejected at plan time.
func TestAccCheckpointsaseUser_profileAndAccessGroups(t *testing.T) {
	suffix := randStringBytesRmndr()
	email := "tf-acc-" + suffix + "@example.invalid"
	config := fmt.Sprintf(`
resource "checkpointsase_user" "test" {
  email          = %[1]q
  invite_message = "Terraform acceptance test, safe to ignore."
  email_verified = true
  access_groups  = []

  profile_data {
    first_name = "Ada"
    last_name  = "Lovelace"
    phone      = "+972500000000"
  }
}
`, email)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("checkpointsase_user.test", "access_groups.#", "0"),
					resource.TestCheckResourceAttr("checkpointsase_user.test", "profile_data.0.first_name", "Ada"),
					// Uppercase initials prove overlay entry A24 was right: the
					// exported pattern ^[a-z '-]+$ reads as lowercase-only, but
					// the backend regex carries the /i flag and the server takes
					// "Ada".
					resource.TestCheckResourceAttr("checkpointsase_user.test", "first_name", "Ada"),
					resource.TestCheckResourceAttr("checkpointsase_user.test", "last_name", "Lovelace"),
				),
			},
			{
				Config:   config,
				PlanOnly: true,
			},
		},
	})
}

// TestAccCheckpointsaseUser_rejectsMalformedEmail covers USR-N01. No tenant is
// touched: the ValidateFunc rejects the config during plan.
func TestAccCheckpointsaseUser_rejectsMalformedEmail(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "checkpointsase_user" "bad" {
  email          = "invalid-email-format"
  invite_message = "never sent"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`must be an email address`),
			},
		},
	})
}

/*
TestAccCheckpointsaseUser_rejectsDuplicateEmail covers USR-N02: two users with
the same address in one configuration.

This one necessarily reaches the API. Terraform's schema has no cross-resource
uniqueness constraint to express with, and the two resources have no dependency
between them, so both are planned as creates and the collision is only visible
in the second POST's response. The tenant sees one successful create; the test's
own destroy removes it.
*/
func TestAccCheckpointsaseUser_rejectsDuplicateEmail(t *testing.T) {
	suffix := randStringBytesRmndr()
	email := "tf-acc-" + suffix + "@example.invalid"
	config := fmt.Sprintf(`
resource "checkpointsase_user" "first" {
  email          = %[1]q
  invite_message = "Terraform acceptance test, safe to ignore."
  email_verified = true
}

resource "checkpointsase_user" "second" {
  email          = %[1]q
  invite_message = "Terraform acceptance test, safe to ignore."
  email_verified = true
}
`, email)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				// The server rejects the duplicate; the exact wording is not
				// pinned, only the status class, because a 400 and a 409 are
				// both defensible answers and the provider must fail either way.
				ExpectError: regexp.MustCompile(`(?i)400|409|conflict|already exist`),
			},
		},
	})
}

/*
TestAccCheckpointsaseUser_deleteIsIdempotent covers USR-N03: destroy must
succeed when the user is already gone.

The user is deleted out of band in the second step's PreConfig. That step is
PlanOnly deliberately -- an applying step would notice the drift and recreate
the user, and the framework's destroy would then get a clean 200 and prove
nothing. A PlanOnly step leaves the now-stale id in state, and
plugintest.WorkingDir.Destroy runs `terraform destroy` with refresh disabled, so
resourceUserDelete is called with that stale id and receives a 404. The row
passes only because Delete swallows it via isNotFound.
*/
func TestAccCheckpointsaseUser_deleteIsIdempotent(t *testing.T) {
	suffix := randStringBytesRmndr()
	email := "tf-acc-" + suffix + "@example.invalid"
	var userID string

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccUserConfigBasic(email),
				Check:  testAccCaptureUserID("checkpointsase_user.test", &userID),
			},
			{
				PreConfig:          testAccDeleteUserOutOfBand(t, &userID),
				Config:             testAccUserConfigBasic(email),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

/*
TestAccCheckpointsaseUser_driftWhenDeletedOutOfBand covers USR-D01, the mirror
image of USR-N03: a user removed from the console must show up as drift, not as
an error.

It passes only because resourceUserRead clears the id when readByIDFromList
returns found == false. A Read that instead reported "user not found" would fail
this plan, and every operator whose colleague deleted a user from the console
would have to remove the resource from state by hand.
*/
func TestAccCheckpointsaseUser_driftWhenDeletedOutOfBand(t *testing.T) {
	suffix := randStringBytesRmndr()
	email := "tf-acc-" + suffix + "@example.invalid"
	var userID string

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccUserConfigBasic(email),
				Check:  testAccCaptureUserID("checkpointsase_user.test", &userID),
			},
			{
				PreConfig: testAccDeleteUserOutOfBand(t, &userID),
				Config:    testAccUserConfigBasic(email),
				// The plan must be non-empty: Read cleared the id, so Terraform
				// plans a create. An empty plan here would mean Read had adopted
				// a user that no longer exists.
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// testAccCaptureUserID records the id Terraform holds for a user resource so a
// later step's PreConfig can manipulate that user directly through the SDK.
// PreConfig takes no state argument, which is why the id has to be carried out
// of the step that created it.
func testAccCaptureUserID(name string, out *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("%s not in state", name)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("%s has an empty id in state", name)
		}
		*out = rs.Primary.ID
		return nil
	}
}

// testAccDeleteUserOutOfBand deletes a user through the SDK, simulating somebody
// removing the account from the console while Terraform is not looking. The id
// is taken by pointer because PreConfig closures are built before the step that
// fills it in has run.
func testAccDeleteUserOutOfBand(t *testing.T, id *string) func() {
	return func() {
		if *id == "" {
			t.Fatal("no user id was captured; the preceding step's Check did not run")
		}
		client := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		if _, _, err := client.TeamAPI.DeleteUser(context.Background(), *id).Execute(); err != nil {
			t.Fatalf("deleting user %s out of band: %s", *id, err)
		}
	}
}

// testAccCheckUserDestroy verifies USR-03's second half. /v3/users has no
// GET-by-id, so absence is proved through the list endpoint -- the same
// list-and-filter the resource's own Read uses.
func testAccCheckUserDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "checkpointsase_user" {
			continue
		}
		users, _, err := client.TeamAPI.ListUsers(context.Background()).Page(1).Limit(1000).Execute()
		if err != nil {
			return fmt.Errorf("listing users to verify destroy: %w", err)
		}
		if _, found := readByIDFromList(users.Data, rs.Primary.ID,
			func(u perimeter81Sdk.User) string { return u.GetId() }); found {
			return fmt.Errorf("user %s still exists after destroy", rs.Primary.ID)
		}
	}
	return nil
}

func testAccUserConfigBasic(email string) string {
	return fmt.Sprintf(`
resource "checkpointsase_user" "test" {
  email          = %[1]q
  invite_message = "Terraform acceptance test, safe to ignore."
  email_verified = true
}
`, email)
}
