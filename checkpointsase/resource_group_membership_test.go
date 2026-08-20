package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
The offline client and page fixture used throughout this file are
newTestUserAPIClient and groupListPage, from resource_user_test.go and
resource_group_test.go. Both are resource-agnostic -- the first only pre-seeds a
bearer token so no test here ever exchanges an API key, the second renders one
page of /v3/groups -- and this resource reads its state out of /v3/groups, so
reusing them keeps one fixture rather than three.
*/

/*
TestParseGroupMembershipID pins the composite-id contract, including the
malformed cases an operator can reach through `terraform import`.

The hyphen and underscore row is the one that documents the separator choice:
both halves are EnglishNumericId (^[a-zA-Z0-9_\-]*$), so "-" and "_" both occur
INSIDE real ids and neither could have served as the separator. ":" cannot.
*/
func TestParseGroupMembershipID(t *testing.T) {
	for _, tc := range []struct {
		name        string
		id          string
		group, user string
		wantErr     bool
	}{
		{"well formed", "grp1:usr1", "grp1", "usr1", false},
		{"ids may contain hyphens and underscores", "g-1_a:u-2_b", "g-1_a", "u-2_b", false},
		{"realistic object ids", "5f8d0d55b54764421b7156c3:5f8d0d55b54764421b7156c9",
			"5f8d0d55b54764421b7156c3", "5f8d0d55b54764421b7156c9", false},
		{"no separator", "grp1usr1", "", "", true},
		{"empty group", ":usr1", "", "", true},
		{"empty user", "grp1:", "", "", true},
		{"empty id", "", "", "", true},
		{"separator only", ":", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, u, err := parseGroupMembershipID(tc.id)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if g != tc.group || u != tc.user {
				t.Errorf("got (%q, %q), want (%q, %q)", g, u, tc.group, tc.user)
			}
			// An error message that does not say what the right shape is leaves
			// the operator guessing at a `terraform import` argument.
			if tc.wantErr && !strings.Contains(err.Error(), "<group_id>:<user_id>") {
				t.Errorf("error %q does not state the expected form", err)
			}
		})
	}
}

/*
TestGroupMembershipResourceIsAJoin pins the properties of a join resource that a
careless implementation breaks: no update path, both ids ForceNew, and no
attributes beyond the two ids -- an attribute here would imply this resource owns
something it does not.
*/
func TestGroupMembershipResourceIsAJoin(t *testing.T) {
	r := resourceGroupMembership()
	if r.UpdateContext != nil {
		t.Error("a membership has nothing to update; changing either id is a different membership")
	}
	if r.CreateContext == nil || r.ReadContext == nil || r.DeleteContext == nil {
		t.Error("Create, Read and Delete are all required")
	}
	if r.Importer == nil || r.Importer.StateContext == nil {
		t.Error("a resource whose id is composite needs an importer that validates it")
	}
	if len(r.Schema) != 2 {
		t.Errorf("schema has %d attributes, want exactly group_id and user_id", len(r.Schema))
	}
	for _, name := range []string{"group_id", "user_id"} {
		s, ok := r.Schema[name]
		if !ok {
			t.Fatalf("%s is missing", name)
		}
		if !s.Required || !s.ForceNew {
			t.Errorf("%s must be Required and ForceNew, got Required=%v ForceNew=%v",
				name, s.Required, s.ForceNew)
		}
		if s.Computed {
			t.Errorf("%s must not be Computed: both halves of the id are supplied by the "+
				"configuration, and a Computed id cannot be referenced before apply", name)
		}
	}
}

/*
TestGroupMembershipNeverDeletesItsParents reads the resource's own source and
fails if it references either parent's delete operation.

This is the failure mode with the worst blast radius and the least visibility. A
join resource that deleted a parent would satisfy every read-back assertion in
this file -- Read would correctly report the membership gone, because the group
IS gone -- and would show up only as a destroyed user or group in someone's
tenant. GRP-04 catches it on a live run; this catches it on every PR.
*/
func TestGroupMembershipNeverDeletesItsParents(t *testing.T) {
	src, err := os.ReadFile("resource_group_membership.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"DeleteGroup(", "DeleteUser("} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("resource_group_membership.go calls %s: a membership must delete only "+
				"the pairing, never a parent", forbidden)
		}
	}
}

/*
TestGroupMembershipDeleteSwallowsA404ButNothingElse is GRP-D02, gated offline
rather than as an acceptance test.

The acceptance shape of this row cannot work, and the same correction was needed
for USR-N03 and GRP-N03. GRP-D02 wants "remove the membership out of band, then
destroy". The driver refreshes around every Config step, so the refresh clears
the id, the state file empties, the post-test destroy is skipped
(testing_new.go:75) and Delete is NEVER CALLED. The version of this row that
looks right asserts nothing about the code it names.

Hence an httptest server, which also gates the guard on every PR rather than only
on a live run. The 500 case is half the test: the swallow must be narrow, or a
server that is merely broken would look like a successful destroy and the
membership would leave state while surviving in the tenant.
*/
func TestGroupMembershipDeleteSwallowsA404ButNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantErr    bool
		wantIDGone bool
	}{
		{"404 means the pairing is already gone", http.StatusNotFound,
			`{"message":"member not found"}`, false, true},
		{"200 is an ordinary destroy", http.StatusOK,
			`{"id":"grp-1","name":"Engineering","users":[]}`, false, true},
		{"500 must not be mistaken for success", http.StatusInternalServerError,
			`{"message":"boom"}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath = r.Method, r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceGroupMembership().Schema, map[string]interface{}{})
			d.SetId("grp-1:usr-1")

			diags := resourceGroupMembershipDelete(context.Background(), d, newTestUserAPIClient(srv.URL))

			// The path is asserted, not assumed: the whole point of this
			// resource is that its Delete addresses the MEMBER endpoint and not
			// /v3/groups/grp-1 or /v3/users/usr-1.
			if gotMethod != http.MethodDelete || gotPath != "/v3/groups/grp-1/member/usr-1" {
				t.Errorf("request was %s %s, want DELETE /v3/groups/grp-1/member/usr-1",
					gotMethod, gotPath)
			}
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
TestGroupMembershipRejectsAMalformedIDBeforeIssuingARequest is the other half of
the composite-id contract: what the resource DOES with an id it cannot split.

An unchecked SplitN result would produce a request against an empty path
segment -- DELETE /v3/groups//member/usr-1 -- which is a different route, not an
error, and url.PathEscape does not save it because an empty segment escapes to an
empty segment. The assertion is therefore that ZERO requests are issued, which is
what distinguishes "rejected the id" from "asked the server about nonsense".

Delete keeps the id in state rather than clearing it. A malformed id is only
reachable through a hand-written import or an edited state file, so failing
loudly is right: clearing it would drop a resource whose real membership may well
exist, silently.
*/
func TestGroupMembershipRejectsAMalformedIDBeforeIssuingARequest(t *testing.T) {
	for _, id := range []string{"grp1usr1", ":usr-1", "grp-1:", "", ":"} {
		t.Run(fmt.Sprintf("id %q", id), func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				t.Errorf("unexpected %s %s: a malformed id must be rejected before any request",
					r.Method, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			client := newTestUserAPIClient(srv.URL)

			for _, fn := range []struct {
				name string
				call func(d *schema.ResourceData) bool
			}{
				{"Delete", func(d *schema.ResourceData) bool {
					return resourceGroupMembershipDelete(context.Background(), d, client).HasError()
				}},
				{"Read", func(d *schema.ResourceData) bool {
					return resourceGroupMembershipRead(context.Background(), d, client).HasError()
				}},
				{"Import", func(d *schema.ResourceData) bool {
					_, err := resourceGroupMembershipImportState(context.Background(), d, client)
					return err != nil
				}},
			} {
				d := schema.TestResourceDataRaw(t, resourceGroupMembership().Schema,
					map[string]interface{}{})
				d.SetId(id)
				if !fn.call(d) {
					t.Errorf("%s accepted the malformed id %q", fn.name, id)
				}
			}
			if requests != 0 {
				t.Errorf("%d request(s) issued for a malformed id, want 0", requests)
			}
		})
	}
}

/*
TestGroupMembershipReadInspectsTheGroupsMemberList covers the three answers Read
must distinguish, and the endpoint it must use to get them.

There is no membership object to GET, so Read reads the parent group's `users`
list. That makes findGroupByID's PAGING part of this resource's correctness too:
a group sitting on page 2 read as absent would clear the id, and Terraform would
POST the member again -- harmless-looking, but it means the resource can never
converge for any tenant with more than one page of groups.

Every request path is asserted to be /v3/groups. A Read that reached for
/v3/groups/{id} or /v3/users/{id} would be addressing endpoints this resource has
no business touching -- and /v3/groups has no GET-by-id at all, so such a request
would 404 and read as drift forever.
*/
func TestGroupMembershipReadInspectsTheGroupsMemberList(t *testing.T) {
	for _, tc := range []struct {
		name       string
		id         string
		wantPages  int
		wantIDGone bool
	}{
		{"member of a group on page 1", "grp-1:usr-1", 1, false},
		{"member of a group on page 2", "grp-2:usr-9", 2, false},
		// One page, not two: the GROUP was found on page 1, so the walk stops
		// there and the absence being reported is the user's, from that group's
		// own member list.
		{"the user is not in the group", "grp-1:usr-404", 1, true},
		{"the group does not exist", "grp-404:usr-1", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Query().Get("page") {
				case "1":
					_, _ = w.Write([]byte(groupListPage(1, 2, 2,
						`{"id":"grp-1","name":"Engineering","users":["usr-1","usr-2"]}`)))
				case "2":
					// No `users` key at all: A22b makes every Group field
					// optional, so a nil slice is reachable and ranging over it
					// must be zero iterations rather than a panic.
					_, _ = w.Write([]byte(groupListPage(2, 2, 2,
						`{"id":"grp-3","name":"Empty"},{"id":"grp-2","name":"Ingénierie","users":["usr-9"]}`)))
				default:
					t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
					_, _ = w.Write([]byte(groupListPage(1, 1, 0, "")))
				}
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceGroupMembership().Schema, map[string]interface{}{})
			d.SetId(tc.id)

			diags := resourceGroupMembershipRead(context.Background(), d, newTestUserAPIClient(srv.URL))
			if diags.HasError() {
				t.Fatalf("Read failed: %v", diags)
			}
			if gone := d.Id() == ""; gone != tc.wantIDGone {
				t.Fatalf("id cleared = %v, want %v (id is %q)", gone, tc.wantIDGone, d.Id())
			}
			if len(paths) != tc.wantPages {
				t.Errorf("issued %d request(s) (%v), want %d: a single-page read cannot tell a "+
					"group on page 2 from one that was deleted", len(paths), paths, tc.wantPages)
			}
			for _, p := range paths {
				if p != "/v3/groups" {
					t.Errorf("requested %q; a membership reads the group COLLECTION and must "+
						"never address a parent's own endpoint", p)
				}
			}
			if !tc.wantIDGone {
				wantGroup, wantUser, _ := parseGroupMembershipID(tc.id)
				if d.Get("group_id").(string) != wantGroup || d.Get("user_id").(string) != wantUser {
					t.Errorf("state holds (%q, %q), want (%q, %q): both halves come from the id, "+
						"which is what makes an import work", d.Get("group_id"), d.Get("user_id"),
						wantGroup, wantUser)
				}
			}
		})
	}
}

/*
TestGroupMembershipCreateSurfacesANotFound is GRP-N04's offline half.

Create must NOT be idempotent on 404 the way Delete is. The two look symmetrical
and are not: a 404 on DELETE means the pairing is already absent, which is the
desired end state, while a 404 on POST means no membership was created. A Create
that swallowed it would write an id for a pairing the tenant does not have, and
the next plan would show no drift because Read cannot distinguish "never created"
from "removed out of band" -- it clears the id in both cases, so Terraform would
re-POST forever against a group that does not exist.

The request count matters as much as the error: an id must not be written, and
the failed POST must not be followed by a read.
*/
func TestGroupMembershipCreateSurfacesANotFound(t *testing.T) {
	var paths, methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		methods = append(methods, r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"statusCode":404,"message":"group not found"}`))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceGroupMembership().Schema, map[string]interface{}{
		"group_id": "grp-404",
		"user_id":  "usr-1",
	})

	diags := resourceGroupMembershipCreate(context.Background(), d, newTestUserAPIClient(srv.URL))
	if !diags.HasError() {
		t.Fatal("Create reported success against a 404: no membership exists, so no id may be written")
	}
	if d.Id() != "" {
		t.Errorf("id = %q after a failed create, want empty", d.Id())
	}
	if len(paths) != 1 || methods[0] != http.MethodPost || paths[0] != "/v3/groups/grp-404/member/usr-1" {
		t.Errorf("requests were %v %v, want exactly one POST /v3/groups/grp-404/member/usr-1",
			methods, paths)
	}
}

/*
TestGroupMembershipCreatePostsToTheMemberEndpoint pins the happy path's request
and the id it derives from it.

The id is built from the CONFIGURED ids rather than from the response, and it has
to be: AddGroupMember returns the whole Group, whose own id is the group's -- an
implementation that used group.GetId() would put the group's id in state as the
membership's, and every later Read would fail to parse it.
*/
func TestGroupMembershipCreatePostsToTheMemberEndpoint(t *testing.T) {
	var methods, paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"id":"grp-1","name":"Engineering","users":["usr-1"]}`))
			return
		}
		_, _ = w.Write([]byte(groupListPage(1, 1, 1,
			`{"id":"grp-1","name":"Engineering","users":["usr-1"]}`)))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceGroupMembership().Schema, map[string]interface{}{
		"group_id": "grp-1",
		"user_id":  "usr-1",
	})

	if diags := resourceGroupMembershipCreate(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("Create failed: %v", diags)
	}
	if d.Id() != "grp-1:usr-1" {
		t.Errorf("id = %q, want %q", d.Id(), "grp-1:usr-1")
	}
	if len(methods) < 1 || methods[0] != http.MethodPost || paths[0] != "/v3/groups/grp-1/member/usr-1" {
		t.Errorf("first request was %v %v, want POST /v3/groups/grp-1/member/usr-1", methods, paths)
	}
	// Create ends in Read, so the membership is confirmed against the group's
	// own member list before the apply is reported as successful.
	if len(paths) != 2 || paths[1] != "/v3/groups" {
		t.Errorf("requests were %v, want the POST followed by a read of /v3/groups", paths)
	}
}

/*
TestGroupMembershipImportResolvesOrFails covers the two outcomes of an import that
parsed, which the malformed-id test above does not reach.

The failure case is the one worth gating: Read reports an absent membership by
CLEARING THE ID rather than by erroring, so an importer that only checked
diagnostics would report success and write an empty resource -- and the operator
would discover it as a plan that creates the membership they had just imported.
*/
func TestGroupMembershipImportResolvesOrFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      string
		wantErr string
	}{
		{"the pairing exists", "grp-1:usr-1", ""},
		{"the user is not a member", "grp-1:usr-404", "no such membership"},
		{"the group does not exist", "grp-404:usr-1", "no such membership"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(groupListPage(1, 1, 1,
					`{"id":"grp-1","name":"Engineering","users":["usr-1"]}`)))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceGroupMembership().Schema, map[string]interface{}{})
			d.SetId(tc.id)

			results, err := resourceGroupMembershipImportState(context.Background(), d,
				newTestUserAPIClient(srv.URL))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("import failed: %v", err)
				}
				if len(results) != 1 {
					t.Fatalf("import returned %d resources, want 1", len(results))
				}
				if results[0].Get("group_id").(string) != "grp-1" ||
					results[0].Get("user_id").(string) != "usr-1" {
					t.Errorf("imported (%q, %q), want (grp-1, usr-1)",
						results[0].Get("group_id"), results[0].Get("user_id"))
				}
				return
			}
			if err == nil {
				t.Fatalf("import of %q reported success; Read clears the id for an absent "+
					"membership, so an importer that only checks diagnostics writes an empty "+
					"resource", tc.id)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

/*
TestGroupMembershipAccConfigReferencesItsParents is GRP-05's real gate, and it is
offline because the live row cannot carry the assertion by itself.

GRP-05 destroys a user, a group and a membership in one step and passes only if
Terraform orders the membership's DELETE first. But nothing in the diagnostics
distinguishes the right order from the wrong one: if a parent went first, the
membership's DELETE would 404 -- and GRP-D02 requires that 404 to be SWALLOWED.
A mis-ordered destroy therefore succeeds silently, and CheckDestroy still finds
everything gone.

What actually produces the ordering is the config's REFERENCES: `group_id =
checkpointsase_group.test.id` is what puts an edge in the dependency graph.
Literal ids -- the natural thing to write once the ids are known -- give
Terraform three unrelated resources and no edge at all. So the property is
asserted where it lives, in the config the acceptance tests use, and it is
checked on every PR rather than only when a credential is available.
*/
func TestGroupMembershipAccConfigReferencesItsParents(t *testing.T) {
	config := testAccGroupMembershipConfig("tf-acc-group", "tf-acc@example.invalid")
	for attr, want := range map[string]*regexp.Regexp{
		"group_id": regexp.MustCompile(`group_id\s*=\s*checkpointsase_group\.test\.id`),
		"user_id":  regexp.MustCompile(`user_id\s*=\s*checkpointsase_user\.test\.id`),
	} {
		if !want.MatchString(config) {
			t.Errorf("the membership's %s is not a reference to its parent (want %s). A literal "+
				"id leaves no edge in the dependency graph, and a mis-ordered destroy is "+
				"invisible: the membership's DELETE 404s and GRP-D02 requires that to be "+
				"swallowed", attr, want)
		}
	}
}

/*
TestAccCheckpointsaseGroupMembership_basic covers GRP-04: apply a user, a group
and a membership joining them, then remove ONLY the membership block and apply
again. Both parents must survive.

The surviving-parents assertion goes through the API rather than through state,
and deliberately. Step 2's state is not evidence: Terraform refreshes the group
BEFORE destroying the membership and does not re-read it afterwards, since the
group itself has no changes -- so `users.#` in the post-apply state still shows
the member that was just removed. A check written on that attribute passes when
the membership was not removed at all, and fails when it was. Reading the group
fresh through findGroupByID is the only version of this row that measures the
right thing.
*/
func TestAccCheckpointsaseGroupMembership_basic(t *testing.T) {
	suffix := randStringBytesRmndr()
	groupName := "tf-acc-" + suffix
	email := "tf-acc-" + suffix + "@example.invalid"
	var groupID, userID string

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckGroupMembershipAndParentsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupMembershipConfig(groupName, email),
				Check: resource.ComposeTestCheckFunc(
					testAccCaptureResourceID("checkpointsase_group.test", &groupID),
					testAccCaptureResourceID("checkpointsase_user.test", &userID),
					// The id is the two parents' ids joined, in that order.
					// Built from state rather than hardcoded because the real
					// ids are only known after the apply.
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["checkpointsase_group_membership.test"]
						if !ok {
							return fmt.Errorf("the membership is not in state")
						}
						want := rs.Primary.Attributes["group_id"] + groupMembershipIDSeparator +
							rs.Primary.Attributes["user_id"]
						if rs.Primary.ID != want {
							return fmt.Errorf("membership id is %q, want %q", rs.Primary.ID, want)
						}
						return nil
					},
					// The group's own read model is where a membership becomes
					// visible: one member, and it is this user.
					resource.TestCheckResourceAttr("checkpointsase_group.test", "users.#", "1"),
					resource.TestCheckResourceAttrPair(
						"checkpointsase_group.test", "users.0",
						"checkpointsase_user.test", "id"),
				),
			},
			// GRP-04 proper: the membership block is gone, both parents stay.
			{
				Config: testAccGroupMembershipConfigParentsOnly(groupName, email),
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						if _, ok := s.RootModule().Resources["checkpointsase_group_membership.test"]; ok {
							return fmt.Errorf("the membership is still in state after its block " +
								"was removed")
						}
						return nil
					},
					testAccCheckGroupMembershipRemovedAndParentsAlive(&groupID, &userID),
				),
			},
		},
	})
}

/*
TestAccCheckpointsaseGroupMembership_destroyOrder covers GRP-05: one apply of all
three resources, then the driver's own full destroy at the end of the test.

Read TestGroupMembershipAccConfigReferencesItsParents before relying on this row.
The destroy completing without error is NECESSARY but not sufficient: a
mis-ordered destroy would delete a parent first, the membership's DELETE would
404, and GRP-D02 requires that 404 to be swallowed -- so the wrong order also
"passes". The ordering itself is gated offline, on the references in the config
this test shares. What this row adds that the offline test cannot is that a real
tenant is left with nothing behind: CheckDestroy proves the pairing, the user and
the group are all gone.
*/
func TestAccCheckpointsaseGroupMembership_destroyOrder(t *testing.T) {
	suffix := randStringBytesRmndr()
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckGroupMembershipAndParentsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupMembershipConfig("tf-acc-"+suffix,
					"tf-acc-"+suffix+"@example.invalid"),
				Check: resource.TestCheckResourceAttrSet(
					"checkpointsase_group_membership.test", "id"),
			},
		},
	})
}

/*
TestAccCheckpointsaseGroupMembership_nonexistentGroup covers GRP-N04: a
membership whose group_id names a group that does not exist.

Live-only because it is the SERVER's answer that is being tested, and it needs no
fixture: both ids are literals, so a failed apply leaves nothing behind. The
offline half -- that Create surfaces the failure and writes no id rather than
swallowing it the way Delete swallows a 404 -- is
TestGroupMembershipCreateSurfacesANotFound.

The pattern is deliberately broad. appendErrorDiags prefers the response body
over the status line, and an id of the right SHAPE that names nothing may come
back as a 404 or, if the server validates it as an object id first, as a 400. The
row's requirement is that the apply fails and no state is written; which of the
two the tenant says is not the provider's behaviour.
*/
func TestAccCheckpointsaseGroupMembership_nonexistentGroup(t *testing.T) {
	config := `
resource "checkpointsase_group_membership" "test" {
  # Shaped like an object id -- 24 hex characters -- so the server reaches the
  # lookup rather than rejecting the format, but all zeroes so it names nothing.
  group_id = "000000000000000000000000"
  user_id  = "000000000000000000000001"
}
`
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`(?i)404|400|not.?found|does not exist|invalid`),
			},
		},
	})
}

/*
testAccCheckGroupMembershipAndParentsDestroy is the CheckDestroy for both rows
above. It asserts the pairing is gone, and then defers to the parents' own
destroy checks so that a membership test can never report success while leaving a
user or a group behind.
*/
func testAccCheckGroupMembershipAndParentsDestroy(s *terraform.State) error {
	if err := testAccCheckGroupMembershipDestroy(s); err != nil {
		return err
	}
	if err := testAccCheckGroupDestroy(s); err != nil {
		return err
	}
	return testAccCheckUserDestroy(s)
}

/*
testAccCheckGroupMembershipDestroy proves a membership is gone the only way the
API allows: by reading the parent group and looking for the user in its member
list.

The group being absent counts as destroyed rather than as an error. A full
destroy removes the group too, and a group with no members cannot hold this one.
*/
func testAccCheckGroupMembershipDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "checkpointsase_group_membership" {
			continue
		}
		groupID, userID, err := parseGroupMembershipID(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("membership %q in state is not a well-formed id: %w",
				rs.Primary.ID, err)
		}
		group, found, _, err := findGroupByID(context.Background(), client, groupID)
		if err != nil {
			return fmt.Errorf("listing groups to verify membership destroy: %w", err)
		}
		if !found {
			// The group went with it; there is nothing left to hold a member.
			continue
		}
		for _, id := range group.Users {
			if id == userID {
				return fmt.Errorf("user %s is still a member of group %s after destroy",
					userID, groupID)
			}
		}
	}
	return nil
}

/*
testAccCheckGroupMembershipRemovedAndParentsAlive is GRP-04's assertion: the
pairing is gone AND both parents are still there.

Both halves read the API directly, for the reason given on
TestAccCheckpointsaseGroupMembership_basic -- step 2's state still carries the
group's pre-destroy member list, so state cannot answer either question. The ids
are taken by pointer because the closure is built before the step that captures
them has run.
*/
func testAccCheckGroupMembershipRemovedAndParentsAlive(groupID, userID *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if *groupID == "" || *userID == "" {
			return fmt.Errorf("no parent ids were captured; the first step's Check did not run")
		}
		client := testAccProvider.Meta().(*perimeter81Sdk.APIClient)

		group, found, _, err := findGroupByID(context.Background(), client, *groupID)
		if err != nil {
			return fmt.Errorf("reading group %s after the membership was removed: %w", *groupID, err)
		}
		if !found {
			return fmt.Errorf("group %s no longer exists: removing a membership must not delete "+
				"the group", *groupID)
		}
		for _, id := range group.Users {
			if id == *userID {
				return fmt.Errorf("user %s is still a member of group %s; the membership's "+
					"destroy did not take effect", *userID, *groupID)
			}
		}

		if _, found, _, err := findUserByID(context.Background(), client, *userID); err != nil {
			return fmt.Errorf("reading user %s after the membership was removed: %w", *userID, err)
		} else if !found {
			return fmt.Errorf("user %s no longer exists: removing a membership must not delete "+
				"the account", *userID)
		}
		return nil
	}
}

/*
testAccGroupMembershipConfig is the configuration GRP-04 and GRP-05 share.

The two ids are REFERENCES, not literals, and that is the load-bearing detail of
GRP-05 -- see TestGroupMembershipAccConfigReferencesItsParents, which asserts it
offline because a mis-ordered destroy produces no diagnostic.
*/
func testAccGroupMembershipConfig(groupName, email string) string {
	return testAccGroupMembershipConfigParentsOnly(groupName, email) + `
resource "checkpointsase_group_membership" "test" {
  group_id = checkpointsase_group.test.id
  user_id  = checkpointsase_user.test.id
}
`
}

// testAccGroupMembershipConfigParentsOnly is the same configuration with the
// membership block removed -- GRP-04's second step, and the base of the config
// above so the two cannot drift apart.
func testAccGroupMembershipConfigParentsOnly(groupName, email string) string {
	return fmt.Sprintf(`
resource "checkpointsase_group" "test" {
  name        = %[1]q
  description = "Terraform acceptance test, safe to ignore."
}

resource "checkpointsase_user" "test" {
  email          = %[2]q
  invite_message = "Terraform acceptance test, safe to ignore."
  email_verified = true
}
`, groupName, email)
}
