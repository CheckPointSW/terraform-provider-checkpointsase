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
TestParseGroupMembershipID pins the composite-id contract, including the malformed
cases an operator can reach through `terraform import`.

The hyphen and underscore row documents the separator choice: both halves are
EnglishNumericId (^[a-zA-Z0-9_\-]*$), so "-" and "_" both occur INSIDE real ids
and neither could have served as the separator. ":" cannot.

The whitespace rows are the reachable defect, not a hypothetical. An id is
something an operator pastes, and a paste carries a trailing space or a newline;
without the charset check " grp1" is sent as %20grp1, which is a 404 nobody can
explain from the message. Each rejection has to name WHICH half is wrong, or the
operator reads the wrong end of a 50-character id.
*/
func TestParseGroupMembershipID(t *testing.T) {
	for _, tc := range []struct {
		name        string
		id          string
		group, user string
		wantMsg     string // "" means the id must parse
	}{
		{"well formed", "grp1:usr1", "grp1", "usr1", ""},
		{"ids may contain hyphens and underscores", "g-1_a:u-2_b", "g-1_a", "u-2_b", ""},
		{"realistic object ids", "5f8d0d55b54764421b7156c3:5f8d0d55b54764421b7156c9",
			"5f8d0d55b54764421b7156c3", "5f8d0d55b54764421b7156c9", ""},

		// Shape: the separator is missing or a half is empty.
		{"no separator", "grp1usr1", "", "", "<group_id>:<user_id>"},
		{"empty group", ":usr1", "", "", "<group_id>:<user_id>"},
		{"empty user", "grp1:", "", "", "<group_id>:<user_id>"},
		{"empty id", "", "", "", "<group_id>:<user_id>"},
		{"separator only", ":", "", "", "<group_id>:<user_id>"},

		// Charset: the shape is right and the contents cannot be an id. The
		// message names the offending half.
		{"leading space on the group", " grp1:usr1", "", "", "unusable group_id"},
		{"trailing space on the user", "grp1:usr1 ", "", "", "unusable user_id"},
		{"trailing newline from a paste", "grp1:usr1\n", "", "", "unusable user_id"},
		{"a space inside the group", "grp 1:usr1", "", "", "unusable group_id"},
		{"path traversal in the group", "../grp1:usr1", "", "", "unusable group_id"},
		// Both halves are unusable here; the group is reported because it is
		// checked first, and the name says so rather than implying the user half
		// was the one that failed.
		{"slashes in both halves, the group reported first", "usr1/../..:usr1/..",
			"", "", "unusable group_id"},
		{"a percent escape spelled out", "%20grp1:usr1", "", "", "unusable group_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, u, err := parseGroupMembershipID(tc.id)
			if (err != nil) != (tc.wantMsg != "") {
				t.Fatalf("err = %v, want an error = %v", err, tc.wantMsg != "")
			}
			if g != tc.group || u != tc.user {
				t.Errorf("got (%q, %q), want (%q, %q)", g, u, tc.group, tc.user)
			}
			// An error that does not say what is wrong leaves the operator
			// guessing at a `terraform import` argument.
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q does not contain %q", err, tc.wantMsg)
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
TestGroupMembershipNeverDeletesItsParents is a TRIPWIRE, NOT THE GUARD. The guard
is the request-count assertion in TestGroupMembershipDeleteSwallowsA404ButNothingElse:
exactly one request leaves Delete, and its method and path are pinned.

This test greps the source, and a grep cannot see what a resource actually does.
Review demonstrated the defeat: `nuke := client.TeamAPI.DeleteGroup` followed by
`nuke(ctx, groupID).Execute()` deletes the parent group on every membership
destroy and the whole package still reports ok. A wrapper function, an aliased
import, or the call made from another file in the package all evade it equally.

It is kept because it is free and it names the mistake at the point where someone
would make it -- a reviewer reading a diff that adds "DeleteGroup(" to this file
gets a failing test rather than a passing one. Comments are stripped before the
search so the test cannot be tripped by prose describing the rule it enforces,
which is how review's first attempt at a mutation was "caught".
*/
func TestGroupMembershipNeverDeletesItsParents(t *testing.T) {
	src, err := os.ReadFile("resource_group_membership.go")
	if err != nil {
		t.Fatal(err)
	}
	// Comments out, code only. Block comments first: this file's doc comments
	// name both operations in prose, and a grep that reads them is measuring the
	// documentation.
	code := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(string(src), "")
	code = regexp.MustCompile(`(?m)//[^\n]*$`).ReplaceAllString(code, "")
	for _, forbidden := range []string{"DeleteGroup", "DeleteUser"} {
		if strings.Contains(code, forbidden) {
			t.Errorf("resource_group_membership.go names %s in code: a membership must delete "+
				"only the pairing, never a parent", forbidden)
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

THE NAME NOW READS NARROWER THAN THE TEST IS, and deliberately so -- it is
referenced from three other comments in this package. A 404 is not the only
answer that means "the pairing is already gone": the first live probe measured the
SECOND remove of the same pairing answering 409 USER_ALREADY_NOT_IN_GROUP, while
the two siblings on the same route (USER_NOT_FOUND, GROUP_NOT_FOUND) answer 404.
The old guard was written for a 404 alone, so it could never fire on the case
GRP-D02 actually exercises. The two rows after it are what keep the new swallow
honest: a DIFFERENT 409 and a 409 with nothing to match on must both still fail,
because 409 in general means the server refused on account of state -- and
isNotFound is deliberately not widened to cover it.

THE REQUEST COUNT IS THE PARENT-DELETE GUARD, and it is the reason this test
records every request rather than the last one. Exactly one request may leave
Delete. A resource that also deleted the parent group would issue two, and it
would do so however the call was spelled -- through a method value, a wrapper, an
aliased import, or another file in the package -- none of which
TestGroupMembershipNeverDeletesItsParents can see, as review demonstrated by
defeating it. Asserting only the LAST request's path hides the case where the
parent is deleted FIRST, which is exactly the order a destroy would use.
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
		// MEASURED: the second DELETE of the same pairing answers 409, not 404,
		// with this exact body. Its two siblings on the same route answer 404
		// (USER_NOT_FOUND, GROUP_NOT_FOUND), which is why the guard was written
		// for a 404 and why nothing offline caught it. Without the marker check
		// this row fails and GRP-D02 is broken as shipped.
		{"409 USER_ALREADY_NOT_IN_GROUP is the same statement as a 404", http.StatusConflict,
			`{"message":"USER_ALREADY_NOT_IN_GROUP","messageCode":"CONFLICT","status":409}`,
			false, true},
		// The narrowness of the swallow, and the reason it is keyed on the
		// marker and not on the status. A 409 in general means "the server
		// refused because of state" -- DELETE /v3/gum/custom-roles/{id} returns
		// one to say the role still has users assigned -- and swallowing that
		// would report a successful destroy for an object that still exists.
		{"a different 409 must still fail", http.StatusConflict,
			`{"message":"ROLE_HAS_ASSIGNED_USERS","messageCode":"CONFLICT","status":409}`,
			true, false},
		// Same rule with nothing to match on. A body the provider cannot read
		// is not evidence that the pairing is gone.
		{"a 409 with no marker in the body must still fail", http.StatusConflict,
			`{}`, true, false},
		{"500 must not be mistaken for success", http.StatusInternalServerError,
			`{"message":"boom"}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceGroupMembership().Schema, map[string]interface{}{})
			d.SetId("grp-1:usr-1")

			diags := resourceGroupMembershipDelete(context.Background(), d, newTestUserAPIClient(srv.URL))

			// ONE request, and this one. Two would mean a parent was deleted as
			// well -- see the note above on why the count, and not a grep, is
			// the guard. The path is asserted rather than assumed because the
			// whole point of this resource is that its Delete addresses the
			// MEMBER endpoint and never /v3/groups/grp-1 or /v3/users/usr-1.
			want := []string{"DELETE /v3/groups/grp-1/member/usr-1"}
			if !testComparableArraiesEq(requests, want) {
				t.Errorf("requests were %v, want exactly %v: a membership destroy touches the "+
					"pairing and nothing else", requests, want)
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
	for _, id := range []string{
		// Wrong shape.
		"grp1usr1", ":usr-1", "grp-1:", "", ":",
		// Right shape, impossible contents. These are the ones that would
		// otherwise reach the wire: " grp-1" goes out as %20grp-1, and
		// "../grp-1" as ..%2Fgrp-1, both against a path this provider composed.
		" grp-1:usr-1", "grp-1:usr-1 ", "grp-1:usr-1\n", "../grp-1:usr-1",
	} {
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
TestGroupMembershipReadDoesNotMistakeAServerErrorForDrift is Read's half of the
narrowness TestGroupMembershipDeleteSwallowsA404ButNothingElse asserts for Delete.
Review found this branch untested, asymmetrically, and it deserves the same care:
making Read treat EVERY error as drift left the whole package reporting ok.

The consequence of getting it wrong is not a failed plan, it is a destroyed
membership. Read reports absence by clearing the id, so a 500 read as absence
removes a live pairing from state; Terraform then plans a create, and if the
member is in fact still there the re-POST papers over it -- while any operator
running `terraform plan` during a server incident sees phantom changes across
every membership they own.

A 404 on the COLLECTION is different and must still clear the id: /v3/groups
answering "not found" means the tenant has no such collection to search, so the
membership cannot be established either way. That is the drift path GRP-D02's
precondition uses.
*/
func TestGroupMembershipReadDoesNotMistakeAServerErrorForDrift(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantErr    bool
		wantIDGone bool
	}{
		{"500 is a broken server, not an absent membership", http.StatusInternalServerError,
			`{"message":"boom"}`, true, false},
		{"503 likewise", http.StatusServiceUnavailable,
			`{"message":"upstream unavailable"}`, true, false},
		{"404 on the collection is drift", http.StatusNotFound,
			`{"message":"not found"}`, false, true},
		{"200 with the pairing present is no drift at all", http.StatusOK,
			groupListPage(1, 1, 1, `{"id":"grp-1","name":"Engineering","users":["usr-1"]}`),
			false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceGroupMembership().Schema, map[string]interface{}{})
			d.SetId("grp-1:usr-1")

			diags := resourceGroupMembershipRead(context.Background(), d, newTestUserAPIClient(srv.URL))
			if diags.HasError() != tc.wantErr {
				t.Errorf("HasError = %v, want %v: %v", diags.HasError(), tc.wantErr, diags)
			}
			if gone := d.Id() == ""; gone != tc.wantIDGone {
				t.Errorf("id cleared = %v, want %v: clearing it on a server error deletes a live "+
					"membership from state", gone, tc.wantIDGone)
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
TestAccCheckpointsaseGroupMembership_basic covers GRP-04: apply a user, a group
and a membership joining them, then remove ONLY the membership block and apply
again. Both parents must survive.

THE STEP BOUNDARIES ARE THE WHOLE DESIGN HERE, because state is not evidence at
the moment most assertions want to read it. step.Check runs against the state
returned by the apply it belongs to, with NO refresh first --
testing_new_config.go takes the state at line 79 and calls Check at line 99,
while the post-apply refresh is at line 146, after both. So:

  - Step 1 must NOT assert the group's `users` list. The group is created before
    the membership, and resourceGroupCreate ends in a Read that ran while the
    group still had no members, so state holds an empty list. Review caught an
    earlier version asserting users.# == 1 here: that assertion could never pass,
    whatever the provider did.
  - Step 2 re-applies the same configuration, which begins by refreshing. Only
    then does the group's state carry the member, so that is where the `users`
    assertion lives.
  - Step 3 removes the membership block, and asserts the parents SURVIVE, which is
    what the row actually specifies: both still in state, with the same ids they
    had in step 1.

Step 3's live half reads the API rather than state, and for the mirror-image
reason: Terraform refreshes the group before destroying the membership and does
not re-read it afterwards, since the group has no changes of its own -- so
`users.#` in step 3's state still shows the member that was just removed. A check
written on that attribute passes when the membership was NOT removed and fails
when it was.
*/
func TestAccCheckpointsaseGroupMembership_basic(t *testing.T) {
	suffix := randStringBytesRmndr()
	groupName := "tf-acc-" + suffix
	// testAccUserEmail, not a literal: the domain is defined once in
	// resource_user_test.go, and the note there records why it is example.com
	// and not the RFC 2606 .invalid the server rejects.
	email := testAccUserEmail(suffix)
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
					// NO assertion on checkpointsase_group.test.users here. See
					// the note above: the group's Read ran before the member
					// existed, and this step does not refresh.
				),
			},
			// The same configuration again. The step refreshes before it plans,
			// so this is the first point at which the group's state can carry
			// the member -- and the plan must still be empty, which is what
			// makes the membership's own read-back consistent.
			{
				Config: testAccGroupMembershipConfig(groupName, email),
				Check: resource.ComposeTestCheckFunc(
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
					// The row's actual requirement: the parents are still there,
					// and are the SAME objects -- not replacements.
					testAccCheckResourceIDUnchanged("checkpointsase_group.test", &groupID),
					testAccCheckResourceIDUnchanged("checkpointsase_user.test", &userID),
					// And they are still there in the tenant, not just in state.
					testAccCheckGroupMembershipRemovedAndParentsAlive(&groupID, &userID),
				),
			},
		},
	})
}

/*
testAccCheckResourceIDUnchanged asserts a resource is still in state under the
same id it had earlier in the test.

Both halves matter for GRP-04. Absent from state means the parent was destroyed
along with the membership -- the failure this whole resource is written to avoid.
A DIFFERENT id means it was replaced: every attribute of both parents is ForceNew
(neither /v3/groups nor /v3/users has an update endpoint), so a replacement is a
delete and a recreate, which for a group would silently drop every other
membership in it.

The id is taken by pointer because the closure is built before the step that
captures it has run.
*/
func testAccCheckResourceIDUnchanged(name string, want *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if *want == "" {
			return fmt.Errorf("no id was captured for %s; an earlier step's Check did not run", name)
		}
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("%s is no longer in state: removing a membership must not remove "+
				"either parent", name)
		}
		if rs.Primary.ID != *want {
			return fmt.Errorf("%s id changed from %s to %s: removing a membership must not "+
				"replace either parent", name, *want, rs.Primary.ID)
		}
		return nil
	}
}

/*
TestAccCheckpointsaseGroupMembership_destroyOrder covers GRP-05: one apply of all
three resources, then the driver's own full destroy at the end of the test.

WHAT THIS ROW CANNOT PROVE, said plainly so that a green run is not mistaken for
evidence of ordering: it cannot tell a correct destroy order from a wrong one. If
a parent were destroyed first the membership's DELETE would 404 -- and GRP-D02
requires that 404 to be SWALLOWED -- so the destroy succeeds either way and
CheckDestroy still finds everything gone.

The ordering is produced by Terraform core from the config's references to the
parents' ids. It is not provider behaviour, and nothing available here observes
it. An earlier version of this file substituted a regex over the config string for
that assertion; review defeated it by replacing both references with literal ids
while the test still passed, so it was deleted rather than left as decoration. A
documented limitation beats a test that cannot fail. If this ever needs a real
gate, it is an hclparse of the config asserting the reference edges -- not a
substring search.

What the row does prove is worth the live minutes: three resources that reference
one another apply cleanly, and a real tenant is left with nothing behind, since
CheckDestroy verifies the pairing, the user and the group are all gone.
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
					testAccUserEmail(suffix)),
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

The pattern is ANCHORED ON THE PROVIDER'S OWN SUMMARY, and it has to be. The
previous version was a bare alternation that included the word "invalid", which
an authentication failure satisfies -- so the row would have passed on an expired
credential without ever reaching the endpoint it names. "Unable to add member to
group" is the summary resourceGroupMembershipCreate attaches and nothing else
does, so it proves the failure came from this call.

The status term stays as a secondary requirement rather than the primary one
because appendErrorDiags prefers the response BODY over the status line: an id of
the right shape that names nothing may come back as a 404, or as a 400 if the
server validates the id format first, and the body may spell either as words. If
a live run fails on the second term alone, read the body it reports and widen that
term -- do not remove the summary anchor.
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
				Config: config,
				ExpectError: regexp.MustCompile(
					`(?s)Unable to add member to group.*(?i:404|400|not.?found|does not exist|no such)`),
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
	client := testAccEnvClient()
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
		client := testAccEnvClient()

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

The two ids are REFERENCES, not literals, and that is load-bearing: the references
are what put edges in Terraform's dependency graph, and the edges are what order
the membership's DELETE before either parent's. Nothing in this suite can observe
that ordering -- see the note on
TestAccCheckpointsaseGroupMembership_destroyOrder -- so if you replace either
reference with a literal id, no test will tell you.
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
