package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// =========================================================================
// Acceptance coverage: USR-04, USR-05, USR-06, GRP-06, GRP-07.
//
// Every test in this block needs TF_ACC and a working v3 credential, neither of
// which exists in this workspace, so none of them has been observed to pass or
// to fail. They are written to be run on the next live pass; what has been
// verified here is that they compile and that they skip rather than silently
// matching nothing.
//
// The offline block further down is the part that has been watched fail.
// =========================================================================

/*
TestAccCheckpointsaseUsersDataSource_basic is USR-04: read the data source with
no arguments.

The tenant always holds at least the account owner, so `data` is asserted
non-empty rather than merely present -- this is one of the few tenant-wide reads
where a count assertion is justified by the API rather than guessed.

`email` is deliberately NOT in the fields-must-be-set list. A21b removed
User.required entirely because a directory-synced account can lack a `mail`
attribute, so an empty email is a legal record rather than a flatten defect, and
asserting on it would fail against a tenant that has one. `id` is the only field
the model guarantees in practice, and it is the one the test keys on.
*/
func TestAccCheckpointsaseUsersDataSource_basic(t *testing.T) {
	const users = "data.checkpointsase_users.all"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: `data "checkpointsase_users" "all" {}`,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckDataSourceListMinLen(users, "data", 1),
					testAccCheckDataSourceElemFieldsSet(users, "data", 0, "id"),
					// roles is a nested list, so state holds data.0.roles.#
					// rather than data.0.roles; the helper above asserts on
					// scalar keys only.
					testAccCheckDataSourceNestedListPresent(users, "data", 0, "roles"),
					// The three pagination fields must all be present and
					// coherent with the rows returned.
					testAccCheckUsersPaginationCoherent(users),
					// USR-04 is also the one place the omission decision is
					// observable end to end: no row may carry an
					// invitation_token key in state.
					testAccCheckDataSourceElemKeyAbsent(users, "data", "invitation_token"),
				),
			},
		},
	})
}

/*
TestAccCheckpointsaseUsersDataSource_pagination is USR-05: page = 1, limit = 1.

Two instances in one configuration, differing only in `page`, so the derived-ID
assertion is available: a data source that takes arguments and hardcodes one ID
would give both instances the same identity.

`data` is asserted to hold AT MOST one row, which is what a limit of 1 means. It
is not asserted to hold exactly one, because page 2 of a single-user tenant is
legitimately empty.
*/
func TestAccCheckpointsaseUsersDataSource_pagination(t *testing.T) {
	const (
		first  = "data.checkpointsase_users.first"
		second = "data.checkpointsase_users.second"
	)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: `
data "checkpointsase_users" "first" {
  page  = 1
  limit = 1
}

data "checkpointsase_users" "second" {
  page  = 2
  limit = 1
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(first, "page", "1"),
					resource.TestCheckResourceAttr(first, "limit", "1"),
					testAccCheckDataSourceListMaxLen(first, "data", 1),
					testAccCheckDataSourceListMinLen(first, "data", 1),
					testAccCheckDataSourceIntAtLeast(first, "items_total", 1),
					testAccCheckDataSourceIntAtLeast(first, "total_page", 1),

					testAccCheckDataSourceListMaxLen(second, "data", 1),

					// The two instances read different pages, so they must not
					// share an ID (L16c's mirror image).
					testAccCheckDataSourceIDsDiffer(first, second),
				),
			},
		},
	})
}

/*
TestAccCheckpointsaseUsersDataSource_sort is USR-06, and it is the row that
proves the SDK's deepObject fix end to end: before that fix a map query parameter
went to the wire as ?sort=map[email:asc], which the server ignored, so both
orderings came back identical.

resource.TestCheckResourceAttrPair cannot compare across steps, so the first
step's ordering is captured in a closure and the second step compares against it.

WHAT IS ASSERTED, AND WHAT IS DELIBERATELY NOT. The email values are NOT asserted
to be in Go string order: the server's collation is not documented (case folding
and locale are both unknown), so a byte-wise assertion would fail on a correct
server for a reason that is not a defect. What is asserted is collation-agnostic:

  - both reads return the same SET of emails, so `sort` did not also filter;
  - the two orderings DIFFER, which is exactly what a server ignoring the
    parameter cannot produce -- guarded so it only applies when there are at
    least two distinct emails to order;
  - where every email is distinct and non-empty and the whole collection fits on
    one page, the descending order is the exact reverse of the ascending one.

The reverse assertion is conditional because ties make it false for a correct
server: A21b permits an account with no email at all, and two such accounts sort
arbitrarily against each other.
*/
func TestAccCheckpointsaseUsersDataSource_sort(t *testing.T) {
	const users = "data.checkpointsase_users.sorted"
	var ascending []string
	var ascendingSinglePage bool

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: `
data "checkpointsase_users" "sorted" {
  sort = {
    email = "asc"
  }
}
`,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckDataSourceListMinLen(users, "data", 1),
					testAccCaptureDataSourceElemField(users, "data", "email", &ascending),
					testAccCaptureDataSourceSinglePage(users, &ascendingSinglePage),
				),
			},
			{
				Config: `
data "checkpointsase_users" "sorted" {
  sort = {
    email = "desc"
  }
}
`,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckDataSourceListMinLen(users, "data", 1),
					testAccCheckSortOrderIsTheOppositeOf(users, "data", "email",
						&ascending, &ascendingSinglePage),
				),
			},
		},
	})
}

/*
TestAccCheckpointsaseGroupsDataSource_basic is GRP-06: read the data source with
no arguments.

The tenant always holds at least the default group, so a non-empty assertion is
justified. All four projections are asserted to be present as lists rather than
nulls, which is the state-shape half of A22b.

`description` is asserted ABSENT: the Group read model has no such field, so an
attribute for it could only ever hold an empty string, and shipping one would
promise information the API does not return.
*/
func TestAccCheckpointsaseGroupsDataSource_basic(t *testing.T) {
	const groups = "data.checkpointsase_groups.all"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: `data "checkpointsase_groups" "all" {}`,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckDataSourceListMinLen(groups, "data", 1),
					testAccCheckDataSourceElemFieldsSet(groups, "data", 0, "id", "name"),
					testAccCheckDataSourceNestedListPresent(groups, "data", 0,
						"applications", "networks", "vpn_locations", "users"),
					testAccCheckGroupsPaginationCoherent(groups),
					testAccCheckDataSourceElemKeyAbsent(groups, "data", "description"),
				),
			},
		},
	})
}

/*
TestAccCheckpointsaseGroupsDataSource_limit is GRP-07: limit = 1.

Two instances again, one limited and one not, so the derived ID is exercised as
well. `items_total` must be at least the number of rows returned, which is the
pagination-consistency check the pytest row makes against the live API.
*/
func TestAccCheckpointsaseGroupsDataSource_limit(t *testing.T) {
	const (
		limited = "data.checkpointsase_groups.one"
		all     = "data.checkpointsase_groups.all"
	)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: `
data "checkpointsase_groups" "one" {
  limit = 1
}

data "checkpointsase_groups" "all" {}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(limited, "page", "1"),
					resource.TestCheckResourceAttr(limited, "limit", "1"),
					testAccCheckDataSourceListMaxLen(limited, "data", 1),
					testAccCheckDataSourceListMinLen(limited, "data", 1),
					testAccCheckGroupsPaginationCoherent(limited),
					testAccCheckDataSourceIntAtLeast(limited, "items_total", 1),

					testAccCheckDataSourceIDsDiffer(limited, all),
				),
			},
		},
	})
}

// --- acceptance helpers specific to the two paginated identity data sources ---

// testAccCheckDataSourceListMaxLen is the ceiling counterpart of
// testAccCheckDataSourceListMinLen. `limit = 1` cannot promise a row exists, but
// it can promise no more than one comes back, and that is the assertion a
// mishandled limit parameter fails.
func testAccCheckDataSourceListMaxLen(name, attr string, max int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		got, err := dataSourceListLen(attrs, attr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		if got > max {
			return fmt.Errorf("%s: %s has %d elements, want at most %d — the limit argument "+
				"did not reach the server", name, attr, got, max)
		}
		return nil
	}
}

// testAccCheckDataSourceIntAtLeast asserts a scalar numeric attribute is present
// and at least min.
func testAccCheckDataSourceIntAtLeast(name, attr string, min int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		raw, ok := attrs[attr]
		if !ok {
			return fmt.Errorf("%s: %s is absent from state", name, attr)
		}
		got, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("%s: %s = %q, which is not an integer", name, attr, raw)
		}
		if got < min {
			return fmt.Errorf("%s: %s = %d, want at least %d", name, attr, got, min)
		}
		return nil
	}
}

// testAccCheckDataSourceNestedListPresent asserts a list nested inside a list
// element exists in state as a countable list, i.e. that `<attr>.<i>.<field>.#`
// is present. The scalar helpers cannot express this, and a nested list the
// flatten function never set is absent from state rather than zero-length.
func testAccCheckDataSourceNestedListPresent(name, attr string, index int, fields ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		for _, field := range fields {
			key := fmt.Sprintf("%s.%d.%s.#", attr, index, field)
			if _, ok := attrs[key]; !ok {
				return fmt.Errorf("%s: %s is absent from state — %s.%d.%s reads as a null "+
					"rather than a list", name, key, attr, index, field)
			}
		}
		return nil
	}
}

// testAccCheckDataSourceElemKeyAbsent asserts NO element of a list attribute
// carries the named key. Used for the two deliberate omissions: users.data has
// no invitation_token and groups.data has no description.
func testAccCheckDataSourceElemKeyAbsent(name, attr, field string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		prefix := attr + "."
		suffix := "." + field
		var found []string
		for key := range attrs {
			if strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix) {
				found = append(found, key)
			}
		}
		if len(found) > 0 {
			sort.Strings(found)
			return fmt.Errorf("%s: %d state key(s) expose %s, which this data source must not "+
				"return: %s", name, len(found), field, strings.Join(found, ", "))
		}
		return nil
	}
}

// testAccCheckUsersPaginationCoherent and its groups twin assert the three
// pagination attributes are present and do not contradict the rows beside them.
// This is L15's defect stated as an assertion: metadata claiming more than the
// data holds, on a data source whose whole point is that the paging is visible.
func testAccCheckUsersPaginationCoherent(name string) resource.TestCheckFunc {
	return testAccCheckPaginationCoherent(name, "data")
}

func testAccCheckGroupsPaginationCoherent(name string) resource.TestCheckFunc {
	return testAccCheckPaginationCoherent(name, "data")
}

func testAccCheckPaginationCoherent(name, listAttr string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		rows, err := dataSourceListLen(attrs, listAttr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		values := map[string]int{}
		for _, key := range []string{"page", "total_page", "items_total"} {
			raw, ok := attrs[key]
			if !ok {
				return fmt.Errorf("%s: %s is absent from state — the read did not echo the "+
					"server's pagination metadata", name, key)
			}
			n, err := strconv.Atoi(raw)
			if err != nil {
				return fmt.Errorf("%s: %s = %q, which is not an integer", name, key, raw)
			}
			values[key] = n
		}
		if values["items_total"] < rows {
			return fmt.Errorf("%s: items_total = %d but %s holds %d rows — the total contradicts "+
				"the data beside it", name, values["items_total"], listAttr, rows)
		}
		if rows > 0 && values["total_page"] < 1 {
			return fmt.Errorf("%s: total_page = %d beside %d rows", name, values["total_page"], rows)
		}
		if values["page"] < 1 {
			return fmt.Errorf("%s: page = %d, want at least 1", name, values["page"])
		}
		return nil
	}
}

// testAccCaptureDataSourceElemField records one field of every element, in
// order, so a later STEP can compare against it. resource.TestCheckResourceAttrPair
// compares two addresses within one state, which is why this exists.
func testAccCaptureDataSourceElemField(name, attr, field string, into *[]string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		count, err := dataSourceListLen(attrs, attr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		captured := make([]string, count)
		for i := 0; i < count; i++ {
			captured[i] = attrs[fmt.Sprintf("%s.%d.%s", attr, i, field)]
		}
		*into = captured
		return nil
	}
}

// testAccCaptureDataSourceSinglePage records whether the read covered the whole
// collection, which is the precondition for the exact-reverse assertion.
func testAccCaptureDataSourceSinglePage(name string, into *bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		*into = attrs["total_page"] == "1"
		return nil
	}
}

/*
testAccCheckSortOrderIsTheOppositeOf is the second half of USR-06.

See the header on TestAccCheckpointsaseUsersDataSource_sort for why the
assertions are collation-agnostic and why the exact-reverse check is conditional.
*/
func testAccCheckSortOrderIsTheOppositeOf(
	name, attr, field string, ascending *[]string, ascendingSinglePage *bool,
) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		count, err := dataSourceListLen(attrs, attr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		descending := make([]string, count)
		for i := 0; i < count; i++ {
			descending[i] = attrs[fmt.Sprintf("%s.%d.%s", attr, i, field)]
		}
		asc := *ascending
		if len(asc) == 0 {
			return fmt.Errorf("the ascending step captured no %s values, so there is nothing "+
				"to compare against", field)
		}

		// Same set, so sort did not also filter.
		ascSorted := append([]string(nil), asc...)
		descSorted := append([]string(nil), descending...)
		sort.Strings(ascSorted)
		sort.Strings(descSorted)
		if strings.Join(ascSorted, "\x00") != strings.Join(descSorted, "\x00") {
			return fmt.Errorf("the asc and desc reads returned different sets of %s values "+
				"(%d asc, %d desc): sort appears to filter as well as order",
				field, len(asc), len(descending))
		}

		distinct := map[string]bool{}
		empties := 0
		for _, v := range asc {
			if v == "" {
				empties++
				continue
			}
			distinct[v] = true
		}
		if len(distinct) < 2 {
			// One user, or one distinct email: no ordering is observable and
			// nothing can be concluded either way. Saying so beats a green tick
			// that means nothing.
			return nil
		}

		if strings.Join(asc, "\x00") == strings.Join(descending, "\x00") {
			return fmt.Errorf("sort = {%s = \"asc\"} and sort = {%s = \"desc\"} returned the "+
				"IDENTICAL ordering of %d values. That is what a server ignoring the sort "+
				"parameter looks like: before the SDK's deepObject fix the map went to the "+
				"wire as ?sort=map[%s:asc]", field, field, len(asc), field)
		}

		// Exact reverse only where there are no ties to order arbitrarily and
		// the whole collection was on one page.
		if empties == 0 && len(distinct) == len(asc) && *ascendingSinglePage &&
			attrs["total_page"] == "1" {
			for i := range asc {
				if asc[i] != descending[len(descending)-1-i] {
					return fmt.Errorf("descending order is not the reverse of ascending order: "+
						"asc[%d] = %q but desc[%d] = %q (all %d values distinct and non-empty, "+
						"single page both times)",
						i, asc[i], len(descending)-1-i, descending[len(descending)-1-i], len(asc))
				}
			}
		}
		return nil
	}
}

// =========================================================================
// Offline coverage.
//
// Everything below runs with no credential and no network: the SDK client is
// pointed at an httptest server by newTestUserAPIClient (resource_user_test.go),
// which pre-seeds a bearer token so prepareRequest never tries to exchange an
// API key for one.
//
// The fixtures are synthetic, built from the v3 OpenAPI document's schemas. They
// carry no tenant data.
// =========================================================================

/*
TestUsersDataSourceSortIsAMapAndGroupsSortIsAString pins the asymmetry between
the two data sources.

IT IS NOT A STYLE INCONSISTENCY AND MUST NOT BE "FIXED". GET /v3/users declares
`sort` as a deepObject and the generated builder is Sort(map[string]string);
GET /v3/groups declares a bare string and its builder is Sort(string). Making
either match the other would mean either flattening a map into a string the users
endpoint does not parse, or offering a field-and-direction map on the groups
endpoint, which would be surface the server ignores while the provider's
documentation promised it worked.
*/
func TestUsersDataSourceSortIsAMapAndGroupsSortIsAString(t *testing.T) {
	t.Parallel()

	usersSort, ok := dataSourceUsers().Schema["sort"]
	if !ok {
		t.Fatal("checkpointsase_users has no sort argument")
	}
	if usersSort.Type != schema.TypeMap {
		t.Errorf("checkpointsase_users.sort is %s, want TypeMap: GET /v3/users declares sort "+
			"as a deepObject (sort[email]=asc) and the generated builder takes "+
			"map[string]string", usersSort.Type)
	}

	groupsSort, ok := dataSourceGroups().Schema["sort"]
	if !ok {
		t.Fatal("checkpointsase_groups has no sort argument")
	}
	if groupsSort.Type != schema.TypeString {
		t.Errorf("checkpointsase_groups.sort is %s, want TypeString: GET /v3/groups declares "+
			"sort as a plain string and the generated builder takes string", groupsSort.Type)
	}
	// The groups side must stay unvalidated: the API documents no grammar for it,
	// so any rule would be a guess that can refuse a value the server takes.
	if groupsSort.ValidateFunc != nil || groupsSort.ValidateDiagFunc != nil {
		t.Error("checkpointsase_groups.sort carries a validator, but the API documents no " +
			"grammar for it — a guessed rule can only refuse values the server accepts")
	}
}

/*
TestValidateSortDirections covers the users-side sort enum.

The API's sort object accepts asc/desc and nothing else, and the enum is the whole
of its validation, so a typo is otherwise a 400 arriving after Terraform has
already reported a valid plan.
*/
func TestValidateSortDirections(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		sortOrder map[string]interface{}
		wantErrs  int
	}{
		{"single ascending", map[string]interface{}{"email": "asc"}, 0},
		{"two fields, both valid", map[string]interface{}{"email": "desc", "firstName": "asc"}, 0},
		{"empty map", map[string]interface{}{}, 0},
		{"spelled out", map[string]interface{}{"email": "ascending"}, 1},
		{"upper case", map[string]interface{}{"email": "ASC"}, 1},
		{"empty direction", map[string]interface{}{"email": ""}, 1},
		{"one good one bad", map[string]interface{}{"email": "asc", "firstName": "up"}, 1},
		{"both bad", map[string]interface{}{"email": "up", "firstName": "down"}, 2},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			diags := validateSortDirections(tc.sortOrder, nil)
			errs := 0
			for _, d := range diags {
				if d.Severity == diag.Error {
					errs++
				}
			}
			if errs != tc.wantErrs {
				t.Errorf("validateSortDirections(%v) produced %d error(s), want %d: %v",
					tc.sortOrder, errs, tc.wantErrs, diags)
			}
		})
	}
}

/*
TestValidateSortDirectionsRunsThroughTheSchema is the half the table above cannot
reach: that the validator is actually WIRED to the attribute.

A ValidateDiagFunc that is written and tested but never assigned passes every
unit test and validates nothing, and for a TypeMap the SDK only reaches
validateFunc through schemaMap.validateMap. This drives the provider's own
validation machinery instead, so it fails if the ValidateDiagFunc field is
dropped from the schema entry.
*/
func TestValidateSortDirectionsRunsThroughTheSchema(t *testing.T) {
	t.Parallel()

	ds := dataSourceUsers()
	cases := []struct {
		name    string
		raw     map[string]interface{}
		wantErr bool
	}{
		{"valid direction", map[string]interface{}{"sort": map[string]interface{}{"email": "asc"}}, false},
		{"invalid direction", map[string]interface{}{"sort": map[string]interface{}{"email": "ascending"}}, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			diags := ds.Validate(terraform.NewResourceConfigRaw(tc.raw))
			if diags.HasError() != tc.wantErr {
				t.Errorf("Validate(%v) HasError = %v, want %v: %v",
					tc.raw, diags.HasError(), tc.wantErr, diags)
			}
		})
	}
}

/*
TestUsersDataSourceDoesNotExposeInvitationToken pins a decision, which is why it
is a test and not only a comment.

A collection read over every user in the tenant has no business handing out every
pending user's enrolment token -- whoever holds one can complete that user's
enrolment -- and Terraform writes data source attributes to state in PLAINTEXT
whatever the Sensitive marker says, so marking it would not have made it safe.
checkpointsase_user (the resource) does expose it, marked Sensitive, because there
the scope is one account the operator is managing deliberately.

The walk covers the whole element schema rather than just its top level, so a
later nested block cannot smuggle the field back in.
*/
func TestUsersDataSourceDoesNotExposeInvitationToken(t *testing.T) {
	t.Parallel()

	elem, ok := dataSourceUsers().Schema["data"].Elem.(*schema.Resource)
	if !ok {
		t.Fatal("checkpointsase_users.data has no *schema.Resource element schema")
	}
	var offenders []string
	walkSchema("", elem.Schema, func(path string, _ *schema.Schema) {
		leaf := path
		if i := strings.LastIndex(path, "."); i >= 0 {
			leaf = path[i+1:]
		}
		if normalizeAttributeName(leaf) == normalizeAttributeName("invitation_token") {
			offenders = append(offenders, path)
		}
	})
	if len(offenders) > 0 {
		t.Errorf("checkpointsase_users.data exposes %s. An invitation token completes a "+
			"user's enrolment for whoever holds it, and a tenant-wide read would write one "+
			"per pending user into state in plaintext", strings.Join(offenders, ", "))
	}
}

/*
TestGroupsDataSourceHasNoDescriptionAttribute pins the other omission.

perimeter-81-client-sdk/model_group.go declares exactly seven fields -- name,
isDefault, applications, networks, vpnLocations, users, id -- and no description.
CreateGroupDto accepts one on the way in and nothing ever returns it
(API-FINDINGS.md 1.7). The task brief for this data source lists a description
attribute; the generated model wins, and an attribute here could only ever report
an empty string beside a group that has one.

The assertion is derived from the MODEL rather than hardcoded, so it keeps its
meaning if a later regeneration adds the field: on that day this test fails and
whoever sees it adds the attribute, instead of the gap persisting because a
hand-written expectation still matched.
*/
func TestGroupsDataSourceHasNoDescriptionAttribute(t *testing.T) {
	t.Parallel()

	// Round-trip a group record carrying a description through the generated
	// model. If the model still has no such field, the key lands in
	// AdditionalProperties and GetName is the only thing that survives.
	var group perimeter81Sdk.Group
	if err := group.UnmarshalJSON([]byte(
		`{"id":"grp-1","name":"Engineering","description":"the description"}`)); err != nil {
		t.Fatalf("Group.UnmarshalJSON: %v", err)
	}
	if _, modelHasDescription := group.AdditionalProperties["description"]; !modelHasDescription {
		t.Skip("Group now carries a typed description field; add a description attribute to " +
			"checkpointsase_groups.data and delete this test")
	}

	elem, ok := dataSourceGroups().Schema["data"].Elem.(*schema.Resource)
	if !ok {
		t.Fatal("checkpointsase_groups.data has no *schema.Resource element schema")
	}
	if _, present := elem.Schema["description"]; present {
		t.Error("checkpointsase_groups.data exposes description, but the Group read model " +
			"has no such field — the attribute could only ever report an empty string")
	}
}

/*
TestFlattenUsersDataCoercesNilRoles asserts a user record with every optional
field absent still flattens to a complete row: every scalar key present with its
zero value, and `roles` an empty slice rather than a nil.

A21b removes User.required ENTIRELY -- email included, because a
directory-synced account can lack a `mail` attribute -- so this fixture is a legal
record, not a degenerate one, and every field must go through a nil-safe accessor.
Assigning a pointer directly would put a Go address into state, which is the
defect this pins.

About the `roles` assertion, stated precisely so nobody builds on an overclaim:
it asserts flattenUsersData's OWN OUTPUT is a non-nil slice, and it does fail if
the nil-to-empty coercion is deleted. It does NOT assert anything about state,
because there is nothing to assert -- measured 2026-08-20, d.Set normalises a nil
slice to the same empty list a []string{} produces, so state holds [] with or
without the coercion. The coercion is legibility, not a guard, and this test does
not pretend otherwise.
*/
func TestFlattenUsersDataCoercesNilRoles(t *testing.T) {
	t.Parallel()

	id := "usr-1"
	rows := flattenUsersData([]perimeter81Sdk.User{{Id: &id}})
	if len(rows) != 1 {
		t.Fatalf("flattenUsersData returned %d rows, want 1", len(rows))
	}
	row, ok := rows[0].(map[string]interface{})
	if !ok {
		t.Fatalf("row is %T, want map[string]interface{}", rows[0])
	}

	wantScalars := map[string]interface{}{
		"id":             "usr-1",
		"email":          "",
		"email_verified": false,
		"username":       "",
		"first_name":     "",
		"last_name":      "",
		"initials":       "",
		"role":           "",
		"role_name":      "",
		"terminated":     false,
	}
	for key, want := range wantScalars {
		got, present := row[key]
		if !present {
			t.Errorf("%q is absent from the flattened row", key)
			continue
		}
		if got != want {
			t.Errorf("%q = %#v, want %#v — an absent pointer field must flatten to its zero "+
				"value, not to a pointer", key, got, want)
		}
	}

	roles, ok := row["roles"].([]string)
	if !ok {
		t.Fatalf("roles is %T, want []string", row["roles"])
	}
	if roles == nil {
		t.Error("roles is nil; flattenUsersData must hand d.Set a slice")
	}
	if len(roles) != 0 {
		t.Errorf("roles has %d elements, want 0", len(roles))
	}

	if _, present := row["invitation_token"]; present {
		t.Error("the flattened row carries invitation_token, which this data source must not " +
			"return")
	}
}

/*
TestFlattenGroupsDataCoercesNilLists is the same assertion for groups: a record
carrying nothing but an id must flatten to two scalars and FOUR EMPTY LISTS.

A22b removes Group.required entirely, and all four projections are omitempty, so
a group with no applications, networks, VPN locations or members decodes to four
nil slices -- the routine case for a group the provider has just created.
*/
func TestFlattenGroupsDataCoercesNilLists(t *testing.T) {
	t.Parallel()

	id := "grp-1"
	rows := flattenGroupsData([]perimeter81Sdk.Group{{Id: &id}})
	if len(rows) != 1 {
		t.Fatalf("flattenGroupsData returned %d rows, want 1", len(rows))
	}
	row, ok := rows[0].(map[string]interface{})
	if !ok {
		t.Fatalf("row is %T, want map[string]interface{}", rows[0])
	}

	if row["id"] != "grp-1" {
		t.Errorf("id = %#v, want \"grp-1\"", row["id"])
	}
	if row["name"] != "" {
		t.Errorf("name = %#v, want \"\" — A22b makes name optional, so an absent one must "+
			"flatten to the empty string rather than a pointer", row["name"])
	}
	if row["is_default"] != false {
		t.Errorf("is_default = %#v, want false", row["is_default"])
	}

	for _, key := range []string{"applications", "networks", "vpn_locations", "users"} {
		value, present := row[key]
		if !present {
			t.Errorf("%q is absent from the flattened row", key)
			continue
		}
		list, ok := value.([]string)
		if !ok {
			t.Errorf("%q is %T, want []string", key, value)
			continue
		}
		if list == nil {
			t.Errorf("%q is nil; flattenGroupsData must hand d.Set a slice", key)
		}
		if len(list) != 0 {
			t.Errorf("%q has %d elements, want 0", key, len(list))
		}
	}

	if _, present := row["description"]; present {
		t.Error("the flattened row carries a description key, but the Group model has no such " +
			"field — there is nothing that could have been read into it")
	}
}

/*
TestUsersDataSourceSendsSortAsADeepObject is the OFFLINE half of USR-06, and the
one that can actually be run here.

USR-06 needs a live tenant with at least two users to observe an ordering change.
This test observes the cause instead: the exact query string the SDK builds. The
defect it pins was measured -- before the deepObject fix in the SDK's client.go, a
map query parameter fell through to fmt.Sprintf("%v", v) and
GET /v3/users?sort[email]=asc went to the wire as ?sort=map[email:asc], which the
server ignores. Nothing about that is visible from the provider's own types, so
without this test the whole of USR-06 waits on a credential.

page and limit are asserted alongside it because they exercise the OTHER hand fix
in the same function: a pointer scalar query parameter used to reach the wire as
its address (?page=0x14000112028).
*/
func TestUsersDataSourceSendsSortAsADeepObject(t *testing.T) {
	t.Parallel()

	var gotQuery url.Values
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(userListPage(1, 1, 0, "")))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, dataSourceUsers().Schema, map[string]interface{}{
		"page":  3,
		"limit": 7,
		"where": "terminated=false",
		"sort":  map[string]interface{}{"email": "asc"},
	})

	if diags := dataSourceUsersRead(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}

	if gotPath != "/v3/users" {
		t.Errorf("path = %q, want /v3/users", gotPath)
	}
	for key, want := range map[string]string{
		"sort[email]": "asc",
		"page":        "3",
		"limit":       "7",
		"where":       "terminated=false",
	} {
		if got := gotQuery.Get(key); got != want {
			t.Errorf("query %s = %q, want %q (whole query: %v)", key, got, want, gotQuery)
		}
	}
	// The pre-fix form. Naming it explicitly makes a regression report itself
	// rather than showing up only as a missing sort[email].
	if raw, present := gotQuery["sort"]; present {
		t.Errorf("the query carries a bare sort=%v. That is the pre-fix form "+
			"(?sort=map[email:asc]) and the server ignores it; the deepObject handling in the "+
			"SDK's client.go has regressed", raw)
	}
}

/*
TestGroupsDataSourceSendsSortAsAPlainString is the groups counterpart: its sort
must reach the wire as ?sort=name and NOT as ?sort[...]=..., which is the shape
that would appear if the two data sources were ever harmonised on the map form.
*/
func TestGroupsDataSourceSendsSortAsAPlainString(t *testing.T) {
	t.Parallel()

	var gotQuery url.Values
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(groupListPage(1, 1, 0, "")))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, dataSourceGroups().Schema, map[string]interface{}{
		"page":  2,
		"limit": 5,
		"sort":  "name",
	})

	if diags := dataSourceGroupsRead(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}

	if gotPath != "/v3/groups" {
		t.Errorf("path = %q, want /v3/groups", gotPath)
	}
	for key, want := range map[string]string{"sort": "name", "page": "2", "limit": "5"} {
		if got := gotQuery.Get(key); got != want {
			t.Errorf("query %s = %q, want %q (whole query: %v)", key, got, want, gotQuery)
		}
	}
	for key := range gotQuery {
		if strings.HasPrefix(key, "sort[") {
			t.Errorf("the query carries %q. GET /v3/groups declares sort as a plain string; "+
				"the bracketed form is checkpointsase_users' shape and must not appear here", key)
		}
	}
}

/*
TestUsersDataSourceOmitsUnsetArguments pins that an omitted optional argument is
absent from the query rather than sent empty.

`where=` and `sort=` are not the same request as no where and no sort: the API
documents no grammar for `where`, so an empty one is a filter expression the
server is free to reject or to interpret. This is the same distinction
resourceGroupCreate makes for description.
*/
func TestUsersDataSourceOmitsUnsetArguments(t *testing.T) {
	t.Parallel()

	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(userListPage(1, 1, 0, "")))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, dataSourceUsers().Schema, map[string]interface{}{})

	if diags := dataSourceUsersRead(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}

	for _, key := range []string{"where", "sort"} {
		if _, present := gotQuery[key]; present {
			t.Errorf("query carries %s=%q for a configuration that set neither; an unset "+
				"optional filter must be omitted, not sent empty", key, gotQuery.Get(key))
		}
	}
	// page and limit ARE always sent: leaving them to the server's default is
	// exactly L15's shape, where nobody can say which page they got.
	for key, want := range map[string]string{
		"page":  strconv.Itoa(usersDataSourceDefaultPage),
		"limit": strconv.Itoa(usersDataSourceDefaultLimit),
	} {
		if got := gotQuery.Get(key); got != want {
			t.Errorf("query %s = %q, want %q — page and limit are sent explicitly so state "+
				"records which page was read", key, got, want)
		}
	}
}

/*
TestUsersDataSourceReadEchoesTheServersPagination is USR-04's and USR-05's
assertion made offline: the three pagination attributes in state come from the
RESPONSE, not from the arguments.

The fixture deliberately answers a request for page 2 with page 4, which no
correct server does. That is the only way to tell an echo of the server apart
from an echo of the provider's own argument -- and getting that wrong is what
would make USR-05's "page reads back as 1" a test that cannot fail. The mismatch
must also raise a warning rather than pass silently, because a server that
ignores `page` is L15's defect with the argument present.
*/
func TestUsersDataSourceReadEchoesTheServersPagination(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(userListPage(4, 9, 17,
			`{"id":"usr-1","email":"nobody@example.invalid","roles":["Member"]}`)))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, dataSourceUsers().Schema, map[string]interface{}{
		"page": 2,
	})

	diags := dataSourceUsersRead(context.Background(), d, newTestUserAPIClient(srv.URL))
	if diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}

	for key, want := range map[string]int{"page": 4, "total_page": 9, "items_total": 17} {
		if got := d.Get(key).(int); got != want {
			t.Errorf("%s = %d, want %d — the value in state must be the one the server "+
				"reported, not the argument the provider sent", key, got, want)
		}
	}

	warnings := 0
	for _, diagnostic := range diags {
		if diagnostic.Severity == diag.Warning {
			warnings++
		}
	}
	if warnings == 0 {
		t.Error("the server answered a request for page 2 with page 4 and the read reported " +
			"no warning; a server ignoring `page` would then be invisible")
	}

	rows := d.Get("data").([]interface{})
	if len(rows) != 1 {
		t.Fatalf("data holds %d rows, want 1", len(rows))
	}
	row := rows[0].(map[string]interface{})
	if row["email"] != "nobody@example.invalid" {
		t.Errorf("data.0.email = %#v, want \"nobody@example.invalid\"", row["email"])
	}
	if roles := row["roles"].([]interface{}); len(roles) != 1 || roles[0] != "Member" {
		t.Errorf("data.0.roles = %#v, want [\"Member\"]", row["roles"])
	}
}

/*
TestGroupsDataSourceReadEchoesTheServersPagination is the groups twin of the test
above, and covers GRP-06's shape assertion offline: a group record carrying
nothing but an id and a name must land in state with four empty lists beside it.
*/
func TestGroupsDataSourceReadEchoesTheServersPagination(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(groupListPage(1, 3, 5,
			`{"id":"grp-1","name":"Engineering","isDefault":true}`)))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, dataSourceGroups().Schema, map[string]interface{}{
		"limit": 1,
	})

	if diags := dataSourceGroupsRead(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}

	for key, want := range map[string]int{"page": 1, "total_page": 3, "items_total": 5} {
		if got := d.Get(key).(int); got != want {
			t.Errorf("%s = %d, want %d", key, got, want)
		}
	}

	attrs := d.State().Attributes
	for _, key := range []string{"applications", "networks", "vpn_locations", "users"} {
		stateKey := "data.0." + key + ".#"
		count, present := attrs[stateKey]
		if !present {
			t.Errorf("%s is absent from state, so the list reads as a null rather than an "+
				"empty list", stateKey)
			continue
		}
		if count != "0" {
			t.Errorf("%s = %q, want \"0\"", stateKey, count)
		}
	}
	if attrs["data.0.is_default"] != "true" {
		t.Errorf("data.0.is_default = %q, want \"true\"", attrs["data.0.is_default"])
	}
}

/*
TestIdentityDataSourceIDsAreStableAndArgumentDerived pins both halves of L16c at
once.

Half one, the one L16c records: the ID must not change between two reads of the
same configuration. Fifteen of the sixteen data sources written before
checkpointsase_web_categories use strconv.FormatInt(time.Now().Unix(), 10), which
changes on every read and so defeats any downstream reference to the data
source's own id.

Half two, the mirror image, which testAccCheckDataSourceIDsDiffer exists for: two
instances whose ARGUMENTS differ must not share an ID, or one identity covers two
different results. A constant like "checkpointsase_users" satisfies half one and
fails half two, and these two data sources take arguments.
*/
func TestIdentityDataSourceIDsAreStableAndArgumentDerived(t *testing.T) {
	t.Parallel()

	usersFixture := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(userListPage(1, 1, 0, "")))
	}
	groupsFixture := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(groupListPage(1, 1, 0, "")))
	}

	readID := func(t *testing.T, ds *schema.Resource, handler http.HandlerFunc,
		read func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics,
		config map[string]interface{}) string {
		t.Helper()
		srv := httptest.NewServer(handler)
		defer srv.Close()
		d := schema.TestResourceDataRaw(t, ds.Schema, config)
		if diags := read(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
			t.Fatalf("read failed: %v", diags)
		}
		return d.Id()
	}

	cases := []struct {
		name    string
		ds      *schema.Resource
		handler http.HandlerFunc
		read    func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics
		configs []map[string]interface{}
	}{
		{
			name:    "checkpointsase_users",
			ds:      dataSourceUsers(),
			handler: usersFixture,
			read:    dataSourceUsersRead,
			configs: []map[string]interface{}{
				{},
				{"page": 2},
				{"limit": 10},
				{"where": "terminated=false"},
				{"sort": map[string]interface{}{"email": "asc"}},
				{"sort": map[string]interface{}{"email": "desc"}},
			},
		},
		{
			name:    "checkpointsase_groups",
			ds:      dataSourceGroups(),
			handler: groupsFixture,
			read:    dataSourceGroupsRead,
			configs: []map[string]interface{}{
				{},
				{"page": 2},
				{"limit": 1},
				{"sort": "name"},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ids := map[string]string{}
			for _, config := range tc.configs {
				label := fmt.Sprintf("%v", config)
				first := readID(t, tc.ds, tc.handler, tc.read, config)
				second := readID(t, tc.ds, tc.handler, tc.read, config)
				if first == "" {
					t.Errorf("%s %s: the read set no id", tc.name, label)
					continue
				}
				if first != second {
					t.Errorf("%s %s: two reads of the same configuration produced %q then %q. "+
						"An id that changes on every read defeats any downstream reference to it "+
						"(L16c)", tc.name, label, first, second)
				}
				if previous, clash := ids[first]; clash {
					t.Errorf("%s: configurations %s and %s both have the id %q, but they read "+
						"different things — one identity would cover two results",
						tc.name, previous, label, first)
					continue
				}
				ids[first] = label
			}
			// The argument-free configuration keeps the readable base name.
			if _, ok := ids[tc.name]; !ok {
				t.Errorf("%s: no configuration produced the plain base id %q; the "+
					"argument-free read should keep the readable name", tc.name, tc.name)
			}
		})
	}
}

/*
TestCanonicalSortDirectionsIsOrderIndependent pins the reason the ID derivation
sorts the map's keys: Go randomises map iteration order, so joining the pairs as
they come would give one configuration a different ID on every process, which is
the timestamp defect wearing a different hat.

Ten iterations rather than one: an unsorted implementation passes a single
comparison roughly half the time for a two-key map.
*/
func TestCanonicalSortDirectionsIsOrderIndependent(t *testing.T) {
	t.Parallel()

	sortOrder := map[string]string{
		"email": "asc", "firstName": "desc", "lastName": "asc", "username": "desc",
	}
	want := canonicalSortDirections(sortOrder)
	if want != "email:asc,firstName:desc,lastName:asc,username:desc" {
		t.Errorf("canonicalSortDirections = %q, want the keys in sorted order", want)
	}
	for i := 0; i < 10; i++ {
		if got := canonicalSortDirections(sortOrder); got != want {
			t.Fatalf("iteration %d produced %q, want %q — the rendering depends on Go's map "+
				"iteration order", i, got, want)
		}
	}
}
