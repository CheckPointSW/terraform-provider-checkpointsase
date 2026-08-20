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
					// `roles` is asserted on by nothing here, and that is not an
					// oversight. It is a nested list, so the scalar helper cannot
					// reach it; a presence check on data.0.roles.# cannot fail
					// (d.Set writes .# = 0 even for a key the flatten function
					// dropped); and a count assertion would be a guess about a
					// tenant's role assignments. The mapping is covered offline
					// instead, by TestUsersDataSourceReadEchoesTheServersPagination
					// against a fixture whose roles are known.
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

  - the two orderings DIFFER, which is exactly what a server ignoring the
    parameter cannot produce. Unconditional except for needing at least two
    distinct emails to order, and safe on a paged tenant: a server that ignored
    `sort` would return the same page 1 twice.
  - WHERE BOTH READS COVERED THE WHOLE COLLECTION IN ONE PAGE, the two return the
    same SET of emails, so `sort` did not also filter;
  - and, additionally, where every email in that single page is distinct and
    non-empty, the descending order is the exact reverse of the ascending one.

BOTH OF THE LAST TWO ARE GATED ON SINGLE-PAGE, and the first of them was not
originally. On a tenant whose users do not fit in one page, page 1 ascending and
page 1 descending are legitimately DIFFERENT SETS -- the first users and the last
users -- so an ungated set-equality check accuses a correct server of filtering.
Both steps therefore ask for `limit = 1000`, the API's documented maximum, which
makes the gate true by construction for any tenant up to 1000 users; past that the
two strong assertions stand down and the ordering check carries the row alone.

The reverse assertion is conditional on distinctness as well, because ties make it
false for a correct server: A21b permits an account with no email at all, and two
such accounts sort arbitrarily against each other.
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
  limit = 1000

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
  limit = 1000

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
					// The four projections are deliberately not asserted here.
					// See the note in USR-04 above: a presence check on a nested
					// list cannot fail, and a live tenant's group memberships are
					// not ours to predict. The mapping of all four is pinned
					// offline by TestGroupsDataSourceReadEchoesTheServersPagination
					// against a fixture with four distinct non-empty lists.
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

// DELETED, DELIBERATELY: testAccCheckDataSourceNestedListPresent.
//
// It asserted that `<attr>.<i>.<field>.#` was present in state, on the stated
// grounds that a nested list the flatten function never set would read as a null.
// THAT IS FALSE, and the helper was unfailable because of it: d.Set fills a
// schema key the flatten function omitted with the zero value, so a dropped key
// still writes `<field>.# = 0`. The only way it could fail was `data` having no
// element 0, which testAccCheckDataSourceListMinLen already covers in both
// USR-04 and GRP-06.
//
// It is recorded here rather than silently removed because this is the THIRD
// place in this phase where an assertion was built on the belief that the
// nil-to-empty coercion is load-bearing. It is not. If a future row needs to
// check a nested list, check its CONTENTS against a known fixture -- see
// TestGroupsDataSourceReadEchoesTheServersPagination, which does exactly that and
// catches a mis-wired field the presence check could not.

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

		// SINGLE PAGE ON BOTH READS is the precondition for comparing the two
		// results as sets, and getting this wrong made the check accuse a
		// correct server. Neither step pages: on a tenant whose users do not fit
		// in one page, page 1 ascending and page 1 descending are legitimately
		// DIFFERENT SETS -- the first users and the last users -- and the
		// set-equality check below would fire with "sort appears to filter as
		// well as order" against a server doing exactly the right thing.
		//
		// The steps ask for the API's maximum limit, so this holds for any tenant
		// up to 1000 users, which is the overwhelming majority. Past that the
		// strong assertions stand down and the ordering check below carries the
		// row on its own.
		singlePage := *ascendingSinglePage && attrs["total_page"] == "1"

		if singlePage {
			// Same set, so sort did not also filter. Only meaningful when both
			// reads covered the whole collection.
			ascSorted := append([]string(nil), asc...)
			descSorted := append([]string(nil), descending...)
			sort.Strings(ascSorted)
			sort.Strings(descSorted)
			if strings.Join(ascSorted, "\x00") != strings.Join(descSorted, "\x00") {
				return fmt.Errorf("the asc and desc reads each returned a single complete page "+
					"but different sets of %s values (%d asc, %d desc): sort appears to filter "+
					"as well as order", field, len(asc), len(descending))
			}
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
		if empties == 0 && len(distinct) == len(asc) && singlePage {
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
TestTenantWideCollectionsExposeNoSecretAttribute pins a decision, which is why it
is a test and not only a comment.

`checkpointsase_users` deliberately omits `invitation_token`. A collection read
over every user in the tenant has no business handing out every pending user's
enrolment token -- whoever holds one can complete that user's enrolment -- and
Terraform writes data source attributes to state in PLAINTEXT whatever the
Sensitive marker says, so marking it would not have made it safe.
`checkpointsase_user` (the resource) does expose it, marked Sensitive, because
there the scope is one account the operator is managing deliberately.

THE RULE IS DERIVED FROM secretAttributeNames, NOT FROM ONE HARDCODED NAME.
schema_conformance_test.go already owns the provider's canonical list of secret
attribute names, and an earlier version of this test walked for the literal
"invitation_token" instead -- so a future `enrollment_token` added to that list
would have been caught only by the Sensitive conformance rule, which demands a
MARKER. The whole point of this omission is that a marker does not help, so the
two rules now read the same list: mark it wherever it appears, and do not let it
appear in a tenant-wide collection at all.

Both new data sources are checked, not just users. `checkpointsase_groups` has no
candidate today, and that is exactly why it belongs here rather than being added
on the day it does.

The walk covers the whole element schema rather than just its top level, so a
later nested block cannot smuggle a field back in.
*/
func TestTenantWideCollectionsExposeNoSecretAttribute(t *testing.T) {
	t.Parallel()

	collections := map[string]*schema.Resource{
		"checkpointsase_users":  dataSourceUsers(),
		"checkpointsase_groups": dataSourceGroups(),
	}
	secrets := normalizedSecretAttributeNames()
	if !secrets[normalizeAttributeName("invitation_token")] {
		t.Fatal("secretAttributeNames no longer lists invitation_token, so this test would " +
			"pass for the wrong reason; restore it or replace this guard")
	}

	for name, ds := range collections {
		elem, ok := ds.Schema["data"].Elem.(*schema.Resource)
		if !ok {
			t.Errorf("%s.data has no *schema.Resource element schema", name)
			continue
		}
		var offenders []string
		walkSchema("", elem.Schema, func(path string, _ *schema.Schema) {
			leaf := path
			if i := strings.LastIndex(path, "."); i >= 0 {
				leaf = path[i+1:]
			}
			if secrets[normalizeAttributeName(leaf)] {
				offenders = append(offenders, path)
			}
		})
		if len(offenders) > 0 {
			sort.Strings(offenders)
			t.Errorf("%s.data exposes %s, which secretAttributeNames lists as secret material. "+
				"A tenant-wide read would write one copy per row into state in plaintext, and "+
				"Sensitive: true would not change that — the attribute has to be absent",
				name, strings.Join(offenders, ", "))
		}
	}
}

/*
TestDataSourceArgumentDigestIsUnambiguous pins the corrected claim in
dataSourceArgumentDigest's own comment.

An earlier version of that comment said a newline separator made a collision by
concatenation impossible "because a newline cannot appear in any of the parts".
IT CAN. `where` is a free-form pass-through and validateSortDirections constrains
sort DIRECTIONS but not sort KEYS, so a reviewer constructed the pair below and
both arguments produced the same id. The consequence was mild -- two data source
instances sharing an id string, not crossed data -- but a stated invariant that is
provably untrue is the defect regardless, so the parts are now length-prefixed and
this test is what keeps the claim honest.

Contrived on purpose. Nobody writes a newline into a sort field name; the point is
that the encoding no longer depends on nobody doing so.
*/
func TestDataSourceArgumentDigestIsUnambiguous(t *testing.T) {
	t.Parallel()

	crafted := usersDataSourceID("x", 1, 500,
		map[string]string{"\npage=1\nlimit=500\nsort=b": "asc"})
	viaWhere := usersDataSourceID("x\npage=1\nlimit=500\nsort=", 1, 500,
		map[string]string{"b": "asc"})
	if crafted == viaWhere {
		t.Errorf("two different argument sets both produced the id %q. The parts are meant to "+
			"be length-prefixed so the joined form cannot be read as any other sequence of "+
			"parts", crafted)
	}

	// The property that actually matters, restated here so a refactor cannot
	// trade determinism for collision resistance: identical arguments, identical
	// id, every time.
	for i := 0; i < 5; i++ {
		again := usersDataSourceID("x", 1, 500,
			map[string]string{"\npage=1\nlimit=500\nsort=b": "asc"})
		if again != crafted {
			t.Fatalf("iteration %d produced %q, want %q — the digest is not deterministic",
				i, again, crafted)
		}
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
above, and covers GRP-06's shape assertion offline.

THE FOUR-LIST ASSERTION HERE IS A MAPPING CHECK, NOT AN EMPTINESS CHECK, and the
difference is the whole reason it was rewritten. The first version fed this test a
group with no projections at all and asserted each `data.0.<list>.#` was present
and "0", on the stated grounds that an absent key would mean state held a null.
That claim is false and the assertion was unfailable: measured 2026-08-20,
removing every nil coercion from flattenGroupsData left it passing, and DELETING
the "applications" key from the flatten map outright left it passing too, because
d.Set fills a schema key the flatten function omitted with the zero value anyway.

So the fixture now carries four DISTINCT non-empty lists -- distinct in length
(2, 1, 3, 1) and in value prefix -- and the assertion is on the contents. That
fails three ways the old one could not: a key the flatten function drops, a count
that disagrees with the response, and, the one that matters, a key wired to the
wrong model field. vpnLocations reading Networks is the plausible copy-paste error
in a four-line block of near-identical entries, and nothing in the previous
version could see it.
*/
func TestGroupsDataSourceReadEchoesTheServersPagination(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(groupListPage(1, 3, 5,
			`{"id":"grp-1","name":"Engineering","isDefault":true,`+
				`"applications":["app-1","app-2"],`+
				`"networks":["net-1"],`+
				`"vpnLocations":["vpn-1","vpn-2","vpn-3"],`+
				`"users":["usr-1"]}`)))
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
	wantLists := map[string][]string{
		"applications":  {"app-1", "app-2"},
		"networks":      {"net-1"},
		"vpn_locations": {"vpn-1", "vpn-2", "vpn-3"},
		"users":         {"usr-1"},
	}
	for _, key := range []string{"applications", "networks", "vpn_locations", "users"} {
		want := wantLists[key]
		countKey := fmt.Sprintf("data.0.%s.#", key)
		if got := attrs[countKey]; got != strconv.Itoa(len(want)) {
			t.Errorf("%s = %q, want %q — the flatten function is not carrying this list "+
				"through", countKey, got, strconv.Itoa(len(want)))
			continue
		}
		for i, value := range want {
			elemKey := fmt.Sprintf("data.0.%s.%d", key, i)
			if got := attrs[elemKey]; got != value {
				t.Errorf("%s = %q, want %q — %s appears to be wired to the wrong field on the "+
					"Group model", elemKey, got, value, key)
			}
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

/*
stateWithDataSource builds the minimal terraform.State the acceptance check
helpers read, so a TestCheckFunc can be exercised offline.

The helpers all go through dataSourceAttrs, which only ever touches
RootModule().Resources[name].Primary.Attributes, so nothing else needs filling in.
*/
func stateWithDataSource(name string, attrs map[string]string) *terraform.State {
	s := terraform.NewState()
	s.RootModule().Resources = map[string]*terraform.ResourceState{
		name: {
			Type:     "checkpointsase_users",
			Primary:  &terraform.InstanceState{ID: "checkpointsase_users", Attributes: attrs},
			Provider: "provider.checkpointsase",
		},
	}
	return s
}

// usersSortState renders the flat state a users read produces for one ordering.
func usersSortState(name string, totalPage int, emails ...string) *terraform.State {
	attrs := map[string]string{
		"data.#":      strconv.Itoa(len(emails)),
		"page":        "1",
		"total_page":  strconv.Itoa(totalPage),
		"items_total": strconv.Itoa(len(emails) * totalPage),
	}
	for i, email := range emails {
		attrs[fmt.Sprintf("data.%d.email", i)] = email
		attrs[fmt.Sprintf("data.%d.id", i)] = fmt.Sprintf("usr-%d", i)
	}
	return stateWithDataSource(name, attrs)
}

/*
TestSortOrderCheckIsHonestAboutAPagedTenant exercises USR-06's cross-step closure
OFFLINE, against synthetic state.

WHY THIS EXISTS: USR-06 needs TF_ACC and a live tenant, so its closure — the most
intricate assertion written for this task — was originally shipped reasoned about
rather than run. It also shipped with a real defect that only reading caught: the
set-equality check was ungated, so on a tenant whose users do not fit in one page,
page 1 ascending and page 1 descending are legitimately DIFFERENT SETS and the
closure accused a correct server of filtering. That is a red test for a green
server, and the sort of thing that gets a genuine assertion deleted rather than
fixed.

Case "paged tenant, disjoint pages" is the regression: it FAILS if the
single-page gate is removed, and passes with it. The other cases keep the gate
from being loosened into uselessness — "sort ignored" must still fail, and
"single page, different sets" must still fail.
*/
func TestSortOrderCheckIsHonestAboutAPagedTenant(t *testing.T) {
	t.Parallel()

	const name = "data.checkpointsase_users.sorted"

	cases := []struct {
		name string
		// the ascending step's captured emails and whether it saw one page
		ascEmails       []string
		ascSinglePage   bool
		descTotalPage   int
		descEmails      []string
		wantErr         bool
		wantErrFragment string
	}{
		{
			name:          "single page, exact reverse",
			ascEmails:     []string{"a@x.invalid", "b@x.invalid", "c@x.invalid"},
			ascSinglePage: true,
			descTotalPage: 1,
			descEmails:    []string{"c@x.invalid", "b@x.invalid", "a@x.invalid"},
			wantErr:       false,
		},
		{
			// A server ignoring `sort` returns the same order twice. This is the
			// defect USR-06 exists for and it must fail whatever the paging.
			name:            "sort ignored, identical ordering",
			ascEmails:       []string{"a@x.invalid", "b@x.invalid", "c@x.invalid"},
			ascSinglePage:   true,
			descTotalPage:   1,
			descEmails:      []string{"a@x.invalid", "b@x.invalid", "c@x.invalid"},
			wantErr:         true,
			wantErrFragment: "IDENTICAL ordering",
		},
		{
			// THE I2 REGRESSION. 600 users at limit 500: asc page 1 is the first
			// 500, desc page 1 is the last 500. Different sets, correct server.
			name:          "paged tenant, disjoint pages",
			ascEmails:     []string{"a@x.invalid", "b@x.invalid"},
			ascSinglePage: false,
			descTotalPage: 2,
			descEmails:    []string{"y@x.invalid", "z@x.invalid"},
			wantErr:       false,
		},
		{
			// Single page both times, so a set difference really is the server
			// filtering as well as ordering.
			name:            "single page, different sets",
			ascEmails:       []string{"a@x.invalid", "b@x.invalid"},
			ascSinglePage:   true,
			descTotalPage:   1,
			descEmails:      []string{"a@x.invalid", "q@x.invalid"},
			wantErr:         true,
			wantErrFragment: "filter",
		},
		{
			// One distinct email: no ordering is observable, so the closure
			// returns nil rather than pretending to have proved anything. USR-06
			// is vacuous on such a tenant and the report says so.
			name:          "single user, nothing observable",
			ascEmails:     []string{"only@x.invalid"},
			ascSinglePage: true,
			descTotalPage: 1,
			descEmails:    []string{"only@x.invalid"},
			wantErr:       false,
		},
		{
			// Two accounts with no email at all (A21b permits it) tie, so the
			// exact-reverse branch must not fire. Distinct count is 1, so the
			// closure returns early.
			name:          "emailless accounts tie",
			ascEmails:     []string{"", "", "one@x.invalid"},
			ascSinglePage: true,
			descTotalPage: 1,
			descEmails:    []string{"one@x.invalid", "", ""},
			wantErr:       false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ascending := append([]string(nil), tc.ascEmails...)
			singlePage := tc.ascSinglePage
			check := testAccCheckSortOrderIsTheOppositeOf(name, "data", "email",
				&ascending, &singlePage)
			err := check(usersSortState(name, tc.descTotalPage, tc.descEmails...))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), tc.wantErrFragment) {
				t.Errorf("error %q does not mention %q", err, tc.wantErrFragment)
			}
		})
	}
}
