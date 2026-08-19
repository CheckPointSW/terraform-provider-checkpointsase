package checkpointsase

import (
	"encoding/json"
	"strings"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// TestAccDataSourceObjectsCatalog_basic is the first live exercise of the three
// Objects catalogs: checkpointsase_web_categories,
// checkpointsase_application_control_applications and
// checkpointsase_updatable_objects.
//
// All three are tenant-independent read-only catalogs, so they go in one config
// and one step. Nothing is created and nothing is a network, so this finishes in
// seconds.
//
// # What is asserted, and why it is not a count
//
// The tenant-wide data source test measured its tenant first and asserted
// non-empty only where the measurement justified it. That was not possible here:
// the only API key discoverable in this workspace
// (sase-terraform-api/terraform.tfvars) belongs to the production US host, where
// every /v3 route including /v3/auth/authorize answers 404, and it is rejected
// with 401 by the v3 staging host in demo/README.md. So the three catalogs have
// never been read, and their sizes on the target tenant are unknown.
//
// A `>= 1` assertion would therefore be a guess in the one direction that
// matters. Two of these catalogs are SWG (Internet Access) product data, and
// whether a tenant without the SWG add-on gets a populated catalog, an empty
// one, or a 403 is exactly the kind of thing the last two phases of this port
// kept getting wrong by reading the spec instead of the server. So the
// assertions here are the ones that cannot be wrong in either direction: the
// list attribute exists in state, and — as soon as the catalog does hold
// anything — its first element's fields are populated, which is what actually
// covers the flatten functions.
//
// TIGHTEN THIS ONCE MEASURED: after the first successful live run, replace the
// testAccCheckDataSourceListPresent calls on web_categories and applications
// with testAccCheckDataSourceListMinLen(..., 1) and record the counts, the way
// TestAccDataSourceTenantWide_basic did for the region catalogues. A catalog
// that is genuinely non-empty should be asserted non-empty.
//
// # The one strong assertion available
//
// checkpointsase_updatable_objects pages to exhaustion, so its row count must
// equal the items_total the server reported. That holds on an empty tenant and a
// full one, and it fails for the L15 defect this data source exists to avoid: a
// read that stops after one page while state claims a larger total. The filtered
// instance asserts the same invariant on a filter that matches nothing, which
// covers the query-string path and the zero-result path at once.
//
// NOT COVERED, deliberately: the `type` filter. The v3 document declares the
// enum splitTunneling/internetAccess; perimeter81-public-api's own controller
// describes the same parameter as ST/SWG. Sending one of them from a test would
// make the test fail over an unresolved API question rather than a provider
// defect. Try `type = "splitTunneling"` by hand on the next live run and record
// which spelling the server takes — TestFlattenUpdatableObjectsAcceptsEitherTypeSpelling
// covers the response half of the same divergence offline.
func TestAccDataSourceObjectsCatalog_basic(t *testing.T) {
	const (
		webCategories = "data.checkpointsase_web_categories.catalog"
		appControl    = "data.checkpointsase_application_control_applications.catalog"
		updatable     = "data.checkpointsase_updatable_objects.all"
		filtered      = "data.checkpointsase_updatable_objects.no_such_name"
	)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceObjectsCatalogConfig(),
				Check: resource.ComposeTestCheckFunc(
					// checkpointsase_web_categories. `codes` is excluded from
					// the field check on purpose: it is a nested list, so state
					// holds web_categories.0.codes.# rather than
					// web_categories.0.codes, and the helper asserts on scalar
					// keys.
					testAccCheckDataSourceListPresent(webCategories, "web_categories"),
					testAccCheckDataSourceFirstElemFieldsSetIfAny(webCategories, "web_categories",
						"id", "name"),

					// checkpointsase_application_control_applications. Both
					// fields are non-pointer required strings on
					// ApplicationControlApplication, so an empty value here
					// means the flatten function failed to map it rather than
					// the server omitting it.
					testAccCheckDataSourceListPresent(appControl, "applications"),
					testAccCheckDataSourceFirstElemFieldsSetIfAny(appControl, "applications",
						"id", "name"),

					// checkpointsase_updatable_objects, unfiltered. The count
					// vs items_total equality is the assertion that fails if
					// the paging loop stops early.
					testAccCheckDataSourceListPresent(updatable, "updatable_objects"),
					testAccCheckDataSourceListLenMatchesTotal(updatable, "updatable_objects", "items_total"),
					testAccCheckDataSourceFirstElemFieldsSetIfAny(updatable, "updatable_objects",
						"cp_id", "vendor_id", "name"),

					// checkpointsase_updatable_objects, filtered on a name no
					// catalog entry can have. Exercises the query-string path
					// and asserts the same invariant on a zero-row read.
					testAccCheckDataSourceListPresent(filtered, "updatable_objects"),
					testAccCheckDataSourceListLenMatchesTotal(filtered, "updatable_objects", "items_total"),

					// The two updatable_objects instances must not share an ID:
					// L16c is about an ID that changes when it should not, and
					// the mirror-image defect is an ID that stays the same when
					// the configuration — and so the result — differs.
					testAccCheckDataSourceIDsDiffer(updatable, filtered),
				),
			},
		},
	})
}

func testAccDataSourceObjectsCatalogConfig() string {
	return `
data "checkpointsase_web_categories" "catalog" {}

data "checkpointsase_application_control_applications" "catalog" {}

data "checkpointsase_updatable_objects" "all" {}

data "checkpointsase_updatable_objects" "no_such_name" {
  name = "checkpointsase-acc-test-no-such-updatable-object"
}
  `
}

// --- offline coverage ------------------------------------------------------
//
// The acceptance test above cannot run without a working v3 credential, and no
// such credential exists in this workspace. Everything below runs offline, and
// between them the tests cover the two things a live run would otherwise have
// discovered the hard way: that two of the three response models refuse to
// decode a response missing a field, and that the third's `type` object is
// documented with two different sets of keys.
//
// The fixtures are reconstructed from the v3 OpenAPI document's schemas and from
// perimeter81-public-api's UpdatableObject interface, not captured from a
// tenant. They are obviously synthetic and carry no tenant data.

const webCategoryFixture = `{
  "status": 200,
  "data": [
    {"id": "fakeWebCat1", "name": "Fake Gambling", "codes": ["fake-c1", "fake-c2"]},
    {"id": "fakeWebCat2", "name": "Fake News", "codes": []}
  ]
}`

const applicationControlFixture = `{
  "status": 200,
  "data": [
    {"id": "fakeApp1", "name": "Fake Dropbox"},
    {"id": "fakeApp2", "name": "Fake Slack"}
  ]
}`

// updatableObjectsSpecFixture uses the key names the v3 OpenAPI document
// declares for the nested `type` object.
const updatableObjectsSpecFixture = `{
  "page": 1,
  "totalPage": 1,
  "itemsTotal": 2,
  "data": [
    {
      "type": {"splitTunneling": true, "internetAccess": false},
      "cpId": "fakeCp1",
      "vendorId": "fakeVendor1",
      "vendorParentId": "fakeVendorRoot",
      "vendorChildrenIds": ["fakeVendor1a", "fakeVendor1b"],
      "name": "Fake AWS eu-west-1",
      "inheritDescription": true,
      "inheritInfoText": false,
      "inheritInfoUrl": true,
      "dataObjectsCount": 42
    },
    {
      "cpId": "fakeCp2",
      "vendorId": "fakeVendor2",
      "name": "Fake object with no type object at all"
    }
  ]
}`

// updatableObjectsBackendFixture uses the key names perimeter81-public-api's own
// UpdatableObject interface declares for the same nested object, plus the four
// fields that interface carries and the v3 document does not.
const updatableObjectsBackendFixture = `{
  "page": 1,
  "totalPage": 1,
  "itemsTotal": 1,
  "data": [
    {
      "type": {"ST": true, "SWG": true},
      "cpId": "fakeCp3",
      "vendorId": "fakeVendor3",
      "vendorChildrenIds": [],
      "isRoot": true,
      "name": "Fake object in the backend's shape",
      "description": "fake description",
      "infoText": "fake info text",
      "infoUrl": "https://example.invalid/fake",
      "dataObjectsCount": 7
    }
  ]
}`

/*
TestWebCategoryDecodeRejectsAMissingRequiredField pins the sharpest live-run risk
in this task, so that whoever meets it recognises it instead of debugging the
provider.

WebCategory declares id, name and codes as required, and the generated
UnmarshalJSON enforces that by checking the raw JSON object for each key before
it unmarshals anything. So a single category in the catalog that omits `codes`
does not produce a category with no codes — it fails the whole
GetWebCategories call with "no value given for required property codes", and
checkpointsase_web_categories reports it as an unreadable catalog.

An empty array is fine, which the second fixture element covers; it is absence
that fails. Nothing in either repo settles whether the server can omit the key:
/v3/objects/web-category has no controller in perimeter81-public-api at all.
*/
func TestWebCategoryDecodeRejectsAMissingRequiredField(t *testing.T) {
	t.Parallel()

	var ok perimeter81Sdk.WebCategoryResponse
	if err := json.Unmarshal([]byte(webCategoryFixture), &ok); err != nil {
		t.Fatalf("the well-formed fixture must decode, got: %v", err)
	}
	if len(ok.Data) != 2 {
		t.Fatalf("decoded %d categories, want 2", len(ok.Data))
	}
	if got := len(ok.Data[1].Codes); got != 0 {
		t.Errorf("fixture element 1 has %d codes, want 0 — an empty codes array is legal", got)
	}

	const missingCodes = `{"status":200,"data":[{"id":"fakeWebCat1","name":"Fake Gambling"}]}`
	var bad perimeter81Sdk.WebCategoryResponse
	if err := json.Unmarshal([]byte(missingCodes), &bad); err == nil {
		t.Errorf("a category omitting `codes` decoded without error. If the SDK has been " +
			"regenerated to make codes optional, flattenWebCategories and this test can be " +
			"simplified; until then the whole catalog read fails on such a response and the " +
			"comment on flattenWebCategories must say so")
	}

	const missingName = `{"status":200,"data":[{"id":"fakeApp1"}]}`
	var badApp perimeter81Sdk.ApplicationControlResponse
	if err := json.Unmarshal([]byte(missingName), &badApp); err == nil {
		t.Errorf("an Application Control application omitting `name` decoded without error; " +
			"the same reasoning as for WebCategory applies")
	}
}

func TestFlattenWebCategories(t *testing.T) {
	t.Parallel()

	var response perimeter81Sdk.WebCategoryResponse
	if err := json.Unmarshal([]byte(webCategoryFixture), &response); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}

	rows := flattenWebCategories(response.Data)
	if len(rows) != 2 {
		t.Fatalf("flattened %d rows, want 2", len(rows))
	}

	first := rows[0].(map[string]interface{})
	if got := first["id"]; got != "fakeWebCat1" {
		t.Errorf("id = %v, want fakeWebCat1", got)
	}
	if got := first["name"]; got != "Fake Gambling" {
		t.Errorf("name = %v, want Fake Gambling", got)
	}
	codes, ok := first["codes"].([]string)
	if !ok {
		t.Fatalf("codes is %T, want []string", first["codes"])
	}
	if !testComparableArraiesEq(codes, []string{"fake-c1", "fake-c2"}) {
		t.Errorf("codes = %v, want [fake-c1 fake-c2]", codes)
	}

	// An empty codes array must reach state as an empty list, not as nil: a nil
	// slice and an empty one are the same to Terraform here, but returning a
	// typed empty slice keeps the element schema honest if that ever changes.
	second := rows[1].(map[string]interface{})
	emptyCodes, ok := second["codes"].([]string)
	if !ok {
		t.Fatalf("codes on the second row is %T, want []string", second["codes"])
	}
	if len(emptyCodes) != 0 {
		t.Errorf("codes = %v, want an empty list", emptyCodes)
	}

	// nil input, which is what the SDK hands over for a `data`-less 200.
	if got := flattenWebCategories(nil); got == nil || len(got) != 0 {
		t.Errorf("flattenWebCategories(nil) = %v, want an empty non-nil list", got)
	}
}

func TestFlattenApplicationControlApplications(t *testing.T) {
	t.Parallel()

	var response perimeter81Sdk.ApplicationControlResponse
	if err := json.Unmarshal([]byte(applicationControlFixture), &response); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}

	rows := flattenApplicationControlApplications(response.Data)
	if len(rows) != 2 {
		t.Fatalf("flattened %d rows, want 2", len(rows))
	}
	first := rows[0].(map[string]interface{})
	if got := first["id"]; got != "fakeApp1" {
		t.Errorf("id = %v, want fakeApp1", got)
	}
	if got := first["name"]; got != "Fake Dropbox" {
		t.Errorf("name = %v, want Fake Dropbox", got)
	}

	if got := flattenApplicationControlApplications(nil); got == nil || len(got) != 0 {
		t.Errorf("flattenApplicationControlApplications(nil) = %v, want an empty non-nil list", got)
	}
}

func TestFlattenUpdatableObjects(t *testing.T) {
	t.Parallel()

	var response perimeter81Sdk.GetUpdatableObjects200Response
	if err := json.Unmarshal([]byte(updatableObjectsSpecFixture), &response); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}

	rows := flattenUpdatableObjects(response.Data)
	if len(rows) != 2 {
		t.Fatalf("flattened %d rows, want 2", len(rows))
	}

	first := rows[0].(map[string]interface{})
	for field, want := range map[string]interface{}{
		"cp_id":               "fakeCp1",
		"vendor_id":           "fakeVendor1",
		"vendor_parent_id":    "fakeVendorRoot",
		"name":                "Fake AWS eu-west-1",
		"inherit_description": true,
		"inherit_info_text":   false,
		"inherit_info_url":    true,
		"data_objects_count":  42,
		"split_tunneling":     true,
		"internet_access":     false,
	} {
		if got := first[field]; got != want {
			t.Errorf("%s = %#v, want %#v", field, got, want)
		}
	}
	children, ok := first["vendor_children_ids"].([]string)
	if !ok {
		t.Fatalf("vendor_children_ids is %T, want []string", first["vendor_children_ids"])
	}
	if !testComparableArraiesEq(children, []string{"fakeVendor1a", "fakeVendor1b"}) {
		t.Errorf("vendor_children_ids = %v, want [fakeVendor1a fakeVendor1b]", children)
	}

	// Every field on the model is an optional pointer, so a row that carries
	// only three of them must still produce a complete map — a missing key would
	// be an absent attribute in state, which reads as a provider defect rather
	// than as a field the server did not send.
	second := rows[1].(map[string]interface{})
	for _, field := range []string{
		"cp_id", "vendor_id", "vendor_parent_id", "vendor_children_ids", "name",
		"inherit_description", "inherit_info_text", "inherit_info_url",
		"data_objects_count", "split_tunneling", "internet_access",
	} {
		if _, present := second[field]; !present {
			t.Errorf("%s is absent from the flattened sparse row", field)
		}
	}
	if got := second["vendor_parent_id"]; got != "" {
		t.Errorf("vendor_parent_id = %#v on a row that omits it, want the empty string", got)
	}
	if got := second["split_tunneling"]; got != false {
		t.Errorf("split_tunneling = %#v on a row with no type object, want false", got)
	}

	if got := flattenUpdatableObjects(nil); got == nil || len(got) != 0 {
		t.Errorf("flattenUpdatableObjects(nil) = %v, want an empty non-nil list", got)
	}
}

/*
TestFlattenUpdatableObjectsAcceptsEitherTypeSpelling covers the one live-run
hazard in this task that would have been silent rather than loud.

The v3 OpenAPI document declares the nested `type` object as
{splitTunneling, internetAccess}. perimeter81-public-api's UpdatableObject
interface declares the same field as {ST, SWG}, and nothing in that repo
normalises it: ObjectsService.listUpdatableObjects fetches the upstream JSON,
casts it, and returns it — no class-transformer, no validation. So neither
declaration is authoritative for what reaches the wire.

Both schemas are additionalProperties:true, so the generated struct routes the
keys it does not know into AdditionalProperties instead of failing. A flatten
that read only the typed fields would therefore have turned an ST/SWG response
into split_tunneling=false, internet_access=false for every object in the
catalog — a catalog where nothing is compatible with anything, which looks
exactly like a correct read of a restricted tenant. This test pins that both
spellings produce true.
*/
func TestFlattenUpdatableObjectsAcceptsEitherTypeSpelling(t *testing.T) {
	t.Parallel()

	var response perimeter81Sdk.GetUpdatableObjects200Response
	if err := json.Unmarshal([]byte(updatableObjectsBackendFixture), &response); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}
	if len(response.Data) != 1 {
		t.Fatalf("decoded %d rows, want 1", len(response.Data))
	}

	// The premise: the SDK's typed fields see nothing in the backend's spelling.
	row := response.Data[0]
	if row.Type == nil {
		t.Fatalf("type decoded to nil; the fixture carries one")
	}
	if row.Type.SplitTunneling != nil || row.Type.InternetAccess != nil {
		t.Fatalf("the SDK's typed type fields are populated from ST/SWG after all "+
			"(splitTunneling=%v internetAccess=%v). If the SDK has been regenerated to "+
			"understand both spellings, updatableObjectTypeFlag's fallback is dead code "+
			"and should be removed rather than left to rot",
			row.Type.SplitTunneling, row.Type.InternetAccess)
	}

	rows := flattenUpdatableObjects(response.Data)
	flat := rows[0].(map[string]interface{})
	if got := flat["split_tunneling"]; got != true {
		t.Errorf("split_tunneling = %#v for a row carrying ST:true, want true", got)
	}
	if got := flat["internet_access"]; got != true {
		t.Errorf("internet_access = %#v for a row carrying SWG:true, want true", got)
	}

	// The canonical spelling must still win when both are present, so that a
	// server which starts sending the documented keys is not shadowed by a
	// leftover legacy one.
	both := perimeter81Sdk.GetUpdatableObjects200ResponseDataInnerType{
		SplitTunneling:       perimeter81Sdk.PtrBool(true),
		AdditionalProperties: map[string]interface{}{"ST": false},
	}
	if got := updatableObjectTypeFlag(&both, "splitTunneling", "ST"); got != true {
		t.Errorf("with splitTunneling=true and ST=false, got %v, want true", got)
	}

	// A non-boolean legacy value must not panic or be coerced.
	junk := perimeter81Sdk.GetUpdatableObjects200ResponseDataInnerType{
		AdditionalProperties: map[string]interface{}{"ST": "yes"},
	}
	if got := updatableObjectTypeFlag(&junk, "splitTunneling", "ST"); got != false {
		t.Errorf(`with ST="yes", got %v, want false`, got)
	}

	if got := updatableObjectTypeFlag(nil, "splitTunneling", "ST"); got != false {
		t.Errorf("updatableObjectTypeFlag(nil, ...) = %v, want false", got)
	}
}

/*
TestUpdatableObjectsDataSourceIDIsStableAndFilterSpecific covers both halves of
what a data source ID has to do. L16c is about the first half — an ID that
changes on every read defeats any downstream reference — and a constant fixes
it. But this data source takes filters, so a constant would give two instances
holding different results the same ID. The ID is derived from the filters
instead.
*/
func TestUpdatableObjectsDataSourceIDIsStableAndFilterSpecific(t *testing.T) {
	t.Parallel()

	unfiltered := updatableObjectsDataSourceID("", "", "", nil)
	if unfiltered != "checkpointsase_updatable_objects" {
		t.Errorf("unfiltered ID = %q, want checkpointsase_updatable_objects", unfiltered)
	}
	if again := updatableObjectsDataSourceID("", "", "", []string{}); again != unfiltered {
		t.Errorf("an empty cp_id slice changed the ID: %q vs %q", again, unfiltered)
	}

	ids := map[string]string{}
	for label, id := range map[string]string{
		"unfiltered": unfiltered,
		"name":       updatableObjectsDataSourceID("fake-name", "", "", nil),
		"type":       updatableObjectsDataSourceID("", "splitTunneling", "", nil),
		"sort":       updatableObjectsDataSourceID("", "", "name:asc", nil),
		"cp_id":      updatableObjectsDataSourceID("", "", "", []string{"fakeCp1"}),
		"cp_id2":     updatableObjectsDataSourceID("", "", "", []string{"fakeCp1", "fakeCp2"}),
		"all":        updatableObjectsDataSourceID("fake-name", "splitTunneling", "name:asc", []string{"fakeCp1"}),
	} {
		if clash, seen := ids[id]; seen {
			t.Errorf("%s and %s share the ID %q — two different filters must not produce one ID",
				label, clash, id)
		}
		ids[id] = label
	}

	// Stability: the same filters must give the same ID on every read, which is
	// the whole point of not using a timestamp.
	for i := 0; i < 3; i++ {
		got := updatableObjectsDataSourceID("fake-name", "splitTunneling", "name:asc", []string{"fakeCp1", "fakeCp2"})
		want := updatableObjectsDataSourceID("fake-name", "splitTunneling", "name:asc", []string{"fakeCp1", "fakeCp2"})
		if got != want {
			t.Fatalf("ID is not stable across calls: %q vs %q", got, want)
		}
	}
}

/*
TestCountNewUpdatableObjects covers the paging loop's no-progress guard.

The guard is there because the page parameter has never been exercised live from
this provider. A server that ignored it would return page 1 forever; without the
guard the loop would append the same rows up to updatableObjectsMaxPages,
producing a plan that appears to hang and 500,000 duplicate rows in state. With
it, the read stops and warns.
*/
func TestCountNewUpdatableObjects(t *testing.T) {
	t.Parallel()

	var response perimeter81Sdk.GetUpdatableObjects200Response
	if err := json.Unmarshal([]byte(updatableObjectsSpecFixture), &response); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}

	seen := map[string]bool{}
	if got := countNewUpdatableObjects(response.Data, seen); got != 2 {
		t.Fatalf("first page contributed %d new rows, want 2", got)
	}
	for _, row := range response.Data {
		seen[updatableObjectKey(row)] = true
	}
	// The same page again: this is what a server ignoring `page` looks like.
	if got := countNewUpdatableObjects(response.Data, seen); got != 0 {
		t.Errorf("a repeated page contributed %d new rows, want 0 — the guard would not fire", got)
	}

	// One overlapping row and one new one still counts as progress, so a server
	// with a shifting result set is paged through rather than abandoned.
	var second perimeter81Sdk.GetUpdatableObjects200Response
	if err := json.Unmarshal([]byte(updatableObjectsBackendFixture), &second); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}
	mixed := append([]perimeter81Sdk.GetUpdatableObjects200ResponseDataInner{}, response.Data[0])
	mixed = append(mixed, second.Data[0])
	if got := countNewUpdatableObjects(mixed, seen); got != 1 {
		t.Errorf("a page with one new row contributed %d, want 1", got)
	}
}

/*
TestReportedTotalForMessage pins the distinction the paging warnings depend on.

Every field on GetUpdatableObjects200Response is an optional pointer, itemsTotal
included, so "the server reported 0 objects" and "the server reported no total at
all" are different facts. Rendering both as "0" would send whoever read the
warning looking for a truncation that never happened, and it is the same class of
unfalsifiable value as L16b's zero timestamps.
*/
func TestReportedTotalForMessage(t *testing.T) {
	t.Parallel()

	if got := reportedTotalForMessage(0, true); got != "0" {
		t.Errorf("a reported total of 0 rendered as %q, want \"0\"", got)
	}
	if got := reportedTotalForMessage(17, true); got != "17" {
		t.Errorf("a reported total of 17 rendered as %q, want \"17\"", got)
	}
	got := reportedTotalForMessage(0, false)
	if got == "0" {
		t.Errorf("an unreported total rendered as %q, which is indistinguishable from a "+
			"server that reported zero objects", got)
	}
	if !strings.Contains(got, "itemsTotal") {
		t.Errorf("an unreported total rendered as %q; it should name the field that was "+
			"missing so the reader can tell what happened", got)
	}
}
