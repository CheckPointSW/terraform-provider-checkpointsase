package checkpointsase

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
groupListPage renders one page of /v3/groups.

All four keys are required on GroupList (model_group_list.go has a
requiredProperties loop), so a fixture missing any of them fails to decode and
the test would be measuring the fixture rather than the provider. Group records
themselves are the opposite: A22b removes Group.required entirely, so a record
may carry nothing but an id.

The offline SDK client these tests use is newTestUserAPIClient, from
resource_user_test.go. It is named for the resource that introduced it but is
resource-agnostic -- it only pre-seeds a bearer token so prepareRequest never
tries to exchange an API key for one, which is what keeps every test here
offline. Duplicating it under a group-flavoured name would create a second thing
to keep in step with the SDK's auth path.
*/
func groupListPage(page, totalPage, itemsTotal int, records string) string {
	return fmt.Sprintf(`{"data":[%s],"page":%d,"totalPage":%d,"itemsTotal":%d}`,
		records, page, totalPage, itemsTotal)
}

/*
groupImportStateVerifyIgnore is GRP-I01's ImportStateVerifyIgnore list.

It is a variable rather than a literal in the TestStep so that
TestGroupImportStateVerifyIgnoreMatchesWhatImportOmits can check it against what
an import actually leaves out, offline. Getting this list wrong is a
live-run-only failure otherwise: ImportStateVerify compares the raw attribute
maps with reflect.DeepEqual after deleting these prefixes
(testing_new_import_state.go:226-237), and it only forgives `.#`/`.%` keys whose
value is "0".

description is the single entry, and it is NOT a judgement call: the Group read
model declares name, isDefault, applications, networks, vpnLocations, users and
id, and no description at all (perimeter-81-client-sdk/model_group.go). Both the
task brief and V3-TERRAFORM-TEST-PLAN row GRP-I01 state that Read populates
description and that no ignore list is needed; both are wrong about the generated
schema, which is why this list is derived by the test below rather than asserted
by hand.
*/
var groupImportStateVerifyIgnore = []string{"description"}

// TestGroupResourceHasNoUpdate pins Pattern C, the schema half of GRP-02.
// /v3/groups has no PUT, so an UpdateContext could only re-POST -- creating a
// second group while Terraform believed it had renamed one, and leaving every
// membership attached to the original.
func TestGroupResourceHasNoUpdate(t *testing.T) {
	r := resourceGroup()
	if r.UpdateContext != nil {
		t.Error("resourceGroup registers an UpdateContext, but /v3/groups has no PUT: " +
			"an update could only re-POST and would create a second group")
	}
	// Descends into blocks as well as top-level attributes: InternalValidate
	// (which TestProvider runs) already covers most of the top level, but it
	// skips Computed attributes.
	var writableNotForceNew []string
	walkSchema("", r.Schema, func(path string, s *schema.Schema) {
		if (s.Required || s.Optional) && !s.ForceNew {
			writableNotForceNew = append(writableNotForceNew, path)
		}
	})
	if len(writableNotForceNew) > 0 {
		t.Errorf("writable but not ForceNew: %s. With no update endpoint every writable "+
			"attribute must force replacement", strings.Join(writableNotForceNew, ", "))
	}
}

/*
TestGroupDecodesWithNothingButAnID is the provider-side pin on overlay entry
A22b, which removes Group.required ENTIRELY -- all six fields it used to name,
including name itself.

The reason is that /v3/groups is a LIST endpoint: one record missing one key
fails the whole page, which is how the WebCategory defect (A20) presented. The
consequence for this resource is that every scalar is a pointer and every one of
the four list attributes can be nil, so Read must go through Get* accessors and
must write all four lists into state itself.
*/
func TestGroupDecodesWithNothingButAnID(t *testing.T) {
	body := []byte(groupListPage(1, 1, 1, `{"id":"g1"}`))

	var list perimeter81Sdk.GroupList
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("a group record carrying only id must decode; got %v. "+
			"If this fails, overlay entry A22b is not applied", err)
	}
	if len(list.Data) != 1 || list.Data[0].GetId() != "g1" {
		t.Fatalf("decoded %d records, want 1 with id g1: %+v", len(list.Data), list.Data)
	}
	if list.Data[0].Name != nil {
		t.Errorf("Name = %v, want nil: A22b makes name optional too, so an absent key "+
			"must read back as nil rather than as \"\"", *list.Data[0].Name)
	}
	// The four list attributes are the other half of A22b: each of them is
	// omitempty, so "this group has no members" arrives as a nil slice rather
	// than as an empty one, and Read has to turn that into an empty list in
	// state. See TestGroupReadCoercesNilListsToEmpty.
	for name, got := range map[string][]string{
		"Applications": list.Data[0].Applications,
		"Networks":     list.Data[0].Networks,
		"VpnLocations": list.Data[0].VpnLocations,
		"Users":        list.Data[0].Users,
	} {
		if got != nil {
			t.Errorf("%s = %v, want nil: an absent list key must decode to nil, which is "+
				"the shape resourceGroupRead has to write into state as an empty list", name, got)
		}
	}
}

/*
TestGroupNameValidationAcceptsUnicodeAndRejectsEmpty covers GRP-N01 offline.

The row is a ValidateFunc rejection: it needs no tenant, no credential and no
apply, so gating it behind TF_ACC would only mean it never runs.

THE UNICODE CASES ARE THE POINT. createGroup.dto.ts matches name against
`^${xssSafeCharacters}{1,64}$` with the 'u' flag, and xssSafeCharacters opens
with \p{L}\p{M}\p{Nd} -- letters in every script. A provider that transliterated
that to [a-zA-Z0-9] would reject "Ingénierie" and "研究開発" at plan time for
configurations the server accepts, which is worse than no validation: the
operator cannot work around it.

AND THE UNICODE CASES HAVE TO REACH THE BOUNDARIES, which is what an earlier
version of this table got wrong. Its length rows were both ASCII, so it passed
while two independent over-strictness defects shipped: a
validation.StringLenBetween(1, 64) counting BYTES next to a pattern counting
runes, which refused a 22-character CJK name and a 40-character name of "é"; and
Go's ASCII-only `\s`, which refused U+3000 and a non-breaking space. Both
refused server-legal names at plan time with no workaround. So the length rows
below are run in CJK and in "é" as well as in ASCII, on both sides of 64, and the
whitespace rows name the code points rather than trusting a shorthand.

The last sub-test goes through Resource.Validate rather than the ValidateFunc,
because GRP-N01 says "rejected at plan time" and that is the code path
`terraform plan` actually takes.
*/
func TestGroupNameValidationAcceptsUnicodeAndRejectsEmpty(t *testing.T) {
	sixtyFour := strings.Repeat("a", 64)
	validate := resourceGroup().Schema["name"].ValidateFunc
	if validate == nil {
		t.Fatal("name has no ValidateFunc, so GRP-N01's empty name reaches POST /v3/groups")
	}

	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"ascii", "Engineering", false},
		{"latin with accents", "Ingénierie", false},
		{"cjk", "研究開発", false},
		{"cyrillic", "Инженерия", false},
		// \p{M} is in the class for a reason, and this case is why: the accent
		// here is a SEPARATE combining code point (U+0301) after a plain "e",
		// which is what an NFD-normalised name looks like. \p{L} alone rejects it.
		{"decomposed accent, a real combining mark", "Ingene\u0301rie", false},
		{"digits, spaces and the allowed punctuation", "R&D 2 (EMEA) - a_b.c'd/e\\f,g|h{i}j~k!l@m#n$o%p^q*r[s]t:u", false},
		{"exactly 64 characters", sixtyFour, false},
		// The rows a byte-counting length check fails. "研" is 3 bytes and "é" is
		// 2, so each of these is comfortably inside the server's 64-CHARACTER
		// limit and comfortably outside a 64-BYTE one.
		{"22 CJK characters, 66 bytes", strings.Repeat("研", 22), false},
		{"40 e-acute, 80 bytes", strings.Repeat("é", 40), false},
		{"64 CJK characters, 192 bytes -- the boundary, in the wide case", strings.Repeat("研", 64), false},
		// The rows an ASCII-only whitespace class fails. U+3000 is the idiomatic
		// separator in Japanese; U+00A0 is what a paste from a console or a
		// spreadsheet produces.
		{"ideographic space U+3000", "研究\u3000開発", false},
		{"non-breaking space U+00A0", "Ingénierie\u00a0Group", false},
		{"vertical tab U+000B, in ECMAScript whitespace but not in Go's", "vert\u000btab", false},
		{"empty", "", true},
		{"65 characters", sixtyFour + "a", true},
		// The length boundary has to stay honest in the other direction too: a
		// fix that simply deleted the length rule would pass every row above.
		{"65 CJK characters", strings.Repeat("研", 65), true},
		{"65 e-acute", strings.Repeat("é", 65), true},
		{"semicolon is outside the class", "R&D;DevOps", true},
		{"double quote is outside the class", `Say "hello"`, true},
		{"angle brackets are outside the class", "<script>", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := validate(tc.value, "name")
			if gotErr := len(errs) > 0; gotErr != tc.wantErr {
				t.Fatalf("ValidateFunc(%q) errors = %v, want error = %v", tc.value, errs, tc.wantErr)
			}
		})
	}

	t.Run("an empty name is rejected at plan time", func(t *testing.T) {
		diags := resourceGroup().Validate(terraform.NewResourceConfigRaw(
			map[string]interface{}{"name": ""}))
		if !diags.HasError() {
			t.Fatal("an empty name planned cleanly; GRP-N01 requires it to be refused before " +
				"the config reaches POST /v3/groups")
		}
	})

	// The same class, without the length bound, guards description -- and an
	// explicitly empty description must be refused because the server refuses
	// it: CreateGroupDto.description is @IsOptional() AND @IsNotEmpty(). The
	// argument has to be omitted, which is a different thing from set-to-"".
	t.Run("an explicitly empty description is rejected at plan time", func(t *testing.T) {
		diags := resourceGroup().Validate(terraform.NewResourceConfigRaw(
			map[string]interface{}{"name": "Engineering", "description": ""}))
		if !diags.HasError() {
			t.Error(`description = "" planned cleanly, but @IsNotEmpty() makes it a 400. ` +
				"Omitting the argument is the way to have no description")
		}
	})
	t.Run("an omitted description plans cleanly", func(t *testing.T) {
		diags := resourceGroup().Validate(terraform.NewResourceConfigRaw(
			map[string]interface{}{"name": "Engineering"}))
		if diags.HasError() {
			t.Errorf("a group with no description failed validation: %v", diags)
		}
	})
}

/*
TestGroupWhitespaceClassCoversEveryECMAScriptSpace enumerates the whitespace rule
instead of trusting a shorthand, because the shorthand is what was wrong.

Go's `\s` is `[\t\n\f\r ]`. ECMAScript's is Unicode regardless of flags:
WhiteSpace (TAB, VT, FF, ZWNBSP and every Space_Separator) plus LineTerminator
(LF, CR, LS, PS) -- the 25 code points below. Writing `\s` in the Go port
therefore narrowed the server's rule by 20 code points, and each one of those is
a name an operator can legitimately write and the provider would refuse at plan
time with nothing to do about it.

`\p{Zs}` alone is not the fix either: it misses U+0009-U+000D, U+2028, U+2029 and
U+FEFF. The list is spelled out so that a future edit to
groupWhitespaceCharacters has to keep all of it.

The second half asserts the class did not become a free-for-all in the process:
the characters createGroup.dto.ts excludes must still be excluded, or the
"validation" is decorative.
*/
func TestGroupWhitespaceClassCoversEveryECMAScriptSpace(t *testing.T) {
	// WhiteSpace + LineTerminator, per the ECMAScript grammar. Space_Separator
	// is enumerated rather than referred to, so \p{Zs} being swapped for
	// something narrower cannot pass.
	ecmaScriptSpace := []rune{
		0x0009, 0x000A, 0x000B, 0x000C, 0x000D, // TAB LF VT FF CR
		0x0020, 0x00A0, 0x1680, // SPACE NBSP OGHAM SPACE MARK
		0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, // EN QUAD .. FOUR-PER-EM
		0x2006, 0x2007, 0x2008, 0x2009, 0x200A, // SIX-PER-EM .. HAIR SPACE
		0x2028, 0x2029, // LINE SEPARATOR, PARAGRAPH SEPARATOR
		0x202F, 0x205F, 0x3000, // NARROW NBSP, MEDIUM MATHEMATICAL, IDEOGRAPHIC
		0xFEFF, // ZERO WIDTH NO-BREAK SPACE
	}
	if len(ecmaScriptSpace) != 25 {
		t.Fatalf("the ECMAScript whitespace list has %d entries, want 25; the comment on "+
			"groupWhitespaceCharacters cites that number", len(ecmaScriptSpace))
	}

	validateName := resourceGroup().Schema["name"].ValidateFunc
	validateDescription := resourceGroup().Schema["description"].ValidateFunc
	for _, r := range ecmaScriptSpace {
		value := "a" + string(r) + "b"
		if _, errs := validateName(value, "name"); len(errs) > 0 {
			t.Errorf("name rejected U+%04X, which the server accepts: %v. Go's \\s does not "+
				"cover it -- see groupWhitespaceCharacters", r, errs)
		}
		if _, errs := validateDescription(value, "description"); len(errs) > 0 {
			t.Errorf("description rejected U+%04X, which the server accepts: %v", r, errs)
		}
	}

	// Widening whitespace must not have widened anything else. These are all
	// outside xssSafeCharacters in createGroup.dto.ts.
	for _, value := range []string{
		"semi;colon", `double"quote`, "<script>", "back`tick", "a=b", "a+b", "a?b",
		"zero\u200bwidth", // U+200B is NOT whitespace in ECMAScript, despite the name
	} {
		if _, errs := validateName(value, "name"); len(errs) == 0 {
			t.Errorf("name accepted %q, which is outside the server's character class; the "+
				"whitespace widening was supposed to be the only divergence", value)
		}
	}
}

/*
TestGroupReadPagesPastTheFirstPage is the gate on Read's pagination, and for this
resource it guards more than a wrong answer.

/v3/groups has no GET-by-id, so Read must walk the collection. Requesting a
bigger limit instead of paging only moves the ceiling: a group that sits past the
first page reads back as absent, Read clears the id, Terraform plans a create,
and the live group is either duplicated or deleted and recreated -- which
silently DROPS EVERY MEMBERSHIP IN IT, because memberships hang off the group's
id.

The absent case is asserted in the same test because the two answers must stay
distinguishable: "not on this page" and "not in this tenant" look identical to a
single-page read.
*/
func TestGroupReadPagesPastTheFirstPage(t *testing.T) {
	for _, tc := range []struct {
		name       string
		id         string
		wantFound  bool
		wantName   string
		wantPages  int
		wantIDGone bool
	}{
		{"the group is on page 2", "grp-2", true, "Ingénierie", 2, false},
		{"the group is on page 1", "grp-1", true, "Engineering", 1, false},
		{"the group is in neither page", "grp-404", false, "", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pagesRequested, limitsRequested []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				page := r.URL.Query().Get("page")
				pagesRequested = append(pagesRequested, page)
				limitsRequested = append(limitsRequested, r.URL.Query().Get("limit"))
				w.Header().Set("Content-Type", "application/json")
				switch page {
				case "1":
					_, _ = w.Write([]byte(groupListPage(1, 2, 2,
						`{"id":"grp-1","name":"Engineering"}`)))
				case "2":
					_, _ = w.Write([]byte(groupListPage(2, 2, 2,
						`{"id":"grp-2","name":"Ingénierie","isDefault":false,"users":["usr-1"]}`)))
				default:
					t.Errorf("unexpected page %q requested", page)
					_, _ = w.Write([]byte(groupListPage(1, 2, 2, "")))
				}
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceGroup().Schema, map[string]interface{}{})
			d.SetId(tc.id)

			diags := resourceGroupRead(context.Background(), d, newTestUserAPIClient(srv.URL))
			if diags.HasError() {
				t.Fatalf("Read failed: %v", diags)
			}
			if len(pagesRequested) != tc.wantPages {
				t.Errorf("requested pages %v, want %d request(s): a single-page read cannot "+
					"tell a group on page 2 from a group that was deleted, and recreating a "+
					"live group drops every membership in it", pagesRequested, tc.wantPages)
			}
			if gone := d.Id() == ""; gone != tc.wantIDGone {
				t.Fatalf("id cleared = %v, want %v", gone, tc.wantIDGone)
			}
			if tc.wantFound && d.Get("name").(string) != tc.wantName {
				t.Errorf("name = %q, want %q", d.Get("name"), tc.wantName)
			}
			// Limit is a page size, not a ceiling -- but it still has to be one
			// the server will serve. /v3/groups caps limit at 1000 and defaults
			// to 500 (v3.yaml), so anything above the cap would 400 every read.
			for _, limit := range limitsRequested {
				if limit != "500" {
					t.Errorf("requested limit=%q, want the endpoint's own default of 500", limit)
				}
			}
		})
	}
}

/*
TestGroupReadHasNoTerminatedCheck PINS THE ASYMMETRY between users and groups,
and it exists to stop the fix for the user soft delete from being "completed"
here.

MEASURED, both halves, against the tenant:

  - DELETE /v3/users/{id} answers 200 and the account STAYS in GET /v3/users
    with terminated: true, still counted by itemsTotal. findUserByID therefore
    treats a terminated record as absent -- see
    TestUserReadTreatsATerminatedUserAsAbsent.
  - DELETE /v3/groups/{id} removes the group from GET /v3/groups OUTRIGHT. There
    is no terminated field on the group read model, no terminated attribute on
    this resource, and nothing for an equivalent check to test.

So the symmetry is a trap: copying the user filter across would add a condition
that never fires, and -- worse -- would invite the reverse mistake of dropping
groups whose payload happens to carry a stray key. This test asserts both the
absence of the attribute and the behaviour: a group record that arrives WITH
"terminated": true, whether from a future server or a hand-written fixture, must
still read back as PRESENT, because for groups that key means nothing.

The other direction is already covered: GRP-D01's drift case
(TestAccCheckpointsaseGroupMembership_* aside) rests on the group vanishing from
the collection, which is what testAccCheckGroupDestroy asserts.
*/
func TestGroupReadHasNoTerminatedCheck(t *testing.T) {
	if _, present := resourceGroup().Schema["terminated"]; present {
		t.Error("checkpointsase_group grew a `terminated` attribute. Groups are HARD-deleted: " +
			"a deleted group is gone from GET /v3/groups outright, and the read model has " +
			"no such field. Only /v3/users soft-deletes")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A stray terminated: true on a GROUP. For users this is a soft delete;
		// here it is a key with no meaning and must change nothing.
		_, _ = w.Write([]byte(groupListPage(1, 1, 1,
			`{"id":"grp-1","name":"Engineering","isDefault":false,"terminated":true,`+
				`"users":["usr-1"],"networks":[],"applications":[],"vpnLocations":[]}`)))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceGroup().Schema, map[string]interface{}{})
	d.SetId("grp-1")

	if diags := resourceGroupRead(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("Read failed: %v", diags)
	}
	if d.Id() != "grp-1" {
		t.Fatal("resourceGroupRead cleared the id for a group carrying terminated: true. " +
			"The user soft-delete filter has been copied onto the group path, where the " +
			"field has no meaning: a live group would be dropped from state and recreated, " +
			"and recreating a group silently drops every membership in it")
	}
	if got := d.Get("name").(string); got != "Engineering" {
		t.Errorf("name = %q, want \"Engineering\": Read stopped populating the group", got)
	}
	if got := d.Get("users.#").(int); got != 1 {
		t.Errorf("users.# = %d, want 1", got)
	}
}

/*
TestGroupReadSurvivesANullListBody covers the one failure mode in findGroupByID
that is a provider CRASH rather than a wrong answer.

A 2xx whose body is the literal `null` leaves the SDK returning a nil *GroupList
with a nil error: localVarReturnValue starts as a nil pointer, and
json.Unmarshal into a **GroupList sets it to nil for `null` without ever calling
GroupList's generated UnmarshalJSON, so the requiredProperties check that would
otherwise reject the body never runs. Every field access after that panics, and a
panicking provider gives the operator a Go stack trace instead of a diagnostic.

Treating it as "absent" is the conservative reading: Read reports drift, and the
next plan proposes a create the operator can inspect.
*/
func TestGroupReadSurvivesANullListBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`null`))
	}))
	defer srv.Close()

	// Confirms the premise rather than assuming it: if the SDK ever starts
	// returning an error here, the nil guard becomes dead code and this test
	// should be the thing that says so.
	list, _, err := newTestUserAPIClient(srv.URL).TeamAPI.ListGroups(context.Background()).Execute()
	if err != nil || list != nil {
		t.Fatalf("ListGroups on a null body returned (%v, %v); the nil guard in findGroupByID "+
			"is written for (nil, nil) and should be revisited", list, err)
	}

	d := schema.TestResourceDataRaw(t, resourceGroup().Schema, map[string]interface{}{})
	d.SetId("grp-1")

	diags := resourceGroupRead(context.Background(), d, newTestUserAPIClient(srv.URL))
	if diags.HasError() {
		t.Fatalf("Read failed: %v", diags)
	}
	if d.Id() != "" {
		t.Errorf("id = %q, want it cleared: a body the provider cannot read must present as "+
			"drift, not as a surviving resource", d.Id())
	}
}

/*
TestGroupReadCoercesNilListsToEmpty is the state-shape half of A22b: a group with
nothing in any of its four projections must read back as four EMPTY LISTS, which
is what GRP-01 asserts and what Task 5's Read compares `users` against.

All four are omitempty on the generated model, so this fixture -- no
applications, networks, vpnLocations or users keys at all -- decodes to four nil
slices, which is the shape Read has to turn into state.

WHAT THIS TEST DOES AND DOES NOT PIN, measured rather than assumed. It fails when
Read stops setting the four attributes: they are Computed, so nothing else writes
them and they are simply absent from state. It does NOT fail when only the
`if list == nil { list = []string{} }` coercion inside Read is removed, because
d.Set already normalises a typed nil slice to the same state a []string{}
produces -- MapFieldWriter.setList decodes it to a zero-length slice and writes
`<key>.# = 0`. Rather than dress that up as a guard it is not, the assertion is
written against the requirement (state holds an empty list) and the comment in
resourceGroupRead says the same about the coercion.

The assertion is on the raw state attributes rather than on d.Get, because d.Get
normalises an absent list to an empty []interface{} and would pass either way.
*/
func TestGroupReadCoercesNilListsToEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// No applications, networks, vpnLocations or users keys at all: a
		// brand-new group with no members, exactly what Create's read-back sees.
		_, _ = w.Write([]byte(groupListPage(1, 1, 1, `{"id":"grp-1","name":"Engineering"}`)))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceGroup().Schema, map[string]interface{}{})
	d.SetId("grp-1")

	if diags := resourceGroupRead(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("Read failed: %v", diags)
	}

	attrs := d.State().Attributes
	for _, key := range []string{"applications", "networks", "vpn_locations", "users"} {
		count, present := attrs[key+".#"]
		if !present {
			t.Errorf("%s is absent from state (no %s.# key), so it reads as a null rather than "+
				"an empty list. Read must set every one of the four projections, even when the "+
				"server sends no key for it", key, key)
			continue
		}
		if count != "0" {
			t.Errorf("%s.# = %q, want 0", key, count)
		}
	}
	// A fix that stopped setting anything would satisfy the loop above for the
	// wrong reason.
	if got := d.Get("name").(string); got != "Engineering" {
		t.Errorf("name = %q, want Engineering: Read stopped populating state", got)
	}
	if d.Get("is_default").(bool) {
		t.Error("is_default = true for a record with no isDefault key; a group Terraform " +
			"created reads back false (GRP-01)")
	}
}

/*
TestGroupDeleteSwallowsA404ButNothingElse is the CI gate for GRP-N03, and it
exists because the acceptance-test form of that row cannot work.

The 404 swallow at the end of resourceGroupDelete is reachable in practice --
`terraform destroy -refresh=false`, or a colleague deleting the group from the
console between refresh and destroy -- but it is NOT reachable from the SDKv2
binary test driver through a Config step. Every such step ends with a plan, a
REFRESH and another plan (testing_new_config.go:143-151), and the pre-apply
refresh at testing_new_config.go:26-31 does the same at the start of every step,
PlanOnly included. Whichever step deletes the group out of band, the next refresh
calls Read, Read clears the id, the state file ends up with no resource in it,
and testing_new.go:75 then skips the post-test destroy entirely -- so Delete is
never called with a stale id and CheckDestroy never runs either. The version of
this row that looks right proves nothing.

Hence an httptest server. It also gates the guard on every PR, which no
acceptance test would have done. The 500 case is half the test: the swallow must
be narrow, or a server that is merely broken would look like a successful destroy
and the resource would leave state while the group -- and every membership in it
-- survived.
*/
func TestGroupDeleteSwallowsA404ButNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantErr    bool
		wantIDGone bool
	}{
		{"404 means somebody already deleted it", http.StatusNotFound,
			`{"message":"group not found"}`, false, true},
		{"200 is an ordinary destroy", http.StatusOK,
			`{"id":"grp-1","name":"Engineering"}`, false, true},
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

			d := schema.TestResourceDataRaw(t, resourceGroup().Schema, map[string]interface{}{})
			d.SetId("grp-1")

			diags := resourceGroupDelete(context.Background(), d, newTestUserAPIClient(srv.URL))

			if gotMethod != http.MethodDelete || gotPath != "/v3/groups/grp-1" {
				t.Errorf("request was %s %s, want DELETE /v3/groups/grp-1", gotMethod, gotPath)
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
TestGroupCreateSendsDescriptionOnlyWhenSet asserts on the REQUEST BODY, which is
the only place either of the two mistakes it guards is visible.

First mistake: sending `"description": ""`. createGroup.dto.ts carries BOTH
@IsOptional() and @IsNotEmpty() on the field, so an explicit empty string is a
400 while an absent key is accepted. An omitted key and a present-but-empty
string are different requests, and only one of them works.

Second mistake, and the reason this test cannot be replaced by an assertion on
d.Get: the DiffSuppressFunc on description. A create diffs against no state, so
`old` is "" for every attribute. Suppression keyed only on that -- without
suppressDiffOnEmptyOldValue's `d.Id() != ""` condition -- drops description from
the create diff, and the ResourceData a CreateContext receives is built from that
diff. The provider would silently create every group without its description
while the plan showed one.
*/
func TestGroupCreateSendsDescriptionOnlyWhenSet(t *testing.T) {
	for _, tc := range []struct {
		name        string
		config      map[string]interface{}
		wantPresent bool
	}{
		{"no description argument", map[string]interface{}{
			"name": "Engineering",
		}, false},
		{"a description argument", map[string]interface{}{
			"name": "Engineering", "description": "Owns the platform services.",
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotBody []byte
			var gotMethod, gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPost {
					gotMethod, gotPath = r.Method, r.URL.Path
					gotBody, _ = io.ReadAll(r.Body)
					_, _ = w.Write([]byte(`{"id":"grp-1","name":"Engineering"}`))
					return
				}
				// Create ends by calling Read.
				_, _ = w.Write([]byte(groupListPage(1, 1, 1,
					`{"id":"grp-1","name":"Engineering","isDefault":false}`)))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceGroup().Schema, tc.config)
			if diags := resourceGroupCreate(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
				t.Fatalf("Create failed: %v", diags)
			}
			if gotMethod != http.MethodPost || gotPath != "/v3/groups" {
				t.Errorf("request was %s %s, want POST /v3/groups", gotMethod, gotPath)
			}
			if d.Id() != "grp-1" {
				t.Errorf("id = %q, want grp-1", d.Id())
			}

			var payload map[string]interface{}
			if err := json.Unmarshal(gotBody, &payload); err != nil {
				t.Fatalf("create body was not JSON (%v): %s", err, gotBody)
			}
			if payload["name"] != "Engineering" {
				t.Errorf("name = %#v, want Engineering: %s", payload["name"], gotBody)
			}
			got, present := payload["description"]
			if present != tc.wantPresent {
				t.Fatalf("description present = %v, want %v: %s. An empty description here "+
					"is a 400 (@IsOptional plus @IsNotEmpty), and a MISSING one for a "+
					"configuration that set it means the DiffSuppressFunc is suppressing "+
					"the create diff, not just the post-import one", present, tc.wantPresent, gotBody)
			}
			if tc.wantPresent && got != "Owns the platform services." {
				t.Errorf("description = %#v, want the configured value: %s", got, gotBody)
			}
		})
	}
}

/*
TestGroupPostImportPlanDoesNotReplaceTheGroup is the gate on the DiffSuppressFunc,
and the harm it prevents is larger here than it was for users.

description is write-only because the Group read model has no field for it at
all (model_group.go), so an imported group has no description in state. The
attribute is ForceNew, so without suppression the FIRST plan after an import sees
"" -> the configured description and forces a REPLACEMENT: import a group, apply
the configuration that describes it, and the group is deleted -- taking every
membership in it with it.

The second case is the other half: the suppression is for "state has no value",
not for "any value", so a real change on a resource this provider created must
still force replacement.
*/
func TestGroupPostImportPlanDoesNotReplaceTheGroup(t *testing.T) {
	config := map[string]interface{}{
		"name":        "Engineering",
		"description": "Owns the platform services.",
	}

	for _, tc := range []struct {
		name            string
		state           map[string]string
		wantRequiresNew bool
	}{
		{
			// State exactly as resourceGroupImportState leaves it: Read
			// populated everything the read model carries, which does not
			// include description.
			name: "state as an import leaves it",
			state: map[string]string{
				"id":              "grp-1",
				"name":            "Engineering",
				"is_default":      "false",
				"applications.#":  "0",
				"networks.#":      "0",
				"vpn_locations.#": "0",
				"users.#":         "0",
			},
			wantRequiresNew: false,
		},
		{
			name: "a real change to a resource this provider created",
			state: map[string]string{
				"id":          "grp-1",
				"name":        "Engineering",
				"description": "Some older description",
			},
			wantRequiresNew: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diff, err := resourceGroup().Diff(
				context.Background(),
				&terraform.InstanceState{ID: tc.state["id"], Attributes: tc.state},
				terraform.NewResourceConfigRaw(config),
				nil,
			)
			if err != nil {
				t.Fatalf("planning failed: %v", err)
			}
			requiresNew := diff != nil && diff.RequiresNew()
			if requiresNew != tc.wantRequiresNew {
				// Name the attributes responsible; "RequiresNew = true" on its
				// own does not say which write-only field leaked into the plan.
				var forcing []string
				if diff != nil {
					for attr, d := range diff.Attributes {
						if d.RequiresNew {
							forcing = append(forcing, fmt.Sprintf("%s %q -> %q", attr, d.Old, d.New))
						}
					}
					sort.Strings(forcing)
				}
				t.Errorf("RequiresNew = %v, want %v; forced by: %s",
					requiresNew, tc.wantRequiresNew, strings.Join(forcing, ", "))
			}
		})
	}
}

/*
TestGroupImportStateVerifyIgnoreMatchesWhatImportOmits derives GRP-I01's ignore
list from behaviour instead of guessing it.

Guessing is exactly what went wrong upstream of this task: both the task brief
and V3-TERRAFORM-TEST-PLAN row GRP-I01 assert that Read populates description and
that ImportStateVerify therefore needs no ignore list. The generated Group model
has no description field, so that ImportStateVerify would have failed on its
first live run -- and only on a live run, since ImportStateVerify compares raw
attribute maps and nothing offline was checking them.

Asserting in BOTH directions means neither an omission nor a stale over-broad
entry survives. The two states are built the way the two code paths build them:
one through Create (which ends in Read), one through the import's Read, both
served the same fixture. The comparison mirrors the framework's own, including
its one concession: `.#` and `.%` keys whose value is "0" are ignored.
*/
func TestGroupImportStateVerifyIgnoreMatchesWhatImportOmits(t *testing.T) {
	const record = `{"id":"grp-1","name":"Engineering","isDefault":false,` +
		`"applications":[],"networks":[],"vpnLocations":[],"users":["usr-1"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"id":"grp-1"}`))
			return
		}
		_, _ = w.Write([]byte(groupListPage(1, 1, 1, record)))
	}))
	defer srv.Close()
	client := newTestUserAPIClient(srv.URL)
	r := resourceGroup()

	// The state an apply leaves, from the same configuration GRP-I01 applies.
	applied := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"name":        "Engineering",
		"description": "Terraform acceptance test, safe to ignore.",
	})
	if diags := resourceGroupCreate(context.Background(), applied, client); diags.HasError() {
		t.Fatalf("Create failed: %v", diags)
	}

	// The state an import leaves.
	imported := r.Data(nil)
	imported.SetId("grp-1")
	out, err := resourceGroupImportState(context.Background(), imported, client)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	// skipEmpty is the framework's rule, reproduced.
	skipEmpty := func(k, v string) bool {
		return (strings.HasSuffix(k, ".#") || strings.HasSuffix(k, ".%")) && v == "0"
	}
	collect := func(attrs map[string]string) map[string]string {
		kept := map[string]string{}
		for k, v := range attrs {
			if !skipEmpty(k, v) {
				kept[k] = v
			}
		}
		return kept
	}
	appliedAttrs := collect(applied.State().Attributes)
	importedAttrs := collect(out[0].State().Attributes)

	differing := map[string]bool{}
	for k, v := range appliedAttrs {
		if iv, ok := importedAttrs[k]; !ok || iv != v {
			differing[k] = true
		}
	}
	for k := range importedAttrs {
		if _, ok := appliedAttrs[k]; !ok {
			differing[k] = true
		}
	}

	// Direction 1: everything that differs must be ignored, or GRP-I01 fails on
	// its first live run.
	for k := range differing {
		covered := false
		for _, prefix := range groupImportStateVerifyIgnore {
			if strings.HasPrefix(k, prefix) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("%q differs between an applied and an imported group (%q vs %q) and is "+
				"not in groupImportStateVerifyIgnore; ImportStateVerify will fail on it",
				k, appliedAttrs[k], importedAttrs[k])
		}
	}
	// Direction 2: nothing is ignored that does not need to be. An over-broad
	// entry hides a real round-trip defect.
	for _, prefix := range groupImportStateVerifyIgnore {
		needed := false
		for k := range differing {
			if strings.HasPrefix(k, prefix) {
				needed = true
				break
			}
		}
		if !needed {
			t.Errorf("groupImportStateVerifyIgnore lists %q, but it round-trips through an "+
				"import unchanged; ignoring it hides any future defect in it", prefix)
		}
	}
}

/*
TestAccCheckpointsaseGroup_basic covers GRP-01 (apply, then an empty plan, with
is_default false and four empty lists), GRP-03 (destroy, verified through the
list endpoint since there is no GET-by-id) and GRP-I01 (import, then no diff).
*/
func TestAccCheckpointsaseGroup_basic(t *testing.T) {
	name := "tf-acc-" + randStringBytesRmndr()
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupConfigBasic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("checkpointsase_group.test", "id"),
					resource.TestCheckResourceAttr("checkpointsase_group.test", "name", name),
					resource.TestCheckResourceAttr("checkpointsase_group.test", "is_default", "false"),
					// The four membership projections: a group Terraform just
					// created has nothing in any of them, and they must read
					// back as empty lists rather than as nulls.
					resource.TestCheckResourceAttr("checkpointsase_group.test", "applications.#", "0"),
					resource.TestCheckResourceAttr("checkpointsase_group.test", "networks.#", "0"),
					resource.TestCheckResourceAttr("checkpointsase_group.test", "vpn_locations.#", "0"),
					resource.TestCheckResourceAttr("checkpointsase_group.test", "users.#", "0"),
					// description is the configuration's own value, not a
					// round-trip: the read model has no field for it.
					resource.TestCheckResourceAttr("checkpointsase_group.test", "description",
						"Terraform acceptance test, safe to ignore."),
				),
			},
			// GRP-01's second half: the same config must produce no diff.
			{
				Config:   testAccGroupConfigBasic(name),
				PlanOnly: true,
			},
			// GRP-I01: import, then no diff.
			//
			// The ignore list is derived offline, not guessed: see
			// groupImportStateVerifyIgnore and
			// TestGroupImportStateVerifyIgnoreMatchesWhatImportOmits. Its one
			// entry, description, has no field on the Group read model, so an
			// import cannot populate it however the plan behaves -- the brief's
			// claim that no ignore list is needed does not survive reading
			// model_group.go.
			//
			// The plan-time half of the same problem is the DiffSuppressFunc on
			// description, not this list.
			{
				ResourceName:            "checkpointsase_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: groupImportStateVerifyIgnore,
			},
		},
	})
}

// TestAccCheckpointsaseGroup_replaceOnNameChange covers GRP-02: with no PUT on
// /v3/groups, changing name must plan as -/+ and never as an in-place update.
// Asserted by capturing the id in step 1 and requiring a DIFFERENT id in step 2 --
// an in-place update would keep it, and no ComposeTestCheckFunc built-in can
// express "differs from the previous step".
func TestAccCheckpointsaseGroup_replaceOnNameChange(t *testing.T) {
	suffix := randStringBytesRmndr()
	first := "tf-acc-" + suffix + "-a"
	second := "tf-acc-" + suffix + "-b"
	var firstID string

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupConfigBasic(first),
				Check:  testAccCaptureResourceID("checkpointsase_group.test", &firstID),
			},
			{
				Config: testAccGroupConfigBasic(second),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("checkpointsase_group.test", "name", second),
					func(s *terraform.State) error {
						rs := s.RootModule().Resources["checkpointsase_group.test"]
						if rs.Primary.ID == firstID {
							return fmt.Errorf("id is unchanged (%s) after a name change: the "+
								"resource was updated in place, but /v3/groups has no PUT so it "+
								"must have been replaced", firstID)
						}
						return nil
					},
				),
			},
		},
	})
}

/*
TestAccCheckpointsaseGroup_rejectsDuplicateName covers GRP-N02: two groups with
the same name in one configuration.

This one necessarily reaches the API, which is why the row is live-only.
Terraform's schema has no cross-resource uniqueness constraint to express with,
and the two resources have no dependency between them, so both are planned as
creates and the collision is only visible in the second POST's response. The
tenant sees one successful create; the test's own destroy removes it.
*/
func TestAccCheckpointsaseGroup_rejectsDuplicateName(t *testing.T) {
	name := "tf-acc-" + randStringBytesRmndr()
	config := fmt.Sprintf(`
resource "checkpointsase_group" "first" {
  name        = %[1]q
  description = "Terraform acceptance test, safe to ignore."
}

resource "checkpointsase_group" "second" {
  name        = %[1]q
  description = "Terraform acceptance test, safe to ignore."
}
`, name)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				// appendErrorDiags prefers the response BODY over the status
				// line, so this matches only if the body carries the code or
				// the wording. Deliberately broad for that reason; if a live
				// run fails here, read the body it reports and narrow it.
				ExpectError: regexp.MustCompile(`(?i)400|409|conflict|already exist|duplicate`),
			},
		},
	})
}

/*
TestAccCheckpointsaseGroup_driftOnOutOfBandDelete covers GRP-D01: a group deleted
from the console must show up as drift, not as an error.

It passes only because resourceGroupRead clears the id when findGroupByID returns
found == false. A Read that instead reported "group not found" would fail this
plan, and every operator whose colleague deleted a group from the console would
have to remove the resource from state by hand.

GRP-N03 -- destroy tolerating the same absence -- is NOT covered here or in any
other acceptance test in this file. Any Config step that follows an out-of-band
delete refreshes first, which clears the id from the state file, so the post-test
destroy is skipped (testing_new.go:75) and Delete is never called.

One shape does reach it, and is deliberately not used: an ImportState step never
enters testStepNewConfig (dispatched at testing_new.go:203) and so never
refreshes, which would leave the stale id in state for the deferred destroy. That
would assert Delete's behaviour only indirectly, through an unrelated step type,
and would break if the driver ever changed where import is dispatched. See
TestGroupDeleteSwallowsA404ButNothingElse, which gates the same path offline,
directly, and on every PR rather than only on a live run.
*/
func TestAccCheckpointsaseGroup_driftOnOutOfBandDelete(t *testing.T) {
	name := "tf-acc-" + randStringBytesRmndr()
	var groupID string

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupConfigBasic(name),
				Check:  testAccCaptureResourceID("checkpointsase_group.test", &groupID),
			},
			{
				PreConfig: testAccDeleteGroupOutOfBand(t, &groupID),
				Config:    testAccGroupConfigBasic(name),
				// The plan must be non-empty: Read cleared the id, so Terraform
				// plans a create. An empty plan here would mean Read had adopted
				// a group that no longer exists.
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// testAccDeleteGroupOutOfBand deletes a group through the SDK, simulating
// somebody removing it from the console while Terraform is not looking. The id is
// taken by pointer because PreConfig closures are built before the step that
// fills it in has run.
func testAccDeleteGroupOutOfBand(t *testing.T, id *string) func() {
	return func() {
		if *id == "" {
			t.Fatal("no group id was captured; the preceding step's Check did not run")
		}
		client := testAccEnvClient()
		if _, _, err := client.TeamAPI.DeleteGroup(context.Background(), *id).Execute(); err != nil {
			t.Fatalf("deleting group %s out of band: %s", *id, err)
		}
	}
}

// testAccCheckGroupDestroy verifies GRP-03's second half. /v3/groups has no
// GET-by-id, so absence is proved through the list endpoint -- and through
// findGroupByID rather than a single page, so a tenant with more than one page of
// groups cannot report a surviving group as destroyed.
func testAccCheckGroupDestroy(s *terraform.State) error {
	client := testAccEnvClient()
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "checkpointsase_group" {
			continue
		}
		_, found, _, err := findGroupByID(context.Background(), client, rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("listing groups to verify destroy: %w", err)
		}
		if found {
			return fmt.Errorf("group %s still exists after destroy", rs.Primary.ID)
		}
	}
	return nil
}

func testAccGroupConfigBasic(name string) string {
	return fmt.Sprintf(`
resource "checkpointsase_group" "test" {
  name        = %[1]q
  description = "Terraform acceptance test, safe to ignore."
}
`, name)
}
