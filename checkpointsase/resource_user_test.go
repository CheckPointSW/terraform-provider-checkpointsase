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
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
newTestUserAPIClient builds an SDK client aimed at a test server.

The bearer token is pre-seeded so prepareRequest (client.go:517) never tries to
exchange the API key for one, which is what keeps every test in this file
offline -- no credential, no network. The pattern is lifted from the SDK's own
client_test.go, which uses it for the same reason.

  - @param serverURL string - the httptest server's base URL

@return *perimeter81Sdk.APIClient
*/
func newTestUserAPIClient(serverURL string) *perimeter81Sdk.APIClient {
	cfg := perimeter81Sdk.NewConfiguration("unused-api-key", serverURL)
	cfg.BearerTokenData = &perimeter81Sdk.TokenData{
		TokenType:         "Bearer",
		AccessToken:       "test-token",
		AccessTokenExpire: time.Now().Add(time.Hour).Unix(),
	}
	return perimeter81Sdk.NewAPIClient(cfg)
}

// userListPage renders one page of /v3/users. All four keys are required on
// UserList (model_user_list.go has a requiredProperties loop), so a fixture
// missing any of them fails to decode and the test would be measuring the
// fixture rather than the provider.
func userListPage(page, totalPage, itemsTotal int, records string) string {
	return fmt.Sprintf(`{"data":[%s],"page":%d,"totalPage":%d,"itemsTotal":%d}`,
		records, page, totalPage, itemsTotal)
}

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
	// Descends into blocks as well as top-level attributes: InternalValidate
	// (which TestProvider runs) already covers most of the top level, but it
	// skips Computed attributes and does not reach profile_data's four
	// sub-attributes at all.
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
	body := []byte(userListPage(1, 1, 1, `{"id":"u1"}`))

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

/*
TestUserReadIsExactOnID pins that Read cannot adopt a different user's state.

THE FIXTURE ORDER IS THE TEST. A prefix candidate must come FIRST in the slice,
otherwise a strings.HasPrefix implementation reaches the exact match before it
reaches anything it could get wrong, and the test passes under the very defect
it claims to guard. Both directions are asserted so neither ordering can be
"fixed" by luck.
*/
func TestUserReadIsExactOnID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture []string
		query   string
	}{
		// The prefix candidate is first: a HasPrefix implementation returns
		// "usr12" here and fails the assertion, which is the point.
		{"prefix candidate first", []string{"usr12", "usr1"}, "usr1"},
		{"exact match first", []string{"usr1", "usr12"}, "usr1"},
		{"query is the longer id", []string{"usr1", "usr12"}, "usr12"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := []perimeter81Sdk.User{}
			for _, id := range tc.fixture {
				u := perimeter81Sdk.User{}
				u.SetId(id)
				users = append(users, u)
			}
			got, found := readByIDFromList(users, tc.query,
				func(u perimeter81Sdk.User) string { return u.GetId() })
			if !found || got.GetId() != tc.query {
				t.Errorf("got (%q, %v), want (%q, true)", got.GetId(), found, tc.query)
			}
		})
	}
}

/*
TestUserRejectsMalformedEmailAtPlanTime covers USR-N01 offline.

The row is a ValidateFunc rejection: it needs no tenant, no credential and no
apply, so gating it behind TF_ACC would only mean it never runs. Running it
through Resource.Validate is the same code path `terraform plan` takes.
*/
func TestUserRejectsMalformedEmailAtPlanTime(t *testing.T) {
	for _, tc := range []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"no domain at all", "invalid-email-format", true},
		{"missing local part", "@example.com", true},
		{"dot-less domain", "someone@localhost", true},
		{"embedded space", "some one@example.com", true},
		{"ordinary address", "someone@example.com", false},
		{"plus addressing and a sub-domain", "some.one+tag@mail.example.co.uk", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := resourceUser().Validate(terraform.NewResourceConfigRaw(
				map[string]interface{}{
					"email":          tc.email,
					"invite_message": "never sent",
				}))
			if diags.HasError() != tc.wantErr {
				t.Fatalf("Validate(%q) HasError = %v, want %v: %v",
					tc.email, diags.HasError(), tc.wantErr, diags)
			}
			if !tc.wantErr {
				return
			}
			// The message is the deliverable: it is the only thing the operator
			// sees, and "must be an email address" is what USR-N01 asserts.
			var joined []string
			for _, d := range diags {
				joined = append(joined, d.Summary, d.Detail)
			}
			if !strings.Contains(strings.Join(joined, " "), "must be an email address") {
				t.Errorf("rejection did not say what was wrong: %v", diags)
			}
		})
	}
}

/*
TestUserDeleteSwallowsA404ButNothingElse is the CI gate for USR-N03, and it
exists because the acceptance-test form of that row cannot work.

The 404 swallow at the end of resourceUserDelete is reachable in practice --
`terraform destroy -refresh=false`, or a colleague removing the account from the
console between refresh and destroy -- but it is NOT reachable from the SDKv2
binary test driver. Every step ends with a plan, a REFRESH, and another plan
(testing_new_config.go:143-151), and that refresh persists state; the pre-apply
refresh at testing_new_config.go:26-31 does the same at the start of every step,
PlanOnly included. Whichever step deletes the user out of band, the next refresh
calls Read, Read clears the id, the state file ends up with no resource in it,
and testing_new.go:75 then skips the post-test destroy entirely -- so Delete is
never called with a stale id and CheckDestroy never runs either.

Hence an httptest server. It also gates the guard on every PR, which no
acceptance test would have done. The 500 case is half the test: the swallow must
be narrow, or a server that is merely broken would look like a successful
destroy and the resource would leave state while the account survived.
*/
func TestUserDeleteSwallowsA404ButNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantErr    bool
		wantIDGone bool
	}{
		{"404 means somebody already deleted it", http.StatusNotFound,
			`{"message":"user not found"}`, false, true},
		{"200 is an ordinary destroy", http.StatusOK,
			`{"id":"usr-1"}`, false, true},
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

			d := schema.TestResourceDataRaw(t, resourceUser().Schema, map[string]interface{}{})
			d.SetId("usr-1")

			diags := resourceUserDelete(context.Background(), d, newTestUserAPIClient(srv.URL))

			if gotMethod != http.MethodDelete || gotPath != "/v3/users/usr-1" {
				t.Errorf("request was %s %s, want DELETE /v3/users/usr-1", gotMethod, gotPath)
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
TestUserReadPagesPastTheFirstPage is the gate on Read's pagination.

Requesting a bigger limit instead of paging is not a cosmetic shortcut here. A
user who sits past the first page reads back as absent, Read clears the id,
Terraform plans a create, and a live account is either duplicated or the apply
dies on the duplicate address. The absent case is asserted in the same test
because the two answers must stay distinguishable: "not on this page" and "not
in this tenant" look identical to a single-page read.
*/
func TestUserReadPagesPastTheFirstPage(t *testing.T) {
	for _, tc := range []struct {
		name       string
		id         string
		wantFound  bool
		wantEmail  string
		wantPages  int
		wantIDGone bool
	}{
		{"the user is on page 2", "usr-2", true, "second@example.invalid", 2, false},
		{"the user is on page 1", "usr-1", true, "first@example.invalid", 1, false},
		{"the user is in neither page", "usr-404", false, "", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pagesRequested []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				page := r.URL.Query().Get("page")
				pagesRequested = append(pagesRequested, page)
				w.Header().Set("Content-Type", "application/json")
				switch page {
				case "1":
					_, _ = w.Write([]byte(userListPage(1, 2, 2,
						`{"id":"usr-1","email":"first@example.invalid"}`)))
				case "2":
					_, _ = w.Write([]byte(userListPage(2, 2, 2,
						`{"id":"usr-2","email":"second@example.invalid","emailVerified":true,"username":"second","roles":["Member"]}`)))
				default:
					t.Errorf("unexpected page %q requested", page)
					_, _ = w.Write([]byte(userListPage(1, 2, 2, "")))
				}
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceUser().Schema, map[string]interface{}{})
			d.SetId(tc.id)

			diags := resourceUserRead(context.Background(), d, newTestUserAPIClient(srv.URL))
			if diags.HasError() {
				t.Fatalf("Read failed: %v", diags)
			}
			if len(pagesRequested) != tc.wantPages {
				t.Errorf("requested pages %v, want %d request(s): a single-page read cannot "+
					"tell a user on page 2 from a user who was deleted", pagesRequested, tc.wantPages)
			}
			if gone := d.Id() == ""; gone != tc.wantIDGone {
				t.Fatalf("id cleared = %v, want %v", gone, tc.wantIDGone)
			}
			if tc.wantFound && d.Get("email").(string) != tc.wantEmail {
				t.Errorf("email = %q, want %q", d.Get("email"), tc.wantEmail)
			}
			// Limit is a page size, not a ceiling, and the server must be asked
			// for one it will serve.
		})
	}
}

/*
TestUserReadNeverWritesEmailVerifiedIntoState is the regression gate on the
worst defect this resource has had.

email_verified names two different things: on CreateUserDto it is an instruction
("skip the verification email"), on the User read model it is an observation
("has this person verified their address"). While Read copied the observation
into the attribute, and the attribute was ForceNew, an invited user verifying
her own address flipped state from false to true and the NEXT NO-OP APPLY
DELETED HER ACCOUNT and re-invited her.

So: the server says true, the configuration says false, and after Read the
attribute must still be false with no diff to act on. The Computed assertion is
part of the same guard -- Optional+Computed is what would let a server value
back in.
*/
func TestUserReadNeverWritesEmailVerifiedIntoState(t *testing.T) {
	if resourceUser().Schema["email_verified"].Computed {
		t.Error("email_verified is Computed again. It is a create-time instruction, not an " +
			"observation; making it Computed is the first half of the bug that deleted a " +
			"user for verifying her own address")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// The tenant's truth: she verified her address after being invited.
		_, _ = w.Write([]byte(userListPage(1, 1, 1,
			`{"id":"usr-1","email":"ada@example.invalid","emailVerified":true}`)))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceUser().Schema, map[string]interface{}{
		"email":          "ada@example.invalid",
		"invite_message": "Welcome aboard",
		"email_verified": false,
	})
	d.SetId("usr-1")

	if diags := resourceUserRead(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("Read failed: %v", diags)
	}
	if d.Get("email_verified").(bool) {
		t.Error("Read wrote the server's emailVerified into state. That is the create-time " +
			"instruction, not an observation, and the attribute is ForceNew: the next apply " +
			"would delete and re-invite the user")
	}
	// The rest of Read must still work; a fix that stopped setting everything
	// would pass the assertion above for the wrong reason.
	if got := d.Get("email").(string); got != "ada@example.invalid" {
		t.Errorf("email = %q, want ada@example.invalid: Read stopped populating state", got)
	}
}

/*
TestUserPostImportPlanDoesNotReplaceTheUser is the gate on the DiffSuppressFunc,
and the reason it exists is that the obvious alternative is worse.

invite_message and idp_type are write-only: the first is deliberately not read
back (a Required+ForceNew attribute populated from the server turns any
round-trip mismatch into a delete-and-re-invite), and the second has no field on
the read model at all. So an imported user has neither in state, and without
suppression the FIRST plan after an import forces replacement on both -- import
a user, apply the config that describes her, and she is deleted.

The second case is the other half: the suppression is for "state has no value",
not for "any value", so a real change on a resource this provider created must
still force replacement.
*/
func TestUserPostImportPlanDoesNotReplaceTheUser(t *testing.T) {
	config := map[string]interface{}{
		"email":          "ada@example.invalid",
		"invite_message": "Welcome aboard",
		"idp_type":       "database",
	}

	for _, tc := range []struct {
		name            string
		state           map[string]string
		wantRequiresNew bool
	}{
		{
			// State exactly as resourceUserImportState leaves it: Read
			// populated the readable fields and neither write-only attribute.
			name: "state as an import leaves it",
			state: map[string]string{
				"id":       "usr-1",
				"email":    "ada@example.invalid",
				"username": "ada",
			},
			wantRequiresNew: false,
		},
		{
			name: "a real change to a resource this provider created",
			state: map[string]string{
				"id":             "usr-1",
				"email":          "ada@example.invalid",
				"invite_message": "Some older message",
				"idp_type":       "database",
			},
			wantRequiresNew: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diff, err := resourceUser().Diff(
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
TestExpandUserProfileOmitsAnEmptyBlock pins what expandUserProfile's own comment
promises: `profileData` is either absent from the request body or carries a
field. A bare `profile_data {}` block yields a non-nil map of empty strings, so
guarding on the block's presence rather than on its contents would send
`"profileData": {}` -- the present-but-empty object the comment says it avoids.
*/
func TestExpandUserProfileOmitsAnEmptyBlock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		items   []interface{}
		wantNil bool
	}{
		{"no block", []interface{}{}, true},
		{"nil element", []interface{}{nil}, true},
		{"empty block", []interface{}{map[string]interface{}{
			"first_name": "", "last_name": "", "role_name": "", "phone": "",
		}}, true},
		{"one field set", []interface{}{map[string]interface{}{
			"first_name": "Ada", "last_name": "", "role_name": "", "phone": "",
		}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := expandUserProfile(tc.items)
			if (got == nil) != tc.wantNil {
				t.Fatalf("expandUserProfile() = %+v, wantNil = %v", got, tc.wantNil)
			}
			if tc.wantNil {
				return
			}
			payload := perimeter81Sdk.CreateUserDto{
				Email: "ada@example.invalid", InviteMessage: "hi", ProfileData: got,
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshalling the create payload: %v", err)
			}
			if !strings.Contains(string(body), `"firstName":"Ada"`) {
				t.Errorf("profileData did not reach the request body: %s", body)
			}
		})
	}
}

/*
userImportStateVerifyIgnore is USR-I01's ImportStateVerifyIgnore list.

It is a variable rather than a literal in the TestStep so that
TestUserImportStateVerifyIgnoreMatchesWhatImportOmits can check it against what
an import actually leaves out, offline. Getting this list wrong is a live-run-only
failure otherwise: ImportStateVerify compares the raw attribute maps with
reflect.DeepEqual after deleting these prefixes (testing_new_import_state.go:226-237),
and it only forgives `.#`/`.%` keys whose value is "0".

All three are write-only. invite_message and idp_type are not returned by the
server at all; email_verified is returned but deliberately not read back, because
it is a create-time instruction rather than an observation.
*/
var userImportStateVerifyIgnore = []string{"email_verified", "idp_type", "invite_message"}

/*
TestUserCreateSendsTheWriteOnlyAttributes is the other half of the
DiffSuppressFunc on invite_message and idp_type, and it is not a formality: the
obvious form of that function -- `old == ""` and nothing else -- silently breaks
CREATE.

A create diffs against no state, so `old` is "" for every attribute. Suppression
keyed only on that drops invite_message and idp_type from the create diff, the
ResourceData Create receives is built from that diff, and d.Get returns "". The
provider would POST an empty inviteMessage on every single create, on a field the
API requires. Measured before the fix: d.Get("invite_message") == "" for a
configuration that set it.

So this test asserts on the REQUEST BODY, which is the only place the mistake is
visible. profileData is asserted absent for the same reason expandUserProfile
returns nil: an omitted key and a present-but-empty object are different
requests.
*/
func TestUserCreateSendsTheWriteOnlyAttributes(t *testing.T) {
	var gotBody []byte
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			gotMethod, gotPath = r.Method, r.URL.Path
			gotBody, _ = io.ReadAll(r.Body)
			_, _ = w.Write([]byte(`{"id":"usr-1","email":"ada@example.invalid"}`))
			return
		}
		// Create ends by calling Read.
		_, _ = w.Write([]byte(userListPage(1, 1, 1,
			`{"id":"usr-1","email":"ada@example.invalid","username":"ada"}`)))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceUser().Schema, map[string]interface{}{
		"email":          "ada@example.invalid",
		"invite_message": "Welcome aboard",
		"idp_type":       "database",
		"email_verified": true,
	})

	if diags := resourceUserCreate(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("Create failed: %v", diags)
	}
	if gotMethod != http.MethodPost || gotPath != "/v3/users" {
		t.Errorf("request was %s %s, want POST /v3/users", gotMethod, gotPath)
	}
	if d.Id() != "usr-1" {
		t.Errorf("id = %q, want usr-1", d.Id())
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("create body was not JSON (%v): %s", err, gotBody)
	}
	for key, want := range map[string]interface{}{
		"email":         "ada@example.invalid",
		"inviteMessage": "Welcome aboard",
		"idpType":       "database",
		"emailVerified": true,
	} {
		if payload[key] != want {
			t.Errorf("%s = %#v, want %#v. An empty write-only field here means the "+
				"DiffSuppressFunc is suppressing the create diff, not just the "+
				"post-import one", key, payload[key], want)
		}
	}
	if _, present := payload["profileData"]; present {
		t.Errorf("profileData was sent for a configuration with no profile_data block: %s", gotBody)
	}
}

/*
TestUserImportStateVerifyIgnoreMatchesWhatImportOmits derives USR-I01's ignore
list from behaviour instead of guessing it.

The list is a live-run-only failure otherwise, and it moves whenever Read's
setters move: dropping email_verified from Read -- the fix for the defect that
deleted a user for verifying her own address -- is exactly what added the third
entry. Asserting in BOTH directions means neither an omission nor a stale
over-broad entry survives.

The two states are built the way the two code paths build them: one through
Create (which ends in Read), one through the import's Read, both served the same
fixture. The comparison mirrors the framework's own, including its one
concession: `.#` and `.%` keys whose value is "0" are ignored, which is why a
configuration setting access_groups or profile_data would need those ignored too.
*/
func TestUserImportStateVerifyIgnoreMatchesWhatImportOmits(t *testing.T) {
	const record = `{"id":"usr-1","email":"ada@example.invalid","username":"ada",` +
		`"emailVerified":true,"roles":["Member"],"invitationAttempts":1}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"id":"usr-1"}`))
			return
		}
		_, _ = w.Write([]byte(userListPage(1, 1, 1, record)))
	}))
	defer srv.Close()
	client := newTestUserAPIClient(srv.URL)
	r := resourceUser()

	// The state an apply leaves, from the same configuration USR-I01 applies.
	applied := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"email":          "ada@example.invalid",
		"invite_message": "Terraform acceptance test, safe to ignore.",
		"email_verified": true,
	})
	if diags := resourceUserCreate(context.Background(), applied, client); diags.HasError() {
		t.Fatalf("Create failed: %v", diags)
	}

	// The state an import leaves.
	imported := r.Data(nil)
	imported.SetId("usr-1")
	out, err := resourceUserImportState(context.Background(), imported, client)
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

	// Direction 1: everything that differs must be ignored, or USR-I01 fails on
	// its first live run.
	for k := range differing {
		covered := false
		for _, prefix := range userImportStateVerifyIgnore {
			if strings.HasPrefix(k, prefix) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("%q differs between an applied and an imported user (%q vs %q) and is "+
				"not in userImportStateVerifyIgnore; ImportStateVerify will fail on it",
				k, appliedAttrs[k], importedAttrs[k])
		}
	}
	// Direction 2: nothing is ignored that does not need to be. An over-broad
	// entry hides a real round-trip defect.
	for _, prefix := range userImportStateVerifyIgnore {
		needed := false
		for k := range differing {
			if strings.HasPrefix(k, prefix) {
				needed = true
				break
			}
		}
		if !needed {
			t.Errorf("userImportStateVerifyIgnore lists %q, but it round-trips through an "+
				"import unchanged; ignoring it hides any future defect in it", prefix)
		}
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
			// USR-I01: import, then no diff.
			//
			// The ignore list is derived offline, not guessed: see
			// userImportStateVerifyIgnore and
			// TestUserImportStateVerifyIgnoreMatchesWhatImportOmits. All three
			// entries are write-only attributes an import cannot populate, and
			// ImportStateVerify compares raw attribute maps, so each one would
			// fail the comparison however the plan behaves.
			//
			// The plan-time half of the same problem is a DiffSuppressFunc on
			// invite_message and idp_type, not this list.
			{
				ResourceName:            "checkpointsase_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: userImportStateVerifyIgnore,
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
				Check:  testAccCaptureResourceID("checkpointsase_user.test", &firstID),
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
// rather than being rejected at plan time. The load-bearing assertion is that
// the apply succeeds at all -- access_groups is write-only, so checking its
// value in state would only restate the configuration.
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
TestAccCheckpointsaseUser_driftWhenDeletedOutOfBand covers USR-D01: a user
removed from the console must show up as drift, not as an error.

It passes only because resourceUserRead clears the id when findUserByID returns
found == false. A Read that instead reported "user not found" would fail this
plan, and every operator whose colleague deleted a user from the console would
have to remove the resource from state by hand.

USR-N03 -- destroy tolerating the same absence -- is NOT covered here or in any
other acceptance test in this file. Any Config step that follows an out-of-band
delete refreshes first, which clears the id from the state file, so the post-test
destroy is skipped (testing_new.go:75) and Delete is never called.

One shape does reach it, and is deliberately not used: an ImportState step never
enters testStepNewConfig (dispatched at testing_new.go:203) and so never
refreshes, which would leave the stale id in state for the deferred destroy. That
would assert Delete's behaviour only indirectly, through an unrelated step type,
and would break if the driver ever changed where import is dispatched. See
TestUserDeleteSwallowsA404ButNothingElse, which gates the same path offline,
directly, and on every PR rather than only on a live run.
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
				Check:  testAccCaptureResourceID("checkpointsase_user.test", &userID),
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

// testAccCaptureResourceID records the id Terraform holds for a resource so a
// later step can refer to it. PreConfig takes no state argument, which is why
// the id has to be carried out of the step that created it. Resource-agnostic --
// it takes an address -- and shared with resource_group_test.go.
func testAccCaptureResourceID(name string, out *string) resource.TestCheckFunc {
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
// GET-by-id, so absence is proved through the list endpoint -- and through
// findUserByID rather than a single page, so a tenant larger than one page
// cannot report a surviving account as destroyed.
func testAccCheckUserDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "checkpointsase_user" {
			continue
		}
		_, found, _, err := findUserByID(context.Background(), client, rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("listing users to verify destroy: %w", err)
		}
		if found {
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
