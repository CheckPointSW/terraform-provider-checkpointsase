package checkpointsase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
This file holds BOTH tiers, and the split is by name.

TestInternetAccessStatus* are offline. The servers are httptest.Servers on
localhost and the client is newTestUserAPIClient, which pre-seeds a bearer token
so no test exchanges an API key. None of them makes a network call.

TestAccCheckpointsaseInternetAccessStatus_flipsAndRestores at the bottom of the
file is an ACCEPTANCE test, and it is the most dangerous test in this provider:
it switches Internet Access, Threat Prevention and DLP on or off for a whole
tenant. Read its comment and testAccRestoreInternetAccessStatus in
swg_acc_check_helpers_test.go before touching it.

The two response fixtures below are the reason this file has more read tests than
a one-field resource would seem to need. The two authorities available disagree
about the shape of GET /v3/ia/status, and readInternetAccessStatus accepts both;
see the comment on that function. Both fixtures are therefore exercised through
the real decode path rather than one being chosen.
*/

// internetAccessStatusFlatBody is the response shape the OpenAPI document
// declares for GET /v3/ia/status: the field at the top level, with
// `additionalProperties: true`. This is what the generated SDK model was built
// from, so this body populates GetIAStatus200Response.IaStatus directly.
func internetAccessStatusFlatBody(status string) string {
	return `{"iaStatus":"` + status + `"}`
}

/*
internetAccessStatusEnvelopeBody is the shape phase4-verification's surface table
records for the same endpoint, and the shape its two siblings on /v3/ia/
demonstrably use (compare accessPolicyGetBody in policy_list_test.go).

Against the generated model this body leaves IaStatus nil and puts `status` and
`data` in AdditionalProperties -- so a reader that trusted the document alone
would return "" from a healthy 200. That is what
TestInternetAccessStatusReadAcceptsBothResponseShapes is for.
*/
func internetAccessStatusEnvelopeBody(status string) string {
	return `{"status":200,"data":{"iaStatus":"` + status + `"}}`
}

// ---------------------------------------------------------------------------
// Delete: the one that matters
// ---------------------------------------------------------------------------

/*
TestInternetAccessStatusDeleteMakesNoRequest is the most important test in this
file and the reason the Delete function is as long as it is.

`terraform destroy` on this resource must issue ZERO requests. The tempting
implementation -- POST {"iaStatus":"inactive"}, "undoing" what was applied --
would disable Internet Access, Threat Prevention and DLP for the whole tenant as
a side effect of removing a Terraform resource, with no plan line saying so. The
API has no DELETE for /v3/ia/status because there is nothing to delete.

The assertion is on the whole request list and on its LENGTH, not on the last
request or on the absence of one particular verb: a test that asserted "no POST"
would pass a Delete that issued a GET, and one that inspected only the final call
cannot see an extra one at all. An empty list is the only assertion that fails
for every way of getting this wrong.

The warning is asserted in the same test because the two halves are one
behaviour. A destroy that silently changes nothing and a destroy that silently
changes everything look identical in the console output; the diagnostic is what
tells the operator which one happened, and it is part of what "a no-op that
explains itself" means.
*/
func TestInternetAccessStatusDeleteMakesNoRequest(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(internetAccessStatusFlatBody("inactive")))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceInternetAccessStatus().Schema,
		map[string]interface{}{"ia_status": "active"})
	d.SetId(internetAccessStatusResourceID)

	diags := resourceInternetAccessStatusDelete(context.Background(), d,
		newTestUserAPIClient(srv.URL))
	if diags.HasError() {
		t.Fatalf("the delete reported an error: %v", diags)
	}

	calls, _ := log.snapshot()
	if len(calls) != 0 {
		t.Fatalf("destroy issued %d request(s), %v, and must issue NONE. This resource owns "+
			"the value of a tenant switch, not an object: the only thing a write here could "+
			"be is setting it to \"inactive\", which would disable %s for the whole tenant "+
			"because somebody removed a Terraform resource.", len(calls), calls,
			internetAccessStatusScope)
	}

	if d.Id() != "" {
		t.Errorf("the id is still %q after destroy; Terraform would keep tracking a resource "+
			"it was told to release", d.Id())
	}

	var warned bool
	var joined string
	for _, dg := range diags {
		joined += dg.Summary + " " + dg.Detail + " "
		if dg.Severity == diag.Warning {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("destroy emitted no warning. A no-op destroy and a destructive one print the "+
			"same thing otherwise, so the operator has to be told the tenant was left "+
			"untouched. Diagnostics were: %v", diags)
	}
	// The three features have to be named, for the same reason the resource
	// description names them: "ia_status" sounds like one switch and is three.
	for _, fragment := range []string{"Threat Prevention", "DLP", "active"} {
		if !strings.Contains(joined, fragment) {
			t.Errorf("the destroy warning does not mention %q, so it does not say what was "+
				"left in force:\n%s", fragment, joined)
		}
	}
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/*
TestInternetAccessStatusCreateAndUpdateAreOneFunction pins Pattern B's shape.

There is one endpoint and one field: POST /v3/ia/status sets iaStatus whether or
not it differs from what is stored, so adopting the setting and changing it are
byte-for-byte the same request. Two functions would be two copies of one call and
the only thing that could differ between them is a bug.
*/
func TestInternetAccessStatusCreateAndUpdateAreOneFunction(t *testing.T) {
	r := resourceInternetAccessStatus()
	if r.CreateContext == nil || r.UpdateContext == nil {
		t.Fatal("the resource must have both a CreateContext and an UpdateContext")
	}
	if reflect.ValueOf(r.CreateContext).Pointer() != reflect.ValueOf(r.UpdateContext).Pointer() {
		t.Error("CreateContext and UpdateContext are different functions. Both are the same " +
			"single-field POST, so they must be the same function or the two will drift.")
	}
}

/*
TestInternetAccessStatusWriteSendsOneFieldAndThenReads pins the whole write path
in one request log.

Three things are asserted because they are one property from three angles:

  - exactly one POST followed by exactly one GET. The GET is the re-read that
    exercises the decode path every later plan compares against; an extra call of
    any kind on this endpoint family is worth failing over.
  - the POST body carries `iaStatus` and NOTHING ELSE. Measured (W2): that one
    field is the entire write surface. The generated model serialises
    AdditionalProperties too, so an implementation that passed a decoded GET body
    through would send `status` and `data` as well.
  - state ends up holding what the SERVER returned, not what was configured. The
    fixture answers the GET with "inactive" while the configuration says
    "active", so a write that populated state from its own request body -- which
    would look correct against a well-behaved server -- fails here.
*/
func TestInternetAccessStatusWriteSendsOneFieldAndThenReads(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(internetAccessStatusFlatBody("inactive")))
			return
		}
		_, _ = w.Write([]byte(internetAccessStatusFlatBody("active")))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceInternetAccessStatus().Schema,
		map[string]interface{}{"ia_status": "active"})

	if diags := resourceInternetAccessStatusWrite(context.Background(), d,
		newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("the write failed: %v", diags)
	}

	calls, bodies := log.snapshot()
	want := []string{"POST /v3/ia/status", "GET /v3/ia/status"}
	if !testComparableArraiesEq(calls, want) {
		t.Fatalf("requests were %v, want exactly %v: create and update are one POST, and the "+
			"GET after it is what puts the server's own answer into state", calls, want)
	}

	var sent map[string]interface{}
	if err := json.Unmarshal([]byte(bodies[0]), &sent); err != nil {
		t.Fatalf("the POST body is not JSON: %v\n%s", err, bodies[0])
	}
	if len(sent) != 1 || sent["iaStatus"] != "active" {
		t.Errorf("the POST body is %s, want exactly {\"iaStatus\":\"active\"}. W2 measured "+
			"that one field as the entire write surface of this endpoint.", bodies[0])
	}

	if got := d.Id(); got != internetAccessStatusResourceID {
		t.Errorf("the id is %q, want the constant %q", got, internetAccessStatusResourceID)
	}
	if got := d.Get("ia_status").(string); got != "inactive" {
		t.Errorf("ia_status is %q after the write, want %q -- state must hold what the GET "+
			"returned, not what the configuration sent, or no apply ever exercises the "+
			"decode path the next plan compares against", got, "inactive")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/*
TestInternetAccessStatusReadAcceptsBothResponseShapes covers the disagreement
between the two authorities, in both directions.

The OpenAPI document declares the 200 body flat; phase4-verification's surface
table records it enveloped in `{status, data}`, which is what the two sibling
endpoints on /v3/ia/ verifiably return. Nothing available offline settles which
one this endpoint sends, so the reader accepts both and this test drives both
through the real SDK decode.

Delete either branch of readInternetAccessStatus and one subtest fails with
ia_status = "" from a 200 -- which is the failure this is really about. An empty
string is not in the enum, so state would hold a value the tenant cannot have,
and the next plan would propose "changing" the tenant's security enforcement back
to the configured value on every run.
*/
func TestInternetAccessStatusReadAcceptsBothResponseShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"flat, as the OpenAPI document declares", internetAccessStatusFlatBody("active"), "active"},
		{"enveloped, as the surface table records", internetAccessStatusEnvelopeBody("active"), "active"},
		{"flat and inactive", internetAccessStatusFlatBody("inactive"), "inactive"},
		{"enveloped and inactive", internetAccessStatusEnvelopeBody("inactive"), "inactive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceInternetAccessStatus().Schema,
				map[string]interface{}{})
			d.SetId(internetAccessStatusResourceID)

			if diags := resourceInternetAccessStatusRead(context.Background(), d,
				newTestUserAPIClient(srv.URL)); diags.HasError() {
				t.Fatalf("the read failed on a 200: %v", diags)
			}
			if got := d.Get("ia_status").(string); got != tc.want {
				t.Errorf("ia_status = %q, want %q. An empty value here is not a state the "+
					"enum admits, and it would make every plan propose changing the "+
					"tenant's %s enforcement.", got, tc.want, internetAccessStatusScope)
			}
		})
	}
}

/*
TestInternetAccessStatusReadReportsAnErrorRatherThanAnEmptyStatus is the Phase 3
lesson -- a read error is never a falsy value -- applied to a scalar setting.

On the two policy endpoints the wrong answer was an empty LIST; here it is an
empty STRING, and it is worse in one specific way: an empty policy is a real
state a tenant can be in, but "" is not one of the two values iaStatus admits, so
there is no case in which writing it is right.

The 200-with-no-iaStatus row is the one that is easy to get wrong. It is a
SUCCESSFUL response that carries no value -- neither shape matched -- and the
generated model returns "" for it without complaint, so nothing upstream fails.
It must be an error.

Two properties are asserted on every failing row: the id survives, because
clearing it would make the next plan a create and a create here is a POST that
changes the tenant's enforcement; and ia_status keeps its previous value rather
than being overwritten with "".
*/
func TestInternetAccessStatusReadReportsAnErrorRatherThanAnEmptyStatus(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr bool
		want    string
	}{
		{"a 404, which means the URL is wrong", http.StatusNotFound,
			`{"message":"Cannot GET /api/v3/ia/status"}`, true, "active"},
		{"a 500", http.StatusInternalServerError, `{"message":"boom"}`, true, "active"},
		{"a 200 carrying no iaStatus in either shape", http.StatusOK,
			`{"status":200,"data":{}}`, true, "active"},
		{"a 200 that is an empty object", http.StatusOK, `{}`, true, "active"},
		{"a 200 with the value, flat", http.StatusOK,
			internetAccessStatusFlatBody("inactive"), false, "inactive"},
		{"a 200 with the value, enveloped", http.StatusOK,
			internetAccessStatusEnvelopeBody("inactive"), false, "inactive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &requestLog{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.record(r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceInternetAccessStatus().Schema,
				map[string]interface{}{"ia_status": "active"})
			d.SetId(internetAccessStatusResourceID)

			diags := resourceInternetAccessStatusRead(context.Background(), d,
				newTestUserAPIClient(srv.URL))

			if diags.HasError() != tc.wantErr {
				t.Fatalf("HasError() = %t, want %t (diags: %v)", diags.HasError(), tc.wantErr, diags)
			}
			if got := d.Get("ia_status").(string); got != tc.want {
				t.Errorf("ia_status = %q, want %q", got, tc.want)
			}
			if tc.wantErr && d.Id() != internetAccessStatusResourceID {
				t.Errorf("the id was cleared by a failed read; the next plan would be a "+
					"create, and a create here POSTs a new value over the tenant's %s "+
					"enforcement (id is now %q)", internetAccessStatusScope, d.Id())
			}

			calls, _ := log.snapshot()
			if want := []string{"GET /v3/ia/status"}; !testComparableArraiesEq(calls, want) {
				t.Errorf("requests were %v, want exactly %v: a read must never write", calls, want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Schema and description
// ---------------------------------------------------------------------------

/*
TestInternetAccessStatusRejectsValuesTheServerRejects pins the enum and the
absence of a default.

Both values come from the OpenAPI document's `enum: [active, inactive]`, which is
declared identically on the request body and both 200 responses, and W2 measured
that one field as the whole write surface. So unlike the `inspect`/`appliedOn`
matrix in the HTTPS-inspection resource, this restriction is in the contract
rather than in a tenant's feature flags, and enforcing it at plan time cannot
refuse configuration the server would accept.

The case row is deliberate: StringInSlice is called with ignoreCase=false, so
"Active" fails at plan time instead of reaching a server that answers the enum.

The missing-value row pins Required. A Default here would let a configuration
that simply omits the field change the tenant's security posture, which is the
one thing a declarative tool must not do quietly.
*/
func TestInternetAccessStatusRejectsValuesTheServerRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config map[string]interface{}
		valid  bool
	}{
		{"active", map[string]interface{}{"ia_status": "active"}, true},
		{"inactive", map[string]interface{}{"ia_status": "inactive"}, true},
		{"a value outside the enum", map[string]interface{}{"ia_status": "enabled"}, false},
		{"the right value in the wrong case", map[string]interface{}{"ia_status": "Active"}, false},
		{"an empty string", map[string]interface{}{"ia_status": ""}, false},
		{"no ia_status at all", map[string]interface{}{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := resourceInternetAccessStatus().Validate(terraform.NewResourceConfigRaw(tc.config))
			if diags.HasError() == tc.valid {
				t.Fatalf("HasError() = %t for %v, want %t", diags.HasError(), tc.config, !tc.valid)
			}
			if tc.valid {
				return
			}
			var joined string
			for _, dg := range diags {
				joined += dg.Summary + " " + dg.Detail + " "
			}
			if !strings.Contains(joined, "ia_status") {
				t.Errorf("the plan error does not name `ia_status`, so it cannot be acted "+
					"on:\n%s", joined)
			}
		})
	}
}

/*
TestInternetAccessStatusDescriptionNamesAllThreeFeatures pins the sentence this
resource exists to say.

The attribute is called ia_status and the resource is called
internet_access_status, so every name a user sees mentions ONE feature. The API's
own description of both operations says the setting indicates "whether Internet
Access, Threat Prevention, and DLP are enabled or disabled" -- three, one of them
the tenant's data-loss prevention. A user who sets `inactive` believing they are
turning off web filtering is turning off two more things, and the only place that
can be corrected is the text.

The destroy behaviour is pinned in the same test because it is the other thing a
reader cannot guess: destroy makes no API call, which is unusual enough that
saying so is part of the contract.
*/
func TestInternetAccessStatusDescriptionNamesAllThreeFeatures(t *testing.T) {
	r := resourceInternetAccessStatus()

	for _, target := range []struct {
		what string
		text string
	}{
		{"resource description", r.Description},
		{"ia_status description", r.Schema["ia_status"].Description},
	} {
		for _, fragment := range []string{"Internet Access", "Threat Prevention", "DLP"} {
			if !strings.Contains(target.what, fragment) && !strings.Contains(target.text, fragment) {
				t.Errorf("the %s does not mention %q. This one field disables three things "+
					"and only two of them are in its name:\n%s", target.what, fragment, target.text)
			}
		}
	}

	for _, fragment := range []string{"NO API call", "does not set the tenant to `inactive`"} {
		if !strings.Contains(r.Description, fragment) {
			t.Errorf("the resource description does not contain %q, so an operator cannot "+
				"tell what terraform destroy will do here:\n%s", fragment, r.Description)
		}
	}
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/*
TestInternetAccessStatusImportAdoptsTheTenantSetting covers the import path,
including the two parts that are easy to get wrong: the id a user types is
ignored so an imported resource is byte-identical in state to a created one, and
import makes exactly ONE request, the GET. An import that wrote would change the
tenant's enforcement before the operator had seen a plan.
*/
func TestInternetAccessStatusImportAdoptsTheTenantSetting(t *testing.T) {
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(internetAccessStatusEnvelopeBody("active")))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceInternetAccessStatus().Schema,
		map[string]interface{}{})
	d.SetId("whatever-the-user-typed")

	imported, err := resourceInternetAccessStatusImportState(context.Background(), d,
		newTestUserAPIClient(srv.URL))
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("import returned %d resources, want 1", len(imported))
	}
	if got := imported[0].Id(); got != internetAccessStatusResourceID {
		t.Errorf("the imported id is %q, want the constant %q -- there is one setting per "+
			"tenant, addressed by path, so no id a user could type selects anything else",
			got, internetAccessStatusResourceID)
	}
	if got := imported[0].Get("ia_status").(string); got != "active" {
		t.Errorf("the imported ia_status is %q, want %q", got, "active")
	}

	calls, _ := log.snapshot()
	if want := []string{"GET /v3/ia/status"}; !testComparableArraiesEq(calls, want) {
		t.Errorf("import issued %v, want exactly %v: import must never write, or the "+
			"tenant's enforcement changes before anybody has seen a plan", calls, want)
	}
}

/*
TestInternetAccessStatusImportFailsLoudlyWhenTheReadFails pins that a failed
import is an error rather than a resource holding "". Importing an unknown value
and then applying would set the tenant's enforcement to whatever the
configuration happened to say, with nobody having seen what it was.
*/
func TestInternetAccessStatusImportFailsLoudlyWhenTheReadFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Cannot GET /api/v3/ia/status"}`))
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceInternetAccessStatus().Schema,
		map[string]interface{}{})
	if _, err := resourceInternetAccessStatusImportState(context.Background(), d,
		newTestUserAPIClient(srv.URL)); err == nil {
		t.Fatal("import succeeded over a failed read; it must report the error rather than " +
			"adopting a setting it never saw")
	}
}

/*
================================================================================
ACCEPTANCE TEST -- SIA-01, SIA-02, SIA-05 and the live half of SIA-06.

ONE test, not four, and that is deliberate. Every step below changes the tenant's
Internet Access, Threat Prevention and DLP enforcement, so the fewer independent
entry points there are into that, the fewer places a restore can be forgotten.

The rows are covered as steps of a single sequence that starts at the tenant's
current value, flips it, and comes back -- with a t.Cleanup underneath that puts
it back however the test ends.
================================================================================
*/

// testAccInternetAccessStatusConfig renders the singleton with one value.
func testAccInternetAccessStatusConfig(status string) string {
	return fmt.Sprintf(`
resource "checkpointsase_internet_access_status" "test" {
  ia_status = %q
}
`, status)
}

/*
testAccCheckInternetAccessStatusUnchangedByDestroy is SIA-06's live half.

The offline test TestInternetAccessStatusDeleteMakesNoRequest already pins that
Delete issues zero requests, by counting them against an httptest server. What it
cannot show is the consequence: that the tenant's value is still whatever was
last applied once Terraform has stopped managing it. This does, and it does it
without hardcoding a value.

It compares the LIVE value against the value Terraform held in state immediately
before the destroy -- CheckDestroy receives the pre-destroy state
(testing_new.go:32), so `ia_status` there is exactly what the last successful
apply wrote. Comparing against that rather than against the test's `original`
keeps this assertion about Delete's behaviour even when an earlier step failed
and left the tenant flipped; restoring in that case is t.Cleanup's job, not this
function's, and having both try would produce two confusing failures for one
cause.

  - @param s *terraform.State - the pre-destroy state

@return error
*/
func testAccCheckInternetAccessStatusUnchangedByDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "checkpointsase_internet_access_status" {
			continue
		}
		want := rs.Primary.Attributes["ia_status"]
		if want == "" {
			return fmt.Errorf("the pre-destroy state holds no ia_status, so there is nothing " +
				"to compare the tenant against")
		}
		got, err := readInternetAccessStatus(context.Background(), testAccEnvClient())
		if err != nil {
			return fmt.Errorf("reading the tenant's Internet Access status after destroy: %w", err)
		}
		if got != want {
			return fmt.Errorf("the tenant's ia_status is %q after destroy but was %q before it: "+
				"destroying this resource CHANGED the tenant's %s enforcement. Delete must make "+
				"no API call at all",
				got, want, internetAccessStatusScope)
		}
	}
	return nil
}

/*
TestAccCheckpointsaseInternetAccessStatus_flipsAndRestores covers SIA-01
(apply the current value, then an empty re-plan), SIA-02 (flip to the opposite
value, in place), SIA-05 (import with the constant id, then an empty plan) and
the live half of SIA-06 (destroy changes nothing).

WHAT THIS TEST DOES TO THE TENANT, stated plainly, because no other test in this
provider does anything comparable: step 3 flips `ia_status`. If the tenant is
`inactive` that ENABLES Internet Access, Threat Prevention and DLP; if it is
`active` that DISABLES all three. Step 5 flips it back, and the t.Cleanup
registered before the first step flips it back again if any step fails before
step 5 runs.

FOUR THINGS MAKE THAT SAFE, and all four matter:

 1. THE ORIGINAL VALUE IS READ, NEVER ASSUMED. The tenant this was written
    against is `inactive`, but nothing here hardcodes that; the restore target is
    whatever the tenant actually reported before the first apply. A test that
    assumed `inactive` would switch off three security features on a tenant that
    had them on, and would report a pass for doing it.

 2. THE RESTORE IS A t.Cleanup, NOT A FINAL STEP. Cleanups run when the test
    fails, when it calls t.Fatal, and while a panic is unwinding -- which is
    precisely the set of cases where a final step does not. Destroy cannot serve
    as the restore either: this resource's Delete deliberately makes NO API call
    (SIA-06), so `terraform destroy` leaves the flipped value in force.

 3. THE RESTORE VERIFIES ITSELF and calls t.Errorf naming the value to set by
    hand if it cannot. A silently failed restore is worse than none, because
    nobody would have a reason to look.

 4. THE TEST FLIPS BACK ON THE HAPPY PATH TOO (step 5), so the cleanup is a
    safety net rather than the mechanism. That keeps the tenant correct even in
    the one case a cleanup cannot cover -- the process being killed between the
    last step and the cleanup.

Step 2 and step 4 are the pair that earns the whole test. Both are PlanOnly, and
they are the only live evidence that Read decodes the response at all: §1.22
measured GET /v3/ia/status as ENVELOPED while the OpenAPI document declares it
flat, so a reader trusting the document gets an empty string from a healthy 200
and writes it into a Required attribute -- which plans a change to the tenant's
security posture on every run. That failure is invisible to a fixture-driven
test, because the fixture is written by whoever chose the shape. It is visible
here as a non-empty plan.

Step 4 exists separately from step 2 because they check different things: step 2
proves the read decodes the value the tenant already had, step 4 proves it
decodes the value this test just wrote.
*/
func TestAccCheckpointsaseInternetAccessStatus_flipsAndRestores(t *testing.T) {
	const address = "checkpointsase_internet_access_status.test"

	/*
		resource.Test does the TF_ACC skip itself, but not until after this
		function has built its TestCase -- and this test has to READ the tenant
		before it can say what its configuration is, because the first step
		applies the tenant's CURRENT value. So the skip is duplicated here,
		ahead of the read, and it must stay ahead of it: without it the offline
		suite would make a network call from a file whose other tests are all
		httptest.
	*/
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("Acceptance tests skipped unless %s set. This one switches %s on or off for "+
			"the whole tenant.", resource.EnvTfAcc, internetAccessStatusScope)
	}
	testAccPreCheck(t)

	original := testAccReadInternetAccessStatus(t)
	opposite := testAccOppositeInternetAccessStatus(t, original)

	// Registered BEFORE the first apply, so it covers every failure from here on.
	t.Cleanup(func() { testAccRestoreInternetAccessStatus(t, original) })

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckInternetAccessStatusUnchangedByDestroy,
		Steps: []resource.TestStep{
			// SIA-01: adopt the tenant's current value. This step changes
			// nothing on the tenant -- it writes back what is already there.
			{
				Config: testAccInternetAccessStatusConfig(original),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(address, "id", internetAccessStatusResourceID),
					resource.TestCheckResourceAttr(address, "ia_status", original),
				),
			},
			// SIA-01's second half, and the §1.22 assertion.
			{
				Config:   testAccInternetAccessStatusConfig(original),
				PlanOnly: true,
			},
			// SIA-02: the flip. In place via POST -- nothing here is ForceNew,
			// and Create and Update are the same function.
			{
				Config: testAccInternetAccessStatusConfig(opposite),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(address, "id", internetAccessStatusResourceID),
					resource.TestCheckResourceAttr(address, "ia_status", opposite),
				),
			},
			// The flipped value survives a refresh, which is what proves the
			// POST persisted rather than only updating state.
			{
				Config:   testAccInternetAccessStatusConfig(opposite),
				PlanOnly: true,
			},
			// Back to where the tenant started, on the happy path. The cleanup
			// is the net; this is the mechanism.
			{
				Config: testAccInternetAccessStatusConfig(original),
				Check:  resource.TestCheckResourceAttr(address, "ia_status", original),
			},
			// SIA-05: import with the constant id. Import only READS, so it
			// cannot change the tenant's enforcement -- but the first apply
			// after one can, which is why the resource description says to read
			// the plan. ImportStateId is given explicitly to pin the documented
			// command rather than defaulting to the resource's own id.
			{
				ResourceName:      address,
				ImportState:       true,
				ImportStateId:     internetAccessStatusResourceID,
				ImportStateVerify: true,
			},
		},
	})
}
