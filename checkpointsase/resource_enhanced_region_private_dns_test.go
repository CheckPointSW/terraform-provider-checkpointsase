package checkpointsase

import (
	"context"
	"net/http"
	"strings"
	"testing"

	ctyjson "github.com/hashicorp/go-cty/cty/json"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
Offline tests for checkpointsase_enhanced_region_private_dns.

Everything here runs against httptest or against the SDK's diff machinery;
nothing makes a network call or needs TF_ACC. NONE OF THESE NAMES CARRIES THE
TestAcc PREFIX, which in this codebase means "acceptance test, skips without
TF_ACC=1". Phase 4 shipped 21 offline tests wearing that prefix, which reads in
the summary as 21 skipped acceptance tests and zero offline coverage. The one
acceptance test for this resource lives in
resource_enhanced_region_private_dns_acc_test.go and genuinely is one.

THE FIXTURES ARE SPEC-DERIVED, NOT MEASURED, AND EVERY TEST BELOW HAS TO BE READ
IN THAT LIGHT. This is the one honest difference from the network resource's test
file, which drives the same JSON as a MEASUREMENT. Read that carefully:

  - the bodies are the ones API-FINDINGS.md 1.31 measured, and it measured them
    against GET/PUT /v3/networks/enhanced/{networkId}/privateDNS -- the NETWORK
    path. No probe in Phase 5's run, or any run before it, has touched
    /v3/networks/enhanced/{networkId}/regions/{regionId}/privateDNS at all.
  - what justifies reusing them is the SPEC: both operations declare the same
    request model (CustomDnsUpdate), the same response model (CustomDns), the same
    response map (202 only, no 200) and the same word-for-word full-replacement
    description (openapi.yaml:1121 for the region, :633 for the network).
  - so these tests prove the PROVIDER reads and writes the shape the spec
    declares, on the region's path, with both ids in it. They do not prove the
    region endpoint behaves like the network one. Nothing here may claim it does.
    TestAccEnhancedRegionPrivateDNS_basic is the first thing that will find out.

This project has twice shipped a fixture claiming wire fidelity it did not have,
and both times somebody else found it. The reuse of the network's fake and its
body constants is what keeps the two resources honestly comparable; the paragraph
above is what keeps the claim the right size.
*/

// The composite id the fixtures below use throughout, and its two halves. They
// are separate constants because several assertions are about the JOIN rather
// than about either half -- an id built with the wrong separator still contains
// both.
const (
	testRegionPDNSNetworkID = "net-1"
	testRegionPDNSRegionID  = "reg-1"
	testRegionPDNSID        = testRegionPDNSNetworkID + ":" + testRegionPDNSRegionID
	// The region path both ids have to appear in, in the right order. Written out
	// literally rather than built from the constants above so that a test asserting
	// on it cannot agree with a resource that swapped the two path parameters.
	testRegionPDNSPath = "/v3/networks/enhanced/net-1/regions/reg-1/privateDNS"
)

// testEnhancedRegionPrivateDNSData builds a ResourceData over the REGISTERED
// resource schema -- not a copy of it -- holding the values a CRUD function
// reads.
func testEnhancedRegionPrivateDNSData(t *testing.T,
	raw map[string]interface{}) *schema.ResourceData {

	t.Helper()
	return schema.TestResourceDataRaw(t, resourceEnhancedRegionPrivateDNS().Schema, raw)
}

/*
planEnhancedRegionPrivateDNS runs the SDK's real diff machinery -- including
CustomizeDiff -- over a configuration, the way `terraform plan` does.

It is deliberately a second copy of planEnhancedNetworkPrivateDNS rather than a
shared helper parameterised by resource, and the reason is what it is here to
catch. The rules themselves are shared (validatePrivateDNSDiff); what is NOT
shared is each resource's CustomizeDiff being registered on the resource at all.
A helper that took a *schema.Resource argument would still test that wiring, but
this file's cases would then read as if they were testing the rules, and the one
defect only this file can find -- a region resource that forgot CustomizeDiff --
would look like duplicate coverage and be deleted. Naming the resource here makes
that the visible subject.

  - @param t *testing.T
  - @param configJSON string - the configuration, as JSON object keys matching HCL

@return error - what `terraform plan` would report, or nil
*/
func planEnhancedRegionPrivateDNS(t *testing.T, configJSON string) error {
	t.Helper()

	r := resourceEnhancedRegionPrivateDNS()
	config, err := ctyjson.Unmarshal([]byte(configJSON), r.CoreConfigSchema().ImpliedType())
	if err != nil {
		t.Fatalf("the test's own configuration does not match the resource schema: %v\nconfig: %s",
			err, configJSON)
	}

	_, diffErr := r.Diff(
		context.Background(),
		&terraform.InstanceState{RawConfig: config},
		terraform.NewResourceConfigShimmed(config, r.CoreConfigSchema()),
		nil,
	)
	return diffErr
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/*
TestEnhancedRegionPrivateDNSReadUsesBothIdsInThePath is the one assertion this
resource needs that its sibling does not, and it is the whole reason the resource
exists separately.

A region is addressed by TWO path parameters, and getting them the wrong way round
compiles, type-checks and produces a perfectly plausible 404 at runtime. The SDK
takes them positionally --
GetEnhancedRegionPrivateDNS(ctx, networkId, regionId) -- so nothing but the URL
that went out can tell a correct call from a transposed one.

The assertion is on the FULL PATH string, not on "contains reg-1": a resource that
sent /regions/net-1/... with the network id in the region slot would satisfy any
containment check written with the two ids in either order.
*/
func TestEnhancedRegionPrivateDNSReadUsesBothIdsInThePath(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSConfigured,
	})

	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
		"network_id": testRegionPDNSNetworkID,
		"region_id":  testRegionPDNSRegionID,
	})
	d.SetId(testRegionPDNSID)

	diags := resourceEnhancedRegionPrivateDNSRead(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("the read failed: %s", diagsText(diags))
	}

	want := []string{"GET " + testRegionPDNSPath}
	if got := fake.calls(); !testComparableArraiesEq(got, want) {
		t.Errorf("the read issued\n  %v\nwant\n  %v\nThe two ids are positional arguments to the "+
			"SDK call, so transposing them compiles and produces a 404 that looks exactly like a "+
			"region that does not exist", got, want)
	}
}

/*
TestEnhancedRegionPrivateDNSReadClearsIdWhenTheParentIsGone pins EPD-D01, and it
pins a branch that this codebase has three times been wrong to add elsewhere.

A 404 here clears the id and returns NO diagnostics, so the next plan proposes
recreating the configuration rather than failing. That is correct HERE and was
wrong in Phase 3/4, and the difference is what the 404 means on each endpoint:

  - Phase 3/4's were COLLECTION reads, where a 404 meant the URL was wrong.
    Treating that as drift emptied Terraform's state on a misconfiguration.
  - This is a SINGLE OBJECT addressed by two user-supplied ids. Probe P10 measured
    what a wrong NETWORK id gets -- 404 with
    {"message":"Network doesn't exist.","messageCode":"NOT_FOUND","status":404} --
    on the network path. The message names the OBJECT, not the route.

BOTH IDS ARE REQUIRED ARGUMENTS, so an operator deleting the network or the region
outside Terraform is directly reachable through HCL and has to plan as a
recreation.

WHAT IS ASSUMED HERE AND WHAT IS NOT. That a 404 is what a bogus id gets on THIS
path is spec-derived: 404 is in the region operation's declared response map
(openapi.yaml:1121) exactly as it is in the network's, and P10 never sent a bogus
id to it. What the test itself pins is unconditional and does not depend on that
-- given a 404, this resource treats it as drift. If the endpoint turns out to
answer something else for a missing region, this test still holds and the
resource's Read comment is what needs correcting.

The companion assertion is in the test below: a non-404 must NOT clear the id.
Without it this test passes for an implementation that clears the id on every
error, which would turn a transient 500 into a silent state wipe.
*/
func TestEnhancedRegionPrivateDNSReadClearsIdWhenTheParentIsGone(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getStatus: http.StatusNotFound,
		getBody:   measuredPrivateDNSNetworkGone,
	})

	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
		"network_id": "net-gone",
		"region_id":  "reg-gone",
		"enabled":    true,
	})
	d.SetId("net-gone:reg-gone")

	diags := resourceEnhancedRegionPrivateDNSRead(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("a vanished parent must read as DRIFT, not as a failure, or `terraform plan` "+
			"cannot propose recreating the configuration (EPD-D01). Diagnostics: %s",
			diagsText(diags))
	}
	if d.Id() != "" {
		t.Errorf("the id is still %q after a 404. Terraform would keep tracking the private DNS "+
			"of a region that no longer exists, and every later plan would fail on the same 404 "+
			"instead of proposing a recreation", d.Id())
	}
}

/*
TestEnhancedRegionPrivateDNSReadKeepsTheIdOnEveryOtherError is the other half of
the test above, and it exists so that "clear the id on 404" cannot degrade into
"clear the id whenever the read fails".

A 500 is transient. Clearing state for one would tell Terraform the configuration
is gone, and the next apply would rewrite a region's DNS on the strength of a
blip.
*/
func TestEnhancedRegionPrivateDNSReadKeepsTheIdOnEveryOtherError(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
	}{
		{"server error", http.StatusInternalServerError, `{"message":"boom","status":500}`},
		{"forbidden", http.StatusForbidden, `{"message":"forbidden","status":403}`},
		{"unprocessable", http.StatusUnprocessableEntity, measuredPrivateDNSValidationError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
				getStatus: tt.status,
				getBody:   tt.body,
			})

			d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
				"network_id": testRegionPDNSNetworkID,
				"region_id":  testRegionPDNSRegionID,
			})
			d.SetId(testRegionPDNSID)

			diags := resourceEnhancedRegionPrivateDNSRead(context.Background(), d, fake.client())
			if !diags.HasError() {
				t.Fatalf("a %d must be reported, not swallowed", tt.status)
			}
			if d.Id() == "" {
				t.Errorf("the id was cleared for a %d. Only a 404 means the parent is gone; "+
					"clearing state for anything else tells Terraform to recreate a "+
					"configuration that is still there, on the strength of a blip", tt.status)
			}
		})
	}
}

/*
TestEnhancedRegionPrivateDNSReadStoresTheConfigurationAsReturned is the companion
that stops the path test above passing by having Read store nothing.

The body is the byte-exact round trip API-FINDINGS.md 1.31 measured ON THE NETWORK
PATH (see this file's header): two servers with DIFFERENT isTLS values, and two
search domains sent in deliberately non-alphabetical order that came back in the
order sent. Position is the contract the SPEC and that measurement together
describe, and the index assertions below are what a TypeSet would break -- which
is why this resource's lists are TypeList despite the spec's uniqueItems.

`region_id` is asserted alongside `network_id`. A Read that set only one of them
would leave the other blank in state after an import, and the NEXT plan would
propose a ForceNew replacement of a resource nothing was wrong with.
*/
func TestEnhancedRegionPrivateDNSReadStoresTheConfigurationAsReturned(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSConfigured,
	})

	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
		"network_id": testRegionPDNSNetworkID,
		"region_id":  testRegionPDNSRegionID,
	})
	d.SetId(testRegionPDNSID)

	diags := resourceEnhancedRegionPrivateDNSRead(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("reading a configured region failed: %s", diagsText(diags))
	}

	for attr, want := range map[string]interface{}{
		"network_id":                     testRegionPDNSNetworkID,
		"region_id":                      testRegionPDNSRegionID,
		"enabled":                        true,
		"attributes.#":                   1,
		"attributes.0.servers.#":         2,
		"attributes.0.servers.0.address": "10.0.0.53",
		"attributes.0.servers.0.is_tls":  false,
		"attributes.0.servers.1.address": "10.0.1.53",
		"attributes.0.servers.1.is_tls":  true,
		"attributes.0.search_domains.#":  2,
		"attributes.0.search_domains.0":  "b.example.com",
		"attributes.0.search_domains.1":  "a.example.com",
		"attributes.0.dns_policy.#":      0,
	} {
		if got := d.Get(attr); got != want {
			t.Errorf("%s = %#v, want %#v", attr, got, want)
		}
	}
}

/*
TestEnhancedRegionPrivateDNSReadOnUnconfiguredRegion covers what the spec says is
the ORDINARY state of this endpoint, which looks like an edge case and is not.

API-FINDINGS.md 1.31 measured GET on a NETWORK nobody has configured returning
exactly {"enabled": false} -- no `attributes` key, decoding to a nil
*CustomDnsAttributes. The region operation returns the same CustomDns model with
the same optional `attributes`, so a region nobody has configured is expected to
read the same way; that expectation is spec-derived, and it is every Read that
runs before the first apply lands. A Read that dereferenced the nil would panic
the provider on the normal path.

The assertion is that `attributes` lands in state as an EMPTY LIST, which is what
an unset Optional block holds -- so a configuration that writes no `attributes`
block produces no diff after this read.
*/
func TestEnhancedRegionPrivateDNSReadOnUnconfiguredRegion(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSUnconfigured,
	})

	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
		"network_id": testRegionPDNSNetworkID,
		"region_id":  testRegionPDNSRegionID,
	})
	d.SetId(testRegionPDNSID)

	diags := resourceEnhancedRegionPrivateDNSRead(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("reading an unconfigured region failed: %s", diagsText(diags))
	}

	if enabled := d.Get(privateDNSAttrEnabled).(bool); enabled {
		t.Errorf("enabled = %v, want false: the body says false", enabled)
	}
	attributes, ok := d.Get(privateDNSAttrAttributes).([]interface{})
	if !ok {
		t.Fatalf("attributes is %T, want []interface{}", d.Get(privateDNSAttrAttributes))
	}
	if len(attributes) != 0 {
		t.Errorf("attributes = %#v, want an empty list. The API sent no `attributes` key, and an "+
			"unset Optional block holds an empty list -- anything else diffs forever against a "+
			"configuration that writes no block", attributes)
	}
}

// ---------------------------------------------------------------------------
// Create and Update
// ---------------------------------------------------------------------------

/*
TestEnhancedRegionPrivateDNSCreateAdoptsWritesWaitsAndReadsBack walks the whole
create path and asserts the ORDER of what it did, because every defect this
resource can have is visible in that order and in nothing else.

Five things are pinned at once, and each has a distinct failure:

 1. The adoption GET comes FIRST. There is no create endpoint here, so "create"
    is a PUT against a configuration that already exists; checking it is reachable
    before writing turns "this region does not exist" into an error before
    anything is changed.
 2. The id is the COMPOSITE, "<network_id>:<region_id>". Not the region id alone,
    which is not unique across networks as far as anything measured says, and not
    the network id, which is the sibling resource's id and would collide with it
    in a state file holding both.
 3. Both ids reach the URL, in the right slots, on EVERY call -- the adoption GET,
    the PUT and the read-back. They are positional arguments to three separate SDK
    calls, so getting one right proves nothing about the other two.
 4. The provider POLLS. The status endpoint answers completed:false twice before
    completed:true, so a Create that returned as soon as the PUT succeeded lands
    here, not in production. That is the failure putGranularFirewallPolicy's
    comment records shipping three times.
 5. It reads back AFTER the operation completes, and the read-back is what ends
    up in state. The fake serves a different body once it has seen the PUT, so a
    read that happened too early would store the pre-write values -- the exact
    symptom a non-waiting implementation produces, and one that looks like success.

The status path is /v3/networks/status/{statusId}, which is ASSUMED rather than
measured for private DNS at all (probe P6) and is shared with the network
resource. See putPrivateDNSAndWait's comment.
*/
func TestEnhancedRegionPrivateDNSCreateAdoptsWritesWaitsAndReadsBack(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody:         measuredPrivateDNSUnconfigured,
		getBodyAfterPut: measuredPrivateDNSConfigured,
		statusBodies: []string{
			`{"completed":false}`,
			`{"completed":false}`,
			`{"completed":true,"result":{"statusCode":200}}`,
		},
	})

	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
		"network_id": testRegionPDNSNetworkID,
		"region_id":  testRegionPDNSRegionID,
		"enabled":    true,
		"attributes": []interface{}{map[string]interface{}{
			"servers": []interface{}{
				map[string]interface{}{"address": "10.0.0.53", "is_tls": false},
				map[string]interface{}{"address": "10.0.1.53", "is_tls": true},
			},
			"search_domains": []interface{}{"b.example.com", "a.example.com"},
		}},
	})

	diags := resourceEnhancedRegionPrivateDNSCreate(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("create failed: %s", diagsText(diags))
	}

	if d.Id() != testRegionPDNSID {
		t.Errorf("id = %q, want the composite %q. A region's private DNS is addressed by BOTH "+
			"ids, so neither alone can be its id -- the network id is the sibling resource's id "+
			"and would collide with it", d.Id(), testRegionPDNSID)
	}

	want := []string{
		"GET " + testRegionPDNSPath,
		"PUT " + testRegionPDNSPath,
		"GET /v3/networks/status/exu7TTfsPg",
		"GET /v3/networks/status/exu7TTfsPg",
		"GET /v3/networks/status/exu7TTfsPg",
		"GET " + testRegionPDNSPath,
	}
	if got := fake.calls(); !testComparableArraiesEq(got, want) {
		t.Errorf("the create issued\n  %v\nwant\n  %v\nThe order is the assertion: adopt, write, "+
			"poll to completion, then read back. A create that returned after the PUT would show "+
			"no status GETs at all", got, want)
	}

	// The status id came from the LAST PATH SEGMENT of the statusUrl, resolved
	// against the configured client -- not from following the URL, which is
	// absolute, names a different host and carries an /api/rest/v2.3/ path
	// (API-FINDINGS.md 1.28). A non-US tenant that followed it would poll the
	// wrong deployment, and that deployment would answer well-formed JSON.
	for _, call := range fake.calls() {
		if strings.Contains(call, "/api/rest/") {
			t.Errorf("a request went to %q -- statusUrl was followed literally rather than "+
				"resolved against the configured base URL (API-FINDINGS.md 1.28)", call)
		}
	}

	// What landed in state is what the read-back returned, not what was sent.
	if got := d.Get("attributes.0.servers.1.is_tls"); got != true {
		t.Errorf("attributes.0.servers.1.is_tls = %#v, want true from the read-back body", got)
	}
}

/*
TestEnhancedRegionPrivateDNSCreateRefusesAMissingParentAndWritesNothing is the
mirror image of the drift branch in Read, and the pair is the point.

A 404 during Read means an object Terraform was tracking has gone: drift. A 404
during Create means the operator named a network or a region that does not exist:
an error. Reusing the drift branch here would let an apply "succeed" against an
address that was never valid, storing an empty resource and reporting nothing.

The no-PUT assertion is separate from the error assertion because an
implementation that wrote first and checked afterwards would still produce an
error -- and would have issued a write against a path it had no business touching.
*/
func TestEnhancedRegionPrivateDNSCreateRefusesAMissingParentAndWritesNothing(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getStatus: http.StatusNotFound,
		getBody:   measuredPrivateDNSNetworkGone,
	})

	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
		"network_id": "net-gone",
		"region_id":  "reg-gone",
		"enabled":    false,
	})

	diags := resourceEnhancedRegionPrivateDNSCreate(context.Background(), d, fake.client())
	if !diags.HasError() {
		t.Fatal("creating against a parent that does not exist must fail. A 404 is DRIFT in " +
			"Read and an ERROR here: nothing is being tracked yet, so there is nothing to " +
			"report as gone -- the operator simply named an address that is not there")
	}
	if d.Id() != "" {
		t.Errorf("id = %q after a failed adoption, want empty", d.Id())
	}
	for _, call := range fake.calls() {
		if strings.HasPrefix(call, http.MethodPut) {
			t.Errorf("the create issued %q despite the adoption check failing. Calls were %v",
				call, fake.calls())
		}
	}
	if text := diagsText(diags); !strings.Contains(text, "Network doesn't exist") {
		t.Errorf("the diagnostic does not carry the server's own explanation, which is the only "+
			"part that tells the operator what to fix. Got: %s", text)
	}
}

/*
TestEnhancedRegionPrivateDNSUpdateSendsTheFullReplacementBodyToTheRegionPath pins
what goes on the wire, which no assertion about the resulting state can see.

Three things are checked. Two of them are 400s or 422s on the network endpoint and
are expected to be the same here because the request MODEL is the same
(CustomDnsUpdate, openapi.yaml:1121 and :633 both):

  - `attributes` is present even when disabling. API-FINDINGS.md 1.31 measured
    {"enabled": false} on its own as a 422 on the network path -- and that is
    EXACTLY the body GET returns for an unconfigured one, so the read cannot be
    echoed back as a write. The legal "off" body carries both empty arrays.
  - the arrays are `[]` and never `null`. Servers and SearchDomains are declared
    without omitempty, so a nil slice reaches the wire as `"servers": null`, which
    the endpoint's @IsArray refuses with a 400 that names a field the operator may
    well have set.

The third is this resource's own: the PUT goes to the REGION path, with both ids
in the right slots. UpdateEnhancedRegionPrivateDNS takes them positionally, so a
transposition is invisible in Go and is a 404 at runtime.

The body assertions are on the recorded REQUEST BODY rather than on the Go value,
because nil-versus-empty is precisely the distinction a struct comparison erases.
*/
func TestEnhancedRegionPrivateDNSUpdateSendsTheFullReplacementBodyToTheRegionPath(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSOff,
	})

	// The "off" configuration, written the way an operator would: enabled = false
	// and no attributes block at all.
	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
		"network_id": testRegionPDNSNetworkID,
		"region_id":  testRegionPDNSRegionID,
		"enabled":    false,
	})
	d.SetId(testRegionPDNSID)

	diags := resourceEnhancedRegionPrivateDNSUpdate(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("update failed: %s", diagsText(diags))
	}

	var putBody, putCall string
	for i, call := range fake.calls() {
		if strings.HasPrefix(call, http.MethodPut) {
			putCall = call
			putBody = fake.bodies()[i]
		}
	}
	if putCall == "" {
		t.Fatalf("no PUT was issued at all; calls were %v", fake.calls())
	}
	if putCall != "PUT "+testRegionPDNSPath {
		t.Errorf("the PUT went to %q, want %q. Both ids are positional arguments to "+
			"UpdateEnhancedRegionPrivateDNS, so transposing them compiles and writes to a path "+
			"that does not exist -- or, worse, to one that does and belongs to something else",
			putCall, "PUT "+testRegionPDNSPath)
	}
	for _, fragment := range []string{`"servers":[]`, `"searchDomains":[]`} {
		if !strings.Contains(putBody, fragment) {
			t.Errorf("the PUT body does not contain %s. The read of an unconfigured region is "+
				"{\"enabled\": false} and PUTting that back is a 422 on the network path; the "+
				"legal off body carries both empty arrays (API-FINDINGS.md 1.31).\nbody: %s",
				fragment, putBody)
		}
	}
	if strings.Contains(putBody, "null") {
		t.Errorf("the PUT body contains a null: a nil slice marshals as \"servers\": null, which "+
			"is not an array and is a 400.\nbody: %s", putBody)
	}
}

/*
TestEnhancedRegionPrivateDNSUpdateGuidanceReachesTheDiagnostic pins the thing that
is invisible in review and silent at runtime.

appendErrorDiags promotes the server's response body into Detail whenever
errors.As finds a GenericOpenAPIError -- and DISCARDS whatever the caller wrapped
the error with. Errors out of putPrivateDNSAndWait are exactly that shape, so a
call site that used appendErrorDiags would compile, would produce a perfectly
reasonable-looking diagnostic, and would drop every word of guidance. That was
measured on the SWG policies and is why appendErrorDiagsWithGuidance exists
(utils.go:1252).

The two cases carry DIFFERENT guidance because they send an operator to different
places, and putPrivateDNSAndWait's `accepted` return is the only thing that
distinguishes them:

  - refused: nothing changed, and the body says why.
  - accepted then failed: the region may or may not hold the new configuration, so
    the honest advice is to go and look rather than to assume either way.

An implementation that used one summary for both, or that classified them the
wrong way round, tells an operator their region is untouched when it may not be.

The summaries are asserted to say REGION. Both resources share the two guidance
paragraphs, so a copy-paste that left "network" in the summary would pass every
other assertion here and would point an operator at the wrong endpoint in the one
line of the diagnostic they read first.
*/
func TestEnhancedRegionPrivateDNSUpdateGuidanceReachesTheDiagnostic(t *testing.T) {
	for _, tt := range []struct {
		name         string
		fake         *enhancedPrivateDNSFake
		wantSummary  string
		wantGuidance string
		wantAbsent   string
	}{
		{
			name: "the API refused the write",
			fake: &enhancedPrivateDNSFake{
				putStatus: http.StatusUnprocessableEntity,
				putBody:   measuredPrivateDNSValidationError,
			},
			wantSummary:  "Unable to update enhanced region private DNS",
			wantGuidance: privateDNSWriteRefused,
			wantAbsent:   privateDNSWriteAcceptedButNotCompleted,
		},
		{
			name: "the API accepted the write and the operation then failed",
			fake: &enhancedPrivateDNSFake{
				statusBodies: []string{
					`{"completed":true,"result":{"statusCode":409,"reason":["private DNS is being updated by another operation"]}}`,
				},
			},
			wantSummary:  "enhanced region private DNS update was accepted but did not complete",
			wantGuidance: privateDNSWriteAcceptedButNotCompleted,
			wantAbsent:   privateDNSWriteRefused,
		},
		{
			name: "the API accepted the write with nothing to poll",
			fake: &enhancedPrivateDNSFake{
				putBody: `{"samplingTime":120}`,
			},
			wantSummary:  "enhanced region private DNS update was accepted but did not complete",
			wantGuidance: privateDNSWriteAcceptedButNotCompleted,
			wantAbsent:   privateDNSWriteRefused,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			usePrivateDNSTestPollInterval(t)
			fake := startEnhancedPrivateDNSFake(t, tt.fake)

			d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
				"network_id": testRegionPDNSNetworkID,
				"region_id":  testRegionPDNSRegionID,
				"enabled":    false,
			})
			d.SetId(testRegionPDNSID)

			diags := resourceEnhancedRegionPrivateDNSUpdate(context.Background(), d, fake.client())
			if !diags.HasError() {
				t.Fatalf("the update reported success; calls were %v", fake.calls())
			}

			text := diagsText(diags)
			if !strings.Contains(text, tt.wantSummary) {
				t.Errorf("no diagnostic said %q. The summary is what distinguishes a refused "+
					"write from an accepted one that failed, and what tells the operator WHICH "+
					"endpoint it was -- the two private-DNS resources share the guidance "+
					"paragraphs.\ngot: %s", tt.wantSummary, text)
			}
			if !strings.Contains(text, tt.wantGuidance) {
				t.Errorf("the guidance never reached the diagnostic. appendErrorDiags REPLACES "+
					"Detail with the server's response body for a GenericOpenAPIError, which is "+
					"what every error on this path is -- the call site must use "+
					"appendErrorDiagsWithGuidance.\ngot: %s", text)
			}
			if strings.Contains(text, tt.wantAbsent) {
				t.Errorf("the diagnostic carries the guidance for the OTHER case, so `accepted` "+
					"is being classified backwards.\ngot: %s", text)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Delete: the one that matters
// ---------------------------------------------------------------------------

/*
TestEnhancedRegionPrivateDNSDeleteMakesNoRequest pins decision D9, and it is the
most important test in this file.

`terraform destroy` on this resource must issue ZERO requests. The tempting
implementation -- PUT {"enabled": false, ...}, "undoing" what was applied -- would
change how a live production region RESOLVES NAMES as a side effect of somebody
removing a Terraform resource, with no plan line saying so. The API has no DELETE
on this path because there is nothing to delete: private DNS is a setting on a
region, and the region is not ours.

THE ASSERTION IS ON THE WHOLE REQUEST LIST AND ON ITS LENGTH, not on the last
request and not on the absence of one particular verb. A test that asserted "no
PUT" would pass a Delete that issued a GET; one that inspected only the final call
cannot see an extra one at all. An empty list is the only assertion that fails for
every way of getting this wrong.

The warning is asserted in the same test because the two halves are one behaviour.
A destroy that silently changes nothing and a destroy that silently changes
everything print the same thing otherwise, and the diagnostic is what tells the
operator which one happened -- which is what "a no-op that explains itself" means.

BOTH IDS HAVE TO BE NAMED IN IT. "Terraform stopped managing private DNS on
network net-1" is not actionable for an operator whose network has four regions,
and a warning naming only the network is exactly what a copy of the sibling's
Delete would produce.
*/
func TestEnhancedRegionPrivateDNSDeleteMakesNoRequest(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSConfigured,
	})

	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
		"network_id": testRegionPDNSNetworkID,
		"region_id":  testRegionPDNSRegionID,
		"enabled":    true,
	})
	d.SetId(testRegionPDNSID)

	diags := resourceEnhancedRegionPrivateDNSDelete(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("the delete reported an error: %s", diagsText(diags))
	}

	if calls := fake.calls(); len(calls) != 0 {
		t.Fatalf("destroy issued %d request(s), %v, and must issue NONE (D9). This resource owns "+
			"a SETTING on a region it did not create. The only write a delete could make is "+
			"turning private DNS off, which changes how a live region resolves names because "+
			"somebody removed a Terraform resource", len(calls), calls)
	}

	if d.Id() != "" {
		t.Errorf("the id is still %q after destroy; Terraform would keep tracking a resource it "+
			"was told to release", d.Id())
	}

	var warned bool
	for _, dg := range diags {
		if dg.Severity == diag.Warning {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("destroy emitted no warning. A no-op destroy and a destructive one print the "+
			"same thing otherwise, so the operator has to be told the region was left as it "+
			"is. Diagnostics were: %s", diagsText(diags))
	}
	// Both ids, and what to do instead. A warning that says only "nothing
	// happened" leaves the operator believing private DNS is off; one that names
	// only the network leaves them guessing which region.
	for _, fragment := range []string{
		testRegionPDNSNetworkID, testRegionPDNSRegionID, "enabled = false",
	} {
		if text := diagsText(diags); !strings.Contains(text, fragment) {
			t.Errorf("the destroy warning does not mention %q.\ngot: %s", fragment, text)
		}
	}
}

// ---------------------------------------------------------------------------
// Plan-time rules
// ---------------------------------------------------------------------------

/*
TestEnhancedRegionPrivateDNSPlanEnforcesTheSharedDiffRules pins that this
resource's CustomizeDiff IS WIRED UP, which is the only thing about the diff rules
that is this resource's own.

The rules themselves live in validatePrivateDNSDiff and are already covered
against the network resource. What is NOT shared, and what nothing else can catch,
is the one line in resourceEnhancedRegionPrivateDNS that registers
resourceEnhancedRegionPrivateDNSCustomizeDiff. Omit it and this resource accepts
every configuration the API refuses -- an enabled region with no servers, a
duplicated search domain -- and the operator finds out part-way through an apply.
A grep of the source is not a substitute: planEnhancedRegionPrivateDNS runs the
SDK's real diff machinery through r.Diff, so what it exercises is the registration
and not a mention of the function name.

One row per rule rather than the network file's full matrix, deliberately: a
second copy of every case would drift from the first, and the rules have one
implementation. What this needs to show is that the wire is connected, and any
single refused configuration per rule shows that.
*/
func TestEnhancedRegionPrivateDNSPlanEnforcesTheSharedDiffRules(t *testing.T) {
	for _, tt := range []struct {
		name      string
		config    string
		wantParts []string
	}{
		{
			name:      "enabled with no servers at all",
			config:    `{"network_id":"net-1","region_id":"reg-1","enabled":true}`,
			wantParts: []string{"attributes.0.servers", "enabled"},
		},
		{
			name: "the same server address twice",
			config: `{"network_id":"net-1","region_id":"reg-1","enabled":true,"attributes":[` +
				`{"servers":[{"address":"10.0.0.53","is_tls":false},` +
				`{"address":"10.0.0.53","is_tls":true}]}]}`,
			wantParts: []string{"attributes.0.servers", "10.0.0.53"},
		},
		{
			name: "the same search domain twice",
			config: `{"network_id":"net-1","region_id":"reg-1","enabled":false,"attributes":[` +
				`{"search_domains":["b.example.com","a.example.com","b.example.com"]}]}`,
			wantParts: []string{"attributes.0.search_domains", "b.example.com"},
		},
		{
			name: "the same public domain twice",
			config: `{"network_id":"net-1","region_id":"reg-1","enabled":false,"attributes":[` +
				`{"dns_policy":[{"public":[{"domains":["x.example.com","x.example.com"]}]}]}]}`,
			wantParts: []string{"dns_policy.0.public.0.domains", "x.example.com"},
		},
		{
			name: "the same private domain twice",
			config: `{"network_id":"net-1","region_id":"reg-1","enabled":false,"attributes":[` +
				`{"dns_policy":[{"private":[{"mode":"matchPattern","public_fallback":true,` +
				`"domains":["y.example.com","y.example.com"]}]}]}]}`,
			wantParts: []string{"dns_policy.0.private.0.domains", "y.example.com"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := planEnhancedRegionPrivateDNS(t, tt.config)
			if err == nil {
				t.Fatalf("the plan SUCCEEDED for %s. Either validatePrivateDNSDiff stopped "+
					"enforcing the rule, or -- far more likely for this resource -- "+
					"resourceEnhancedRegionPrivateDNS never registered its CustomizeDiff at "+
					"all, in which case every rule is silently off and the apply fails 15 "+
					"minutes in\nconfig: %s", tt.name, tt.config)
			}
			for _, part := range tt.wantParts {
				if !strings.Contains(err.Error(), part) {
					t.Errorf("the error does not mention %q, so it does not tell the operator "+
						"what to change.\ngot: %v", part, err)
				}
			}
		})
	}
}

/*
TestEnhancedRegionPrivateDNSPlanAcceptsLegalConfigurations is what stops the test
above from being satisfied by a CustomizeDiff that refuses everything.

Each row is a configuration the spec declares legal, and each would be refused by
a plausible over-tightening:

  - the "off" body: refused by MinItems: 1 on servers, which is the obvious way to
    express the conditional minimum and would remove the only way to turn private
    DNS off.
  - four servers and four search domains: the maxItems the spec actually declares
    for those two lists (swagger.yaml:4489, :4496).
  - more than four domains in a dns_policy list: maxItems there is 100, NOT 4
    (swagger.yaml:4601, :4626). The two 4s above invite the wrong inference, and a
    MaxItems: 4 on either domains list would refuse valid configuration at plan
    time.
  - the same string in DIFFERENT lists: uniqueness is per list, and a check that
    shared one seen-set across them would refuse a domain that is legitimately
    both a search domain and a private domain.
*/
func TestEnhancedRegionPrivateDNSPlanAcceptsLegalConfigurations(t *testing.T) {
	for _, tt := range []struct {
		name   string
		config string
	}{
		{
			name:   "disabled with no attributes block",
			config: `{"network_id":"net-1","region_id":"reg-1","enabled":false}`,
		},
		{
			name: "disabled with both arrays explicitly empty",
			config: `{"network_id":"net-1","region_id":"reg-1","enabled":false,"attributes":[` +
				`{"servers":[],"search_domains":[]}]}`,
		},
		{
			name: "four servers and four search domains",
			config: `{"network_id":"net-1","region_id":"reg-1","enabled":true,"attributes":[` +
				`{"servers":[{"address":"10.0.0.1","is_tls":false},` +
				`{"address":"10.0.0.2","is_tls":true},{"address":"10.0.0.3","is_tls":false},` +
				`{"address":"10.0.0.4","is_tls":true}],"search_domains":["d.example.com",` +
				`"c.example.com","b.example.com","a.example.com"]}]}`,
		},
		{
			name: "more than four domains in each dns_policy list",
			config: `{"network_id":"net-1","region_id":"reg-1","enabled":true,"attributes":[{` +
				`"servers":[{"address":"10.0.0.53","is_tls":false}],"dns_policy":[{` +
				`"public":[{"domains":["p1.example.com","p2.example.com","p3.example.com",` +
				`"p4.example.com","p5.example.com","p6.example.com"]}],` +
				`"private":[{"mode":"resolveAllViaPrivate","public_fallback":false,` +
				`"domains":["q1.example.com","q2.example.com","q3.example.com",` +
				`"q4.example.com","q5.example.com","q6.example.com"]}]}]}]}`,
		},
		{
			name: "the same name in a different list each time",
			config: `{"network_id":"net-1","region_id":"reg-1","enabled":true,"attributes":[{` +
				`"servers":[{"address":"10.0.0.53","is_tls":false}],` +
				`"search_domains":["shared.example.com"],"dns_policy":[{` +
				`"public":[{"domains":["shared.example.com"]}],` +
				`"private":[{"mode":"matchPattern","public_fallback":true,` +
				`"domains":["shared.example.com"]}]}]}]}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := planEnhancedRegionPrivateDNS(t, tt.config); err != nil {
				t.Fatalf("a legal configuration was refused at plan time: %v\nconfig: %s",
					err, tt.config)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/*
TestParseEnhancedRegionPrivateDNSIDRejectsMalformedIds pins the parse, and the
malformed rows are the reason it is a separate test from the importer's.

The empty-half rows are the ones that matter, and they are not cosmetic:
url.PathEscape turns an empty path SEGMENT into an empty segment, so an id of
":reg-1" would send GET /v3/networks/enhanced//regions/reg-1/privateDNS. That is a
DIFFERENT ROUTE, not a 404 on this one, and whatever it answers tells the operator
nothing about the id they mistyped.

THE HYPHEN ROW IS THE POINT OF THE WHOLE FUNCTION. Test-plan row EPD-I01 writes
this id as "<network_id>-<region_id>", and a hyphen separator is not merely
inelegant: network ids CONTAIN hyphens. Splitting "net-abc:reg-def" on the first
"-" yields ("net", "abc:reg-def"), so a hyphen-separated implementation would
issue requests against a network id that never existed. The row asserts that a
hyphen-separated id is REFUSED rather than silently half-parsed.

The last row is the one that says why SplitN and not Split: a region id containing
a colon still parses, because only the FIRST colon separates. Nothing has measured
whether region ids can contain one -- the v3 document types regionId as bare
`type: string` with no pattern -- so this is the weakest claim that is still
sufficient, and it costs nothing.
*/
func TestParseEnhancedRegionPrivateDNSIDRejectsMalformedIds(t *testing.T) {
	for _, tt := range []struct {
		name         string
		id           string
		wantNetwork  string
		wantRegion   string
		wantRejected bool
	}{
		{name: "the ordinary case", id: "net-1:reg-1", wantNetwork: "net-1", wantRegion: "reg-1"},
		{
			name: "a realistic pair, both halves containing hyphens",
			id:   "net-0123abcd-89ab:reg-4567efgh-cdef",
			// Both halves survive intact. This is the assertion a hyphen separator
			// fails, and it fails it silently.
			wantNetwork: "net-0123abcd-89ab", wantRegion: "reg-4567efgh-cdef",
		},
		{
			name: "a region id containing a colon",
			id:   "net-1:reg:with:colons",
			// SplitN(n=2), so only the first colon separates.
			wantNetwork: "net-1", wantRegion: "reg:with:colons",
		},
		{name: "empty", id: "", wantRejected: true},
		{name: "no separator at all", id: "net-1", wantRejected: true},
		{
			name: "the hyphen EPD-I01 asks for, which is not the separator",
			id:   "net-1-reg-1",
			// Refused, not half-parsed. A hyphen-splitting implementation would
			// return ("net", "1-reg-1") from this and go on to use it.
			wantRejected: true,
		},
		{name: "empty network half", id: ":reg-1", wantRejected: true},
		{name: "empty region half", id: "net-1:", wantRejected: true},
		{name: "both halves empty", id: ":", wantRejected: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			networkId, regionId, err := parseEnhancedRegionPrivateDNSID(tt.id)

			if tt.wantRejected {
				if err == nil {
					t.Fatalf("%q parsed as (%q, %q) and must be refused. An id with an empty "+
						"half builds a URL with an empty path segment, which is a different "+
						"route rather than a 404 on this one", tt.id, networkId, regionId)
				}
				// The message has to show the format, or the operator has nothing
				// to correct their command line against.
				for _, fragment := range []string{tt.id, "<network_id>", "<region_id>"} {
					if !strings.Contains(err.Error(), fragment) {
						t.Errorf("the rejection does not mention %q, so it does not tell the "+
							"operator what a well-formed id looks like.\ngot: %v", fragment, err)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("%q was refused: %v", tt.id, err)
			}
			if networkId != tt.wantNetwork || regionId != tt.wantRegion {
				t.Errorf("%q parsed as (%q, %q), want (%q, %q)",
					tt.id, networkId, regionId, tt.wantNetwork, tt.wantRegion)
			}
			// The round trip: what Create writes is what this parses. They are
			// separate functions and a future edit to either could drift.
			if rebuilt := enhancedRegionPrivateDNSID(networkId, regionId); rebuilt != tt.id {
				t.Errorf("enhancedRegionPrivateDNSID(%q, %q) = %q, want the original id %q -- the "+
					"format Create writes and the format import parses have drifted apart",
					networkId, regionId, rebuilt, tt.id)
			}
		})
	}
}

/*
TestEnhancedRegionPrivateDNSImportSetsBothIdsBeforeReading pins EPD-I01 and the
one ordering mistake this importer can make.

Read builds its URL from the network_id and region_id ATTRIBUTES rather than from
d.Id(). So an importer that called Read without setting BOTH first would GET
/v3/networks/enhanced//regions//privateDNS -- two empty path segments, which is a
different route rather than a 404 on this one, and whose failure says nothing
useful. Setting one and not the other is the more likely half-error, and the path
assertion below catches either.
*/
func TestEnhancedRegionPrivateDNSImportSetsBothIdsBeforeReading(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSConfigured,
	})

	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{})
	d.SetId(testRegionPDNSID)

	imported, err := resourceEnhancedRegionPrivateDNSImportState(
		context.Background(), d, fake.client())
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("import returned %d resources, want 1", len(imported))
	}

	if got := imported[0].Get(privateDNSAttrNetworkID); got != testRegionPDNSNetworkID {
		t.Errorf("network_id = %#v after import, want %q. Read builds its URL from the "+
			"attributes, not from the resource id", got, testRegionPDNSNetworkID)
	}
	if got := imported[0].Get(privateDNSAttrRegionID); got != testRegionPDNSRegionID {
		t.Errorf("region_id = %#v after import, want %q", got, testRegionPDNSRegionID)
	}
	if got := imported[0].Id(); got != testRegionPDNSID {
		t.Errorf("the imported resource's id is %q, want the composite %q -- an import that left "+
			"a differently formatted id in state would diff against an applied one", got,
			testRegionPDNSID)
	}
	want := []string{"GET " + testRegionPDNSPath}
	if got := fake.calls(); !testComparableArraiesEq(got, want) {
		t.Errorf("import issued %v, want %v. An empty path segment is a different route, not a "+
			"404 on this one", got, want)
	}
	if got := imported[0].Get("attributes.0.servers.0.address"); got != "10.0.0.53" {
		t.Errorf("the imported resource did not pick up the configuration: "+
			"attributes.0.servers.0.address = %#v", got)
	}
}

/*
TestEnhancedRegionPrivateDNSImportRejectsAMalformedIdBeforeCallingTheAPI is why the
parse happens in the importer and not only inside Read.

The operator's mistake has to be reported as a malformed import argument, before
any request goes out, rather than as whatever the API says about a path it was
never meant to see. The zero-requests assertion is the whole test: an importer
that parsed lazily would still fail, and would fail with a 404 about a network id
of "net" -- which is not what the operator typed and is not a clue.
*/
func TestEnhancedRegionPrivateDNSImportRejectsAMalformedIdBeforeCallingTheAPI(t *testing.T) {
	for _, id := range []string{"", "net-1", "net-1-reg-1", ":reg-1", "net-1:"} {
		t.Run(id, func(t *testing.T) {
			fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
				getBody: measuredPrivateDNSConfigured,
			})

			d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{})
			d.SetId(id)

			if _, err := resourceEnhancedRegionPrivateDNSImportState(
				context.Background(), d, fake.client()); err == nil {
				t.Fatalf("importing %q reported SUCCESS", id)
			}
			if calls := fake.calls(); len(calls) != 0 {
				t.Errorf("importing %q issued %v. A malformed id must be refused BEFORE any "+
					"request: the API's answer would be about a path the operator never typed",
					id, calls)
			}
		})
	}
}

/*
TestEnhancedRegionPrivateDNSImportRejectsAnUnknownParent covers the gap between
"Read returned no error" and "import succeeded", which are not the same thing
here.

Read reports a vanished parent by CLEARING THE ID and returning no diagnostics --
deliberately, so that drift plans as a recreation. An importer that only checked
diagnostics would therefore report success for a region that does not exist and
write an empty resource into state, which the operator then has to work out for
themselves.

The message is asserted to mention harmony_sase_region_id, because the reachable
version of this mistake is not a typo. `region_id` here is the region's OWN id;
`checkpointsase_enhanced_network`'s region block is CREATED from a
harmony_sase_region_id out of the catalogue, and the two are different values. An
operator who passes the catalogue id gets this exact 404, and the diagnostic is
the only place that distinction can be pointed out to them.
*/
func TestEnhancedRegionPrivateDNSImportRejectsAnUnknownParent(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getStatus: http.StatusNotFound,
		getBody:   measuredPrivateDNSNetworkGone,
	})

	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{})
	d.SetId("net-gone:reg-gone")

	_, err := resourceEnhancedRegionPrivateDNSImportState(context.Background(), d, fake.client())
	if err == nil {
		t.Fatal("importing a region that does not exist reported SUCCESS. Read clears the id " +
			"and returns no diagnostics for a 404, so checking diagnostics alone is not enough " +
			"-- the empty id has to be checked too")
	}
	for _, fragment := range []string{"net-gone", "reg-gone", "harmony_sase_region_id"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("the failure does not mention %q. Passing the catalogue "+
				"harmony_sase_region_id instead of the region's own id produces exactly this "+
				"404, and this message is the only place that can be pointed out.\ngot: %v",
				fragment, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/*
TestEnhancedRegionPrivateDNSSchemaIsTheSharedOnePlusTwoAddresses pins the two
things about this resource's schema that are decisions rather than transcription.

 1. It IS privateDNSSchema, not a copy. expandCustomDnsUpdate reads the body
    attributes by name, and a name it reads that the schema does not declare
    returns a zero value with no error, no diff and nothing in the logs -- the
    class of defect this codebase has shipped repeatedly. The assertion is that
    every attribute the shared schema declares is present here, so a resource that
    restated the schema and drifted by one key fails.

    THE COMPARISON IS OVER FULL PATHS, NOT TOP-LEVEL KEYS, and the difference is
    the whole value of the assertion. privateDNSSchema returns exactly two
    entries -- `enabled` and `attributes` -- so a loop over its keys is satisfied
    by any resource that has an `attributes` block of ANY shape, including one
    that lost `search_domains` or misspelled `is_tls` four levels down. That was
    the first version of this test and a mutation deleting `search_domains`
    passed it green. walkSchema descends, so the sets compared below are the
    thirteen paths privateDNSSchema really declares.

 2. BOTH network_id and region_id are Required and ForceNew. Together they are the
    object's ADDRESS: this resource owns one setting on the region those two ids
    name, so pointing it elsewhere is a different object, not a change to this
    one. ForceNew is free here precisely because Delete makes no request (D9) --
    the replace destroys nothing.

The `attributes` assertion at the end is not duplicate coverage of the network
resource's. Optional+Computed is a property of the SHARED schema, so it holds here
automatically today -- and that is exactly why it is worth pinning: a future edit
that made this resource's schema its own copy would break convergence silently,
and TestEnhancedRegionPrivateDNSDisablingDoesNotDiffForever is a re-plan that
takes real work to read. This is the one-line version of the same fact.
*/
func TestEnhancedRegionPrivateDNSSchemaIsTheSharedOnePlusTwoAddresses(t *testing.T) {
	s := resourceEnhancedRegionPrivateDNS().Schema

	shared := map[string]bool{}
	walkSchema("", privateDNSSchema(), func(path string, _ *schema.Schema) {
		shared[path] = true
	})
	declared := map[string]bool{}
	walkSchema("", s, func(path string, _ *schema.Schema) {
		declared[path] = true
	})

	for path := range shared {
		if !declared[path] {
			t.Errorf("the resource does not declare %q, which privateDNSSchema does. The "+
				"expander reads it by name and would send a zero value for it, silently", path)
		}
	}
	// The other direction: this resource must add its ADDRESS and nothing else.
	// An extra body attribute here is one privateDNSSchema does not declare and
	// expandCustomDnsUpdate therefore never reads -- it would accept the
	// operator's value, plan cleanly and drop it on the floor.
	for path := range declared {
		if shared[path] || path == privateDNSAttrNetworkID || path == privateDNSAttrRegionID {
			continue
		}
		t.Errorf("the resource declares %q, which is neither in privateDNSSchema nor one of the "+
			"two address attributes. expandCustomDnsUpdate does not read it, so it would be "+
			"accepted in HCL and silently never sent", path)
	}

	for _, name := range []string{privateDNSAttrNetworkID, privateDNSAttrRegionID} {
		attr, ok := s[name]
		if !ok {
			t.Errorf("the resource declares no %q", name)
			continue
		}
		if !attr.Required {
			t.Errorf("%s must be Required: there is no default and no way to discover one", name)
		}
		if !attr.ForceNew {
			t.Errorf("%s must be ForceNew. It is half of the ADDRESS of the setting, not a "+
				"property of it -- without ForceNew, changing it would UPDATE the new region's "+
				"private DNS in place while Terraform believed it was still managing the old "+
				"one, leaving the old region's configuration untracked and unchanged", name)
		}
		if strings.TrimSpace(attr.Description) == "" {
			t.Errorf("%s has no Description; tfplugindocs renders the registry docs from it", name)
		}
	}

	attributes, ok := s[privateDNSAttrAttributes]
	if !ok {
		t.Fatalf("the resource declares no %q", privateDNSAttrAttributes)
	}
	if !attributes.Optional || !attributes.Computed {
		t.Errorf("attributes is Optional=%v Computed=%v, want both true. The API returns the "+
			"object on every read once anything has been written, so a configuration that names "+
			"no block diffs against state for ever without Computed",
			attributes.Optional, attributes.Computed)
	}
}

// ---------------------------------------------------------------------------
// The two disabled read shapes
// ---------------------------------------------------------------------------

/*
replanEnhancedRegionPrivateDNS diffs a configuration against a PRIOR STATE, which
is what `terraform plan` does on every run after the first.

planEnhancedRegionPrivateDNS above passes no prior state, so it can only show
whether a configuration is refused. It cannot see a permanent diff, because a
permanent diff is by definition a disagreement between what the server returned
and what the configuration says -- and with no prior state there is nothing for
the configuration to disagree with. That is the whole class of defect this
function exists to catch.

  - @param t *testing.T
  - @param prior *terraform.InstanceState - state as a previous apply left it
  - @param configJSON string - the unchanged configuration, re-planned

@return *terraform.InstanceDiff - what the second plan proposes; Empty() means clean
*/
func replanEnhancedRegionPrivateDNS(t *testing.T, prior *terraform.InstanceState,
	configJSON string) *terraform.InstanceDiff {

	t.Helper()

	r := resourceEnhancedRegionPrivateDNS()
	config, err := ctyjson.Unmarshal([]byte(configJSON), r.CoreConfigSchema().ImpliedType())
	if err != nil {
		t.Fatalf("the test's own configuration does not match the resource schema: %v", err)
	}
	prior.RawConfig = config

	diff, err := r.Diff(
		context.Background(),
		prior,
		terraform.NewResourceConfigShimmed(config, r.CoreConfigSchema()),
		nil,
	)
	if err != nil {
		t.Fatalf("the re-plan errored rather than producing a diff: %v", err)
	}
	return diff
}

/*
TestEnhancedRegionPrivateDNSDisablingDoesNotDiffForever is the region's copy of
the convergence check, and API-FINDINGS.md 1.31 says in as many words that this
resource needs it: "Anything else reading this endpoint needs the same correction,
including the enhanced REGION private-DNS resource".

THERE ARE TWO DISABLED READ SHAPES on the network path, and they differ in the one
key that decides whether a resource converges:

	never written to      GET -> {"enabled":false}
	                             attributes ABSENT      (p3-privatedns-enhanced.json)
	after an explicit off GET -> {"enabled":false,"attributes":{"servers":[],"searchDomains":[]}}
	                             attributes PRESENT and empty  (p8-get-after.json)

Both captures are from the NETWORK endpoint. That the region endpoint does the
same is SPEC-DERIVED -- same CustomDns response model, same optional `attributes`
-- and it is the assumption this test encodes rather than one it proves. What it
does prove is unconditional: GIVEN either body, this resource re-plans clean. If
the region endpoint turns out to have a third disabled shape, this test is where
the row for it goes.

The configuration this resource's own description recommends --

	enabled = false      (and no attributes block at all)

-- writes successfully, reads back with `attributes` present, and lands in state
holding one attributes block against a configuration holding none. That is a diff
on every plan for ever, and an apply that re-PUTs the same body every time. It is
the API-FINDINGS.md 1.15 canonicalisation trap on a different key, and the first
plan after the first apply is the only place it shows.

THE TEST DRIVES THE REAL CHAIN rather than a hand-written prior state. It runs
Read against the body, takes the state that produced, and re-plans the unchanged
configuration against it -- so it fails for a flattener defect, a schema defect,
or anything else that breaks convergence, and it cannot pass because a fixture was
written to match the code.
*/
func TestEnhancedRegionPrivateDNSDisablingDoesNotDiffForever(t *testing.T) {
	const disabledConfig = `{"network_id":"net-1","region_id":"reg-1","enabled":false}`

	for _, tt := range []struct {
		name string
		// body is what GET returns for a disabled region.
		body string
	}{
		{
			name: "attributes present and empty, as it reads after an explicit off",
			body: measuredPrivateDNSOff,
		},
		{
			name: "attributes absent, as it reads before anything is written",
			body: measuredPrivateDNSUnconfigured,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{getBody: tt.body})

			d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
				"network_id": testRegionPDNSNetworkID,
				"region_id":  testRegionPDNSRegionID,
				"enabled":    false,
			})
			d.SetId(testRegionPDNSID)

			if diags := resourceEnhancedRegionPrivateDNSRead(
				context.Background(), d, fake.client()); diags.HasError() {
				t.Fatalf("the read failed: %s", diagsText(diags))
			}

			diff := replanEnhancedRegionPrivateDNS(t, d.State(), disabledConfig)
			if diff != nil && !diff.Empty() {
				t.Fatalf("re-planning the unchanged `enabled = false` configuration proposes a "+
					"change, so this resource NEVER CONVERGES: every plan shows a diff and every "+
					"apply re-PUTs the same body. The API returns `attributes` once anything has "+
					"been written, and the configuration names none, so `attributes` has to be "+
					"Computed as well as Optional.\ndiff: %s", diff.GoString())
			}
		})
	}
}

/*
TestEnhancedRegionPrivateDNSReadStoresEveryDnsPolicyLeaf closes a hole that the
shared attribute constants CANNOT close, on this resource's own Read.

Those constants make a MISSPELLING impossible -- there is one spelling of each
name in the package, so a typo does not compile. They do nothing about an
OMISSION: a Read that never called flattenCustomDnsAttributes at all, or that
called it and dropped the result, would compile and would write nothing into
state. The network resource's copy of this test proves the FLATTENER reads every
leaf; this one proves this resource's Read carries them into state, which is a
different function and the only part of the chain that is this file's own.

THE BODY IS SPEC-DERIVED, AND MORE SO HERE THAN ANYWHERE ELSE IN THIS FILE. No
probe has ever sent or received a dnsPolicy on EITHER private-DNS path -- P8 and
P8b carried servers and searchDomains only -- so the key names come from the
DnsPolicy schema (swagger.yaml:4589: dnsPolicy.public.domains,
dnsPolicy.private.mode / publicFallback / domains) and from nothing else. What
that limits is the claim: this shows the provider reads the shape the SPEC
declares. Whether either server sends that shape is what the acceptance tests are
the first thing to find out.
*/
func TestEnhancedRegionPrivateDNSReadStoresEveryDnsPolicyLeaf(t *testing.T) {
	const specShaped = `{"enabled":true,"attributes":{` +
		`"servers":[{"address":"10.0.0.53","isTLS":true}],` +
		`"searchDomains":["corp.example.com"],` +
		`"dnsPolicy":{` +
		`"public":{"domains":["pub-b.example.com","pub-a.example.com"]},` +
		`"private":{"mode":"resolveAllViaPrivate","publicFallback":false,` +
		`"domains":["priv-b.example.com","priv-a.example.com"]}}}}`

	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{getBody: specShaped})

	d := testEnhancedRegionPrivateDNSData(t, map[string]interface{}{
		"network_id": testRegionPDNSNetworkID,
		"region_id":  testRegionPDNSRegionID,
	})
	d.SetId(testRegionPDNSID)

	if diags := resourceEnhancedRegionPrivateDNSRead(
		context.Background(), d, fake.client()); diags.HasError() {
		t.Fatalf("the read failed: %s", diagsText(diags))
	}

	for attr, want := range map[string]interface{}{
		"attributes.0.dns_policy.#":                           1,
		"attributes.0.dns_policy.0.public.#":                  1,
		"attributes.0.dns_policy.0.public.0.domains.#":        2,
		"attributes.0.dns_policy.0.public.0.domains.0":        "pub-b.example.com",
		"attributes.0.dns_policy.0.public.0.domains.1":        "pub-a.example.com",
		"attributes.0.dns_policy.0.private.#":                 1,
		"attributes.0.dns_policy.0.private.0.mode":            "resolveAllViaPrivate",
		"attributes.0.dns_policy.0.private.0.domains.#":       2,
		"attributes.0.dns_policy.0.private.0.domains.0":       "priv-b.example.com",
		"attributes.0.dns_policy.0.private.0.domains.1":       "priv-a.example.com",
		"attributes.0.dns_policy.0.private.0.public_fallback": false,
	} {
		if got := d.Get(attr); got != want {
			t.Errorf("%s = %#v, want %#v. A leaf this Read never carries into state is not a "+
				"compile error and not a diff -- it is a zero value, which for `mode` means "+
				"\"\" against a Required enum", attr, got, want)
		}
	}
}
