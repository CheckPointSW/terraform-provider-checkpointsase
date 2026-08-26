package checkpointsase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	ctyjson "github.com/hashicorp/go-cty/cty/json"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
Offline tests for checkpointsase_enhanced_network_private_dns.

Everything here runs against httptest or against the SDK's diff machinery;
nothing makes a network call or needs TF_ACC. NONE OF THESE NAMES CARRIES THE
TestAcc PREFIX, which in this codebase means "acceptance test, skips without
TF_ACC=1". Phase 4 shipped 21 offline tests wearing that prefix, which reads in
the summary as 21 skipped acceptance tests and zero offline coverage. The one
acceptance test for this resource lives in
resource_enhanced_network_private_dns_acc_test.go and genuinely is one.

The body fixtures are the ones measured on 2026-08-26 and recorded in
API-FINDINGS.md 1.28 and 1.31, not JSON authored here to fit the code.
*/

/*
The four bodies this resource's Read has to cope with, all measured 2026-08-26.

  - measuredPrivateDNSUnconfigured is a network nobody has configured:
    API-FINDINGS.md 1.31 measured EXACTLY `{"enabled": false}`, with no
    `attributes` key. This is the ordinary state, not an edge case -- it is what
    every Read before the first apply sees -- and it decodes to a nil
    *CustomDnsAttributes.
  - measuredPrivateDNSOff is the same network AFTER a write that turned private
    DNS off. Note the difference from the line above: once written, `attributes`
    is present with two empty arrays. The read shape depends on history, which is
    why both are here.
  - measuredPrivateDNSConfigured is the byte-exact round trip from the same
    finding: two servers with DIFFERENT isTLS values, and two search domains sent
    in deliberately non-alphabetical order (b before a) that came back in the
    order sent. Ordering is the contract, which is why this resource's lists are
    TypeList and not TypeSet.
  - measuredPrivateDNSNetworkGone is what a bogus networkId gets, verified by
    probe P10 on all three Phase 5 paths.
*/
const (
	measuredPrivateDNSUnconfigured = `{"enabled":false}`
	measuredPrivateDNSOff          = `{"enabled":false,"attributes":{"servers":[],"searchDomains":[]}}`
	measuredPrivateDNSConfigured   = `{"enabled":true,"attributes":{` +
		`"servers":[{"address":"10.0.0.53","isTLS":false},{"address":"10.0.1.53","isTLS":true}],` +
		`"searchDomains":["b.example.com","a.example.com"]}}`
	measuredPrivateDNSNetworkGone = `{"message":"Network doesn't exist.","messageCode":"NOT_FOUND","status":404}`

	// The 422 measured from PUTting a read body straight back (API-FINDINGS.md
	// 1.31): the read of an unconfigured network is not a legal write body.
	measuredPrivateDNSValidationError = `{"message":"VALIDATION_ERROR","messageCode":"UNPROCESSABLE_ENTITY","status":422}`
)

/*
enhancedPrivateDNSFake is one tenant's enhanced private-DNS surface: the GET this
resource reads, the PUT it writes, and the async status endpoint the PUT's 202
points at.

It records every request through requestLog, because several tests below assert
on WHERE the resource went and how many times -- and one asserts it went nowhere
at all, which only an ordered list of every call can prove.

getBodyAfterPut, when set, is what GETs return once a PUT has been seen. That
models the thing this resource exists to get right: the write is asynchronous, so
a read-back that returns pre-write values is exactly what a helper that did not
wait would store as applied.
*/
type enhancedPrivateDNSFake struct {
	log *requestLog
	srv *httptest.Server

	mu          sync.Mutex
	statusCalls int
	sawPut      bool

	// getStatus/getBody answer GET .../privateDNS. Defaults: 200 and an
	// unconfigured network.
	getStatus int
	getBody   string
	// getBodyAfterPut, if set, replaces getBody once a PUT has been received.
	getBodyAfterPut string

	// putStatus/putBody answer PUT .../privateDNS. Defaults: 202 with the
	// measured statusUrl.
	putStatus int
	putBody   string

	// statusBodies are served in order to successive status GETs; the last is
	// repeated if the provider polls more times than there are bodies.
	statusBodies []string
}

// startEnhancedPrivateDNSFake fills in the defaults and starts the server.
func startEnhancedPrivateDNSFake(t *testing.T, f *enhancedPrivateDNSFake) *enhancedPrivateDNSFake {
	t.Helper()

	f.log = &requestLog{}
	if f.getStatus == 0 {
		f.getStatus = http.StatusOK
	}
	if f.getBody == "" {
		f.getBody = measuredPrivateDNSUnconfigured
	}
	if f.putStatus == 0 {
		f.putStatus = http.StatusAccepted
	}
	if f.putBody == "" {
		f.putBody = measuredPrivateDNSAccepted
	}
	if len(f.statusBodies) == 0 {
		f.statusBodies = []string{`{"completed":true,"result":{"statusCode":200}}`}
	}

	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.log.record(r)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(r.URL.Path, privateDNSStatusPathFragment):
			f.mu.Lock()
			index := f.statusCalls
			f.statusCalls++
			f.mu.Unlock()
			if index >= len(f.statusBodies) {
				index = len(f.statusBodies) - 1
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(f.statusBodies[index]))

		case r.Method == http.MethodPut:
			f.mu.Lock()
			f.sawPut = true
			f.mu.Unlock()
			w.WriteHeader(f.putStatus)
			_, _ = w.Write([]byte(f.putBody))

		default:
			f.mu.Lock()
			body := f.getBody
			if f.sawPut && f.getBodyAfterPut != "" {
				body = f.getBodyAfterPut
			}
			f.mu.Unlock()
			w.WriteHeader(f.getStatus)
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// client points a generated SDK client at this fake. newTestUserAPIClient
// pre-seeds a bearer token, so nothing here ever exchanges an API key -- which
// keeps the request log free of plumbing and lets the zero-requests assertion in
// the Delete test mean what it says.
func (f *enhancedPrivateDNSFake) client() *perimeter81Sdk.APIClient {
	return newTestUserAPIClient(f.srv.URL)
}

// calls returns every request the fake received, as "METHOD /path", in order.
func (f *enhancedPrivateDNSFake) calls() []string {
	calls, _ := f.log.snapshot()
	return calls
}

// bodies returns every request body the fake received, positionally matching calls().
func (f *enhancedPrivateDNSFake) bodies() []string {
	_, bodies := f.log.snapshot()
	return bodies
}

// testEnhancedNetworkPrivateDNSData builds a ResourceData over the REGISTERED
// resource schema -- not a copy of it -- holding the values a CRUD function
// reads.
func testEnhancedNetworkPrivateDNSData(t *testing.T, raw map[string]interface{}) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, resourceEnhancedNetworkPrivateDNS().Schema, raw)
}

// diagsText flattens diagnostics into one searchable string.
func diagsText(diags diag.Diagnostics) string {
	var sb strings.Builder
	for _, d := range diags {
		sb.WriteString(d.Summary)
		sb.WriteString(" ")
		sb.WriteString(d.Detail)
		sb.WriteString("\n")
	}
	return sb.String()
}

/*
planEnhancedNetworkPrivateDNS runs the SDK's real diff machinery -- including
CustomizeDiff -- over a configuration, the way `terraform plan` does.

It mirrors PlanResourceChange: the same cty value becomes both the shimmed
ResourceConfig and the prior state's RawConfig, which is how the raw config
reaches a ResourceDiff in production. So it covers the WIRING
(resourceEnhancedNetworkPrivateDNSCustomizeDiff being registered on the resource
at all) as well as the rules themselves -- a validator nobody calls is the defect
this shape catches and a direct call to validatePrivateDNSDiff would not.

The configuration is written as JSON and decoded against the resource's own
ImpliedType rather than assembled as cty by hand. Two reasons: this schema is
four blocks deep, and go-cty's decoder fills every attribute a case omits with a
typed null -- so a case says only what it means to say, and the value's type still
matches the one Terraform would send exactly.

  - @param t *testing.T
  - @param configJSON string - the configuration, as JSON object keys matching HCL

@return error - what `terraform plan` would report, or nil
*/
func planEnhancedNetworkPrivateDNS(t *testing.T, configJSON string) error {
	t.Helper()

	r := resourceEnhancedNetworkPrivateDNS()
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
TestEnhancedNetworkPrivateDNSReadClearsIdWhenTheNetworkIsGone pins EPD-D01, and
it pins a branch that this codebase has three times been wrong to add elsewhere.

A 404 here clears the id and returns NO diagnostics, so the next plan proposes
recreating the configuration rather than failing. That is correct HERE and was
wrong in Phase 3/4, and the difference is what the 404 means on each endpoint:

  - Phase 3/4's were COLLECTION reads, where a 404 meant the URL was wrong.
    Treating that as drift emptied Terraform's state on a misconfiguration.
  - This is a SINGLE OBJECT addressed by a user-supplied network id, and probe
    P10 measured what a wrong one gets: 404 with
    {"message":"Network doesn't exist.","messageCode":"NOT_FOUND","status":404}.
    The message names the OBJECT, not the route.

`network_id` is a required argument, so an operator deleting the network outside
Terraform is directly reachable through HCL, and it has to plan as a recreation.

The companion assertion is in the test below: a non-404 must NOT clear the id.
Without it this test passes for an implementation that clears the id on every
error, which would turn a transient 500 into a silent state wipe.
*/
func TestEnhancedNetworkPrivateDNSReadClearsIdWhenTheNetworkIsGone(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getStatus: http.StatusNotFound,
		getBody:   measuredPrivateDNSNetworkGone,
	})

	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{
		"network_id": "net-gone",
		"enabled":    true,
	})
	d.SetId("net-gone")

	diags := resourceEnhancedNetworkPrivateDNSRead(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("a vanished network must read as DRIFT, not as a failure, or `terraform plan` "+
			"cannot propose recreating the configuration (EPD-D01). Diagnostics: %s",
			diagsText(diags))
	}
	if d.Id() != "" {
		t.Errorf("the id is still %q after a 404. Terraform would keep tracking the private DNS "+
			"of a network that no longer exists, and every later plan would fail on the same "+
			"404 instead of proposing a recreation", d.Id())
	}
}

/*
TestEnhancedNetworkPrivateDNSReadKeepsTheIdOnEveryOtherError is the other half of
the test above, and it exists so that "clear the id on 404" cannot degrade into
"clear the id whenever the read fails".

A 500 is transient. Clearing state for one would tell Terraform the configuration
is gone, and the next apply would rewrite a network's DNS on the strength of a
blip.
*/
func TestEnhancedNetworkPrivateDNSReadKeepsTheIdOnEveryOtherError(t *testing.T) {
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

			d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{
				"network_id": "net-1",
			})
			d.SetId("net-1")

			diags := resourceEnhancedNetworkPrivateDNSRead(context.Background(), d, fake.client())
			if !diags.HasError() {
				t.Fatalf("a %d must be reported, not swallowed", tt.status)
			}
			if d.Id() == "" {
				t.Errorf("the id was cleared for a %d. Only a 404 means the network is gone; "+
					"clearing state for anything else tells Terraform to recreate a "+
					"configuration that is still there, on the strength of a blip", tt.status)
			}
		})
	}
}

/*
TestEnhancedNetworkPrivateDNSReadOnUnconfiguredNetwork covers the ORDINARY state
of this endpoint, which looks like an edge case and is not.

API-FINDINGS.md 1.31 measured GET on a network nobody has configured returning
exactly {"enabled": false} -- no `attributes` key at all, decoding to a nil
*CustomDnsAttributes. That is every Read that runs before the first apply lands,
so a Read that dereferenced it would panic the provider on the normal path.

The assertion is that `attributes` lands in state as an EMPTY LIST, which is what
an unset Optional block holds -- so a configuration that writes no `attributes`
block produces no diff after this read.
*/
func TestEnhancedNetworkPrivateDNSReadOnUnconfiguredNetwork(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSUnconfigured,
	})

	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{"network_id": "net-1"})
	d.SetId("net-1")

	diags := resourceEnhancedNetworkPrivateDNSRead(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("reading an unconfigured network failed: %s", diagsText(diags))
	}

	if enabled := d.Get(privateDNSAttrEnabled).(bool); enabled {
		t.Errorf("enabled = %v, want false: the measured body says false", enabled)
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

/*
TestEnhancedNetworkPrivateDNSReadStoresTheConfigurationAsReturned is the
companion that stops the test above passing by having Read store nothing.

The body is the byte-exact round trip measured on 2026-08-26 (API-FINDINGS.md
1.31): two servers with DIFFERENT isTLS values, and two search domains sent in
deliberately non-alphabetical order that came back in the order sent. Position is
therefore the contract, and the index assertions below are what a TypeSet would
break -- which is why this resource's lists are TypeList despite the spec's
uniqueItems.
*/
func TestEnhancedNetworkPrivateDNSReadStoresTheConfigurationAsReturned(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSConfigured,
	})

	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{"network_id": "net-1"})
	d.SetId("net-1")

	diags := resourceEnhancedNetworkPrivateDNSRead(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("reading a configured network failed: %s", diagsText(diags))
	}

	for attr, want := range map[string]interface{}{
		"network_id":                     "net-1",
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

// ---------------------------------------------------------------------------
// Create and Update
// ---------------------------------------------------------------------------

/*
TestEnhancedNetworkPrivateDNSCreateAdoptsWritesWaitsAndReadsBack walks the whole
create path and asserts the ORDER of what it did, because every defect this
resource can have is visible in that order and in nothing else.

Four things are pinned at once, and each has a distinct failure:

 1. The adoption GET comes FIRST. There is no create endpoint here, so "create"
    is a PUT against a configuration that already exists; checking it is reachable
    before writing turns "this network does not exist" into an error before
    anything is changed.
 2. The id is the network id. No digest, no timestamp -- the network id is already
    unique and is already the address (L16c: a timestamp id changes on every read
    and breaks every depends_on pointing at it).
 3. The provider POLLS. The status endpoint answers completed:false twice before
    completed:true, so a Create that returned as soon as the PUT succeeded lands
    here, not in production. That is the failure putGranularFirewallPolicy's
    comment records shipping three times.
 4. It reads back AFTER the operation completes, and the read-back is what ends
    up in state. The fake serves a different body once it has seen the PUT, so a
    read that happened too early would store the pre-write values -- the exact
    symptom a non-waiting implementation produces, and one that looks like success.
*/
func TestEnhancedNetworkPrivateDNSCreateAdoptsWritesWaitsAndReadsBack(t *testing.T) {
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

	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{
		"network_id": "net-1",
		"enabled":    true,
		"attributes": []interface{}{map[string]interface{}{
			"servers": []interface{}{
				map[string]interface{}{"address": "10.0.0.53", "is_tls": false},
				map[string]interface{}{"address": "10.0.1.53", "is_tls": true},
			},
			"search_domains": []interface{}{"b.example.com", "a.example.com"},
		}},
	})

	diags := resourceEnhancedNetworkPrivateDNSCreate(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("create failed: %s", diagsText(diags))
	}

	if d.Id() != "net-1" {
		t.Errorf("id = %q, want the network id %q: the configuration is addressed entirely by "+
			"the network it belongs to, so nothing else can be its id", d.Id(), "net-1")
	}

	want := []string{
		"GET /v3/networks/enhanced/net-1/privateDNS",
		"PUT /v3/networks/enhanced/net-1/privateDNS",
		"GET /v3/networks/status/exu7TTfsPg",
		"GET /v3/networks/status/exu7TTfsPg",
		"GET /v3/networks/status/exu7TTfsPg",
		"GET /v3/networks/enhanced/net-1/privateDNS",
	}
	if got := fake.calls(); !testComparableArraiesEq(got, want) {
		t.Errorf("the create issued\n  %v\nwant\n  %v\nThe order is the assertion: adopt, write, "+
			"poll to completion, then read back. A create that returned after the PUT would show "+
			"no status GETs at all", got, want)
	}

	// The status id came from the LAST PATH SEGMENT of the measured statusUrl,
	// resolved against the configured client -- not from following the URL, which
	// is absolute, names a different host and carries an /api/rest/v2.3/ path
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
TestEnhancedNetworkPrivateDNSCreateRefusesAMissingNetworkAndWritesNothing is the
mirror image of the drift branch in Read, and the pair is the point.

A 404 during Read means an object Terraform was tracking has gone: drift. A 404
during Create means the operator named a network that does not exist: an error.
Reusing the drift branch here would let an apply "succeed" against a network id
that was never valid, storing an empty resource and reporting nothing.

The no-PUT assertion is separate from the error assertion because an
implementation that wrote first and checked afterwards would still produce an
error -- and would have issued a write against a path it had no business touching.
*/
func TestEnhancedNetworkPrivateDNSCreateRefusesAMissingNetworkAndWritesNothing(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getStatus: http.StatusNotFound,
		getBody:   measuredPrivateDNSNetworkGone,
	})

	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{
		"network_id": "net-gone",
		"enabled":    false,
	})

	diags := resourceEnhancedNetworkPrivateDNSCreate(context.Background(), d, fake.client())
	if !diags.HasError() {
		t.Fatal("creating against a network that does not exist must fail. A 404 is DRIFT in " +
			"Read and an ERROR here: nothing is being tracked yet, so there is nothing to " +
			"report as gone -- the operator simply named a network that is not there")
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
TestEnhancedNetworkPrivateDNSUpdateSendsTheFullReplacementBody pins what goes on
the wire, which no assertion about the resulting state can see.

Two things are checked and both are 400s or 422s on the live endpoint:

  - `attributes` is present even when disabling. API-FINDINGS.md 1.31 measured
    {"enabled": false} on its own as a 422 -- and that is EXACTLY the body GET
    returns for an unconfigured network, so the read cannot be echoed back as a
    write. The legal "off" body carries both empty arrays.
  - the arrays are `[]` and never `null`. Servers and SearchDomains are declared
    without omitempty, so a nil slice reaches the wire as `"servers": null`, which
    the endpoint's @IsArray refuses with a 400 that names a field the operator may
    well have set.

This is asserted on the recorded REQUEST BODY rather than on the Go value,
because nil-versus-empty is precisely the distinction a struct comparison erases.
*/
func TestEnhancedNetworkPrivateDNSUpdateSendsTheFullReplacementBody(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSOff,
	})

	// The "off" configuration, written the way an operator would: enabled = false
	// and no attributes block at all.
	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{
		"network_id": "net-1",
		"enabled":    false,
	})
	d.SetId("net-1")

	diags := resourceEnhancedNetworkPrivateDNSUpdate(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("update failed: %s", diagsText(diags))
	}

	var putBody string
	for i, call := range fake.calls() {
		if strings.HasPrefix(call, http.MethodPut) {
			putBody = fake.bodies()[i]
		}
	}
	if putBody == "" {
		t.Fatal("no PUT was issued at all")
	}
	for _, fragment := range []string{`"servers":[]`, `"searchDomains":[]`} {
		if !strings.Contains(putBody, fragment) {
			t.Errorf("the PUT body does not contain %s. The read of an unconfigured network is "+
				"{\"enabled\": false} and PUTting that back is a 422; the legal off body carries "+
				"both empty arrays (API-FINDINGS.md 1.31).\nbody: %s", fragment, putBody)
		}
	}
	if strings.Contains(putBody, "null") {
		t.Errorf("the PUT body contains a null: a nil slice marshals as \"servers\": null, which "+
			"is not an array and is a 400.\nbody: %s", putBody)
	}
}

/*
TestEnhancedNetworkPrivateDNSUpdateGuidanceReachesTheDiagnostic pins the thing
that is invisible in review and silent at runtime.

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

  - refused: nothing changed, and the body says why. The 422 below is the measured
    one from PUTting a read body back.
  - accepted then failed: the network may or may not hold the new configuration,
    so the honest advice is to go and look rather than to assume either way.

An implementation that used one summary for both, or that classified them the
wrong way round, tells an operator their network is untouched when it may not be.
*/
func TestEnhancedNetworkPrivateDNSUpdateGuidanceReachesTheDiagnostic(t *testing.T) {
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
			wantSummary:  "Unable to update enhanced network private DNS",
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
			wantSummary:  "accepted but did not complete",
			wantGuidance: privateDNSWriteAcceptedButNotCompleted,
			wantAbsent:   privateDNSWriteRefused,
		},
		{
			name: "the API accepted the write with nothing to poll",
			fake: &enhancedPrivateDNSFake{
				putBody: `{"samplingTime":120}`,
			},
			wantSummary:  "accepted but did not complete",
			wantGuidance: privateDNSWriteAcceptedButNotCompleted,
			wantAbsent:   privateDNSWriteRefused,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			usePrivateDNSTestPollInterval(t)
			fake := startEnhancedPrivateDNSFake(t, tt.fake)

			d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{
				"network_id": "net-1",
				"enabled":    false,
			})
			d.SetId("net-1")

			diags := resourceEnhancedNetworkPrivateDNSUpdate(context.Background(), d, fake.client())
			if !diags.HasError() {
				t.Fatalf("the update reported success; calls were %v", fake.calls())
			}

			text := diagsText(diags)
			if !strings.Contains(text, tt.wantSummary) {
				t.Errorf("no diagnostic said %q. The summary is what distinguishes a refused "+
					"write from an accepted one that failed, and the two need different "+
					"actions.\ngot: %s", tt.wantSummary, text)
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
TestEnhancedNetworkPrivateDNSDeleteMakesNoRequest pins decision D9, and it is the
most important test in this file.

`terraform destroy` on this resource must issue ZERO requests. The tempting
implementation -- PUT {"enabled": false, ...}, "undoing" what was applied -- would
change how a live production network RESOLVES NAMES as a side effect of somebody
removing a Terraform resource, with no plan line saying so. The API has no DELETE
on this path because there is nothing to delete: private DNS is a setting on a
network, and the network is not ours.

THE ASSERTION IS ON THE WHOLE REQUEST LIST AND ON ITS LENGTH, not on the last
request and not on the absence of one particular verb. A test that asserted "no
PUT" would pass a Delete that issued a GET; one that inspected only the final call
cannot see an extra one at all. An empty list is the only assertion that fails for
every way of getting this wrong.

The warning is asserted in the same test because the two halves are one behaviour.
A destroy that silently changes nothing and a destroy that silently changes
everything print the same thing otherwise, and the diagnostic is what tells the
operator which one happened -- which is what "a no-op that explains itself" means.
*/
func TestEnhancedNetworkPrivateDNSDeleteMakesNoRequest(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSConfigured,
	})

	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{
		"network_id": "net-1",
		"enabled":    true,
	})
	d.SetId("net-1")

	diags := resourceEnhancedNetworkPrivateDNSDelete(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("the delete reported an error: %s", diagsText(diags))
	}

	if calls := fake.calls(); len(calls) != 0 {
		t.Fatalf("destroy issued %d request(s), %v, and must issue NONE (D9). This resource owns "+
			"a SETTING on a network it did not create. The only write a delete could make is "+
			"turning private DNS off, which changes how a live network resolves names because "+
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
			"same thing otherwise, so the operator has to be told the network was left as it "+
			"is. Diagnostics were: %s", diagsText(diags))
	}
	// The network has to be NAMED, and the operator has to be told what to do
	// instead -- a warning that says only "nothing happened" leaves them
	// believing private DNS is off.
	for _, fragment := range []string{"net-1", "enabled = false"} {
		if text := diagsText(diags); !strings.Contains(text, fragment) {
			t.Errorf("the destroy warning does not mention %q.\ngot: %s", fragment, text)
		}
	}
}

// ---------------------------------------------------------------------------
// Plan-time rules
// ---------------------------------------------------------------------------

/*
TestEnhancedNetworkPrivateDNSPlanRefusesEnabledWithNoServers pins the conditional
minimum that a schema cannot express.

swagger.yaml:4492: servers "must contain at least one entry when enabled is true".
That condition is on a SIBLING attribute, and MinItems cannot see one. Setting
MinItems: 1 to approximate it would refuse the legal "off" body --
{"enabled": false, "attributes": {"servers": [], "searchDomains": []}}, measured
as a 202 in API-FINDINGS.md 1.31 -- and so would remove the only supported way to
turn private DNS off. Hence CustomizeDiff.

Both spellings of "enabled with no servers" are covered: no `attributes` block at
all, and a block whose servers list is empty. They reach the rule by different
routes and an implementation that only guarded one is easy to write.
*/
func TestEnhancedNetworkPrivateDNSPlanRefusesEnabledWithNoServers(t *testing.T) {
	for _, tt := range []struct {
		name   string
		config string
	}{
		{
			name:   "no attributes block at all",
			config: `{"network_id":"net-1","enabled":true}`,
		},
		{
			name: "attributes block with an empty servers list",
			config: `{"network_id":"net-1","enabled":true,"attributes":[` +
				`{"servers":[],"search_domains":["a.example.com"]}]}`,
		},
		{
			name: "attributes block that sets only search domains",
			config: `{"network_id":"net-1","enabled":true,"attributes":[` +
				`{"search_domains":["a.example.com"]}]}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := planEnhancedNetworkPrivateDNS(t, tt.config)
			if err == nil {
				t.Fatal("the plan succeeded. enabled = true with no servers is refused by the " +
					"API (swagger.yaml:4492), and refusing it at plan time is the difference " +
					"between a message naming the HCL attribute and a failure part-way " +
					"through an apply")
			}
			for _, fragment := range []string{"attributes.0.servers", "enabled"} {
				if !strings.Contains(err.Error(), fragment) {
					t.Errorf("the error does not mention %q, so it does not tell the operator "+
						"which attribute to change.\ngot: %v", fragment, err)
				}
			}
		})
	}
}

/*
TestEnhancedNetworkPrivateDNSPlanRefusesDuplicates pins uniqueness on all four
lists the API declares uniqueItems (swagger.yaml:4488, :4495, :4600, :4625).

THIS CANNOT BE A TypeSet, which is the obvious fix and the wrong one.
API-FINDINGS.md 1.31 measured the write round-tripping BYTE-EXACTLY with
non-alphabetical order preserved -- search domains sent b,a came back b,a -- so a
set would discard ordering the API demonstrably keeps, and `servers` is priority
ordered. helper/schema has no uniqueItems for a TypeList, so plan time is the only
place left.

Servers are compared by ADDRESS rather than by whole element, and that is a CHOICE
OF THE NARROWER RULE rather than a measured fact. The spec's uniqueItems is over
whole objects (swagger.yaml:4488), which would allow the same address twice with
different is_tls. P8 got "attributes.All servers's elements must be unique" back,
but its two rejected elements both carried isTLS: false and both used the
non-whitelisted `ip` -- so once `ip` is stripped their entire readable content was
identical, and the capture fits whole-object uniqueness just as well as it fits a
projection onto `address`. This test therefore pins the PROVIDER'S rule, not the
API's; what the API actually does is still unprobed. See validatePrivateDNSDiff,
which says the same thing in the error the operator reads.
*/
func TestEnhancedNetworkPrivateDNSPlanRefusesDuplicates(t *testing.T) {
	for _, tt := range []struct {
		name     string
		config   string
		wantPath string
		wantDupe string
	}{
		{
			name: "the same server address twice",
			config: `{"network_id":"net-1","enabled":true,"attributes":[{"servers":[` +
				`{"address":"10.0.0.53","is_tls":false},` +
				`{"address":"10.0.0.53","is_tls":true}]}]}`,
			wantPath: "attributes.0.servers",
			wantDupe: "10.0.0.53",
		},
		{
			name: "the same search domain twice",
			config: `{"network_id":"net-1","enabled":false,"attributes":[` +
				`{"search_domains":["b.example.com","a.example.com","b.example.com"]}]}`,
			wantPath: "attributes.0.search_domains",
			wantDupe: "b.example.com",
		},
		{
			name: "the same public domain twice",
			config: `{"network_id":"net-1","enabled":false,"attributes":[{"dns_policy":[` +
				`{"public":[{"domains":["x.example.com","x.example.com"]}]}]}]}`,
			wantPath: "dns_policy.0.public.0.domains",
			wantDupe: "x.example.com",
		},
		{
			name: "the same private domain twice",
			config: `{"network_id":"net-1","enabled":false,"attributes":[{"dns_policy":[` +
				`{"private":[{"mode":"matchPattern","public_fallback":true,` +
				`"domains":["y.example.com","y.example.com"]}]}]}]}`,
			wantPath: "dns_policy.0.private.0.domains",
			wantDupe: "y.example.com",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := planEnhancedNetworkPrivateDNS(t, tt.config)
			if err == nil {
				t.Fatalf("the plan succeeded with a duplicate in %s. The API declares the list "+
					"uniqueItems, and helper/schema cannot express that for a TypeList -- which "+
					"this must stay, because the write preserves the order sent", tt.wantPath)
			}
			if !strings.Contains(err.Error(), tt.wantPath) {
				t.Errorf("the error does not name %s, so the operator cannot tell which of the "+
					"four lists is wrong.\ngot: %v", tt.wantPath, err)
			}
			if !strings.Contains(err.Error(), tt.wantDupe) {
				t.Errorf("the error does not quote the duplicated value %q, which is the one "+
					"thing that makes it actionable in a list of a hundred domains.\ngot: %v",
					tt.wantDupe, err)
			}
		})
	}
}

/*
TestEnhancedNetworkPrivateDNSPlanAcceptsLegalConfigurations is what stops the two
tests above from being satisfied by a CustomizeDiff that refuses everything.

Each row is a configuration measured or documented as legal, and each would be
refused by a plausible over-tightening:

  - the "off" body: refused by MinItems: 1 on servers, which is the obvious way to
    express the conditional minimum and would remove the only way to turn private
    DNS off.
  - non-alphabetical search domains: refused by nothing, but reordered by a
    TypeSet -- included because the round trip that motivates TypeList
    (API-FINDINGS.md 1.31) must keep planning cleanly.
  - four servers and four search domains: the maxItems the spec actually declares
    for those two lists.
  - more than four domains in a dns_policy list: maxItems there is 100, NOT 4. The
    task brief's own table exists because the two 4s above invite the wrong
    inference, and a MaxItems: 4 on either domains list would refuse valid
    configuration at plan time.
  - the same string in DIFFERENT lists: uniqueness is per list, and a check that
    shared one seen-set across them would refuse a domain that is legitimately
    both a search domain and a private domain.
*/
func TestEnhancedNetworkPrivateDNSPlanAcceptsLegalConfigurations(t *testing.T) {
	for _, tt := range []struct {
		name   string
		config string
	}{
		{
			name:   "disabled with no attributes block",
			config: `{"network_id":"net-1","enabled":false}`,
		},
		{
			name: "disabled with both arrays explicitly empty",
			config: `{"network_id":"net-1","enabled":false,"attributes":[` +
				`{"servers":[],"search_domains":[]}]}`,
		},
		{
			name: "search domains in non-alphabetical order",
			config: `{"network_id":"net-1","enabled":true,"attributes":[{` +
				`"servers":[{"address":"10.0.0.53","is_tls":false}],` +
				`"search_domains":["b.example.com","a.example.com"]}]}`,
		},
		{
			name: "four servers and four search domains",
			config: `{"network_id":"net-1","enabled":true,"attributes":[{"servers":[` +
				`{"address":"10.0.0.1","is_tls":false},{"address":"10.0.0.2","is_tls":true},` +
				`{"address":"10.0.0.3","is_tls":false},{"address":"10.0.0.4","is_tls":true}],` +
				`"search_domains":["d.example.com","c.example.com","b.example.com","a.example.com"]}]}`,
		},
		{
			name: "more than four domains in each dns_policy list",
			config: `{"network_id":"net-1","enabled":true,"attributes":[{` +
				`"servers":[{"address":"10.0.0.53","is_tls":false}],"dns_policy":[{` +
				`"public":[{"domains":["p1.example.com","p2.example.com","p3.example.com",` +
				`"p4.example.com","p5.example.com","p6.example.com"]}],` +
				`"private":[{"mode":"resolveAllViaPrivate","public_fallback":false,` +
				`"domains":["q1.example.com","q2.example.com","q3.example.com",` +
				`"q4.example.com","q5.example.com","q6.example.com"]}]}]}]}`,
		},
		{
			name: "the same name in a different list each time",
			config: `{"network_id":"net-1","enabled":true,"attributes":[{` +
				`"servers":[{"address":"10.0.0.53","is_tls":false}],` +
				`"search_domains":["shared.example.com"],"dns_policy":[{` +
				`"public":[{"domains":["shared.example.com"]}],` +
				`"private":[{"mode":"matchPattern","public_fallback":true,` +
				`"domains":["shared.example.com"]}]}]}]}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := planEnhancedNetworkPrivateDNS(t, tt.config); err != nil {
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
TestEnhancedNetworkPrivateDNSImportSetsNetworkIdBeforeReading pins EPD-I01 and
the one ordering mistake this importer can make.

The import id IS the network id, and Read builds its URL from the `network_id`
ATTRIBUTE rather than from d.Id(). So an importer that called Read without
setting the attribute first would GET /v3/networks/enhanced//privateDNS -- an
empty path segment, which is a different route rather than a 404 on this one, and
whose failure says nothing useful.
*/
func TestEnhancedNetworkPrivateDNSImportSetsNetworkIdBeforeReading(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getBody: measuredPrivateDNSConfigured,
	})

	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{})
	d.SetId("net-1")

	imported, err := resourceEnhancedNetworkPrivateDNSImportState(
		context.Background(), d, fake.client())
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("import returned %d resources, want 1", len(imported))
	}

	if got := imported[0].Get(privateDNSAttrNetworkID); got != "net-1" {
		t.Errorf("network_id = %#v after import, want the import id. Read builds its URL from "+
			"the attribute, not from the resource id", got)
	}
	want := []string{"GET /v3/networks/enhanced/net-1/privateDNS"}
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
TestEnhancedNetworkPrivateDNSImportRejectsAnUnknownNetwork covers the gap between
"Read returned no error" and "import succeeded", which are not the same thing
here.

Read reports a vanished network by CLEARING THE ID and returning no diagnostics
-- deliberately, so that drift plans as a recreation. An importer that only
checked diagnostics would therefore report success for a network that does not
exist and write an empty resource into state, which the operator then has to
work out for themselves.
*/
func TestEnhancedNetworkPrivateDNSImportRejectsAnUnknownNetwork(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
		getStatus: http.StatusNotFound,
		getBody:   measuredPrivateDNSNetworkGone,
	})

	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{})
	d.SetId("net-gone")

	if _, err := resourceEnhancedNetworkPrivateDNSImportState(
		context.Background(), d, fake.client()); err == nil {
		t.Fatal("importing a network that does not exist reported SUCCESS. Read clears the id " +
			"and returns no diagnostics for a 404, so checking diagnostics alone is not enough " +
			"-- the empty id has to be checked too")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/*
TestEnhancedNetworkPrivateDNSSchemaIsTheSharedOnePlusAnAddress pins the two
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
    the first version of this test, and a mutation deleting `search_domains` from
    enhancedNetworkPrivateDNSSchema passed it green. walkSchema descends, so the
    sets compared below are the thirteen paths privateDNSSchema really declares.

    walkSchema is the package's one implementation (schema_conformance_test.go)
    and the region resource's equivalent test uses the same one. A second copy of
    this walk would be the drift it exists to catch.

 2. network_id is Required and ForceNew. It is the object's ADDRESS: this resource
    owns one setting on the network that id names, so pointing it elsewhere is a
    different object, not a change to this one. ForceNew is free here precisely
    because Delete makes no request (D9) -- the replace destroys nothing.
*/
func TestEnhancedNetworkPrivateDNSSchemaIsTheSharedOnePlusAnAddress(t *testing.T) {
	s := resourceEnhancedNetworkPrivateDNS().Schema

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
		if shared[path] || path == privateDNSAttrNetworkID {
			continue
		}
		t.Errorf("the resource declares %q, which is neither in privateDNSSchema nor the "+
			"address attribute. expandCustomDnsUpdate does not read it, so it would be "+
			"accepted in HCL and silently never sent", path)
	}

	networkId, ok := s[privateDNSAttrNetworkID]
	if !ok {
		t.Fatalf("the resource declares no %q", privateDNSAttrNetworkID)
	}
	if !networkId.Required {
		t.Error("network_id must be Required: there is no default network and no way to " +
			"discover one")
	}
	if !networkId.ForceNew {
		t.Error("network_id must be ForceNew. It is the ADDRESS of the setting, not a property " +
			"of it -- without ForceNew, changing it would UPDATE the new network's private DNS " +
			"in place while Terraform believed it was still managing the old one, leaving the " +
			"old network's configuration untracked and unchanged")
	}
	if strings.TrimSpace(networkId.Description) == "" {
		t.Error("network_id has no Description; tfplugindocs renders the registry docs from it")
	}
}

// ---------------------------------------------------------------------------
// The two disabled read shapes
// ---------------------------------------------------------------------------

/*
replanEnhancedNetworkPrivateDNS diffs a configuration against a PRIOR STATE, which
is what `terraform plan` does on every run after the first.

planEnhancedNetworkPrivateDNS above passes no prior state, so it can only show
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
func replanEnhancedNetworkPrivateDNS(t *testing.T, prior *terraform.InstanceState,
	configJSON string) *terraform.InstanceDiff {

	t.Helper()

	r := resourceEnhancedNetworkPrivateDNS()
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
TestEnhancedNetworkPrivateDNSDisablingDoesNotDiffForever pins the fact API-FINDINGS
1.31 recorded only half of: THERE ARE TWO DISABLED READ SHAPES, and they differ in
the one key that decides whether this resource converges.

Both are measured, and both are on disk in Phase 5's probe captures:

	never configured      GET -> {"enabled":false}
	                             attributes ABSENT
	after an explicit off GET -> {"enabled":false,"attributes":{"servers":[],"searchDomains":[]}}
	                             attributes PRESENT and empty

The finding says "GET on an unconfigured network returns exactly {"enabled": false}".
True, and incomplete in exactly the way that matters: once anything has been
WRITTEN, `attributes` comes back. So the configuration this resource's own
description recommends --

	enabled = false      (and no attributes block at all)

-- writes successfully, reads back with `attributes` present, and lands in state
holding one attributes block against a configuration holding none. That is a diff
on every plan for ever, and an apply that re-PUTs the same body every time. It is
the §1.15 canonicalisation trap on a different key, and the first plan after the
first apply is the only place it shows.

THE TEST DRIVES THE REAL CHAIN rather than a hand-written prior state. It runs
Read against the measured post-disable body, takes the state that produced, and
re-plans the unchanged configuration against it -- so it fails for a flattener
defect, a schema defect, or anything else that breaks convergence, and it cannot
pass because a fixture was written to match the code.

The fix is `attributes` being Optional AND Computed in privateDNSSchema: the API
always returns the object once written, so "no block" is not a state the server can
ever report, and Computed is what tells Terraform that the server's value stands
when the configuration names none.
*/
func TestEnhancedNetworkPrivateDNSDisablingDoesNotDiffForever(t *testing.T) {
	const disabledConfig = `{"network_id":"net-1","enabled":false}`

	for _, tt := range []struct {
		name string
		// body is what GET returns after the disable has been applied.
		body string
	}{
		{
			// The shape a network that has been written to comes back as.
			// probes/p8-get-after.json, 2026-08-26.
			name: "attributes present and empty, as it reads after an explicit off",
			body: measuredPrivateDNSOff,
		},
		{
			// The never-configured shape, kept as a row because a resource that
			// converged only on this one would still diff forever in practice --
			// the moment the first apply lands, the body above is what Read sees.
			name: "attributes absent, as it reads before anything is written",
			body: measuredPrivateDNSUnconfigured,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{getBody: tt.body})

			d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{
				"network_id": "net-1",
				"enabled":    false,
			})
			d.SetId("net-1")

			if diags := resourceEnhancedNetworkPrivateDNSRead(
				context.Background(), d, fake.client()); diags.HasError() {
				t.Fatalf("the read failed: %s", diagsText(diags))
			}

			diff := replanEnhancedNetworkPrivateDNS(t, d.State(), disabledConfig)
			if diff != nil && !diff.Empty() {
				t.Fatalf("re-planning the unchanged `enabled = false` configuration proposes a "+
					"change, so this resource NEVER CONVERGES: every plan shows a diff and every "+
					"apply re-PUTs the same body. The API returns `attributes` once anything has "+
					"been written (probes/p8-get-after.json), and the configuration names none, "+
					"so `attributes` has to be Computed as well as Optional.\ndiff: %s",
					diff.GoString())
			}
		})
	}
}

/*
TestEnhancedNetworkPrivateDNSReadSurvivesANullBody pins the one nil-handling gap
left on a Read whose comments are otherwise scrupulous about nil.

APIClient.decode runs json.Unmarshal into *CustomDns. A literal `null` body
decodes WITHOUT ERROR and leaves the pointer nil, so a 200 carrying `null` reaches
the d.Set block with customDns == nil. GetEnabled() is nil-safe -- the generated
getters check o == nil -- but customDns.Attributes on the next line is a DIRECT
FIELD ACCESS and panics the provider process.

A panic is the one failure mode Terraform cannot report usefully: the operator
gets a plugin crash and a stack trace instead of a diagnostic naming the resource.
That is why this is guarded rather than left as "unlikely".

UNMEASURED, AND SAID SO. No probe has seen this endpoint return `null`; the guard
is here because the cost of being wrong is a crash and the cost of the guard is
two lines. Reading it as the unconfigured shape is the right recovery, because
`{"enabled": false}` with no attributes is what an unconfigured network genuinely
returns (API-FINDINGS.md 1.31).
*/
func TestEnhancedNetworkPrivateDNSReadSurvivesANullBody(t *testing.T) {
	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{getBody: `null`})

	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{"network_id": "net-1"})
	d.SetId("net-1")

	diags := resourceEnhancedNetworkPrivateDNSRead(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("a 200 with a null body must read as the unconfigured shape, not as an "+
			"error: %s", diagsText(diags))
	}

	if d.Id() != "net-1" {
		t.Errorf("the id was cleared, so a null body was reported as DRIFT: the network is "+
			"still there, the body was just empty. id = %q", d.Id())
	}
	if enabled := d.Get(privateDNSAttrEnabled).(bool); enabled {
		t.Errorf("enabled = %v after a null body, want false", enabled)
	}
	if attributes := d.Get(privateDNSAttrAttributes).([]interface{}); len(attributes) != 0 {
		t.Errorf("attributes = %#v after a null body, want an empty list -- the same shape a "+
			"never-configured network reads as", attributes)
	}
}

/*
TestEnhancedNetworkPrivateDNSOmittingAttributesCarriesThemForward pins what the
schema description, the resource description, the example and the registry page
all now SAY, so that none of them can drift back to what they used to say.

WHAT THEY USED TO SAY, and it was wrong: that the provider "sends the empty
`servers` and `search_domains` arrays the API requires on every write", so an
operator could omit the `attributes` block to turn private DNS off with empty
lists. That was true of the first draft, when `attributes` was Optional only. The
Optional+Computed fix -- the one that stopped this resource diffing forever --
made it false from the second write onwards: a computed block that the
configuration does not name holds the LAST APPLIED value, and that is what goes
on the wire.

The two rows are the two halves of the corrected text:

  - omitting `attributes` after a configured apply sends the servers it
    inherited, NOT []. The operator is not clearing anything.
  - writing `attributes {}` explicitly IS how to send empty arrays. What makes
    that work is NOT singleBlock's empty-block branch -- mutating that branch to
    refuse an empty block leaves this row green, because the SDK materialises a
    named block with zero values rather than as []interface{}{nil}. What makes it
    work is that the NESTED leaf lists stayed Optional-only when `attributes`
    became Optional+Computed. Adding Computed to `servers` fails this row, and
    that is the mutation this row is here to catch: Computed leaking one level
    down would silently turn `attributes {}` from "empty the lists" into
    "carry them forward", with no diff and no error.

Both rows assert on the recorded PUT BODY rather than on state, because the body
is the only place the difference is visible: state shows two servers either way
in row one, and the question is what was sent.
*/
func TestEnhancedNetworkPrivateDNSOmittingAttributesCarriesThemForward(t *testing.T) {
	for _, tt := range []struct {
		name       string
		config     string
		wantInBody []string
		notInBody  []string
		why        string
	}{
		{
			name:   "no attributes block at all, after a configured apply",
			config: `{"network_id":"net-1","enabled":false}`,
			wantInBody: []string{
				`"servers":[{"address":"10.0.0.53"`,
				`"searchDomains":["b.example.com","a.example.com"]`,
			},
			why: "`attributes` is Computed, so a configuration that does not name it carries " +
				"the last-applied value forward and the PUT sends THAT. Any text promising " +
				"empty arrays here is false",
		},
		{
			name:   "an explicitly empty attributes block",
			config: `{"network_id":"net-1","enabled":false,"attributes":[{}]}`,
			wantInBody: []string{
				`"servers":[]`,
				`"searchDomains":[]`,
			},
			notInBody: []string{`10.0.0.53`, `b.example.com`},
			why: "`attributes {}` is the documented way to send empty arrays. If this stops " +
				"working, the description, the example and the registry page are all lying",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			usePrivateDNSTestPollInterval(t)

			fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{
				getBody: measuredPrivateDNSConfigured,
			})

			// The prior state is the one Read really produces from the measured
			// configured body -- not a hand-written prior, which could be written
			// to make either answer come out.
			d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{
				"network_id": "net-1",
				"enabled":    true,
			})
			d.SetId("net-1")
			if diags := resourceEnhancedNetworkPrivateDNSRead(
				context.Background(), d, fake.client()); diags.HasError() {
				t.Fatalf("the read that builds the prior state failed: %s", diagsText(diags))
			}
			prior := d.State()
			if got := prior.Attributes["attributes.0.servers.#"]; got != "2" {
				t.Fatalf("the prior state holds %q servers, want 2 -- this test is not set up",
					got)
			}

			r := resourceEnhancedNetworkPrivateDNS()
			diff := replanEnhancedNetworkPrivateDNS(t, prior, tt.config)

			if _, diags := r.Apply(
				context.Background(), prior, diff, fake.client()); diags.HasError() {
				t.Fatalf("the apply failed: %s", diagsText(diags))
			}

			var put string
			for i, call := range fake.calls() {
				if strings.HasPrefix(call, http.MethodPut+" ") {
					put = fake.bodies()[i]
				}
			}
			if put == "" {
				t.Fatalf("the apply issued no PUT; calls were %v", fake.calls())
			}

			for _, want := range tt.wantInBody {
				if !strings.Contains(put, want) {
					t.Errorf("the PUT body does not contain %s.\n%s\nbody: %s", want, tt.why, put)
				}
			}
			for _, unwanted := range tt.notInBody {
				if strings.Contains(put, unwanted) {
					t.Errorf("the PUT body still contains %s, so the block was NOT emptied.\n"+
						"%s\nbody: %s", unwanted, tt.why, put)
				}
			}
		})
	}
}

/*
TestEnhancedNetworkPrivateDNSReadStoresEveryDnsPolicyLeaf closes a hole that the
shared attribute constants CANNOT close.

Those constants make a MISSPELLING impossible -- there is one spelling of each
name in the package, so a typo does not compile. They do nothing about an
OMISSION: a flattenDnsPolicy that simply never assigned `mode` would compile, would
break no test in the suite before this one, and would write "" into a Required enum
on every Read. That is precisely the EnhancedTunnel / routingType: "" failure the
header of private_dns.go cites as the reason the file is built the way it is, and
until this test existed the dns_policy half of the flattener had NO coverage at
all: nothing passed a non-nil DnsPolicy to it, and the round-trip test never read
block["dns_policy"].

Every one of the five leaves is asserted with a DISTINCT value, so dropping any
single assignment fails here and names itself. public_fallback is deliberately
`false` while the sibling booleans in other fixtures are true: a flattener that
hardcoded true, or that dropped the field and got the zero value, must not be able
to pass by coincidence.

THE BODY'S SHAPE IS NOW MEASURED, and this comment used to say the opposite. It was
written when no Phase 5 probe had sent a dns_policy -- P8 and P8b carried servers
and searchDomains only -- so the key names came from the DnsPolicy schema
(swagger.yaml:4589) and from nothing else. API-FINDINGS.md 1.34 (2026-08-26) then
PUT a policy to this endpoint and read it back intact, with `publicFallback`
present and explicitly `false`, decoding through the real generated types.

So the KEY NAMES asserted below are measured, not merely spec-derived. The VALUES
are still this test's own -- 1.34 used matchPattern and one domain per list, this
fixture uses resolveAllViaPrivate and two -- which is deliberate: distinct values
per leaf are what make a dropped assignment name itself.
*/
func TestEnhancedNetworkPrivateDNSReadStoresEveryDnsPolicyLeaf(t *testing.T) {
	const specShaped = `{"enabled":true,"attributes":{` +
		`"servers":[{"address":"10.0.0.53","isTLS":true}],` +
		`"searchDomains":["corp.example.com"],` +
		`"dnsPolicy":{` +
		`"public":{"domains":["pub-b.example.com","pub-a.example.com"]},` +
		`"private":{"mode":"resolveAllViaPrivate","publicFallback":false,` +
		`"domains":["priv-b.example.com","priv-a.example.com"]}}}}`

	fake := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{getBody: specShaped})

	d := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{"network_id": "net-1"})
	d.SetId("net-1")

	if diags := resourceEnhancedNetworkPrivateDNSRead(
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
			t.Errorf("%s = %#v, want %#v. A leaf the flattener never assigns is not a compile "+
				"error and not a diff -- it is a zero value written into state, which for `mode` "+
				"means \"\" against a Required enum", attr, got, want)
		}
	}

	// publicFallback false has to be distinguishable from "the flattener dropped
	// it". The assertion above cannot tell those apart on its own, so this second
	// read flips the value: a flattener that hardcoded or dropped it passes one of
	// these two and fails the other.
	flipped := strings.Replace(specShaped, `"publicFallback":false`, `"publicFallback":true`, 1)
	fakeFlipped := startEnhancedPrivateDNSFake(t, &enhancedPrivateDNSFake{getBody: flipped})

	d2 := testEnhancedNetworkPrivateDNSData(t, map[string]interface{}{"network_id": "net-1"})
	d2.SetId("net-1")
	if diags := resourceEnhancedNetworkPrivateDNSRead(
		context.Background(), d2, fakeFlipped.client()); diags.HasError() {
		t.Fatalf("the second read failed: %s", diagsText(diags))
	}
	if got := d2.Get("attributes.0.dns_policy.0.private.0.public_fallback"); got != true {
		t.Errorf("public_fallback = %#v for a body that sent true, want true. Read together with "+
			"the false case above, this is what distinguishes a flattener that reads the field "+
			"from one that never assigns it", got)
	}
}
