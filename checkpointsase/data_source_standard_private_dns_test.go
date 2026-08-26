package checkpointsase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
Offline tests for checkpointsase_standard_network_private_dns and
checkpointsase_standard_region_private_dns.

Everything here runs against httptest; nothing makes a network call or needs
TF_ACC. NONE OF THESE NAMES CARRIES THE TestAcc PREFIX, which in this codebase
means "acceptance test, skips without TF_ACC=1". The acceptance coverage for
these two data sources lives in data_source_standard_network_scoped_test.go and
data_source_standard_private_dns_acc_test.go and genuinely is acceptance
coverage.

READ THE FIXTURE COMMENTS BEFORE TRUSTING A FIXTURE. Some of the bodies below
were captured from the standard family on the wire and some are derived from
swagger.yaml, and each one says which. This project has twice shipped fixtures
claiming a wire fidelity they did not have, so the split is kept narrow and
literal rather than swept in one direction: a capture proves what is IN it, and
the parts of a shape it left empty are still spec-derived afterwards.
*/

/*
The bodies these tests drive Read against.

CAPTURE-DERIVED (one of them):

  - measuredStandardPrivateDNSUnconfigured is EXACTLY what
    GET /v3/networks/standard/{networkId}/privateDNS returned on a network nobody
    had configured, measured 2026-08-26 and recorded in API-FINDINGS.md 1.31.
    Seventeen bytes, and no `attributes` key at all. This is the ordinary state
    of a standard network, not an edge case: the standard family has no write
    endpoint, so nothing a Terraform operator can do through this provider will
    ever move a network out of it.

  - measuredStandardPrivateDNSNetworkGone is what a bogus networkId gets on the
    STANDARD path, measured by probe P10 on 2026-08-26.

    IT IS NOT THE SAME BODY AS THE ENHANCED PATH'S, and the difference is why
    this constant exists instead of a reference to measuredPrivateDNSNetworkGone
    in resource_enhanced_network_private_dns_test.go. That constant's comment
    says it was "verified by probe P10 on all three Phase 5 paths"; the STATUS
    was, the BODY was not. P10 captured three different spellings:

    enhanced privateDNS   {"message":"Network doesn't exist.", ...}
    standard privateDNS   {"message":"network doesnt exists", ...}
    split-tunneling       {"message":"network doesnt exist",  ...}

    A FOURTH was measured later, and it is not a network 404 at all: the REGION
    private-DNS routes answer an unknown REGION id with
    {"message":"Region with ID <id> not found.", ...} -- naming the object and
    echoing the id (API-FINDINGS.md 1.37, 2026-08-26).

    All three are 404 with messageCode NOT_FOUND, so nothing in the provider
    behaves differently -- but a test asserting on the text would.

  - measuredStandardNetworkPrivateDNSConfigured is the standard NETWORK read of a
    network configured OUT OF BAND FROM THE CONSOLE, measured 2026-08-26 and
    recorded in API-FINDINGS.md 1.36. It exists because 1.35 established that v3
    has NO write method on this family at all, so no probe on this API could ever
    have produced it -- the console was the only route.

    This is the body that settled plan decision D3 on evidence. Decoded with the
    real generated types, `mode`, `publicFallback` and `domains` arrive in
    DnsPolicyResponseAllOfPrivate.AdditionalProperties, exactly as the allOf
    reading predicted, and `forwardDNSUpdate` -- the one field the generated
    struct DOES declare -- was not returned at all.

  - measuredStandardRegionPrivateDNSUntouched is the THIRD DISABLED READ SHAPE
    (API-FINDINGS.md 1.36), captured from the same run. Nobody configured this
    region; only its network was touched. It comes back `enabled: false` with
    `attributes` PRESENT and a fully populated `dnsPolicy` carrying DIFFERENT
    defaults from the network's -- resolveAllViaPrivate and publicFallback true,
    against the network's matchPattern and false.

SPEC-DERIVED (everything else), and BE PRECISE ABOUT WHAT THAT NOW MEANS. The two
captures above are narrow. Between them they cover: one server with isTLS FALSE;
EMPTY searchDomains; EMPTY public.domains; both `mode` enum values; both
`publicFallback` values; and a private `domains` list of one element and of zero.
They do NOT cover, and these therefore remain spec-derived on this family:

  - more than one server, `isTLS: true`, or server ORDER;

  - a non-empty searchDomains list or its order;

  - a non-empty public.domains list or its order;

  - more than one private domain, or their order;

  - `forwardDNSUpdate` in ANY form -- neither capture returned it, so every
    assertion about `forward_dns_update` in this file is about the SPEC;

  - a 404 from the standard REGION path. P10's 404 is the standard NETWORK path;
    a bogus region id has still never been sent to anything.

  - specStandardPrivateDNSConfigured is therefore still a SPEC-DERIVED body, and
    is kept rather than replaced by the capture: it is the only fixture here that
    exercises two servers with different isTLS, non-alphabetical searchDomains and
    a populated public.domains, which is exactly the ordering contract the
    TypeList decision rests on. Its values come from the ENHANCED captures
    (API-FINDINGS.md 1.31, 1.34) so they are realistic; the SHAPE is
    swagger.yaml:4419/:4409/:4632.
*/
const (
	measuredStandardPrivateDNSUnconfigured = `{"enabled":false}`
	measuredStandardPrivateDNSNetworkGone  = `{"message":"network doesnt exists",` +
		`"messageCode":"NOT_FOUND","status":404}`

	// Verbatim from the 1.36 captures, key order included.
	measuredStandardNetworkPrivateDNSConfigured = `{"enabled":true,"attributes":{` +
		`"servers":[{"address":"13.227.192.28","isTLS":false}],"searchDomains":[],` +
		`"dnsPolicy":{"public":{"domains":[]},` +
		`"private":{"mode":"matchPattern","publicFallback":false,` +
		`"domains":["checkpoint.com"]}}}}`
	measuredStandardRegionPrivateDNSUntouched = `{"enabled":false,"attributes":{` +
		`"dnsPolicy":{"public":{"domains":[]},` +
		`"private":{"mode":"resolveAllViaPrivate","publicFallback":true,"domains":[]}},` +
		`"servers":[],"searchDomains":[]}}`

	specStandardPrivateDNSConfigured = `{"enabled":true,"attributes":{` +
		`"servers":[{"address":"10.0.0.53","isTLS":false},{"address":"10.0.1.53","isTLS":true}],` +
		`"searchDomains":["b.example.com","a.example.com"],` +
		`"dnsPolicy":{` +
		`"public":{"domains":["pub-b.example.com","pub-a.example.com"]},` +
		`"private":{"mode":"matchPattern","publicFallback":false,` +
		`"domains":["priv.example.com"],"forwardDNSUpdate":true}}}}`
)

/*
standardPrivateDNSFake is the one GET each data source makes, and nothing else.

It records every request path so a test can assert WHICH endpoint the data source
went to -- the region variant calling the network path would otherwise return a
plausible body and pass every content assertion.
*/
type standardPrivateDNSFake struct {
	log *requestLog
	srv *httptest.Server

	status int
	body   string
}

func startStandardPrivateDNSFake(t *testing.T, status int, body string) *standardPrivateDNSFake {
	t.Helper()

	f := &standardPrivateDNSFake{log: &requestLog{}, status: status, body: body}
	if f.status == 0 {
		f.status = http.StatusOK
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.log.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *standardPrivateDNSFake) client() *perimeter81Sdk.APIClient {
	return newTestUserAPIClient(f.srv.URL)
}

func (f *standardPrivateDNSFake) calls() []string {
	calls, _ := f.log.snapshot()
	return calls
}

// standardNetworkPrivateDNSData and standardRegionPrivateDNSData build a
// ResourceData over the REGISTERED data-source schema, not a copy of it.
func standardNetworkPrivateDNSData(t *testing.T, networkId string) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, dataSourceStandardNetworkPrivateDNS().Schema,
		map[string]interface{}{privateDNSAttrNetworkID: networkId})
}

func standardRegionPrivateDNSData(t *testing.T, networkId, regionId string) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, dataSourceStandardRegionPrivateDNS().Schema,
		map[string]interface{}{
			privateDNSAttrNetworkID: networkId,
			privateDNSAttrRegionID:  regionId,
		})
}

/*
TestStandardPrivateDNSReadOnUnconfiguredNetwork is the CAPTURE-DERIVED test:
the only standard private-DNS body anything has ever measured.

API-FINDINGS.md 1.31, measured 2026-08-26: a standard network nobody has
configured reads back as exactly {"enabled": false}, with no `attributes` key,
which decodes to a nil *CustomDnsAttributesResponse. `attributes.#` must
therefore be 0 -- not one element holding empty lists, which is the OTHER
disabled shape and means something different (that object has been written to).

It also pins that a successful read sets an id at all. A data source with no id
is treated by Terraform as not-yet-read.
*/
func TestStandardPrivateDNSReadOnUnconfiguredNetwork(t *testing.T) {
	f := startStandardPrivateDNSFake(t, http.StatusOK, measuredStandardPrivateDNSUnconfigured)

	d := standardNetworkPrivateDNSData(t, "net-1")
	if diags := dataSourceStandardNetworkPrivateDNSRead(
		context.Background(), d, f.client()); diags.HasError() {
		t.Fatalf("read of an unconfigured network failed: %s", diagsText(diags))
	}

	if enabled := d.Get(privateDNSAttrEnabled).(bool); enabled {
		t.Errorf("enabled = true, want false: the measured body is %s",
			measuredStandardPrivateDNSUnconfigured)
	}
	attributes := d.Get(privateDNSAttrAttributes).([]interface{})
	if len(attributes) != 0 {
		t.Errorf("attributes.# = %d, want 0. The measured body carries NO `attributes` key, and "+
			"synthesising an empty block for it would report the other disabled shape -- the one "+
			"that means somebody has written to this object (API-FINDINGS.md 1.31)",
			len(attributes))
	}
	if d.Id() == "" {
		t.Error("a successful read left the id empty; Terraform reads that as 'not read yet'")
	}
}

/*
TestStandardNetworkPrivateDNSReadStoresTheMeasuredConfiguredBody is the
CAPTURE-DERIVED half of the D3 coverage, and it is the test that turns
flattenDnsPolicyResponsePrivate from a well-argued guess into a measured one.

The body is API-FINDINGS.md 1.36's standard NETWORK read, from a network
configured out of band in the console -- the only route that exists, because 1.35
established v3 has no write method on this family.

WHAT IT PROVES THAT THE SPEC-DERIVED TEST CANNOT: that `mode`, `publicFallback`
and `domains` really do arrive in AdditionalProperties on the standard family,
rather than merely following from reading `allOf` as a merge. Both tests assert
the same three attributes; only this one is evidence about the server.

WHAT IT DELIBERATELY DOES NOT ASSERT. forward_dns_update is absent from the
assertions below because the server DID NOT RETURN forwardDNSUpdate -- the one
field the generated struct declares is the one field the wire omitted. Asserting
`false` here would look like coverage and would in fact be asserting the zero
value of a field nothing has ever sent. The spec-derived tests carry that
attribute, labelled as spec-derived.

search_domains and public.domains are asserted as EMPTY, which is what the
capture holds. That is not the ordering contract -- an empty list cannot show
order. The ordering assertions live in the spec-derived test, on the enhanced
family's measured non-alphabetical shape.
*/
func TestStandardNetworkPrivateDNSReadStoresTheMeasuredConfiguredBody(t *testing.T) {
	f := startStandardPrivateDNSFake(t, http.StatusOK,
		measuredStandardNetworkPrivateDNSConfigured)

	d := standardNetworkPrivateDNSData(t, "net-1")
	if diags := dataSourceStandardNetworkPrivateDNSRead(
		context.Background(), d, f.client()); diags.HasError() {
		t.Fatalf("the MEASURED standard network body failed to read: %s", diagsText(diags))
	}

	for _, want := range []struct {
		path string
		val  interface{}
	}{
		{"enabled", true},
		{"attributes.#", 1},
		{"attributes.0.servers.#", 1},
		{"attributes.0.servers.0.address", "13.227.192.28"},
		{"attributes.0.servers.0.is_tls", false},
		{"attributes.0.search_domains.#", 0},

		{"attributes.0.dns_policy.#", 1},
		{"attributes.0.dns_policy.0.public.#", 1},
		{"attributes.0.dns_policy.0.public.0.domains.#", 0},

		// The three D3 fields, now MEASURED rather than reasoned.
		{"attributes.0.dns_policy.0.private.#", 1},
		{"attributes.0.dns_policy.0.private.0.mode", "matchPattern"},
		{"attributes.0.dns_policy.0.private.0.public_fallback", false},
		{"attributes.0.dns_policy.0.private.0.domains.#", 1},
		{"attributes.0.dns_policy.0.private.0.domains.0", "checkpoint.com"},
	} {
		assertStandardPrivateDNSAttr(t, d, want.path, want.val)
	}
}

/*
TestStandardRegionPrivateDNSReadStoresTheThirdDisabledShape covers the shape
NOBODY PREDICTED, measured 2026-08-26 and recorded as API-FINDINGS.md 1.36.

There are now THREE disabled read shapes, not the two 1.31 recorded:

	never configured (enhanced)    {"enabled":false}
	                               attributes ABSENT, dnsPolicy ABSENT
	after an explicit disable      {"enabled":false,"attributes":{"servers":[],
	  (enhanced)                    "searchDomains":[]}}
	                               attributes PRESENT and empty, dnsPolicy ABSENT
	standard region, NEVER TOUCHED {"enabled":false,"attributes":{"dnsPolicy":{...}
	                                ,"servers":[],"searchDomains":[]}}
	                               attributes PRESENT, dnsPolicy PRESENT AND
	                               POPULATED

The third one is the surprise, and it is the reason this test exists as its own
function rather than as a row in a table. Nobody configured this region -- only
its network was touched -- and it still returns a complete dns_policy carrying
DIFFERENT defaults from its own network's: resolveAllViaPrivate against
matchPattern, publicFallback true against false. So the server holds per-region
defaults that no operator set and that do not match the parent.

WHAT THIS MUST NOT BREAK ON, and what the assertions are chosen to catch:

  - a reader that treats `enabled: false` as "nothing to flatten" and skips
    `attributes` or `dns_policy`. That is the natural, wrong simplification here,
    and it is what mutation M15 is;
  - a reader that treats an empty `domains` list as "no private block" and drops
    the whole sub-object. Both `domains` lists in this body are empty and the
    block is still real -- mutation M16;
  - public_fallback read as its zero value. It is TRUE here, so this is the
    capture-derived twin of the spec-derived boolean test: a reader that never
    looked at the field would store false and fail this row.

THE USER-VISIBLE CONSEQUENCE is on checkpointsase_standard_region_private_dns's
own page, in its top-level Description, and belongs there rather than only here:
the data source WILL surface a dns_policy block for a region nobody has
configured. That is what the server holds, not evidence that somebody configured
it, and a reader will assume the latter unless told.
*/
func TestStandardRegionPrivateDNSReadStoresTheThirdDisabledShape(t *testing.T) {
	f := startStandardPrivateDNSFake(t, http.StatusOK,
		measuredStandardRegionPrivateDNSUntouched)

	d := standardRegionPrivateDNSData(t, "net-1", "reg-1")
	if diags := dataSourceStandardRegionPrivateDNSRead(
		context.Background(), d, f.client()); diags.HasError() {
		t.Fatalf("the MEASURED standard region body failed to read: %s", diagsText(diags))
	}

	for _, want := range []struct {
		path string
		val  interface{}
	}{
		{"enabled", false},
		// PRESENT despite enabled being false. This is the whole finding.
		{"attributes.#", 1},
		{"attributes.0.servers.#", 0},
		{"attributes.0.search_domains.#", 0},

		// And a fully populated policy on an object nobody configured.
		{"attributes.0.dns_policy.#", 1},
		{"attributes.0.dns_policy.0.public.#", 1},
		{"attributes.0.dns_policy.0.public.0.domains.#", 0},
		{"attributes.0.dns_policy.0.private.#", 1},
		// The OTHER enum value, and the OTHER boolean, from the network capture.
		{"attributes.0.dns_policy.0.private.0.mode", "resolveAllViaPrivate"},
		{"attributes.0.dns_policy.0.private.0.public_fallback", true},
		{"attributes.0.dns_policy.0.private.0.domains.#", 0},
	} {
		assertStandardPrivateDNSAttr(t, d, want.path, want.val)
	}
}

/*
TestStandardPrivateDNSReadStoresTheSpecShape is SPEC-DERIVED, and the fixture's
comment says why: no standard endpoint has ever been observed returning a
populated body.

What it is really here to catch is plan decision D3. Three of the four fields
under `dns_policy.private` are ABSENT from the generated struct and arrive in
AdditionalProperties, so a typed flattener reports them empty with no error
anywhere -- the API-FINDINGS.md 2.1 failure, on a new endpoint. mode,
public_fallback and domains are asserted individually for that reason.

THE public_fallback ROW HERE CANNOT FAIL, AND SAYING SO IS THE POINT. The fixture
carries `publicFallback: false` -- deliberately, because that is the shape
API-FINDINGS.md 1.34 singles out -- and false is also what a flattener that never
read the field at all would store. Mutation M1 (dropping all three
AdditionalProperties reads) failed this test on `mode` and on `domains` and was
SILENT on `public_fallback`. The row is kept because it documents the expected
value, and the discriminating coverage for both booleans lives in
TestStandardPrivateDNSReadsEachPrivatePolicyBooleanFromItsOwnSource below. Do not
read this row as evidence.

Both variants run the same body, so the region data source cannot pass by
accident on a flattener only the network one calls.
*/
func TestStandardPrivateDNSReadStoresTheSpecShape(t *testing.T) {
	for _, tc := range []struct {
		name string
		read func(*testing.T, *perimeter81Sdk.APIClient) *schema.ResourceData
	}{
		{
			name: "network",
			read: func(t *testing.T, c *perimeter81Sdk.APIClient) *schema.ResourceData {
				d := standardNetworkPrivateDNSData(t, "net-1")
				if diags := dataSourceStandardNetworkPrivateDNSRead(
					context.Background(), d, c); diags.HasError() {
					t.Fatalf("read failed: %s", diagsText(diags))
				}
				return d
			},
		},
		{
			name: "region",
			read: func(t *testing.T, c *perimeter81Sdk.APIClient) *schema.ResourceData {
				d := standardRegionPrivateDNSData(t, "net-1", "reg-1")
				if diags := dataSourceStandardRegionPrivateDNSRead(
					context.Background(), d, c); diags.HasError() {
					t.Fatalf("read failed: %s", diagsText(diags))
				}
				return d
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := startStandardPrivateDNSFake(t, http.StatusOK, specStandardPrivateDNSConfigured)
			d := tc.read(t, f.client())

			if !d.Get(privateDNSAttrEnabled).(bool) {
				t.Error("enabled = false, want true")
			}

			for _, want := range []struct {
				path string
				val  interface{}
			}{
				{"attributes.#", 1},
				{"attributes.0.servers.#", 2},
				{"attributes.0.servers.0.address", "10.0.0.53"},
				{"attributes.0.servers.0.is_tls", false},
				{"attributes.0.servers.1.address", "10.0.1.53"},
				// is_tls true on the SECOND entry only: a flattener that dropped
				// the field would still agree with the first.
				{"attributes.0.servers.1.is_tls", true},
				// Non-alphabetical and asserted BY INDEX. This is what a TypeSet
				// would break, and the reason these are TypeList.
				{"attributes.0.search_domains.#", 2},
				{"attributes.0.search_domains.0", "b.example.com"},
				{"attributes.0.search_domains.1", "a.example.com"},

				{"attributes.0.dns_policy.#", 1},
				{"attributes.0.dns_policy.0.public.#", 1},
				{"attributes.0.dns_policy.0.public.0.domains.#", 2},
				{"attributes.0.dns_policy.0.public.0.domains.0", "pub-b.example.com"},
				{"attributes.0.dns_policy.0.public.0.domains.1", "pub-a.example.com"},

				{"attributes.0.dns_policy.0.private.#", 1},
				// TYPED on the generated struct.
				{"attributes.0.dns_policy.0.private.0.forward_dns_update", true},
				// The three D3 fields, read out of AdditionalProperties.
				{"attributes.0.dns_policy.0.private.0.mode", "matchPattern"},
				{"attributes.0.dns_policy.0.private.0.public_fallback", false},
				{"attributes.0.dns_policy.0.private.0.domains.#", 1},
				{"attributes.0.dns_policy.0.private.0.domains.0", "priv.example.com"},
			} {
				assertStandardPrivateDNSAttr(t, d, want.path, want.val)
			}
		})
	}
}

/*
TestStandardPrivateDNSReadsEachPrivatePolicyBooleanFromItsOwnSource is the
discriminating coverage for the two booleans under `dns_policy.private`, and it
exists because the test above cannot provide it.

The two are read from DIFFERENT places and that is the whole difficulty:
`forwardDNSUpdate` is a typed field on DnsPolicyResponseAllOfPrivate, while
`publicFallback` is absent from the generated struct and comes out of
AdditionalProperties (plan decision D3). A single body cannot distinguish
"dropped", "hardcoded" and "swapped" for a pair of booleans, so this runs the two
opposite bodies. Between them:

  - a reader that DROPS either field stores false where the body says true;
  - a reader that HARDCODES either stores the same value in both rows;
  - a reader that SWAPS the two sources agrees with neither row.

The second row is also the API-FINDINGS.md 1.34 shape -- `publicFallback`
explicitly false on the wire -- carried here rather than left only in the decode
test, so that "the server sent false" and "nothing read the field" are told apart
somewhere.

WHAT IS MEASURED AND WHAT IS NOT, now that 1.36 exists. BOTH `publicFallback`
values are measured on the standard family: false in the network capture, true in
the region capture, and the two capture-derived tests above assert them.
`forwardDNSUpdate` is NOT measured in any form -- neither capture returned the
key at all -- so the forward_dns_update half of every row here is SPEC-DERIVED.
This test is kept for the pairing it does that no capture does: no single
captured body carries both fields, so nothing but a constructed body can tell a
SWAP of the two sources from a correct read.
*/
func TestStandardPrivateDNSReadsEachPrivatePolicyBooleanFromItsOwnSource(t *testing.T) {
	for _, tc := range []struct {
		name               string
		body               string
		wantPublicFallback bool
		wantForwardUpdate  bool
	}{
		{
			name: "publicFallback true, forwardDNSUpdate false",
			body: `{"enabled":true,"attributes":{"servers":[],"searchDomains":[],` +
				`"dnsPolicy":{"private":{"mode":"resolveAllViaPrivate","publicFallback":true,` +
				`"domains":["a.example.com"],"forwardDNSUpdate":false}}}}`,
			wantPublicFallback: true,
			wantForwardUpdate:  false,
		},
		{
			name: "publicFallback explicitly false, forwardDNSUpdate true",
			body: `{"enabled":true,"attributes":{"servers":[],"searchDomains":[],` +
				`"dnsPolicy":{"private":{"mode":"matchPattern","publicFallback":false,` +
				`"domains":["a.example.com"],"forwardDNSUpdate":true}}}}`,
			wantPublicFallback: false,
			wantForwardUpdate:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := startStandardPrivateDNSFake(t, http.StatusOK, tc.body)
			d := standardNetworkPrivateDNSData(t, "net-1")
			if diags := dataSourceStandardNetworkPrivateDNSRead(
				context.Background(), d, f.client()); diags.HasError() {
				t.Fatalf("read failed: %s", diagsText(diags))
			}

			assertStandardPrivateDNSAttr(t, d,
				"attributes.0.dns_policy.0.private.0.public_fallback", tc.wantPublicFallback)
			assertStandardPrivateDNSAttr(t, d,
				"attributes.0.dns_policy.0.private.0.forward_dns_update", tc.wantForwardUpdate)
		})
	}
}

/*
assertStandardPrivateDNSAttr compares one flat state path against an expected
value, reporting the path so a failure names the attribute rather than an index.

It goes through d.Get, which returns the SCHEMA's Go type -- so a bool attribute
compares against a bool and a count against an int, and the `want` column above
has to be written in that type rather than as a string.

That is what makes a WRONG PATH visible. Observed while writing this file: a path
missing one index, `dns_policy.0.private.forward_dns_update` instead of
`dns_policy.0.private.0.forward_dns_update`, does not return nil -- d.Get answered
map[string]interface{}{}, which any string-formatting comparison would have
rendered as a plausible-looking miss and a %v comparison against "true" would
simply have reported as a value mismatch. Comparing typed values reported it as
a map where a bool was expected, which named the real defect.
*/
func assertStandardPrivateDNSAttr(t *testing.T, d *schema.ResourceData,
	path string, want interface{}) {

	t.Helper()
	got := d.Get(path)
	if got != want {
		t.Errorf("%s = %#v, want %#v", path, got, want)
	}
}

/*
TestStandardPrivateDNSReadSurfacesA404AsAnError covers SPD-N01 and SPD-N02.

A 404 MUST FAIL THE READ. That is the opposite of what the two enhanced
private-DNS RESOURCES do with the same status, and deliberately: a resource can
clear its id and let the next plan propose a recreation, whereas a data source
has no id to clear and nothing to recreate. Clearing here would set an empty
result that every downstream reference would silently consume.

The assertion is on the diagnostic containing "404" (what the test-plan rows ask
for) and on the id being EMPTY. The second half is the one that catches a read
that reported the error and set an id anyway -- state would then hold an identity
against values that were never fetched.
*/
func TestStandardPrivateDNSReadSurfacesA404AsAnError(t *testing.T) {
	for _, tc := range []struct {
		name string
		read func(*testing.T, *perimeter81Sdk.APIClient) (*schema.ResourceData, string)
	}{
		{
			name: "network",
			read: func(t *testing.T, c *perimeter81Sdk.APIClient) (*schema.ResourceData, string) {
				d := standardNetworkPrivateDNSData(t, "no-such-network")
				diags := dataSourceStandardNetworkPrivateDNSRead(context.Background(), d, c)
				return d, diagsText(diags)
			},
		},
		{
			name: "region",
			read: func(t *testing.T, c *perimeter81Sdk.APIClient) (*schema.ResourceData, string) {
				d := standardRegionPrivateDNSData(t, "no-such-network", "no-such-region")
				diags := dataSourceStandardRegionPrivateDNSRead(context.Background(), d, c)
				return d, diagsText(diags)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := startStandardPrivateDNSFake(t, http.StatusNotFound,
				measuredStandardPrivateDNSNetworkGone)

			d, text := tc.read(t, f.client())

			if strings.TrimSpace(text) == "" {
				t.Fatal("a 404 produced NO diagnostic. A data source that swallows a not-found " +
					"returns an empty result, and every reference to it then reads the zero " +
					"value with nothing reported anywhere")
			}
			if !strings.Contains(text, "404") {
				t.Errorf("the diagnostic does not mention 404, which is what SPD-N01/SPD-N02 "+
					"ask an operator to be told:\n%s", text)
			}
			if d.Id() != "" {
				t.Errorf("the read failed and still set the id to %q; state would hold an "+
					"identity for values that were never fetched", d.Id())
			}
		})
	}
}

/*
TestStandardPrivateDNSReadsThePathItsNameClaims pins each data source to its own
endpoint.

Without it the region variant could call the NETWORK endpoint and pass every
content assertion in this file, because the two return the same model and the
fake answers any path. The region path is a superset of the network path as a
string, so both halves of the assertion are needed: the network read must NOT
contain "/regions/".
*/
func TestStandardPrivateDNSReadsThePathItsNameClaims(t *testing.T) {
	t.Run("network", func(t *testing.T) {
		f := startStandardPrivateDNSFake(t, http.StatusOK, measuredStandardPrivateDNSUnconfigured)
		d := standardNetworkPrivateDNSData(t, "net-1")
		if diags := dataSourceStandardNetworkPrivateDNSRead(
			context.Background(), d, f.client()); diags.HasError() {
			t.Fatalf("read failed: %s", diagsText(diags))
		}
		want := []string{"GET /v3/networks/standard/net-1/privateDNS"}
		if got := f.calls(); len(got) != 1 || got[0] != want[0] {
			t.Errorf("requests = %v, want %v", got, want)
		}
	})

	t.Run("region", func(t *testing.T) {
		f := startStandardPrivateDNSFake(t, http.StatusOK, measuredStandardPrivateDNSUnconfigured)
		d := standardRegionPrivateDNSData(t, "net-1", "reg-1")
		if diags := dataSourceStandardRegionPrivateDNSRead(
			context.Background(), d, f.client()); diags.HasError() {
			t.Fatalf("read failed: %s", diagsText(diags))
		}
		want := []string{"GET /v3/networks/standard/net-1/regions/reg-1/privateDNS"}
		if got := f.calls(); len(got) != 1 || got[0] != want[0] {
			t.Errorf("requests = %v, want %v", got, want)
		}
	})
}

/*
TestStandardPrivateDNSIdsAreDerivedFromTheArguments is the guard against the
defect this project has already shipped once: a data source that takes arguments
and hardcodes a constant id, so two instances holding different results share one
Terraform identity.

Four properties, and the third is the one a naive join fails:

 1. different network ids give different ids;

 2. the same arguments give the same id twice, in this process and the next --
    an id that moved would defeat every downstream reference (L16c).

    DO NOT READ THIS ROW AS EVIDENCE. standardNetworkPrivateDNSID is a pure
    function of its one argument, so it cannot fail; and against the
    time.Now().Unix() form it names -- the defect the older network-scoped data
    sources actually ship (L16c) -- it cannot fail either, because two calls one
    line apart land in the same second. MEASURED 2026-08-26 by mutating the
    function to strconv.FormatInt(time.Now().Unix(), 10): rows 1 and 4 both
    failed (two different networks shared the id 1787736062, and the id did not
    carry a readable base) and this row was silent. It is kept because it
    documents the property, the same way the public_fallback row above is;

 3. two DIFFERENT (network, region) pairs whose halves CONCATENATE to the same
    string still give different ids. That is what the region variant must pass
    its two arguments to dataSourceArgumentDigest SEPARATELY for; a function that
    joined them first and hashed one string would collide. Each row below is the
    collision for one plausible join -- no separator, then the four punctuation
    characters somebody might reach for. Neither networkId nor regionId has a
    declared pattern in the v3 document (openapi.yaml:1136 types both as bare
    `type: string`), so none of these characters can be assumed absent.

    THIS TEST DOES NOT RE-PROVE dataSourceArgumentDigest's own unambiguity.
    That is TestDataSourceArgumentDigestIsUnambiguous's job. What is asserted
    here is narrower and is this function's: that the parts reach the digest as
    parts.

 4. the two data sources' ids never collide, because they carry different bases.
*/
func TestStandardPrivateDNSIdsAreDerivedFromTheArguments(t *testing.T) {
	if a, b := standardNetworkPrivateDNSID("net-1"), standardNetworkPrivateDNSID("net-2"); a == b {
		t.Errorf("two different networks share the id %q; the id must derive from the "+
			"arguments, or two instances holding different results have one identity", a)
	}
	if a, b := standardNetworkPrivateDNSID("net-1"), standardNetworkPrivateDNSID("net-1"); a != b {
		t.Errorf("the same network gave two ids, %q and %q; an id that moves between reads "+
			"defeats every downstream reference", a, b)
	}

	for _, sep := range []string{"", ":", "-", "/", ","} {
		// ("a", "b"+sep+"c") and ("a"+sep+"b", "c") are different pairs whose
		// halves both join to "a"+sep+"b"+sep+"c". For sep == "" that is ("a",
		// "bc") against ("ab", "c") joining to "abc".
		leftNetwork, leftRegion := "a", "b"+sep+"c"
		rightNetwork, rightRegion := "a"+sep+"b", "c"
		left := standardRegionPrivateDNSID(leftNetwork, leftRegion)
		right := standardRegionPrivateDNSID(rightNetwork, rightRegion)
		if left == right {
			t.Errorf("(%q, %q) and (%q, %q) share the id %q. Their halves concatenate to the "+
				"same string under the separator %q, so the two arguments must reach "+
				"dataSourceArgumentDigest as SEPARATE parts rather than pre-joined",
				leftNetwork, leftRegion, rightNetwork, rightRegion, left, sep)
		}
	}

	if a, b := standardNetworkPrivateDNSID("net-1"),
		standardRegionPrivateDNSID("net-1", "reg-1"); a == b {
		t.Errorf("the network and region data sources produced the same id %q", a)
	}

	// The base must be part of the id and the digest must not be the whole of
	// it: a bare digest is unreadable in `terraform state list` output, and the
	// base alone is the constant this test exists to refuse.
	for _, id := range []string{
		standardNetworkPrivateDNSID("net-1"),
		standardRegionPrivateDNSID("net-1", "reg-1"),
	} {
		if !strings.Contains(id, "private_dns-") {
			t.Errorf("id %q does not carry a readable base", id)
		}
	}
}

/*
TestStandardPrivateDNSSchemaIsEntirelyComputed pins the shape of the whole
schema: the address attributes are Required, and EVERY other attribute, at every
depth, is Computed and neither Optional nor Required.

Two things depend on it.

The obvious one: there is no write path on this family (swagger.yaml:1726 and
:1752 declare `get` and nothing else), so an Optional attribute would accept a
value that could never be sent anywhere.

The less obvious one, which is why the Optional half is asserted rather than just
the Computed half: TestSchemaListAttributesMatchTheirEmptyArrayVerdict skips an
attribute that is `Computed && !Optional`, as well as skipping every data source
outright. Data sources therefore need no listAttributeEmptyPolicy entries, and
this test is what keeps the second of those two reasons true -- so that a later
change to the first one cannot silently drop these lists out of that sweep.
*/
func TestStandardPrivateDNSSchemaIsEntirelyComputed(t *testing.T) {
	for name, ds := range map[string]*schema.Resource{
		"checkpointsase_standard_network_private_dns": dataSourceStandardNetworkPrivateDNS(),
		"checkpointsase_standard_region_private_dns":  dataSourceStandardRegionPrivateDNS(),
	} {
		addresses := map[string]bool{privateDNSAttrNetworkID: true}
		if name == "checkpointsase_standard_region_private_dns" {
			addresses[privateDNSAttrRegionID] = true
		}

		walkSchema("", ds.Schema, func(path string, s *schema.Schema) {
			if addresses[path] {
				if !s.Required || s.Computed || s.Optional {
					t.Errorf("%s.%s must be Required and nothing else; got Required=%v "+
						"Optional=%v Computed=%v", name, path, s.Required, s.Optional, s.Computed)
				}
				return
			}
			if !s.Computed || s.Optional || s.Required {
				t.Errorf("%s.%s must be Computed and neither Optional nor Required -- this "+
					"family has no write endpoint; got Required=%v Optional=%v Computed=%v",
					name, path, s.Required, s.Optional, s.Computed)
			}
			if s.MaxItems != 0 || s.MinItems != 0 {
				t.Errorf("%s.%s carries MaxItems=%d MinItems=%d. Both constrain a "+
					"CONFIGURATION, and nothing here is configurable",
					name, path, s.MaxItems, s.MinItems)
			}
		})

		// The address attributes have to BE there, not merely be Required if
		// present: walkSchema says nothing about an attribute that is absent.
		for address := range addresses {
			if _, ok := ds.Schema[address]; !ok {
				t.Errorf("%s does not declare %s", name, address)
			}
		}
	}
}

/*
TestStandardPrivateDNSReadSurvivesANullBody: a 200 with a literal `null` body
must not panic.

The generated decode runs json.Unmarshal into a **CustomDnsResponse, and `null`
into a pointer-to-pointer sets the inner pointer nil WITHOUT calling
CustomDnsResponse.UnmarshalJSON -- so the strict `enabled` requiredProperties
check never runs and classifyAPIError never sees a failure. The generated getters
are nil-safe; customDns.Attributes in setStandardPrivateDNSState is a direct
field access and is not.

UNMEASURED on this endpoint. No probe has seen a null body from anything in this
family. It is guarded because a panic is the one failure mode Terraform cannot
report as a diagnostic, and because {"enabled": false} with no attributes is the
correct reading of an empty answer anyway. Same guard, same reasoning, as
TestEnhancedNetworkPrivateDNSReadSurvivesANullBody.
*/
func TestStandardPrivateDNSReadSurvivesANullBody(t *testing.T) {
	f := startStandardPrivateDNSFake(t, http.StatusOK, `null`)

	d := standardNetworkPrivateDNSData(t, "net-1")
	diags := dataSourceStandardNetworkPrivateDNSRead(context.Background(), d, f.client())
	if diags.HasError() {
		t.Fatalf("a null body produced an error rather than the unconfigured shape: %s",
			diagsText(diags))
	}
	if d.Get(privateDNSAttrEnabled).(bool) {
		t.Error("enabled = true from a null body")
	}
	if n := len(d.Get(privateDNSAttrAttributes).([]interface{})); n != 0 {
		t.Errorf("attributes.# = %d from a null body, want 0", n)
	}
}

/*
TestStandardPrivateDNSSpecBodyDecodesThroughTheGeneratedModels answers the
question API-FINDINGS.md 1.34 asked of the enhanced path, for the standard one.

1.34 measured that the ENHANCED read decodes: DnsPolicyPrivate emits a strict
requiredProperties UnmarshalJSON for mode, publicFallback AND domains, and the
server returns all three including `publicFallback: false` explicitly, so the
whole GET does not fail to decode.

THE STANDARD PATH IS A DIFFERENT SET OF MODELS, and until 1.36 had never been
measured, so this test reads what the generated code actually does rather than
assuming 1.34 carries over:

  - CustomDnsResponse requires `enabled` -- present in every fixture here, and in
    the measured unconfigured body.
  - DnsPolicyPublic requires `domains`, and DnsPolicyResponse.Public IS
    DnsPolicyPublic. So a standard server that returned `"public": {}` would fail
    the ENTIRE GET, not just that field. MEASURED 2026-08-26 (API-FINDINGS.md
    1.36): both standard reads returned `"public":{"domains":[]}`, so the check is
    satisfied and the whole-GET failure DOES NOT OCCUR on the bodies anyone has
    seen. The risk is still real and the wantErr row below still exercises it --
    two captured bodies are not a guarantee about every object -- but it is no
    longer an open question about the ordinary case.
  - DnsPolicyResponseAllOfPrivate has NO requiredProperties loop at all
    (model_dns_policy_response_all_of_private.go:99 unmarshals and files the rest
    into AdditionalProperties). This is the good half of the generator's D3
    mistake: because it dropped mode/publicFallback/domains from the struct, it
    also dropped them from the required list, so the standard `private` block
    cannot fail to decode however sparse it is.

The last bullet is asserted directly, with a `private` block carrying ONLY
forwardDNSUpdate. If a future SDK regeneration merges the allOf properly, that
case starts failing and this test is where it shows.
*/
func TestStandardPrivateDNSSpecBodyDecodesThroughTheGeneratedModels(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name: "the measured unconfigured body",
			body: measuredStandardPrivateDNSUnconfigured,
		},
		{
			name: "the spec-shaped populated body, publicFallback explicitly false",
			body: specStandardPrivateDNSConfigured,
		},
		{
			// The two MEASURED bodies, decoded through the real generated types.
			// This is the row that would have caught the whole-GET failure if
			// the server had sent `"public": {}`.
			name: "the measured standard network body (1.36)",
			body: measuredStandardNetworkPrivateDNSConfigured,
		},
		{
			name: "the measured standard region body, third disabled shape (1.36)",
			body: measuredStandardRegionPrivateDNSUntouched,
		},
		{
			// The generator's allOf collapse means this decodes even though the
			// SPEC declares mode, publicFallback and domains required inside
			// `private`. It is here so a regenerated SDK that fixed the collapse
			// -- and thereby gained the strict list -- is caught by a test rather
			// than by a failing plan.
			name: "a private block carrying only forwardDNSUpdate",
			body: `{"enabled":true,"attributes":{"servers":[],"searchDomains":[],` +
				`"dnsPolicy":{"private":{"forwardDNSUpdate":false}}}}`,
		},
		{
			// DnsPolicyPublic's strict list, exercised on purpose. The spec says
			// the server cannot send this; the point is that IF it did, the
			// failure would be the whole GET rather than one empty field.
			name:    "a public block with no domains",
			body:    `{"enabled":true,"attributes":{"dnsPolicy":{"public":{}}}}`,
			wantErr: true,
		},
		{
			// CustomDnsResponse's own strict list.
			name:    "no enabled key",
			body:    `{"attributes":{"servers":[]}}`,
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var decoded perimeter81Sdk.CustomDnsResponse
			err := json.Unmarshal([]byte(tc.body), &decoded)
			if tc.wantErr {
				if err == nil {
					t.Errorf("%s decoded cleanly; the generated model was expected to refuse "+
						"it, and this test's doc comment explains what that means", tc.body)
				}
				return
			}
			if err != nil {
				t.Errorf("%s failed to decode through the real generated models: %v. A body the "+
					"server can send and the SDK cannot read fails plan, refresh and every "+
					"read together", tc.body, err)
			}
		})
	}
}

/*
TestFlattenDnsPolicyResponsePrivateToleratesWrongTypes pins the three
AdditionalProperties readers as TOTAL.

THREE STANDARD PRIVATE-DNS BODIES HAVE BEEN CAPTURED AND NONE OF THEM IS
MALFORMED: P3's {"enabled":false} (API-FINDINGS.md 1.31) and 1.36's two reads --
measuredStandardPrivateDNSUnconfigured, measuredStandardNetworkPrivateDNSConfigured
and measuredStandardRegionPrivateDNSUntouched, declared at the top of this file. In
every one of them `mode` is a string, `publicFallback` a bool and `domains` a list
of strings.

So this test is NOT modelling an observed server. It is the deliberate TOTALITY
choice recorded on additionalPropertyString and its siblings: a read-only
attribute has no user input to reject, and failing an entire plan because one
field of one record was surprising is worse than surfacing a zero value the
operator can see in state. Three bodies from one tenant at one moment are not a
guarantee about every object, which is why the readers stay total.

The domains case asserts SKIPPING rather than substituting: a positional gap in a
domain list is worse than a shorter list, because domains are matched by value
and an empty string matches nothing.
*/
func TestFlattenDnsPolicyResponsePrivateToleratesWrongTypes(t *testing.T) {
	private := &perimeter81Sdk.DnsPolicyResponseAllOfPrivate{
		AdditionalProperties: map[string]interface{}{
			"mode":           42,
			"publicFallback": "yes",
			"domains":        []interface{}{"a.example.com", 7, "b.example.com"},
		},
	}

	block := flattenDnsPolicyResponsePrivate(private)

	if got := block[privateDNSAttrMode]; got != "" {
		t.Errorf("mode = %#v, want \"\" for a non-string on the wire", got)
	}
	if got := block[privateDNSAttrPublicFallback]; got != false {
		t.Errorf("public_fallback = %#v, want false for a non-bool on the wire", got)
	}
	domains, ok := block[privateDNSAttrDomains].([]string)
	if !ok {
		t.Fatalf("domains is %T, want []string", block[privateDNSAttrDomains])
	}
	if len(domains) != 2 || domains[0] != "a.example.com" || domains[1] != "b.example.com" {
		t.Errorf("domains = %#v, want the two string elements with the non-string SKIPPED, "+
			"not replaced by an empty string", domains)
	}

	// A nil bag is the ordinary case for a server that sends only
	// forwardDNSUpdate, and must not panic.
	empty := flattenDnsPolicyResponsePrivate(&perimeter81Sdk.DnsPolicyResponseAllOfPrivate{})
	if got := empty[privateDNSAttrDomains]; len(got.([]string)) != 0 {
		t.Errorf("domains = %#v for an absent key, want an empty slice", got)
	}
}

/*
TestStandardPrivateDNSShapeCheckMatchesTheReadModel drives
testAccCheckStandardPrivateDNSShape -- which lives in the acc-test file but is
ordinary Go -- against hand-built state. It is offline on purpose: the check runs
live only against a tenant nobody here controls, so the bodies it must tolerate
cannot be produced on demand, only reasoned about from the model it reads.

WHY IT EXISTS. The check used to fail the step when `enabled` was "true" and
`attributes.#` was not 1, and again when `servers.#` was 0, citing
swagger.yaml:4492. THAT LINE IS CustomDnsUpdateAttributes.servers -- the
description on the PUT body (swagger.yaml:4471-4492). The standard read decodes
CustomDnsResponse (:4419) -> CustomDnsAttributesResponse (:4409) -> its base
CustomDnsAttributes (:4387), where `servers` is an OPTIONAL array carrying
uniqueItems and maxItems: 4 and no minimum of any kind; and CustomDns (:4376)
requires `enabled` alone, so `{"enabled": true}` with no `attributes` key is a
legal response body.

API-FINDINGS.md 1.35 is why that difference bites on this family and on no other:
the standard pair declares no put, post or patch, so the v3 write validator never
sees these objects at all. The console is the only writer, and 1.36 measured this
same server populating a REGION's dnsPolicy with defaults nobody set. A write
model's conditional rule is not evidence about what a read can return.

The rows are two groups. The first is bodies the READ model permits: each one
would have been reported live as "the block was dropped on the way into state" or
"the API cannot hold that state" -- a provider defect that does not exist, on the
one family where the provider cannot even know what wrote the body. The second is
the defects the check still has to catch, so that dropping two rows did not leave
a check that cannot fail.
*/
func TestStandardPrivateDNSShapeCheckMatchesTheReadModel(t *testing.T) {
	const address = "data.checkpointsase_standard_network_private_dns.test"

	for _, tc := range []struct {
		name    string
		attrs   map[string]string
		wantErr bool
	}{
		// ---- bodies the READ model permits; all of these must pass ----
		{
			// API-FINDINGS.md 1.31, verbatim: {"enabled":false}.
			name:  "the measured unconfigured network body, no attributes key",
			attrs: map[string]string{"enabled": "false"},
		},
		{
			// API-FINDINGS.md 1.36, the console-configured network.
			name: "the measured configured network body",
			attrs: map[string]string{
				"enabled":                        "true",
				"attributes.#":                   "1",
				"attributes.0.servers.#":         "1",
				"attributes.0.servers.0.address": "13.227.192.28",
				"attributes.0.servers.0.is_tls":  "false",
				"attributes.0.search_domains.#":  "0",
			},
		},
		{
			// API-FINDINGS.md 1.36, the third disabled shape: attributes PRESENT,
			// servers EMPTY, dnsPolicy populated, on a region nobody configured.
			name: "the measured untouched region body",
			attrs: map[string]string{
				"enabled":                       "false",
				"attributes.#":                  "1",
				"attributes.0.servers.#":        "0",
				"attributes.0.search_domains.#": "0",
			},
		},
		{
			// CustomDns (:4376) requires `enabled` and nothing else. This is the
			// SPD-02 scenario: a region under a network somebody enabled from the
			// console, whose own object carries no attributes.
			name:  "enabled true with no attributes block at all",
			attrs: map[string]string{"enabled": "true"},
		},
		{
			// CustomDnsAttributes (:4387) declares no minItems and no conditional
			// minimum on `servers`. Only the PUT body does.
			name: "enabled true with an attributes block holding no servers",
			attrs: map[string]string{
				"enabled":                       "true",
				"attributes.#":                  "1",
				"attributes.0.servers.#":        "0",
				"attributes.0.search_domains.#": "0",
			},
		},

		// ---- defects the check must still catch ----
		{
			name:    "no enabled attribute at all",
			attrs:   map[string]string{"attributes.#": "0"},
			wantErr: true,
		},
		{
			name:    "enabled is not a boolean",
			attrs:   map[string]string{"enabled": "yes"},
			wantErr: true,
		},
		{
			// The API returns one attributes object or none, so a list means the
			// flattener wrapped a value that was never a list.
			name:    "attributes flattened into more than one element",
			attrs:   map[string]string{"enabled": "true", "attributes.#": "2"},
			wantErr: true,
		},
		{
			// A missing COUNT key is what a mis-spelled flattener key produces.
			name: "attributes present but servers was never set",
			attrs: map[string]string{
				"enabled": "false", "attributes.#": "1",
				"attributes.0.search_domains.#": "0",
			},
			wantErr: true,
		},
		{
			name: "attributes present but search_domains was never set",
			attrs: map[string]string{
				"enabled": "false", "attributes.#": "1",
				"attributes.0.servers.#": "0",
			},
			wantErr: true,
		},
		{
			// CustomDnsServer (:4429) requires BOTH address and isTLS, on the read
			// model. This is the row that replaces the two write-model rows: a
			// dropped or mis-spelled server key shows up here, on a constraint the
			// read model really declares.
			name: "a server element whose address key was never set",
			attrs: map[string]string{
				"enabled": "true", "attributes.#": "1",
				"attributes.0.servers.#":        "1",
				"attributes.0.servers.0.is_tls": "false",
				"attributes.0.search_domains.#": "0",
			},
			wantErr: true,
		},
		{
			// Mutation M10's live twin: flattenCustomDnsServers dropping is_tls.
			name: "a server element whose is_tls key was never set",
			attrs: map[string]string{
				"enabled": "true", "attributes.#": "1",
				"attributes.0.servers.#":         "1",
				"attributes.0.servers.0.address": "10.0.0.53",
				"attributes.0.search_domains.#":  "0",
			},
			wantErr: true,
		},
		{
			// Set but mapped from nothing, which is the other half of the same
			// defect and the one TestCheckResourceAttrSet cannot see.
			name: "a server element whose address is empty",
			attrs: map[string]string{
				"enabled": "true", "attributes.#": "1",
				"attributes.0.servers.#":         "1",
				"attributes.0.servers.0.address": "",
				"attributes.0.servers.0.is_tls":  "true",
				"attributes.0.search_domains.#":  "0",
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// stateWithDataSource is data_source_identity_test.go's helper: the
			// check reaches state only through dataSourceAttrs, which touches
			// Primary.Attributes and nothing else, so the Type it fills in is not
			// read by anything here.
			err := testAccCheckStandardPrivateDNSShape(address)(stateWithDataSource(address, tc.attrs))
			if tc.wantErr {
				if err == nil {
					t.Errorf("the shape check ACCEPTED %v. That body is a defect the live rows "+
						"exist to catch, and a check that accepts it cannot fail for the "+
						"reason it claims to", tc.attrs)
				}
				return
			}
			if err != nil {
				t.Errorf("the shape check REJECTED a body the read model permits: %v\n"+
					"body: %v\nswagger.yaml:4376 requires only `enabled`, and :4387 puts no "+
					"minimum on `servers`. Live, this reads as a provider defect that does "+
					"not exist", err, tc.attrs)
			}
		})
	}
}
