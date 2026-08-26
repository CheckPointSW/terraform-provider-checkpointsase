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

READ THE FIXTURE COMMENTS BEFORE TRUSTING A FIXTURE. Exactly ONE of the bodies
below was captured from the standard family on the wire. The rest are derived
from swagger.yaml, and each one says so. This project has twice shipped fixtures
claiming a wire fidelity they did not have.
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

    All three are 404 with messageCode NOT_FOUND, so nothing in the provider
    behaves differently -- but a test asserting on the text would.

SPEC-DERIVED (everything else):

  - specStandardPrivateDNSConfigured is a POPULATED standard body, and NOTHING
    HAS EVER MEASURED ONE. No probe has read a standard private-DNS endpoint with
    private DNS configured, at network or region level, in this project or any
    run before it. Every populated body on record -- servers, searchDomains,
    dnsPolicy -- came from the ENHANCED network endpoint (API-FINDINGS.md 1.31 for
    servers and searchDomains, 1.34 for the dnsPolicy round trip). The values
    below are copied from those enhanced captures so they are at least realistic,
    but the SHAPE is what swagger.yaml:4419/:4409/:4632 declares for the standard
    family and the assertions that read it are assertions about the provider's
    handling of the SPEC, not about the server.

    The `private` block is the whole of plan decision D3: `forwardDNSUpdate` is
    on the generated struct, and `mode`, `publicFallback` and `domains` are not --
    they arrive in AdditionalProperties. See flattenDnsPolicyResponsePrivate.
*/
const (
	measuredStandardPrivateDNSUnconfigured = `{"enabled":false}`
	measuredStandardPrivateDNSNetworkGone  = `{"message":"network doesnt exists",` +
		`"messageCode":"NOT_FOUND","status":404}`

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
    an id that moved would defeat every downstream reference (L16c);

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

THE STANDARD PATH IS A DIFFERENT SET OF MODELS AND HAS NEVER BEEN MEASURED, so
this test reads what the generated code actually does rather than assuming 1.34
carries over:

  - CustomDnsResponse requires `enabled` -- present in every fixture here, and in
    the measured unconfigured body.
  - DnsPolicyPublic requires `domains`, and DnsPolicyResponse.Public IS
    DnsPolicyPublic. So a standard server that returned `"public": {}` would fail
    the ENTIRE GET, not just that field. swagger.yaml:4595 makes `domains`
    required inside `public`, so the spec says it cannot happen; nothing has
    verified it on this family.
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

Nothing in this project has seen a standard private-DNS body at all, let alone a
malformed one, so this is not modelling an observed server. It is the deliberate
choice recorded on additionalPropertyString and its siblings: a read-only
attribute has no user input to reject, and failing an entire plan because one
field of one record was surprising is worse than surfacing a zero value the
operator can see in state.

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
