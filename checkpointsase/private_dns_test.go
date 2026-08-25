package checkpointsase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
Offline tests for the machinery both enhanced private-DNS resources share.

Everything here runs against httptest or against a marshalled body; nothing in
this file makes a network call or needs TF_ACC. None of these names carries the
TestAcc prefix, which in this codebase means "acceptance test, skips without
TF_ACC=1" -- an offline test wearing that prefix reads as 21 skipped acceptance
tests in the summary and as zero offline coverage, which is what Phase 4 shipped.

The fixture bodies are the ones measured on 2026-08-26 and recorded in
API-FINDINGS.md 1.28 and 1.31, not JSON authored here to fit the code.
*/

/*
testPrivateDNSResourceSchema mirrors the schema the two enhanced private-DNS
resources declare.

It lives in the test rather than in private_dns.go on purpose: the resource
schema -- Required/Optional, MaxItems, the validators on `mode` -- is Task 2's
decision, and duplicating it in the shared file would pre-empt it. What Task 1
does fix, because expandCustomDnsUpdate reads them by name, is the set of
ATTRIBUTE KEYS:

	enabled
	attributes.servers[].address
	attributes.servers[].is_tls
	attributes.search_domains[]
	attributes.dns_policy.public.domains[]
	attributes.dns_policy.private.mode
	attributes.dns_policy.private.public_fallback
	attributes.dns_policy.private.domains[]

A resource that spells any of those differently silently sends a zero value for
it -- the expander cannot tell a missing key from an unset one. This mirror is
where such a mismatch has to be reconciled.
*/
func testPrivateDNSResourceSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"network_id": {Type: schema.TypeString, Required: true, ForceNew: true},
		"enabled":    {Type: schema.TypeBool, Required: true},
		"attributes": {
			Type:     schema.TypeList,
			Optional: true,
			MaxItems: 1,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"servers": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"address": {Type: schema.TypeString, Required: true},
								"is_tls":  {Type: schema.TypeBool, Optional: true},
							},
						},
					},
					"search_domains": {
						Type:     schema.TypeList,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
					"dns_policy": {
						Type:     schema.TypeList,
						Optional: true,
						MaxItems: 1,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"public": {
									Type:     schema.TypeList,
									Optional: true,
									MaxItems: 1,
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											"domains": {
												Type:     schema.TypeList,
												Optional: true,
												Elem:     &schema.Schema{Type: schema.TypeString},
											},
										},
									},
								},
								"private": {
									Type:     schema.TypeList,
									Optional: true,
									MaxItems: 1,
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											"mode":            {Type: schema.TypeString, Optional: true},
											"public_fallback": {Type: schema.TypeBool, Optional: true},
											"domains": {
												Type:     schema.TypeList,
												Optional: true,
												Elem:     &schema.Schema{Type: schema.TypeString},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// jsonValueAt walks a decoded JSON body down a slash-separated path and returns
// what it finds, plus whether the last key was present at all.
//
// It returns interface{} rather than a typed value because the whole point of
// the caller below is to tell `[]` (a non-nil, empty []interface{}) from `null`
// (a nil interface{}) from an absent key -- three states a typed accessor or a
// struct comparison collapses into one.
func jsonValueAt(t *testing.T, body []byte, path string) (interface{}, bool) {
	t.Helper()

	var decoded interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("could not unmarshal the marshalled body: %v\nbody: %s", err, body)
	}

	current := decoded
	for _, key := range strings.Split(path, "/") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		value, present := object[key]
		if !present {
			return nil, false
		}
		current = value
	}
	return current, true
}

// assertMarshalsArrayAt asserts the body carries a JSON array at path -- present,
// and `[]` rather than `null`.
func assertMarshalsArrayAt(t *testing.T, body []byte, path string) {
	t.Helper()

	value, present := jsonValueAt(t, body, path)
	if !present {
		t.Errorf("%s is absent from the body; it is a required key on this endpoint.\nbody: %s",
			path, body)
		return
	}
	if value == nil {
		t.Errorf("%s marshalled as JSON null, not an array. The endpoint's @IsArray rejects "+
			"null with a 400 that names the field the user did set.\nbody: %s", path, body)
		return
	}
	if _, ok := value.([]interface{}); !ok {
		t.Errorf("%s marshalled as %T, want a JSON array.\nbody: %s", path, value, body)
	}
}

/*
TestExpandCustomDnsUpdateNeverMarshalsNullArrays is a MARSHALLING test, not a
struct test.

CustomDnsUpdateAttributes declares Servers and SearchDomains without omitempty
(model_custom_dns_update_attributes.go:23), and so do DnsPolicyPublic.Domains and
DnsPolicyPrivate.Domains, so a nil slice on any of the four reaches the wire as
`"servers": null` -- not an array, and the endpoint's @IsArray rejects it. The
schema is explicit: "send an empty array if you have none. Omitting it on update
is rejected with 400".

Measured, API-FINDINGS.md 1.31: omitting `servers` from `attributes` returns
400 `attributes.servers must be an array`. `null` fails the same validator, and
the resulting message names `servers` even when the user's config set it -- the
failure is in the empty *neighbouring* case, so the error points at the wrong
place.

The assertions are on json.Marshal output because the Go value being nil vs empty
is exactly the distinction a struct comparison erases: reflect.DeepEqual over
CustomDnsUpdate passes over this defect, and so does any check of len(). Same
class as buildGranularFirewallPolicyClear.
*/
func TestExpandCustomDnsUpdateNeverMarshalsNullArrays(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]interface{}
		// arrays that must be present and non-null in the marshalled body.
		arrays []string
	}{
		{
			// The disable body. This is the one the read cannot produce: an
			// unconfigured network reads back as exactly {"enabled": false},
			// and PUTting that same body is a 422 (API-FINDINGS.md 1.31).
			name:   "disabled with no attributes block at all",
			raw:    map[string]interface{}{"network_id": "net-1", "enabled": false},
			arrays: []string{"attributes/servers", "attributes/searchDomains"},
		},
		{
			name: "attributes block present but every list empty",
			raw: map[string]interface{}{
				"network_id": "net-1",
				"enabled":    false,
				"attributes": []interface{}{map[string]interface{}{
					"servers":        []interface{}{},
					"search_domains": []interface{}{},
				}},
			},
			arrays: []string{"attributes/servers", "attributes/searchDomains"},
		},
		{
			// The asymmetric case that makes this worth a table: servers is set
			// and search_domains is not. A nil search_domains here produces a
			// 400 naming servers as well (measured: the endpoint reports all of
			// its array complaints together), so the operator reads an error
			// about the one field they did configure.
			name: "servers set, search_domains unset",
			raw: map[string]interface{}{
				"network_id": "net-1",
				"enabled":    true,
				"attributes": []interface{}{map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{"address": "10.0.0.53", "is_tls": false},
					},
				}},
			},
			arrays: []string{"attributes/servers", "attributes/searchDomains"},
		},
		{
			// dns_policy carries two more arrays with the same declaration and
			// therefore the same trap. An empty `public` block must not send
			// "domains": null.
			name: "dns_policy blocks present with no domains",
			raw: map[string]interface{}{
				"network_id": "net-1",
				"enabled":    true,
				"attributes": []interface{}{map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{"address": "10.0.0.53", "is_tls": true},
					},
					"search_domains": []interface{}{"a.example.com"},
					"dns_policy": []interface{}{map[string]interface{}{
						"public": []interface{}{map[string]interface{}{}},
						"private": []interface{}{map[string]interface{}{
							"mode":            "matchPattern",
							"public_fallback": true,
						}},
					}},
				}},
			},
			arrays: []string{
				"attributes/servers",
				"attributes/searchDomains",
				"attributes/dnsPolicy/public/domains",
				"attributes/dnsPolicy/private/domains",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, testPrivateDNSResourceSchema(), tt.raw)

			body, err := json.Marshal(expandCustomDnsUpdate(d))
			if err != nil {
				t.Fatalf("json.Marshal(expandCustomDnsUpdate(d)) returned an error: %v", err)
			}

			for _, path := range tt.arrays {
				assertMarshalsArrayAt(t, body, path)
			}
		})
	}
}

/*
TestFlattenCustomDnsAttributesOnUnconfiguredNetwork pins the read half of the
same asymmetry.

Measured, API-FINDINGS.md 1.31: GET .../privateDNS on a network that has never
been configured returns exactly {"enabled": false} -- with NO `attributes` key --
which the generated CustomDns decodes to a nil *CustomDnsAttributes. A flattener
that dereferences it panics the provider on the first Read of any unconfigured
network, which is every Read that runs before the first apply lands.
*/
func TestFlattenCustomDnsAttributesOnUnconfiguredNetwork(t *testing.T) {
	var unconfigured perimeter81Sdk.CustomDns
	if err := json.Unmarshal([]byte(`{"enabled": false}`), &unconfigured); err != nil {
		t.Fatalf("CustomDns could not decode the measured unconfigured body: %v", err)
	}
	if unconfigured.Attributes != nil {
		t.Fatalf("the measured body has no attributes key, so Attributes must decode to nil, got %#v",
			unconfigured.Attributes)
	}

	got := flattenCustomDnsAttributes(unconfigured.Attributes)
	if len(got) != 0 {
		t.Errorf("flattenCustomDnsAttributes(nil) = %#v, want an empty list: an absent "+
			"`attributes` is what an unconfigured network reads back as", got)
	}
}

/*
TestFlattenCustomDnsAttributesRoundTripsAConfiguredNetwork is the companion that
stops the test above passing by having the flattener always return nothing.

The body is the one measured on 2026-08-26 (API-FINDINGS.md 1.31): two servers
with different isTLS values and two search domains sent in deliberately
non-alphabetical order, all returned in the order sent. There is no
canonicalisation for this flattener to reproduce, so position is the contract.
*/
func TestFlattenCustomDnsAttributesRoundTripsAConfiguredNetwork(t *testing.T) {
	const measured = `{"enabled":true,"attributes":{` +
		`"servers":[{"address":"10.0.0.53","isTLS":false},{"address":"10.0.1.53","isTLS":true}],` +
		`"searchDomains":["b.example.com","a.example.com"]}}`

	var configured perimeter81Sdk.CustomDns
	if err := json.Unmarshal([]byte(measured), &configured); err != nil {
		t.Fatalf("CustomDns could not decode the measured configured body: %v", err)
	}

	got := flattenCustomDnsAttributes(configured.Attributes)
	if len(got) != 1 {
		t.Fatalf("flattenCustomDnsAttributes() = %#v, want exactly one attributes block", got)
	}
	block, ok := got[0].(map[string]interface{})
	if !ok {
		t.Fatalf("attributes block is %T, want map[string]interface{}", got[0])
	}

	servers, ok := block["servers"].([]interface{})
	if !ok {
		t.Fatalf("servers is %T, want []interface{}", block["servers"])
	}
	if len(servers) != 2 {
		t.Fatalf("servers = %#v, want the two the API returned", servers)
	}
	first, _ := servers[0].(map[string]interface{})
	second, _ := servers[1].(map[string]interface{})
	if first["address"] != "10.0.0.53" || first["is_tls"] != false {
		t.Errorf("servers[0] = %#v, want address 10.0.0.53 with is_tls false", first)
	}
	// isTLS true on the second entry only: a flattener that dropped the field
	// would still pass on the first, which is why both are asserted.
	if second["address"] != "10.0.1.53" || second["is_tls"] != true {
		t.Errorf("servers[1] = %#v, want address 10.0.1.53 with is_tls true", second)
	}

	wantDomains := []string{"b.example.com", "a.example.com"}
	switch domains := block["search_domains"].(type) {
	case []string:
		if !testComparableArraiesEq(domains, wantDomains) {
			t.Errorf("search_domains = %#v, want %#v in the order the API returned them",
				domains, wantDomains)
		}
	default:
		t.Errorf("search_domains is %T, want []string", block["search_domains"])
	}
}

// fakePrivateDNSAPI is one tenant's v3 API: the PUT that starts the async
// operation, and the status endpoint that reports on it.
//
// It records every request path so a test can assert not only what came back but
// WHERE the helper went -- which is the whole content of API-FINDINGS.md 1.28.
type fakePrivateDNSAPI struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []string

	// putResponse is written verbatim with a 202.
	putResponse string
	// statusBodies are served in order to successive status GETs; the last is
	// repeated if the helper polls more times than there are bodies.
	statusBodies []string
}

func newFakePrivateDNSAPI(t *testing.T, putResponse string, statusBodies ...string) *fakePrivateDNSAPI {
	t.Helper()

	fake := &fakePrivateDNSAPI{putResponse: putResponse, statusBodies: statusBodies}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// The SDK exchanges the API key for a bearer token before any request
		// whose cached token has expired (client.go:517), and an empty token
		// expires immediately, so this fires once per SDK call. It is plumbing,
		// not something any test here asserts on, so it is answered and not
		// recorded. The empty object decodes into Token{} cleanly.
		if strings.HasSuffix(r.URL.Path, "/auth/authorize") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}

		fake.mu.Lock()
		fake.requests = append(fake.requests, r.Method+" "+r.URL.Path)
		statusCalls := 0
		for _, request := range fake.requests {
			if strings.Contains(request, privateDNSStatusPathFragment) {
				statusCalls++
			}
		}
		fake.mu.Unlock()

		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(fake.putResponse))
			return
		}

		body := `{"completed":true,"result":{"statusCode":200}}`
		if len(fake.statusBodies) > 0 {
			index := statusCalls - 1
			if index < 0 {
				index = 0
			}
			if index >= len(fake.statusBodies) {
				index = len(fake.statusBodies) - 1
			}
			body = fake.statusBodies[index]
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// privateDNSStatusPathFragment is what every async status path carries, on the
// configured host (/v3/networks/status/{id}) and on the one statusUrl names
// (/api/rest/v2.3/networks/status/{id}) alike. Matching on it rather than on the
// method is what lets one recorder count polls against either.
const privateDNSStatusPathFragment = "/networks/status/"

// statusRequests returns the recorded requests that went to a status endpoint,
// wherever it was hosted.
func (f *fakePrivateDNSAPI) statusRequests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var matched []string
	for _, request := range f.requests {
		if strings.Contains(request, privateDNSStatusPathFragment) {
			matched = append(matched, request)
		}
	}
	return matched
}

// client points a generated SDK client at this fake, exactly as the provider
// points one at the operator's configured BASE_URL.
//
// "test-key" is a literal, not a credential: nothing in this package's offline
// tests authenticates against anything.
func (f *fakePrivateDNSAPI) client() *perimeter81Sdk.APIClient {
	return perimeter81Sdk.NewAPIClient(perimeter81Sdk.NewConfiguration("test-key", f.server.URL))
}

// sendPrivateDNSPut is the caller-supplied half of putPrivateDNSAndWait: the
// already-built SDK call. It is the exact call the enhanced network resource
// will make.
func sendPrivateDNSPut(client *perimeter81Sdk.APIClient) func(context.Context) (*perimeter81Sdk.AsyncOperationResponse, *http.Response, error) {
	return func(ctx context.Context) (*perimeter81Sdk.AsyncOperationResponse, *http.Response, error) {
		return client.EnhancedPrivateDNSAPI.UpdateEnhancedNetworkPrivateDNS(ctx, "net-1").
			CustomDnsUpdate(perimeter81Sdk.CustomDnsUpdate{
				Enabled: false,
				Attributes: perimeter81Sdk.CustomDnsUpdateAttributes{
					Servers:       []perimeter81Sdk.CustomDnsServer{},
					SearchDomains: []string{},
				},
			}).Execute()
	}
}

// usePrivateDNSTestPollInterval collapses the production poll interval for the
// duration of one test, so a three-poll test costs microseconds instead of
// twenty seconds. See privateDNSPollInterval's comment for why it is a var.
func usePrivateDNSTestPollInterval(t *testing.T) {
	t.Helper()

	original := privateDNSPollInterval
	privateDNSPollInterval = testInterval
	t.Cleanup(func() { privateDNSPollInterval = original })
}

// measuredPrivateDNSAccepted is the 202 body captured on 2026-08-26 from
// PUT /v3/networks/enhanced/{id}/privateDNS with the legal "off" payload
// (API-FINDINGS.md 1.28 and 1.31). Both fields are as measured: the statusUrl is
// absolute, on a DIFFERENT host from the one the request went to, and carries an
// /api/rest/v2.3/ path rather than /v3/.
const measuredPrivateDNSAccepted = `{"statusUrl":"https://api.perimeter81-solo.com/api/rest/v2.3/networks/status/exu7TTfsPg","samplingTime":120}`

/*
TestPutPrivateDNSAndWaitPollsBeforeReturning pins D1.

Both enhanced private-DNS PUTs declare ONLY a 202 (swagger.yaml:633, :699) and
the SDK returns *AsyncOperationResponse, so returning as soon as the PUT succeeds
means the write has not happened yet: Create then reads back pre-write values and
stores them as applied. That is the failure putGranularFirewallPolicy's comment
records shipping three times on this branch.

The server answers `completed:false` twice and then `completed:true` with a 2xx,
so a helper that returns after the first status GET fails here just as loudly as
one that never polls at all.
*/
func TestPutPrivateDNSAndWaitPollsBeforeReturning(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	fake := newFakePrivateDNSAPI(t, measuredPrivateDNSAccepted,
		`{"completed":false}`,
		`{"completed":false}`,
		`{"completed":true,"result":{"statusCode":200}}`,
	)
	client := fake.client()

	accepted, err := putPrivateDNSAndWait(context.Background(), client, sendPrivateDNSPut(client))
	if err != nil {
		t.Fatalf("putPrivateDNSAndWait() error = %v, want nil for an operation that completes 200", err)
	}
	if !accepted {
		t.Error("putPrivateDNSAndWait() accepted = false, want true: the PUT itself returned 202")
	}

	statusGets := fake.statusRequests()
	if len(statusGets) != 3 {
		t.Errorf("the helper made %d status GETs (%v), want 3 -- it must not return until the "+
			"operation reports completed", len(statusGets), statusGets)
	}
}

/*
TestPutPrivateDNSAndWaitResolvesStatusUrlAgainstTheConfiguredClient pins
API-FINDINGS.md 1.28.

Measured 2026-08-26: every async 202 on this API carries a statusUrl that is
absolute, points at a host the request did not go to, and carries an
/api/rest/v2.3/ path. Following it leaves the operator's configured BASE_URL --
which exists precisely so a non-US tenant talks to its own region -- and polls
whatever tenant lives at the other host. It fails invisibly, because that other
deployment still answers with a well-formed {"completed":...}.

The decoy below is that other deployment. It answers every poll with a completed
200, so a helper that follows statusUrl passes every other assertion in this file
and fails only this one.
*/
func TestPutPrivateDNSAndWaitResolvesStatusUrlAgainstTheConfiguredClient(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	decoy := newFakePrivateDNSAPI(t, measuredPrivateDNSAccepted,
		`{"completed":true,"result":{"statusCode":200}}`)

	// The same shape as the measured statusUrl -- absolute, different host, a
	// v2.3 path -- but pointed at a server this test can count hits on.
	statusUrl := decoy.server.URL + "/api/rest/v2.3/networks/status/exu7TTfsPg"
	fake := newFakePrivateDNSAPI(t, `{"statusUrl":"`+statusUrl+`","samplingTime":120}`,
		`{"completed":true,"result":{"statusCode":200}}`)
	client := fake.client()

	if _, err := putPrivateDNSAndWait(context.Background(), client, sendPrivateDNSPut(client)); err != nil {
		t.Fatalf("putPrivateDNSAndWait() error = %v, want nil", err)
	}

	if hits := decoy.statusRequests(); len(hits) != 0 {
		t.Errorf("the helper followed statusUrl to the other host: %v. It must take the last "+
			"path segment and resolve it against the configured client, or a non-US tenant "+
			"polls the wrong deployment (API-FINDINGS.md 1.28)", hits)
	}

	statusGets := fake.statusRequests()
	if len(statusGets) != 1 {
		t.Fatalf("the configured client got %d status GETs (%v), want 1", len(statusGets), statusGets)
	}
	if got, want := statusGets[0], http.MethodGet+" /v3/networks/status/exu7TTfsPg"; got != want {
		t.Errorf("status GET went to %q, want %q -- the id is the last path segment of "+
			"statusUrl, resolved against the configured base URL", got, want)
	}
}

/*
TestPutPrivateDNSAndWaitFailsOnNon2xxCompletion is separate from the polling test
because `completed:true` alone is not success.

checkNetworkStatus, the per-resource helper pollAsync replaced, failed only on
statusCode 500 -- so a 400 or a 409 completion was reported to Terraform as a
successful apply, and the operator's next plan was the first hint. This is
SPT-N02's requirement applied to the private-DNS path, where no test row asks
for it.

The error must carry the status code and the API's reason, because on this path
they are the only trace of what the backend refused: the PUT itself returned 202
and said nothing.
*/
func TestPutPrivateDNSAndWaitFailsOnNon2xxCompletion(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	fake := newFakePrivateDNSAPI(t, measuredPrivateDNSAccepted,
		`{"completed":true,"result":{"statusCode":409,"reason":["private DNS is being updated by another operation"]}}`)
	client := fake.client()

	accepted, err := putPrivateDNSAndWait(context.Background(), client, sendPrivateDNSPut(client))
	if err == nil {
		t.Fatal("putPrivateDNSAndWait() error = nil, want an error for a 409 completion")
	}
	if !accepted {
		t.Error("putPrivateDNSAndWait() accepted = false, want true: the API accepted the PUT " +
			"and the operation then failed, which is a different diagnostic from a refused request")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("error %q should include the status code", err)
	}
	if !strings.Contains(err.Error(), "private DNS is being updated by another operation") {
		t.Errorf("error %q should include the API's reason", err)
	}
}

/*
TestPutPrivateDNSAndWaitOnMissingStatusUrl pins a DECISION rather than an
inherited behaviour.

statusUrl is optional on AsyncOperationResponse, and putGranularFirewallPolicy
returns (false, nil) when it is absent -- it silently does not wait, and reports
the apply as successful. This helper deliberately goes the other way and returns
(true, error).

Why: the helper exists for exactly one reason, which is that a 202 means the
write has NOT happened. A 202 with nothing to poll is a write this provider
cannot confirm, and reporting an unconfirmable write as a successful apply is
the failure mode the whole task is against. accepted stays true because the PUT
was accepted -- the caller's diagnostic should say "the update did not complete",
not "the API refused the request".

This costs a false failure if the server ever legitimately returns a 202 with no
statusUrl for a write that did land. Nine probes on 2026-08-26 never saw one:
every async 202 measured carried a statusUrl (API-FINDINGS.md 1.28). If that
changes, this is a deliberate choice to revisit, not an accident to fix.
*/
func TestPutPrivateDNSAndWaitOnMissingStatusUrl(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	for _, tt := range []struct {
		name        string
		putResponse string
	}{
		{"statusUrl absent", `{"samplingTime":120}`},
		{"statusUrl empty", `{"statusUrl":"","samplingTime":120}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakePrivateDNSAPI(t, tt.putResponse)
			client := fake.client()

			accepted, err := putPrivateDNSAndWait(context.Background(), client, sendPrivateDNSPut(client))
			if err == nil {
				t.Fatal("putPrivateDNSAndWait() error = nil, want an error: a 202 with nothing " +
					"to poll is a write this provider cannot confirm, and reporting it as a " +
					"successful apply is exactly what this helper exists to prevent")
			}
			if !accepted {
				t.Error("putPrivateDNSAndWait() accepted = false, want true: the PUT itself was accepted")
			}
			if !strings.Contains(err.Error(), "statusUrl") {
				t.Errorf("error %q should name statusUrl, so an operator can tell this apart "+
					"from an operation that ran and failed", err)
			}
			if gets := fake.statusRequests(); len(gets) != 0 {
				t.Errorf("the helper polled %v with no status id; an empty id builds "+
					"/v3/networks/status/ and 404s against an operation that may have succeeded", gets)
			}
		})
	}
}

/*
TestPutPrivateDNSAndWaitReturnsNotAcceptedWhenThePutItselfFails keeps the
accepted flag honest in the other direction.

The two summaries the callers pick between -- "the API refused the request" and
"the API accepted the request and the operation then failed" -- send a reader to
different places, and accepted is the only thing that distinguishes them.
*/
func TestPutPrivateDNSAndWaitReturnsNotAcceptedWhenThePutItselfFails(t *testing.T) {
	usePrivateDNSTestPollInterval(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		// The measured 422 from PUTting a read body back (API-FINDINGS.md 1.31).
		_, _ = w.Write([]byte(`{"message":"VALIDATION_ERROR","messageCode":"UNPROCESSABLE_ENTITY","status":422}`))
	}))
	t.Cleanup(server.Close)

	client := perimeter81Sdk.NewAPIClient(perimeter81Sdk.NewConfiguration("test-key", server.URL))

	accepted, err := putPrivateDNSAndWait(context.Background(), client, sendPrivateDNSPut(client))
	if err == nil {
		t.Fatal("putPrivateDNSAndWait() error = nil, want the 422 surfaced")
	}
	if accepted {
		t.Error("putPrivateDNSAndWait() accepted = true, want false: the API refused the request, " +
			"so the caller must not tell the operator the update was accepted and then failed")
	}
}
