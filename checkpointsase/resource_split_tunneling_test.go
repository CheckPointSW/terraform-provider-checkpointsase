package checkpointsase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	ctyjson "github.com/hashicorp/go-cty/cty/json"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
Offline tests for checkpointsase_split_tunneling.

Everything here runs against httptest or against the SDK's own diff and
validation machinery; nothing makes a network call or needs TF_ACC. NONE OF THESE
NAMES CARRIES THE TestAcc PREFIX, which in this codebase means "acceptance test,
skips without TF_ACC=1". Phase 4 shipped 21 offline tests wearing that prefix,
which reads in the summary as 21 skipped acceptance tests and zero offline
coverage. The one acceptance test for this resource lives in
resource_split_tunneling_acc_test.go and genuinely is one.

Every body fixture below is either a capture from 2026-08-26 or an example lifted
verbatim from the spec, and each says which it is. None was authored to fit the
code.
*/

/*
The bodies this resource has to cope with.

  - measuredSplitTunnelingViaTunnel is what GET .../split-tunneling returned for a
    network in via_tunnel mode with nothing excepted. It is the P1 capture, and
    the point of P1 is that THE ENHANCED AND THE STANDARD NETWORK RETURNED
    BYTE-IDENTICAL BODIES -- this one string is both of them. Note what is
    missing: there is no `exceptions` key at all, because exceptions are not
    supported in via_tunnel mode.

  - measuredSplitTunnelingWithException is a standard network in out_of_tunnel
    mode holding one exception. It is the starting state of the four-attempt
    removal experiment in API-FINDINGS.md 1.29 and the state the tenant is STILL
    in, because none of the four attempts removed it (LEFTOVERS.md L33).

  - measuredSplitTunnelingNetworkGone is what a bogus networkId gets on this path,
    verified by probe P10 on 2026-08-26. The message differs from the
    enhanced-privateDNS one ("Network doesn't exist." there, "network doesnt
    exist" here) -- three families, three spellings of the same 404. Nothing in
    the provider reads the text, but a test that asserted on it would be wrong to
    reuse another family's constant, which is why this one is declared here.

  - measuredSplitTunnelingArraysMissing is the 400 from omitting the three
    exceptData arrays (API-FINDINGS.md 1.31). Its data.errors names ALL THREE even
    though the request omitted all three, which is the general shape of this
    validator: it reports every array complaint it has at once.

  - measuredSplitTunnelingExceptionsInViaTunnel is the 400 from API-FINDINGS.md
    1.30. It is the reason there is no CustomizeDiff on this resource.

  - specSplitTunnelingConflict is NOT MEASURED and says so in its name. No probe
    has provoked a 409 on this endpoint. It is the example the spec itself carries
    for 409_SplitTunnelingConflict (swagger.yaml:8208-8215), used only to prove
    that whatever the server puts in `message` reaches the operator's diagnostic.
*/
const (
	measuredSplitTunnelingViaTunnel = `{"defaultTunnelingMode":"via_tunnel","exceptData":` +
		`{"cidr":[],"addressObjectIds":[],"updatableObjectIds":[]}}`
	measuredSplitTunnelingWithException = `{"defaultTunnelingMode":"out_of_tunnel","exceptData":` +
		`{"cidr":["10.99.0.0/16"],"addressObjectIds":[],"updatableObjectIds":[],` +
		`"exceptions":[{"type":"cidr","destination":"10.99.0.1/32"}]}}`
	measuredSplitTunnelingNetworkGone = `{"message":"network doesnt exist",` +
		`"messageCode":"NOT_FOUND","status":404}`
	measuredSplitTunnelingArraysMissing = `{"data":{"errors":[` +
		`"exceptData.cidr must be an array",` +
		`"exceptData.addressObjectIds must be an array",` +
		`"exceptData.updatableObjectIds must be an array"]},` +
		`"message":"Bad Request Exception","messageCode":"BAD_REQUEST","status":400}`
	measuredSplitTunnelingExceptionsInViaTunnel = `{"message":"Exceptions are not supported in ` +
		`via_tunnel mode.","messageCode":"BAD_REQUEST","status":400}`
	specSplitTunnelingConflict = `{"status":409,"message":"UNSUPPORTED_UPDATABLE_OBJECT",` +
		`"messageCode":"CONFLICT"}`

	// The 202 captured from PUT /v3/networks/{id}/split-tunneling/async on
	// 2026-08-26 (API-FINDINGS.md 1.28, 1.29). Both fields are as measured: the
	// statusUrl is absolute, on a DIFFERENT host from the one the request went
	// to, and carries an /api/rest/v2.3/ path rather than /v3/.
	measuredSplitTunnelingAccepted = `{"statusUrl":"https://api.perimeter81-solo.com/api/rest/` +
		`v2.3/networks/status/n29PhQzjHW","samplingTime":120}`
)

/*
splitTunnelingStatusPathFragment is what an async status path carries on BOTH
hosts: the configured one (/v3/networks/status/{id}) and the one statusUrl names
(/api/rest/v2.3/networks/status/{id}). Matching on it rather than on the method
is what lets one recorder count polls against either, which is the whole content
of the statusUrl test below.

It is spelled out here rather than borrowed from private_dns_test.go's identical
constant so that the two resources' fakes stay independent -- these tests assert
on request LISTS, and a shared matcher would make one file's dispatch decisions
into the other file's problem.
*/
const splitTunnelingStatusPathFragment = "/networks/status/"

/*
splitTunnelingFake is one tenant's split-tunnelling surface: the GET this resource
reads, the async PUT it writes, and the status endpoint the PUT's 202 points at.

It records every request through requestLog, because several tests below assert on
WHERE the resource went and how many times -- and one asserts it went nowhere at
all, which only an ordered list of every call can prove.

getBodyAfterPut, when set, is what GETs return once a PUT has been seen. That
models the thing this resource exists to get right: the write is asynchronous, so
a read-back that returns pre-write values is exactly what a resource that did not
wait would store as applied.
*/
type splitTunnelingFake struct {
	log *requestLog
	srv *httptest.Server

	mu          sync.Mutex
	statusCalls int
	sawPut      bool

	// getStatus/getBody answer GET .../split-tunneling. Defaults: 200 and a
	// via_tunnel network with nothing excepted.
	getStatus int
	getBody   string
	// getBodyAfterPut, if set, replaces getBody once a PUT has been received.
	getBodyAfterPut string

	// putStatus/putBody answer PUT .../split-tunneling/async. Defaults: 202 with
	// the measured statusUrl.
	putStatus int
	putBody   string

	// statusBodies are served in order to successive status GETs; the last is
	// repeated if the provider polls more times than there are bodies.
	statusBodies []string
}

// startSplitTunnelingFake fills in the defaults and starts the server.
func startSplitTunnelingFake(t *testing.T, f *splitTunnelingFake) *splitTunnelingFake {
	t.Helper()

	f.log = &requestLog{}
	if f.getStatus == 0 {
		f.getStatus = http.StatusOK
	}
	if f.getBody == "" {
		f.getBody = measuredSplitTunnelingViaTunnel
	}
	if f.putStatus == 0 {
		f.putStatus = http.StatusAccepted
	}
	if f.putBody == "" {
		f.putBody = measuredSplitTunnelingAccepted
	}
	if len(f.statusBodies) == 0 {
		f.statusBodies = []string{`{"completed":true,"result":{"statusCode":200}}`}
	}

	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.log.record(r)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(r.URL.Path, splitTunnelingStatusPathFragment):
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
func (f *splitTunnelingFake) client() *perimeter81Sdk.APIClient {
	return newTestUserAPIClient(f.srv.URL)
}

// calls returns every request the fake received, as "METHOD /path", in order.
func (f *splitTunnelingFake) calls() []string {
	calls, _ := f.log.snapshot()
	return calls
}

// bodies returns every request body the fake received, positionally matching calls().
func (f *splitTunnelingFake) bodies() []string {
	_, bodies := f.log.snapshot()
	return bodies
}

// statusRequests returns the recorded requests that went to a status endpoint,
// wherever it was hosted.
func (f *splitTunnelingFake) statusRequests() []string {
	var matched []string
	for _, call := range f.calls() {
		if strings.Contains(call, splitTunnelingStatusPathFragment) {
			matched = append(matched, call)
		}
	}
	return matched
}

// putBodies returns the bodies of the PUTs the fake received.
func (f *splitTunnelingFake) putBodies() []string {
	calls, bodies := f.log.snapshot()
	var matched []string
	for i, call := range calls {
		if strings.HasPrefix(call, http.MethodPut+" ") {
			matched = append(matched, bodies[i])
		}
	}
	return matched
}

// testSplitTunnelingData builds a ResourceData over the REGISTERED resource
// schema -- not a copy of it -- holding the values a CRUD function reads.
func testSplitTunnelingData(t *testing.T, raw map[string]interface{}) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, resourceSplitTunneling().Schema, raw)
}

// useSplitTunnelingTestPollInterval collapses the production poll interval for
// the duration of one test, so a multi-poll test costs microseconds instead of
// half a minute. See splitTunnelingPollInterval's comment for why it is a var.
func useSplitTunnelingTestPollInterval(t *testing.T) {
	t.Helper()

	original := splitTunnelingPollInterval
	splitTunnelingPollInterval = testInterval
	t.Cleanup(func() { splitTunnelingPollInterval = original })
}

// ---------------------------------------------------------------------------
// The async write
// ---------------------------------------------------------------------------

/*
TestPutSplitTunnelingAndWaitPollsBeforeReturning pins the reason this write is
polled at all.

The PUT declares ONLY a 202 (swagger.yaml:1289) and the SDK returns
*AsyncOperationResponse, so returning as soon as the PUT succeeds means the write
has not happened yet: Create then reads back pre-write values and stores them as
applied. That is the failure putGranularFirewallPolicy's comment records shipping
three times on this branch.

The server answers `completed:false` twice and then `completed:true` with a 2xx,
so a helper that returns after the first status GET fails here just as loudly as
one that never polls at all.
*/
func TestPutSplitTunnelingAndWaitPollsBeforeReturning(t *testing.T) {
	useSplitTunnelingTestPollInterval(t)

	fake := startSplitTunnelingFake(t, &splitTunnelingFake{
		statusBodies: []string{
			`{"completed":false}`,
			`{"completed":false}`,
			`{"completed":true,"result":{"statusCode":200}}`,
		},
	})

	accepted, err := putSplitTunnelingAndWait(context.Background(), fake.client(), "net-1",
		perimeter81Sdk.SplitTunnelingBase{DefaultTunnelingMode: "via_tunnel"})
	if err != nil {
		t.Fatalf("putSplitTunnelingAndWait() error = %v, want nil for an operation that completes 200", err)
	}
	if !accepted {
		t.Error("putSplitTunnelingAndWait() accepted = false, want true: the PUT itself returned 202")
	}

	statusGets := fake.statusRequests()
	if len(statusGets) != 3 {
		t.Errorf("the helper made %d status GETs (%v), want 3 -- it must not return until the "+
			"operation reports completed", len(statusGets), statusGets)
	}
}

/*
TestPutSplitTunnelingAndWaitResolvesStatusUrlAgainstTheConfiguredClient pins
API-FINDINGS.md 1.28, on this endpoint.

Measured 2026-08-26: every async 202 on this API carries a statusUrl that is
absolute, points at a host the request did not go to, and carries an
/api/rest/v2.3/ path. Following it leaves the operator's configured BASE_URL --
which exists precisely so a non-US tenant talks to its own region -- and polls
whatever tenant lives at the other host. It fails INVISIBLY, because that other
deployment still answers with a well-formed {"completed":...}: a green apply for a
write it never saw.

The decoy below is that other deployment. It answers every poll with a completed
200, so a helper that follows statusUrl passes every other assertion in this file
and fails only this one.
*/
func TestPutSplitTunnelingAndWaitResolvesStatusUrlAgainstTheConfiguredClient(t *testing.T) {
	useSplitTunnelingTestPollInterval(t)

	decoy := startSplitTunnelingFake(t, &splitTunnelingFake{})

	// The same shape as the measured statusUrl -- absolute, different host, a
	// v2.3 path -- but pointed at a server this test can count hits on.
	statusUrl := decoy.srv.URL + "/api/rest/v2.3/networks/status/n29PhQzjHW"
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{
		putBody: `{"statusUrl":"` + statusUrl + `","samplingTime":120}`,
	})

	if _, err := putSplitTunnelingAndWait(context.Background(), fake.client(), "net-1",
		perimeter81Sdk.SplitTunnelingBase{DefaultTunnelingMode: "via_tunnel"}); err != nil {
		t.Fatalf("putSplitTunnelingAndWait() error = %v, want nil", err)
	}

	if hits := decoy.statusRequests(); len(hits) != 0 {
		t.Errorf("the helper followed statusUrl to the other host: %v. It must take the last "+
			"path segment and resolve it against the configured client, or a non-US tenant polls "+
			"the wrong deployment and gets a green apply for a write it never saw "+
			"(API-FINDINGS.md 1.28)", hits)
	}

	statusGets := fake.statusRequests()
	if len(statusGets) != 1 {
		t.Fatalf("the configured client got %d status GETs (%v), want 1", len(statusGets), statusGets)
	}
	if !strings.HasSuffix(statusGets[0], "/v3/networks/status/n29PhQzjHW") {
		t.Errorf("the status GET went to %q; the last segment of statusUrl must be resolved "+
			"against the configured client as /v3/networks/status/{id}", statusGets[0])
	}
}

/*
TestPutSplitTunnelingAndWaitOnMissingStatusUrl pins a DECISION, not an
implementation detail, and it is the same one putPrivateDNSAndWait took.

putGranularFirewallPolicy returns (false, nil) for a 202 with no statusUrl -- it
silently does not wait and reports the apply as successful. This returns
(true, error) instead: a 202 means the write has NOT happened yet, so a 202 with
nothing to poll is a write this provider cannot confirm, and reporting an
unconfirmable write as applied is the single outcome the helper exists to prevent.

`accepted` stays TRUE so the caller says "accepted but did not complete" rather
than "refused" -- the PUT itself did succeed, and the two send an operator to
different places.
*/
func TestPutSplitTunnelingAndWaitOnMissingStatusUrl(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{putBody: `{"samplingTime":120}`})

	accepted, err := putSplitTunnelingAndWait(context.Background(), fake.client(), "net-1",
		perimeter81Sdk.SplitTunnelingBase{DefaultTunnelingMode: "via_tunnel"})
	if !errors.Is(err, errSplitTunnelingNoStatusUrl) {
		t.Errorf("putSplitTunnelingAndWait() error = %v, want errSplitTunnelingNoStatusUrl: a 202 "+
			"with nothing to poll is a write this provider cannot confirm", err)
	}
	if !accepted {
		t.Error("putSplitTunnelingAndWait() accepted = false, want true: the PUT itself returned " +
			"202, so the caller must say \"accepted but did not complete\" and not \"refused\"")
	}
	if statusGets := fake.statusRequests(); len(statusGets) != 0 {
		t.Errorf("the helper polled %v with no statusUrl to poll", statusGets)
	}
}

/*
TestPutSplitTunnelingAndWaitReturnsNotAcceptedWhenThePutItselfFails pins the other
half of the `accepted` contract.

A refused PUT must report accepted = false, because the caller uses exactly that
to choose between "the API refused the request, nothing changed" and "the API
accepted the request and the operation then failed, go and look". Getting it
backwards tells an operator to inspect a network that was never touched, or --
worse -- tells them nothing changed when something might have.

The 400 driven here is the measured one for the missing arrays
(API-FINDINGS.md 1.31), so the body an operator would see is the real one.
*/
func TestPutSplitTunnelingAndWaitReturnsNotAcceptedWhenThePutItselfFails(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{
		putStatus: http.StatusBadRequest,
		putBody:   measuredSplitTunnelingArraysMissing,
	})

	accepted, err := putSplitTunnelingAndWait(context.Background(), fake.client(), "net-1",
		perimeter81Sdk.SplitTunnelingBase{DefaultTunnelingMode: "via_tunnel"})
	if err == nil {
		t.Fatal("putSplitTunnelingAndWait() error = nil, want the 400")
	}
	if accepted {
		t.Error("putSplitTunnelingAndWait() accepted = true after a 400: the caller would tell " +
			"the operator to go and inspect a network the API never touched")
	}
	if statusGets := fake.statusRequests(); len(statusGets) != 0 {
		t.Errorf("the helper polled %v after the PUT was refused", statusGets)
	}
}

// ---------------------------------------------------------------------------
// The request body
// ---------------------------------------------------------------------------

// splitTunnelingMarshalledBody expands a configuration and marshals the result,
// which is the only place the nil-vs-empty distinction is visible.
func splitTunnelingMarshalledBody(t *testing.T, raw map[string]interface{}) []byte {
	t.Helper()

	body, err := json.Marshal(expandSplitTunneling(testSplitTunnelingData(t, raw)))
	if err != nil {
		t.Fatalf("marshalling the expanded body failed: %v", err)
	}
	return body
}

/*
TestExpandSplitTunnelingNeverMarshalsNullArrays is a MARSHALLING test, not a
struct test, and it is the D8 trap measured rather than inferred.

MEASURED 2026-08-26 (API-FINDINGS.md 1.31): omitting `cidr`, `addressObjectIds`
or `updatableObjectIds` from exceptData returns a 400 whose data.errors names ALL
THREE, despite each carrying `default: []` in the schema (swagger.yaml:7133,
:7140, :7147). So the arrays are required on the wire even when empty, and the
`default` is a trap rather than a permission.

Nil and empty are the same length, the same type and DeepEqual-different only in
a way reflect will not tell you about, so the assertions are on json.Marshal
output. SplitTunnelingData declares all four fields `omitempty`, but its ToMap
gates on IsNil (utils.go:334) rather than on the struct tag -- so a non-nil empty
slice reaches the wire as `[]` and a nil one is dropped entirely. Both variants
compile and both marshal without error.

The first row is the one that matters most: a configuration naming NOTHING inside
except_data still has to produce three arrays.
*/
func TestExpandSplitTunnelingNeverMarshalsNullArrays(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  map[string]interface{}
	}{
		{
			// `except_data {}`: the block written with nothing in it.
			// helper/schema represents this as a one-element list whose element
			// is NIL rather than as a map of zero values, which is the case
			// singleBlock exists to report correctly.
			//
			// BE HONEST ABOUT WHAT THIS ROW PROVES, because the first version of
			// this comment claimed more: it does NOT fail if singleBlock is
			// "simplified" back to a bare `, ok` type assertion. That guard would
			// return false, the expander would take its early return, and the
			// early return already carries three empty arrays -- so the body is
			// byte-identical either way. Measured by mutation. What this row
			// does prove is that the DEFAULTS are there and are non-nil, which is
			// the thing the 400 is about.
			name: "except_data written empty",
			raw: map[string]interface{}{
				"network_id":             "net-1",
				"default_tunneling_mode": "out_of_tunnel",
				"except_data":            []interface{}{map[string]interface{}{}},
			},
		},
		{
			name: "except_data absent altogether",
			raw: map[string]interface{}{
				"network_id":             "net-1",
				"default_tunneling_mode": "via_tunnel",
			},
		},
		{
			// One list filled, two left out. The 400 names all three arrays even
			// when only one is missing, so this is the row where the operator
			// would be sent looking at the field they DID set.
			name: "one list set, the other two unset",
			raw: map[string]interface{}{
				"network_id":             "net-1",
				"default_tunneling_mode": "out_of_tunnel",
				"except_data": []interface{}{map[string]interface{}{
					"cidr": []interface{}{"10.99.0.0/16"},
				}},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := splitTunnelingMarshalledBody(t, tt.raw)
			for _, path := range []string{
				"exceptData/cidr",
				"exceptData/addressObjectIds",
				"exceptData/updatableObjectIds",
			} {
				assertMarshalsArrayAt(t, body, path)
			}
		})
	}
}

/*
TestExpandSplitTunnelingNeverSendsExceptions pins decision D5 on the wire.

`exceptions` is Computed-only, so no configuration can set it -- but a schema that
forbids writing it and an expander that sends it anyway are two different things,
and the second is reachable: `exceptions` is populated IN STATE by every Read, so
d.Get returns it, and an expander that read the whole except_data block back into
the payload would send whatever the last Read stored.

That is not a hypothetical tidy-up. It is the natural way to write this expander,
and it is exactly the failure API-FINDINGS.md 1.29 describes: the v3 write MERGES
exceptions, so a resource that echoed what it read could never remove one, and a
network that had been switched to via_tunnel (where the read returns none) would
have its stored exceptions resurrected on the switch back.

So this test loads state that HOLDS an exception -- the measured one -- and
asserts the key is absent from the body. A nil slice is not enough: the assertion
is that the KEY is absent, because `"exceptions": []` is not a clear either
(measured: the empty array merges and the exception survives).
*/
func TestExpandSplitTunnelingNeverSendsExceptions(t *testing.T) {
	body := splitTunnelingMarshalledBody(t, map[string]interface{}{
		"network_id":             "net-1",
		"default_tunneling_mode": "out_of_tunnel",
		"except_data": []interface{}{map[string]interface{}{
			"cidr": []interface{}{"10.99.0.0/16"},
			"exceptions": []interface{}{map[string]interface{}{
				"type":        "cidr",
				"destination": "10.99.0.1/32",
			}},
		}},
	})

	if value, present := jsonValueAt(t, body, "exceptData/exceptions"); present {
		t.Errorf("the body carries exceptData.exceptions = %#v. It must not be sent at all "+
			"(decision D5): the v3 write MERGES this field, so nothing sent through it can "+
			"remove a saved exception, and a via_tunnel network reads back with none while "+
			"still holding them -- so echoing what was read resurrects bypass rules the "+
			"operator never wrote (API-FINDINGS.md 1.29).\nbody: %s", value, body)
	}
}

/*
TestExpandSplitTunnelingSendsTheModeAndEveryDestination is the positive half of
the expander: what it DOES send, and in the shape the API accepts.

Without it, an expander that sent three empty arrays and dropped the operator's
actual values would pass every assertion in the two tests above -- they only
prove the arrays are present, not that they carry anything.
*/
func TestExpandSplitTunnelingSendsTheModeAndEveryDestination(t *testing.T) {
	body := splitTunnelingMarshalledBody(t, map[string]interface{}{
		"network_id":             "net-1",
		"default_tunneling_mode": "out_of_tunnel",
		"except_data": []interface{}{map[string]interface{}{
			"cidr":                 []interface{}{"10.99.0.0/16", "10.98.0.0/16"},
			"address_object_ids":   []interface{}{"abcdefghijk"},
			"updatable_object_ids": []interface{}{"6f9619ff-8b86-d011-b42d-00c04fc964ff"},
		}},
	})

	var decoded perimeter81Sdk.SplitTunnelingBase
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("could not decode the expanded body: %v\nbody: %s", err, body)
	}

	if decoded.DefaultTunnelingMode != "out_of_tunnel" {
		t.Errorf("defaultTunnelingMode = %q, want %q", decoded.DefaultTunnelingMode, "out_of_tunnel")
	}
	// Order is asserted as sent, and for cidr that is now backed by a measurement
	// rather than by caution: API-FINDINGS.md 1.31 sent three cidr entries
	// non-ascending and read them back in the order sent, on an ENHANCED network.
	// Only cidr was exercised -- the other two arrays were empty in that probe and
	// the standard family was not covered -- so this assertion is evidence-backed
	// for cidr and conservative for the rest. TypeSet would be wrong under either
	// reading: a set discards an ordering the server is now known to keep on at
	// least one of these arrays.
	if got := decoded.ExceptData.GetCidr(); len(got) != 2 ||
		got[0] != "10.99.0.0/16" || got[1] != "10.98.0.0/16" {
		t.Errorf("exceptData.cidr = %v, want the two CIDRs in the order written", got)
	}
	if got := decoded.ExceptData.GetAddressObjectIds(); len(got) != 1 || got[0] != "abcdefghijk" {
		t.Errorf("exceptData.addressObjectIds = %v, want [abcdefghijk]", got)
	}
	if got := decoded.ExceptData.GetUpdatableObjectIds(); len(got) != 1 ||
		got[0] != "6f9619ff-8b86-d011-b42d-00c04fc964ff" {
		t.Errorf("exceptData.updatableObjectIds = %v, want the one UUID", got)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/*
TestSplitTunnelingReadStoresTheConfigurationAsReturned drives Read against the
measured out_of_tunnel body and asserts every leaf reaches state.

EVERY LEAF, because the defect this catches is an OMISSION rather than a
misspelling. A flattener that never assigned `destination` would break no
compile, produce no diff on a network with no exceptions, and silently blank the
one field an operator reads to find out what is bypassing their tunnel. Task 2's
review found exactly that shape in flattenDnsPolicy, with zero coverage.
*/
func TestSplitTunnelingReadStoresTheConfigurationAsReturned(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{
		getBody: measuredSplitTunnelingWithException,
	})

	d := testSplitTunnelingData(t, map[string]interface{}{"network_id": "net-1"})
	d.SetId("net-1")

	if diags := resourceSplitTunnelingRead(context.Background(), d, fake.client()); diags.HasError() {
		t.Fatalf("the read failed: %s", diagsText(diags))
	}

	if got := d.Get("default_tunneling_mode").(string); got != "out_of_tunnel" {
		t.Errorf("default_tunneling_mode = %q, want %q", got, "out_of_tunnel")
	}
	if got := d.Get("except_data.#").(int); got != 1 {
		t.Fatalf("except_data.# = %d, want 1", got)
	}
	if got := d.Get("except_data.0.cidr.#").(int); got != 1 {
		t.Fatalf("except_data.0.cidr.# = %d, want 1", got)
	}
	if got := d.Get("except_data.0.cidr.0").(string); got != "10.99.0.0/16" {
		t.Errorf("except_data.0.cidr.0 = %q, want %q", got, "10.99.0.0/16")
	}
	if got := d.Get("except_data.0.address_object_ids.#").(int); got != 0 {
		t.Errorf("except_data.0.address_object_ids.# = %d, want 0", got)
	}
	if got := d.Get("except_data.0.updatable_object_ids.#").(int); got != 0 {
		t.Errorf("except_data.0.updatable_object_ids.# = %d, want 0", got)
	}
	if got := d.Get("except_data.0.exceptions.#").(int); got != 1 {
		t.Fatalf("except_data.0.exceptions.# = %d, want 1 -- the exception the tenant still "+
			"holds (LEFTOVERS.md L33) is the whole reason this attribute is surfaced at all", got)
	}
	if got := d.Get("except_data.0.exceptions.0.type").(string); got != "cidr" {
		t.Errorf("except_data.0.exceptions.0.type = %q, want %q", got, "cidr")
	}
	if got := d.Get("except_data.0.exceptions.0.destination").(string); got != "10.99.0.1/32" {
		t.Errorf("except_data.0.exceptions.0.destination = %q, want %q -- an exception with no "+
			"destination tells an operator nothing about what is bypassing their tunnel",
			got, "10.99.0.1/32")
	}
}

/*
TestSplitTunnelingReadOnViaTunnelStoresNoExceptions drives Read against the P1
capture, which has NO `exceptions` key at all.

That absence is the ordinary case in via_tunnel mode, not an edge case: exceptions
are not supported there, so nothing surfaces them. It decodes to a nil slice, and
a flattener that returned nil rather than an empty list would store `null` where
Terraform expects a list.

WHAT THIS EMPTY LIST DOES NOT MEAN, and it is why the attribute is Computed-only:
the exceptions may still exist. Row (d) of API-FINDINGS.md 1.29 switched a network
holding an exception to via_tunnel, read back no exceptions key, switched back
WITHOUT sending exceptions, and got the exception again from server-side storage.
Nothing this Read can see distinguishes "none" from "hidden".
*/
func TestSplitTunnelingReadOnViaTunnelStoresNoExceptions(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{getBody: measuredSplitTunnelingViaTunnel})

	d := testSplitTunnelingData(t, map[string]interface{}{"network_id": "net-1"})
	d.SetId("net-1")

	if diags := resourceSplitTunnelingRead(context.Background(), d, fake.client()); diags.HasError() {
		t.Fatalf("the read failed: %s", diagsText(diags))
	}

	if got := d.Get("default_tunneling_mode").(string); got != "via_tunnel" {
		t.Errorf("default_tunneling_mode = %q, want %q", got, "via_tunnel")
	}
	if got := d.Get("except_data.#").(int); got != 1 {
		t.Fatalf("except_data.# = %d, want 1: the block must be stored even when every list in "+
			"it is empty, or the next plan proposes adding it", got)
	}
	for _, path := range []string{
		"except_data.0.cidr.#",
		"except_data.0.address_object_ids.#",
		"except_data.0.updatable_object_ids.#",
		"except_data.0.exceptions.#",
	} {
		if got := d.Get(path).(int); got != 0 {
			t.Errorf("%s = %d, want 0", path, got)
		}
	}
}

/*
TestSplitTunnelingReadClearsIdWhenTheNetworkIsGone pins SPT-D01, and it pins a
branch this codebase has three times been wrong to add elsewhere.

A 404 here clears the id and returns NO diagnostics, so the next plan proposes
recreating the configuration rather than failing. That is correct HERE and was
wrong in Phase 3/4, and the difference is what the 404 means on each endpoint:

  - Phase 3/4's were COLLECTION reads, where a 404 meant the URL was wrong.
    Treating that as drift emptied Terraform's state on a misconfiguration.
  - This is a SINGLE OBJECT addressed by a user-supplied network id, and probe P10
    measured what a wrong one gets on 2026-08-26: 404 with
    {"message":"network doesnt exist","messageCode":"NOT_FOUND","status":404}.
    The message names the OBJECT, not the route.

The companion assertion is in the test below: a non-404 must NOT clear the id.
Without it this test passes for an implementation that clears the id on every
error, which would turn a transient 500 into a silent state wipe.
*/
func TestSplitTunnelingReadClearsIdWhenTheNetworkIsGone(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{
		getStatus: http.StatusNotFound,
		getBody:   measuredSplitTunnelingNetworkGone,
	})

	d := testSplitTunnelingData(t, map[string]interface{}{"network_id": "net-gone"})
	d.SetId("net-gone")

	diags := resourceSplitTunnelingRead(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("a 404 must be reported as drift, not as an error: %s", diagsText(diags))
	}
	if d.Id() != "" {
		t.Errorf("d.Id() = %q after a 404, want empty: the next plan has to propose recreating "+
			"the configuration on a network the operator will have to recreate too", d.Id())
	}
}

/*
TestSplitTunnelingReadKeepsTheIdOnEveryOtherError is the companion to the test
above, and without it that one is satisfied by clearing the id unconditionally.

A 500 is not drift. Clearing the id on one would silently remove a live resource
from state on a transient server-side failure, and the next apply would propose
recreating something that never went anywhere.
*/
func TestSplitTunnelingReadKeepsTheIdOnEveryOtherError(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
	}{
		{"a server-side failure", http.StatusInternalServerError, `{"message":"boom"}`},
		{"a permission failure", http.StatusForbidden, `{"message":"forbidden"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := startSplitTunnelingFake(t, &splitTunnelingFake{
				getStatus: tt.status,
				getBody:   tt.body,
			})

			d := testSplitTunnelingData(t, map[string]interface{}{"network_id": "net-1"})
			d.SetId("net-1")

			diags := resourceSplitTunnelingRead(context.Background(), d, fake.client())
			if !diags.HasError() {
				t.Fatalf("a %d must be an error, not drift", tt.status)
			}
			if d.Id() != "net-1" {
				t.Errorf("d.Id() = %q after a %d, want it kept: a transient failure is not a "+
					"vanished network, and clearing the id here silently removes a live "+
					"resource from state", d.Id(), tt.status)
			}
		})
	}
}

/*
TestSplitTunnelingReadSurvivesANullBody pins the one nil-handling gap on this
Read.

APIClient.decode runs json.Unmarshal into *SplitTunnelingBase. A literal `null`
body decodes WITHOUT ERROR and leaves the pointer nil, so a 200 carrying `null`
reaches the d.Set block with splitTunneling == nil. GetDefaultTunnelingMode() is
nil-safe -- the generated getters check o == nil -- but splitTunneling.ExceptData
on the next line is a DIRECT FIELD ACCESS, and it has to be: ExceptData is a
VALUE in the generated struct, not a pointer, so there is no nil-safe getter that
returns something a flattener can take.

A panic is the one failure mode Terraform cannot report usefully: the operator
gets a plugin crash and a stack trace instead of a diagnostic naming the resource.

UNMEASURED, AND SAID SO. No probe has seen this endpoint return `null`; the guard
is here because the cost of being wrong is a crash and the cost of the guard is
two lines.
*/
func TestSplitTunnelingReadSurvivesANullBody(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{getBody: `null`})

	d := testSplitTunnelingData(t, map[string]interface{}{"network_id": "net-1"})
	d.SetId("net-1")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Read PANICKED on a 200 with a null body: %v. Terraform cannot report a "+
				"panic as a diagnostic -- the operator gets a plugin crash instead", r)
		}
	}()

	if diags := resourceSplitTunnelingRead(context.Background(), d, fake.client()); diags.HasError() {
		t.Fatalf("the read failed: %s", diagsText(diags))
	}
	if got := d.Get("except_data.#").(int); got != 1 {
		t.Errorf("except_data.# = %d, want 1 -- an empty configuration is the right reading of "+
			"an empty answer", got)
	}
}

// ---------------------------------------------------------------------------
// Create and Update
// ---------------------------------------------------------------------------

/*
TestSplitTunnelingCreateAdoptsWritesWaitsAndReadsBack walks the whole create path
and asserts the ORDER of what it did, because every individual step passing while
the order is wrong is precisely the async bug.

The fake returns the pre-write body until it sees a PUT and the post-write body
afterwards, so a Create that read back before polling would store `via_tunnel`
and report the apply as successful.
*/
func TestSplitTunnelingCreateAdoptsWritesWaitsAndReadsBack(t *testing.T) {
	useSplitTunnelingTestPollInterval(t)

	fake := startSplitTunnelingFake(t, &splitTunnelingFake{
		getBody:         measuredSplitTunnelingViaTunnel,
		getBodyAfterPut: measuredSplitTunnelingWithException,
		statusBodies: []string{
			`{"completed":false}`,
			`{"completed":true,"result":{"statusCode":200}}`,
		},
	})

	d := testSplitTunnelingData(t, map[string]interface{}{
		"network_id":             "net-1",
		"default_tunneling_mode": "out_of_tunnel",
		"except_data": []interface{}{map[string]interface{}{
			"cidr": []interface{}{"10.99.0.0/16"},
		}},
	})

	if diags := resourceSplitTunnelingCreate(context.Background(), d, fake.client()); diags.HasError() {
		t.Fatalf("the create failed: %s", diagsText(diags))
	}

	if d.Id() != "net-1" {
		t.Errorf("d.Id() = %q, want the network id", d.Id())
	}
	want := []string{
		"GET /v3/networks/net-1/split-tunneling",
		"PUT /v3/networks/net-1/split-tunneling/async",
		"GET /v3/networks/status/n29PhQzjHW",
		"GET /v3/networks/status/n29PhQzjHW",
		"GET /v3/networks/net-1/split-tunneling",
	}
	if got := fake.calls(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("the create made\n  %v\nwant\n  %v", got, want)
	}
	if got := d.Get("default_tunneling_mode").(string); got != "out_of_tunnel" {
		t.Errorf("default_tunneling_mode = %q after the create, want the POST-write value: a "+
			"read-back that runs before the operation completes stores pre-write values and "+
			"reports the apply as successful", got)
	}
}

/*
TestSplitTunnelingCreateRefusesAMissingNetworkAndWritesNothing pins the OPPOSITE
of Read's 404 handling, and the two are only apparently inconsistent.

In Read a 404 means an object Terraform was tracking has gone: drift. Here nothing
is tracked yet -- the operator has just named a network that does not exist -- and
treating that as drift would report a successful apply against a network id that
was never valid.

The zero-PUTs assertion is the load-bearing one. A Create that logged the failure
and carried on would write a configuration to a path that answers 404.
*/
func TestSplitTunnelingCreateRefusesAMissingNetworkAndWritesNothing(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{
		getStatus: http.StatusNotFound,
		getBody:   measuredSplitTunnelingNetworkGone,
	})

	d := testSplitTunnelingData(t, map[string]interface{}{
		"network_id":             "net-gone",
		"default_tunneling_mode": "out_of_tunnel",
	})

	diags := resourceSplitTunnelingCreate(context.Background(), d, fake.client())
	if !diags.HasError() {
		t.Fatal("creating against a network the API does not know reported success")
	}
	if d.Id() != "" {
		t.Errorf("d.Id() = %q, want empty after a refused create", d.Id())
	}
	if got := len(fake.putBodies()); got != 0 {
		t.Errorf("the create issued %d PUT(s) after the adoption GET returned 404", got)
	}
}

/*
TestSplitTunnelingCreateFailsOnANon2xxCompletion pins SPT-N02.

pollAsync already requires a 2xx result.statusCode rather than merely
completed == true -- that check is not new code and this test is not asking for
any. What it proves is that the check FIRES ON THIS PATH, which depends entirely
on this resource's poll closure copying result.statusCode into asyncResult.
StatusCode stays 0 when it does not, and isSuccessStatus (async.go:147) treats 0
as success, because some successful completions elsewhere omit statusCode.

So the defect this catches is three lines silently missing from
putSplitTunnelingAndWait, with the symptom that EVERY failed completion is
reported as a successful apply.

The 400 row is the measured failure shape for this endpoint. The 409 row is there
because a conflict completing async is the case where "it said completed, so it
worked" is most tempting and most wrong.

NO ID MAY BE WRITTEN. That is the second half of SPT-N02, and it is why this test
drives Create rather than the helper directly.
*/
func TestSplitTunnelingCreateFailsOnANon2xxCompletion(t *testing.T) {
	useSplitTunnelingTestPollInterval(t)

	for _, tt := range []struct {
		name   string
		status string
	}{
		{"a rejected write", `{"completed":true,"result":{"statusCode":400,` +
			`"reason":["Exceptions are not supported in via_tunnel mode."]}}`},
		{"a conflict", `{"completed":true,"result":{"statusCode":409,` +
			`"reason":["UNSUPPORTED_UPDATABLE_OBJECT"]}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := startSplitTunnelingFake(t, &splitTunnelingFake{
				statusBodies: []string{tt.status},
			})

			d := testSplitTunnelingData(t, map[string]interface{}{
				"network_id":             "net-1",
				"default_tunneling_mode": "out_of_tunnel",
			})

			diags := resourceSplitTunnelingCreate(context.Background(), d, fake.client())
			if !diags.HasError() {
				t.Fatalf("the operation completed with %s and the apply reported SUCCESS. "+
					"`completed: true` is not enough -- result.statusCode has to be carried "+
					"into asyncResult for pollAsync to see it", tt.status)
			}
			if d.Id() != "" {
				t.Errorf("d.Id() = %q after a failed completion, want empty (SPT-N02)", d.Id())
			}
			if text := diagsText(diags); !strings.Contains(text, "async operation failed") {
				t.Errorf("the diagnostic does not report the operation's failure:\n%s", text)
			}
		})
	}
}

/*
TestSplitTunnelingCreateTimesOutWithoutWritingAnId pins SPT-N03.

THE INTERVAL IS DELIBERATELY NOT COLLAPSED HERE, which is the opposite of every
other polling test in this file, and it is what makes this one deterministic. The
production interval is 10s and the context deadline is 50ms, so the sequence is
forced: one status GET returns `completed:false`, sleepCtx is then asked to wait
10s, and the deadline fires during that wait. Exactly one poll, every time, on any
machine. Collapsing the interval instead would make the number of polls a race
against the wall clock.

Two things are asserted and both are in the row:

  - the error is a DEADLINE error, not a hang and not a silent success. pollAsync
    honours ctx precisely so a Terraform timeout produces one; the `Timeouts`
    block on the resource is what gives that ctx a deadline in production
    (asyncResourceTimeout, 30 minutes, overridable per resource).
  - NO ID IS WRITTEN TO STATE. A timed-out apply must leave Terraform saying the
    outcome is unknown, not recording the configured values as applied.
*/
func TestSplitTunnelingCreateTimesOutWithoutWritingAnId(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{
		statusBodies: []string{`{"completed":false}`},
	})

	d := testSplitTunnelingData(t, map[string]interface{}{
		"network_id":             "net-1",
		"default_tunneling_mode": "out_of_tunnel",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	diags := resourceSplitTunnelingCreate(ctx, d, fake.client())
	if !diags.HasError() {
		t.Fatal("an operation that never completes reported a successful apply")
	}
	if d.Id() != "" {
		t.Errorf("d.Id() = %q after the deadline expired, want empty: state must say the "+
			"outcome is unknown, not record the configured values as applied (SPT-N03)", d.Id())
	}
	if text := diagsText(diags); !strings.Contains(text, "timed out waiting for the async operation") {
		t.Errorf("the diagnostic does not name the timeout, so an operator cannot tell a "+
			"deadline from a refusal:\n%s", text)
	}
	if got := len(fake.statusRequests()); got != 1 {
		t.Errorf("the resource made %d status GETs, want exactly 1 -- the deadline has to fire "+
			"during the wait between polls, or this test is timing-dependent", got)
	}
}

/*
TestSplitTunnelingUpdateSendsTheFullReplacementBody asserts what actually reaches
the wire on an update, not what the expander returns.

The two are different tests. The expander tests above marshal its return value;
this one reads the body the SDK put on the socket, which is the only place a
`Body()` that was never called, or a payload built from the wrong ResourceData,
would show.
*/
func TestSplitTunnelingUpdateSendsTheFullReplacementBody(t *testing.T) {
	useSplitTunnelingTestPollInterval(t)

	fake := startSplitTunnelingFake(t, &splitTunnelingFake{})

	d := testSplitTunnelingData(t, map[string]interface{}{
		"network_id":             "net-1",
		"default_tunneling_mode": "out_of_tunnel",
		"except_data": []interface{}{map[string]interface{}{
			"cidr":               []interface{}{"10.99.0.0/16"},
			"address_object_ids": []interface{}{"abcdefghijk"},
		}},
	})
	d.SetId("net-1")

	if diags := resourceSplitTunnelingUpdate(context.Background(), d, fake.client()); diags.HasError() {
		t.Fatalf("the update failed: %s", diagsText(diags))
	}

	putBodies := fake.putBodies()
	if len(putBodies) != 1 {
		t.Fatalf("the update sent %d PUTs (%v), want 1", len(putBodies), putBodies)
	}
	body := []byte(putBodies[0])

	if mode, _ := jsonValueAt(t, body, "defaultTunnelingMode"); mode != "out_of_tunnel" {
		t.Errorf("defaultTunnelingMode on the wire = %v, want out_of_tunnel", mode)
	}
	for _, path := range []string{
		"exceptData/cidr",
		"exceptData/addressObjectIds",
		"exceptData/updatableObjectIds",
	} {
		assertMarshalsArrayAt(t, body, path)
	}
	if _, present := jsonValueAt(t, body, "exceptData/exceptions"); present {
		t.Errorf("exceptData.exceptions reached the wire; it is Computed-only and must never be "+
			"sent (decision D5).\nbody: %s", body)
	}
}

/*
TestSplitTunnelingUpdateGuidanceReachesTheDiagnostic pins the reason
appendErrorDiagsWithGuidance exists.

appendErrorDiags promotes a GenericOpenAPIError's response body into Detail and
DISCARDS whatever the caller wrapped it with. That is right for an ordinary
failure -- the body is the useful half -- but here the wrapper is the entire "what
to do about it". Measured on the SWG policies, the whole diagnostic an operator saw
for a failed read-back was the summary and `{"message":"re-read failed"}`, with
every word of the guidance reaching nobody.

Both branches are driven, because they say opposite things and the `accepted`
return is the only thing that picks between them. Telling an operator "nothing
changed" when the API accepted the write is worse than saying nothing.
*/
func TestSplitTunnelingUpdateGuidanceReachesTheDiagnostic(t *testing.T) {
	useSplitTunnelingTestPollInterval(t)

	for _, tt := range []struct {
		name     string
		fake     *splitTunnelingFake
		guidance string
		// absent is the OTHER branch's guidance, which must not appear.
		absent string
	}{
		{
			// The measured via_tunnel + exceptions 400 (API-FINDINGS.md 1.30).
			// Unreachable through this resource's schema, but it is a real body
			// this endpoint returns and the refusal branch has to render it.
			name: "the API refuses the write",
			fake: &splitTunnelingFake{
				putStatus: http.StatusBadRequest,
				putBody:   measuredSplitTunnelingExceptionsInViaTunnel,
			},
			guidance: splitTunnelingWriteRefused,
			absent:   splitTunnelingWriteAcceptedButNotCompleted,
		},
		{
			name: "the API accepts it and the operation then fails",
			fake: &splitTunnelingFake{
				statusBodies: []string{
					`{"completed":true,"result":{"statusCode":500,"reason":["internal"]}}`,
				},
			},
			guidance: splitTunnelingWriteAcceptedButNotCompleted,
			absent:   splitTunnelingWriteRefused,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := startSplitTunnelingFake(t, tt.fake)

			d := testSplitTunnelingData(t, map[string]interface{}{
				"network_id":             "net-1",
				"default_tunneling_mode": "out_of_tunnel",
			})
			d.SetId("net-1")

			diags := resourceSplitTunnelingUpdate(context.Background(), d, fake.client())
			if !diags.HasError() {
				t.Fatal("the update reported success")
			}
			text := diagsText(diags)
			if !strings.Contains(text, tt.guidance) {
				t.Errorf("the guidance never reached the diagnostic. appendErrorDiags alone "+
					"renders the server's body and discards the caller's wrapper, so this has "+
					"to go through appendErrorDiagsWithGuidance.\ngot:\n%s", text)
			}
			if strings.Contains(text, tt.absent) {
				t.Errorf("the diagnostic carries the OTHER branch's guidance, which says the "+
					"opposite thing about whether anything changed:\n%s", text)
			}
		})
	}
}

/*
TestSplitTunnelingUpdateSurfacesThe409Message pins the one thing this endpoint's
409 needs, and it is not obvious from the SDK.

The SDK decodes a 409 on this path into a DEDICATED model,
UpdateSplitTunnelingConfigurationAsync409Response (api_networks.go:549), and then
runs it through formatErrorMessage -- which fmt.Sprintf("%v")s the struct and
tries to json.Unmarshal the result into a map[string]string. That fails for
anything that is not already JSON, so err.Error() for a 409 here is the BARE
STRING "409 Conflict": no message, no messageCode, nothing an operator can act
on.

The message survives only because appendErrorDiags prefers
GenericOpenAPIError.Body() -- the raw server JSON -- over Error(). This test
asserts the message reaches the diagnostic, so that a future "simplification" of
the error path to err.Error() fails here rather than silently reducing every
conflict to two words.

The body is the SPEC's own example (swagger.yaml:8208-8215), not a measurement:
no probe has provoked a 409 on this endpoint.
*/
func TestSplitTunnelingUpdateSurfacesThe409Message(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{
		putStatus: http.StatusConflict,
		putBody:   specSplitTunnelingConflict,
	})

	d := testSplitTunnelingData(t, map[string]interface{}{
		"network_id":             "net-1",
		"default_tunneling_mode": "out_of_tunnel",
	})
	d.SetId("net-1")

	diags := resourceSplitTunnelingUpdate(context.Background(), d, fake.client())
	if !diags.HasError() {
		t.Fatal("a 409 reported a successful apply")
	}
	text := diagsText(diags)
	if !strings.Contains(text, "UNSUPPORTED_UPDATABLE_OBJECT") {
		t.Errorf("the 409's message never reached the diagnostic, so the operator sees only "+
			"\"409 Conflict\" and has no way to learn which updatable object the API could not "+
			"reconcile:\n%s", text)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

/*
TestSplitTunnelingDeleteMakesNoRequest pins decision D9, and the assertion is on
the WHOLE request list rather than on the absence of one method.

A Delete that "tidily" wrote `via_tunnel` before clearing the id would change
which of a live network's traffic bypasses the tunnel as a side effect of somebody
removing a Terraform resource, with no plan line saying so. Asserting zero
requests is the only form of this test that cannot be satisfied by a Delete that
issues a different call from the one an assertion happened to name.

The warning is part of the behaviour rather than decoration: a destroy that
silently changes nothing and a destroy that silently rewrites a production
network's tunnelling print the same thing in the console.
*/
func TestSplitTunnelingDeleteMakesNoRequest(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{})

	d := testSplitTunnelingData(t, map[string]interface{}{
		"network_id":             "net-1",
		"default_tunneling_mode": "out_of_tunnel",
	})
	d.SetId("net-1")

	diags := resourceSplitTunnelingDelete(context.Background(), d, fake.client())
	if diags.HasError() {
		t.Fatalf("the delete failed: %s", diagsText(diags))
	}
	if calls := fake.calls(); len(calls) != 0 {
		t.Errorf("the delete made %d request(s): %v. D9 is that destroy clears state and issues "+
			"NO call -- there is no \"off\" for a tunnelling mode, so anything it wrote would be "+
			"a silent security change", len(calls), calls)
	}
	if d.Id() != "" {
		t.Errorf("d.Id() = %q after the delete, want empty", d.Id())
	}
	if len(diags) != 1 || diags[0].Severity != diag.Warning {
		t.Fatalf("want exactly one warning diagnostic, got %s", diagsText(diags))
	}
	if !strings.Contains(diags[0].Detail, "net-1") {
		t.Errorf("the warning does not name the network it stopped tracking:\n%s", diags[0].Detail)
	}
}

// ---------------------------------------------------------------------------
// Schema, validation and planning
// ---------------------------------------------------------------------------

/*
splitTunnelingValidateConfig runs the SDK's VALIDATION path over a configuration.

IT IS Validate AND NOT Diff, AND THAT DISTINCTION IS THE WHOLE POINT. Phase 5
found the hard way that MaxItems and every other schema-level constraint --
including ValidateFunc on a list's element schema -- are enforced by
schemaMap.Validate, NOT by Resource.Diff. A test that drove Diff watched
MaxItems 100 -> 4 -> 1 all pass green: it could not fail, whatever the schema
said.

  - @param t *testing.T
  - @param raw map[string]interface{} - the configuration, as HCL decodes to

@return error - the joined validation errors, or nil
*/
func splitTunnelingValidateConfig(t *testing.T, raw map[string]interface{}) error {
	t.Helper()

	// The REGISTERED resource, so this drives the schema that actually ships
	// rather than a copy of it.
	r := resourceSplitTunneling()
	diags := r.Validate(terraform.NewResourceConfigRaw(raw))

	var sb strings.Builder
	for _, d := range diags {
		if d.Severity != diag.Error {
			continue
		}
		sb.WriteString(d.Summary)
		sb.WriteString(" ")
		sb.WriteString(d.Detail)
		sb.WriteString("\n")
	}
	if sb.Len() == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.TrimSpace(sb.String()))
}

/*
TestSplitTunnelingValidationEnforcesTheModeAndCIDRFormat covers the two
plan-time checks this schema makes, in both directions.

THE MODE IS CASE-SENSITIVE ON PURPOSE. The API does not fold case on enums, and a
case-insensitive check would let "Out_Of_Tunnel" through plan and fail well into
an apply -- the Phase 3 `access`/`"Read"` lesson. So "OUT_OF_TUNNEL" has to be
refused, and a test that only checked "nonsense" would pass a validator built with
`ignoreCase = true`.

THE CIDR CHECK IS FORMAT ONLY, and validation.IsCIDR is deliberately WIDER than
the spec's pattern (swagger.yaml:7131 is IPv4-only; IsCIDR accepts IPv6 too). That
is the safe direction: the provider never refuses something the server accepts.
The accepted rows are as load-bearing as the refused one -- a validator that
rejected `10.1.2.3/32`, which is the shape every exception destination takes,
would be worse than none.
*/
func TestSplitTunnelingValidationEnforcesTheModeAndCIDRFormat(t *testing.T) {
	config := func(mode string, cidr ...interface{}) map[string]interface{} {
		return map[string]interface{}{
			"network_id":             "net-1",
			"default_tunneling_mode": mode,
			"except_data": []interface{}{map[string]interface{}{
				"cidr": cidr,
			}},
		}
	}

	for _, tt := range []struct {
		name    string
		raw     map[string]interface{}
		wantErr string
	}{
		{name: "via_tunnel", raw: config("via_tunnel")},
		{name: "out_of_tunnel", raw: config("out_of_tunnel")},
		{
			name:    "a mode the API does not know",
			raw:     config("tunnel_all"),
			wantErr: "default_tunneling_mode",
		},
		{
			// The case-folding row. A validator built with ignoreCase = true
			// passes every other row here and fails only this one.
			name:    "the right mode in the wrong case",
			raw:     config("OUT_OF_TUNNEL"),
			wantErr: "default_tunneling_mode",
		},
		{name: "a subnet", raw: config("out_of_tunnel", "10.99.0.0/16")},
		{
			// The shape every exception destination takes. A /32 must be legal.
			name: "a single address",
			raw:  config("out_of_tunnel", "10.1.2.3/32"),
		},
		{name: "the default route", raw: config("out_of_tunnel", "0.0.0.0/0")},
		{
			name:    "an address with no prefix length",
			raw:     config("out_of_tunnel", "10.99.0.0"),
			wantErr: "cidr",
		},
		{
			name:    "not an address at all",
			raw:     config("out_of_tunnel", "10.99.0.0/16, 10.98.0.0/16"),
			wantErr: "cidr",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := splitTunnelingValidateConfig(t, tt.raw)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("a legal configuration was refused at plan time: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("the configuration was accepted; it must fail the plan rather than the "+
					"apply (wanted an error naming %q)", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("the error does not name %q, so the operator has to guess which "+
					"argument is wrong: %v", tt.wantErr, err)
			}
		})
	}
}

/*
TestSplitTunnelingExceptionsAreComputedOnly pins decision D5 in the SCHEMA, which
is the other half of the expander test above.

Three separate assertions, because Computed-only is three facts and dropping any
one of them reopens the hole:

  - Computed is set, so Read can store what the API reports.
  - Optional and Required are NOT set, so no configuration can name the attribute.
  - the two leaves are Computed-only too, because a Computed list whose elements
    were writable would let a configuration set them.

The fourth assertion is behavioural rather than structural: a configuration that
tries to write `exceptions` must be REFUSED, which is what makes the first three
mean something to an operator rather than only to a reader of the schema.
*/
func TestSplitTunnelingExceptionsAreComputedOnly(t *testing.T) {
	exceptData := resourceSplitTunneling().Schema["except_data"]
	block, ok := exceptData.Elem.(*schema.Resource)
	if !ok {
		t.Fatal("except_data has no element resource")
	}
	exceptions, ok := block.Schema["exceptions"]
	if !ok {
		t.Fatal("except_data no longer declares exceptions; D5 is that it is SURFACED and " +
			"never sent, not that it is absent")
	}

	if !exceptions.Computed {
		t.Error("exceptions is not Computed, so a read cannot store it")
	}
	if exceptions.Optional || exceptions.Required {
		t.Error("exceptions is writable. The v3 write MERGES this field, so a configuration " +
			"that dropped an exception would apply cleanly and read it straight back, diffing " +
			"for ever -- and a resource that stored the empty list a via_tunnel network returns " +
			"would resurrect bypass rules on the switch back to out_of_tunnel " +
			"(API-FINDINGS.md 1.29, LEFTOVERS.md L33)")
	}

	leaves, ok := exceptions.Elem.(*schema.Resource)
	if !ok {
		t.Fatal("exceptions has no element resource")
	}
	for _, name := range []string{"type", "destination"} {
		leaf, ok := leaves.Schema[name]
		if !ok {
			t.Errorf("exceptions no longer surfaces %q", name)
			continue
		}
		if !leaf.Computed || leaf.Optional || leaf.Required {
			t.Errorf("exceptions.%s is writable; the whole block has to be read-only", name)
		}
	}

	err := splitTunnelingValidateConfig(t, map[string]interface{}{
		"network_id":             "net-1",
		"default_tunneling_mode": "out_of_tunnel",
		"except_data": []interface{}{map[string]interface{}{
			"exceptions": []interface{}{map[string]interface{}{
				"type":        "cidr",
				"destination": "10.99.0.1/32",
			}},
		}},
	})
	if err == nil {
		t.Error("a configuration that writes except_data.exceptions was ACCEPTED at plan time")
	}
}

/*
replanSplitTunneling re-plans a configuration against the state a previous apply
left behind.

splitTunnelingValidateConfig above passes no prior state, so it can only show
whether a configuration is refused. It cannot see a permanent diff, because a
permanent diff is by definition a disagreement between what the server returned
and what the configuration says -- and with no prior state there is nothing for
the configuration to disagree with.

  - @param t *testing.T
  - @param prior *terraform.InstanceState - state as a previous apply left it
  - @param configJSON string - the unchanged configuration, re-planned

@return *terraform.InstanceDiff - what the second plan proposes; Empty() means clean
*/
func replanSplitTunneling(t *testing.T, prior *terraform.InstanceState,
	configJSON string) *terraform.InstanceDiff {

	t.Helper()

	r := resourceSplitTunneling()
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
TestSplitTunnelingDoesNotDiffForever is the convergence test, and the exception
row is the one that matters.

The tenant holds a split-tunnelling configuration with a saved exception that
CANNOT BE REMOVED through the v3 API (API-FINDINGS.md 1.29, LEFTOVERS.md L33). So
every Read of that network stores an exception no configuration can name, and if
`exceptions` were writable in any way -- Optional, or Optional+Computed -- the
plan after the first apply would propose removing it, the apply would send an
empty array, the merge would restore it, and the resource would never converge.
Computed-only is what makes "the configuration names none" mean "whatever the
server holds".

THE TEST DRIVES THE REAL CHAIN rather than a hand-written prior state: it runs
Read against the measured body, takes the state that produced, and re-plans the
unchanged configuration against it. So it fails for a flattener defect, a schema
defect, or anything else that breaks convergence, and it cannot pass because a
fixture was written to match the code.

The second row is the empty case, which catches the mirror-image defect: a
flattener that stored nil rather than `[]` for the three id lists would make an
`except_data {}` configuration diff for ever too.
*/
func TestSplitTunnelingDoesNotDiffForever(t *testing.T) {
	for _, tt := range []struct {
		name   string
		body   string
		config string
		raw    map[string]interface{}
	}{
		{
			name:   "a network holding an exception no configuration can name",
			body:   measuredSplitTunnelingWithException,
			config: `{"network_id":"net-1","default_tunneling_mode":"out_of_tunnel","except_data":[{"cidr":["10.99.0.0/16"]}]}`,
			raw: map[string]interface{}{
				"network_id":             "net-1",
				"default_tunneling_mode": "out_of_tunnel",
				"except_data": []interface{}{map[string]interface{}{
					"cidr": []interface{}{"10.99.0.0/16"},
				}},
			},
		},
		{
			name:   "a via_tunnel network with nothing excepted",
			body:   measuredSplitTunnelingViaTunnel,
			config: `{"network_id":"net-1","default_tunneling_mode":"via_tunnel","except_data":[{}]}`,
			raw: map[string]interface{}{
				"network_id":             "net-1",
				"default_tunneling_mode": "via_tunnel",
				"except_data":            []interface{}{map[string]interface{}{}},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := startSplitTunnelingFake(t, &splitTunnelingFake{getBody: tt.body})

			d := testSplitTunnelingData(t, tt.raw)
			d.SetId("net-1")

			if diags := resourceSplitTunnelingRead(
				context.Background(), d, fake.client()); diags.HasError() {
				t.Fatalf("the read failed: %s", diagsText(diags))
			}

			diff := replanSplitTunneling(t, d.State(), tt.config)
			if diff != nil && !diff.Empty() {
				t.Fatalf("re-planning the unchanged configuration proposes a change, so this "+
					"resource NEVER CONVERGES: every plan shows a diff and every apply re-PUTs "+
					"the same body.\ndiff: %s", diff.GoString())
			}
		})
	}
}

/*
TestSplitTunnelingDeclaresAnAsyncTimeout pins SPT-N03's other half.

This resource POLLS an async operation, so without a Timeouts block it silently
inherits SDKv2's 20-minute system default and the operator has no `timeouts {}`
block to raise it with. The timeout is also what gives the ctx in
TestSplitTunnelingCreateTimesOutWithoutWritingAnId a deadline in production; that
test proves the deadline is honoured, and this one proves there is one to honour.

Delete is asserted ABSENT rather than merely unchecked: it makes no API call at
all (D9), so declaring a budget for it would advertise a wait that cannot happen.
*/
func TestSplitTunnelingDeclaresAnAsyncTimeout(t *testing.T) {
	timeouts := resourceSplitTunneling().Timeouts
	if timeouts == nil {
		t.Fatal("checkpointsase_split_tunneling declares no Timeouts, so its polled write " +
			"inherits SDKv2's 20-minute default and no `timeouts {}` block can raise it")
	}
	for name, got := range map[string]*time.Duration{
		"Create": timeouts.Create,
		"Update": timeouts.Update,
	} {
		if got == nil {
			t.Errorf("%s has no timeout", name)
			continue
		}
		if *got != asyncResourceTimeout {
			t.Errorf("%s timeout = %s, want asyncResourceTimeout (%s)", name, *got, asyncResourceTimeout)
		}
	}
	if timeouts.Delete != nil {
		t.Errorf("Delete declares a %s timeout, but Delete makes no API call at all (D9) -- "+
			"the budget advertises a wait that cannot happen", *timeouts.Delete)
	}
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/*
TestSplitTunnelingImportSetsNetworkIdBeforeReading pins the one load-bearing line
in the importer, and it asserts the REQUEST LIST rather than the outcome.

Read addresses the object by the `network_id` ATTRIBUTE, not by d.Id(). On import
the attribute is empty, so an importer that did not set it first would GET
/v3/networks//split-tunneling -- an empty path segment, which is a DIFFERENT ROUTE
rather than a 404 on this one. Asserting the path is what makes the empty segment
visible; asserting only that the import "worked" would pass against a fake that
answers every path.
*/
func TestSplitTunnelingImportSetsNetworkIdBeforeReading(t *testing.T) {
	fake := startSplitTunnelingFake(t, &splitTunnelingFake{
		getBody: measuredSplitTunnelingWithException,
	})

	d := testSplitTunnelingData(t, map[string]interface{}{})
	d.SetId("net-1")

	imported, err := resourceSplitTunnelingImportState(context.Background(), d, fake.client())
	if err != nil {
		t.Fatalf("the import failed: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("the import returned %d resources, want 1", len(imported))
	}

	want := []string{"GET /v3/networks/net-1/split-tunneling"}
	if got := fake.calls(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("the import made\n  %v\nwant\n  %v\nAn empty network_id produces "+
			"/v3/networks//split-tunneling, which is a different route rather than a 404 on "+
			"this one", got, want)
	}
	if got := imported[0].Get("network_id").(string); got != "net-1" {
		t.Errorf("network_id = %q after the import, want the import id", got)
	}
	if got := imported[0].Get("default_tunneling_mode").(string); got != "out_of_tunnel" {
		t.Errorf("default_tunneling_mode = %q after the import, want the value Read stored: "+
			"an import that leaves it empty plans a change against a Required enum", got)
	}
	if got := imported[0].Get("except_data.0.exceptions.0.destination").(string); got != "10.99.0.1/32" {
		t.Errorf("except_data.0.exceptions.0.destination = %q after the import, want the "+
			"saved exception -- surfacing it is the entire benefit of the attribute", got)
	}
}

/*
TestSplitTunnelingImportRejectsAnUnknownNetwork covers the check that is NOT
redundant with the error check above it in the importer.

Read reports a vanished network by clearing the id and returning NO diagnostics
(a 404 is drift, see its comment), so an import of a network that does not exist
would otherwise report SUCCESS and write an empty resource into state -- which
then plans as "create", against a network that is not there.

The empty-id row is separate because it fails before any request is made, and an
importer that only checked afterwards would GET /v3/networks//split-tunneling on
the way.
*/
func TestSplitTunnelingImportRejectsAnUnknownNetwork(t *testing.T) {
	t.Run("a network the API does not know", func(t *testing.T) {
		fake := startSplitTunnelingFake(t, &splitTunnelingFake{
			getStatus: http.StatusNotFound,
			getBody:   measuredSplitTunnelingNetworkGone,
		})

		d := testSplitTunnelingData(t, map[string]interface{}{})
		d.SetId("net-gone")

		imported, err := resourceSplitTunnelingImportState(context.Background(), d, fake.client())
		if err == nil {
			t.Fatalf("importing a network the API answers 404 for reported success and returned "+
				"%d resource(s)", len(imported))
		}
		if !strings.Contains(err.Error(), "net-gone") {
			t.Errorf("the error does not name the id that failed: %v", err)
		}
	})

	t.Run("an empty import id", func(t *testing.T) {
		fake := startSplitTunnelingFake(t, &splitTunnelingFake{})

		d := testSplitTunnelingData(t, map[string]interface{}{})

		if _, err := resourceSplitTunnelingImportState(
			context.Background(), d, fake.client()); err == nil {
			t.Fatal("an empty import id was accepted")
		}
		if calls := fake.calls(); len(calls) != 0 {
			t.Errorf("the importer made %v with an empty id, which is "+
				"/v3/networks//split-tunneling -- a different route, not a 404 on this one", calls)
		}
	})
}
