package checkpointsase

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
These tests cover one attribute of one resource — checkpointsase_enhanced_dynamic_tunnel's
tunnel_name — because that one attribute grew by two characters on every apply.

The server derives each endpoint's interface name as `${tunnelName}01`. Read wrote that derived
name straight into state and a DiffSuppressFunc hid the resulting difference from the configured
name. Suppressing a diff does not discard the state value: the SDK carries it into the apply, so
Update read the DECORATED name back out of d and sent it, and the server decorated it again.
`EnhDynTun1` → `EnhDynTun101` after create → `EnhDynTun10101` after one update, against a
15-character server-side cap.

That mechanism — what Read stores, and what d.Get therefore returns during Update — is what these
tests exercise, and it is why the lifecycle test below goes through the SDK's real Diff/Data
machinery instead of asserting on a hand-built ResourceData. schema.TestResourceDataRaw builds the
ResourceData a Create sees; only schemaMap.Diff followed by schemaMap.Data reproduces the one an
Update sees, which is the only place the defect was visible.
*/

/*
TestDynamicTunnelNameForState pins the reconciliation rule itself: what Read should put in state
given what is already there and what the API reported.
*/
func TestDynamicTunnelNameForState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prior  string
		server string
		want   string
	}{
		{
			name:   "the derived name keeps the configured one",
			prior:  "EnhDynTun1",
			server: "EnhDynTun101",
			want:   "EnhDynTun1",
		},
		{
			name: "an undecorated echo keeps the configured one",
			// Nothing in the API contract promises the suffix, and the sibling static tunnel
			// does not get one. If the server ever stops decorating, that must be a no-op here,
			// not a rename.
			prior:  "EnhDynTun1",
			server: "EnhDynTun1",
			want:   "EnhDynTun1",
		},
		{
			name: "a name the user deliberately ends with 01 is not stripped",
			// The whole reason Read reconciles against the prior value instead of running
			// strings.TrimSuffix over the server's: TrimSuffix would put `dynamicTunnel` in
			// state for a user who asked for `dynamicTunnel01` (the name in this resource's own
			// docs example), and the next Update would rename their tunnel for them.
			prior:  "dynamicTunnel01",
			server: "dynamicTunnel0101",
			want:   "dynamicTunnel01",
		},
		{
			name: "an out-of-band rename is real drift and is written through",
			// Not derivable from prior, so the server genuinely holds a different name.
			// Recording it is what lets the next plan show the rename back.
			prior:  "EnhDynTun1",
			server: "SomeoneElse01",
			want:   "SomeoneElse01",
		},
		{
			name: "a name already compounded by the old code is recorded, so one apply heals it",
			// State written by the pre-fix provider. `EnhDynTun10101` is not derivable from
			// `EnhDynTun1`, so it lands in state, the plan shows a diff against the configured
			// name, and the apply sends the base name — after which the server holds
			// `EnhDynTun101` and this function starts returning the configured value.
			prior:  "EnhDynTun1",
			server: "EnhDynTun10101",
			want:   "EnhDynTun10101",
		},
		{
			name: "an empty response does not blank a configured name",
			// The setIfPresent rule: a refresh that learned nothing must not destroy state.
			prior:  "EnhDynTun1",
			server: "",
			want:   "EnhDynTun1",
		},
		{
			name: "import has no prior, so the decorated name is all there is",
			// resourceEnhancedDynamicTunnelImportState reaches Read with tunnel_name unset.
			// There is no way to recover the base name from `EnhDynTun101` alone — guessing
			// would mangle a tunnel genuinely called that — so state takes the server's value
			// and the first plan honestly shows the difference.
			prior:  "",
			server: "EnhDynTun101",
			want:   "EnhDynTun101",
		},
		{
			name:   "an empty response with no prior stays empty",
			prior:  "",
			server: "",
			want:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dynamicTunnelNameForState(tc.prior, tc.server); got != tc.want {
				t.Errorf("dynamicTunnelNameForState(%q, %q) = %q, want %q", tc.prior, tc.server, got, tc.want)
			}
		})
	}
}

/*
TestDynamicTunnelNameIsDerivedFrom covers the same predicate in its other role: the create
fallback that recovers a tunnel id by listing tunnels and matching on name.

That fallback compared `t.TunnelName == tunnelName` exactly. Against a server that appends `01`
the comparison can never be true, so the one code path that exists to rescue a create whose async
result carried no resource URL could only ever fail — reporting that a tunnel it had just created
did not exist.
*/
func TestDynamicTunnelNameIsDerivedFrom(t *testing.T) {
	for _, tc := range []struct {
		name       string
		serverName string
		configured string
		want       bool
	}{
		{"the derived name matches", "EnhDynTun101", "EnhDynTun1", true},
		{"an exact echo matches", "EnhDynTun1", "EnhDynTun1", true},
		{"a different tunnel does not match", "OtherTun101", "EnhDynTun1", false},
		{
			name: "a longer name that merely starts the same does not match",
			// Only the exact `01` suffix counts; prefix matching would let the fallback adopt
			// the wrong tunnel's id, and the resource would then manage someone else's tunnel.
			serverName: "EnhDynTun1001", configured: "EnhDynTun1", want: false,
		},
		{
			name: "a doubly-suffixed name does not match",
			// A tunnel left compounded by the old code is not the tunnel just created.
			serverName: "EnhDynTun10101", configured: "EnhDynTun1", want: false,
		},
		{"a name ending in 01 matches its own derived form", "dynamicTunnel0101", "dynamicTunnel01", true},
		{
			name: "an empty configured name matches nothing",
			// Otherwise the fallback would adopt any tunnel the server happens to call "01".
			serverName: "01", configured: "", want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dynamicTunnelNameIsDerivedFrom(tc.serverName, tc.configured); got != tc.want {
				t.Errorf("dynamicTunnelNameIsDerivedFrom(%q, %q) = %v, want %v", tc.serverName, tc.configured, got, tc.want)
			}
		})
	}
}

/*
fakeDynamicTunnelServer models the single server behaviour this fix exists for: whatever name it
is sent, the name it then holds is that name plus `01`.

The suffix is spelled out here rather than taken from dynamicTunnelServerNameSuffix on purpose. If
the fake shared the constant, changing the constant would move the fake with it and the tests
would keep passing while the provider no longer matched the server.
*/
type fakeDynamicTunnelServer struct {
	tunnelName string
}

// write applies the server's derivation to a name the provider sent. It is deliberately
// idempotent in the same way the server's is: sending the same base name again produces the same
// stored name, which is exactly the property that stops the growth once the provider sends the
// base name every time.
func (s *fakeDynamicTunnelServer) write(sent string) {
	s.tunnelName = sent + "01"
}

/*
dynamicTunnelLifecycle drives one dynamic tunnel through create / plan / update against
fakeDynamicTunnelServer, using the provider's real schema, the real Read reconciliation
(setEnhancedDynamicTunnelNameState), the real update-body builder
(buildDynamicTunnelUpdatePayload), and the SDK's own diff machinery in between.

Nothing here re-implements provider logic. The only thing the harness supplies is the plumbing
Terraform would: turn config + state into a diff, turn state + diff into the ResourceData an
Update receives, and turn the post-apply ResourceData back into state.
*/
type dynamicTunnelLifecycle struct {
	t        *testing.T
	resource *schema.Resource
	server   fakeDynamicTunnelServer
	state    *terraform.InstanceState
}

// createDynamicTunnelLifecycle runs Create: build the ResourceData from config alone (which is
// what the SDK hands Create), send tunnel_name, then run the post-create Read.
func createDynamicTunnelLifecycle(t *testing.T, config map[string]interface{}) *dynamicTunnelLifecycle {
	t.Helper()
	l := &dynamicTunnelLifecycle{t: t, resource: resourceEnhancedDynamicTunnel()}

	d := schema.TestResourceDataRaw(t, l.resource.Schema, config)
	d.SetId("fake-dyn-tun-1")
	// resourceEnhancedDynamicTunnelCreate sends d.Get("tunnel_name") verbatim.
	l.server.write(d.Get("tunnel_name").(string))
	l.read(d)
	l.state = d.State()
	return l
}

// read is the part of resourceEnhancedDynamicTunnelRead that touches tunnel_name.
func (l *dynamicTunnelLifecycle) read(d *schema.ResourceData) {
	l.t.Helper()
	if err := setEnhancedDynamicTunnelNameState(d, l.server.tunnelName); err != nil {
		l.t.Fatalf("Read could not set tunnel_name: %v", err)
	}
}

// plan produces the diff Terraform would show for config against the current state. A nil or
// empty diff is an empty plan.
func (l *dynamicTunnelLifecycle) plan(config map[string]interface{}) *terraform.InstanceDiff {
	l.t.Helper()
	diff, err := l.resource.Diff(context.Background(), l.state, terraform.NewResourceConfigRaw(config), nil)
	if err != nil {
		l.t.Fatalf("planning failed: %v", err)
	}
	return diff
}

// planIsEmpty reports whether a plan against config would propose no changes at all.
func (l *dynamicTunnelLifecycle) planIsEmpty(config map[string]interface{}) bool {
	l.t.Helper()
	diff := l.plan(config)
	return diff == nil || diff.Empty()
}

/*
update runs one apply of config: take the plan, build the ResourceData from state + diff exactly
as the SDK does before calling UpdateContext, build the update body from it, send that, then run
the post-update Read and commit the resulting state.

Returning the name that went on the wire is the point of the whole harness: that value is
d.Get("tunnel_name") at Update time, and it is what the DiffSuppressFunc used to poison.
*/
func (l *dynamicTunnelLifecycle) update(config map[string]interface{}) string {
	l.t.Helper()

	diff := l.plan(config)
	if diff == nil || diff.Empty() {
		l.t.Fatalf("the plan was empty, so Terraform would never call Update — this step cannot be an update")
	}
	d, err := schema.InternalMap(l.resource.Schema).Data(l.state, diff)
	if err != nil {
		l.t.Fatalf("could not build the Update ResourceData: %v", err)
	}

	sent := buildDynamicTunnelUpdatePayload(d).TunnelName
	l.server.write(sent)

	// resourceEnhancedDynamicTunnelUpdate stamps last_updated and then re-reads.
	if err := d.Set("last_updated", "fixed-for-test"); err != nil {
		l.t.Fatalf("could not set last_updated: %v", err)
	}
	l.read(d)
	l.state = d.State()
	return sent
}

// stateTunnelName is what `terraform show` would print for tunnel_name.
func (l *dynamicTunnelLifecycle) stateTunnelName() string {
	l.t.Helper()
	if l.state == nil {
		l.t.Fatal("there is no state")
	}
	return l.state.Attributes["tunnel_name"]
}

// testDynamicTunnelNameConfig is the acceptance fixture's configuration, reduced to the
// attributes the schema requires, with the two values these tests vary exposed as parameters.
// dpdDelay stands in for "some unrelated field the user edited".
func testDynamicTunnelNameConfig(tunnelName, dpdDelay string) map[string]interface{} {
	phase := []interface{}{map[string]interface{}{
		"auth":                []interface{}{"sha256"},
		"encryption":          []interface{}{"3des"},
		"key_exchange_method": []interface{}{"modp2048"},
	}}
	return map[string]interface{}{
		"network_id":  "fake-network-1",
		"tunnel_name": tunnelName,
		"left_asn":    65000,
		"tunnel": []interface{}{map[string]interface{}{
			"region_id":             "fake-region-1",
			"auth_type":             "psk",
			"passphrase":            "fake_passphrase_1",
			"remote_public_ip":      "198.51.100.45",
			"remote_id":             "198.51.100.45",
			"remote_asn":            65001,
			"p81_gw_internal_ip":    "169.254.100.1",
			"remote_gw_internal_ip": "169.254.100.2",
		}},
		"p81_gateway_subnets":    []interface{}{"0.0.0.0/0"},
		"remote_gateway_subnets": []interface{}{"0.0.0.0/0"},
		"key_exchange":           "ikev1",
		"ike_life_time":          "9h",
		"lifetime":               "2h",
		"dpd_delay":              dpdDelay,
		"dpd_timeout":            "40s",
		"phase1":                 phase,
		"phase2":                 phase,
	}
}

/*
TestEnhancedDynamicTunnelNameSurvivesCreateThenPlan is bullet 1 of the specification: create, then
plan, and the plan must be empty.

It also records what create alone leaves behind — state holding the configured name, the server
holding the derived one — because every later bullet builds on that being right.
*/
func TestEnhancedDynamicTunnelNameSurvivesCreateThenPlan(t *testing.T) {
	config := testDynamicTunnelNameConfig("EnhDynTun1", "20s")
	l := createDynamicTunnelLifecycle(t, config)

	if got := l.stateTunnelName(); got != "EnhDynTun1" {
		t.Errorf("state tunnel_name after create = %q, want %q — state must hold the user's name, not the server's decorated form", got, "EnhDynTun1")
	}
	if got := l.server.tunnelName; got != "EnhDynTun101" {
		t.Errorf("server tunnel_name after create = %q, want %q", got, "EnhDynTun101")
	}
	if !l.planIsEmpty(config) {
		t.Errorf("the plan straight after create is not empty: %v", l.plan(config))
	}
}

/*
TestEnhancedDynamicTunnelNameSurvivesUnrelatedUpdates is bullets 2 and 3: create, change something
that is not the name, and neither the name Terraform sends nor the name the server ends up holding
may move — through one update, and through a second one on top of it.

This is the direct regression test for the live failure. Before the fix, the first update sent
`EnhDynTun101` and the server ended up with `EnhDynTun10101`; a second would have reached
`EnhDynTun1010101`, past the 15-character cap.
*/
func TestEnhancedDynamicTunnelNameSurvivesUnrelatedUpdates(t *testing.T) {
	l := createDynamicTunnelLifecycle(t, testDynamicTunnelNameConfig("EnhDynTun1", "20s"))

	for i, dpdDelay := range []string{"35s", "45s"} {
		config := testDynamicTunnelNameConfig("EnhDynTun1", dpdDelay)

		sent := l.update(config)
		if sent != "EnhDynTun1" {
			t.Fatalf("update %d sent tunnel_name %q, want %q — Update must send the configured name, not the one the server decorated", i+1, sent, "EnhDynTun1")
		}
		if got := l.server.tunnelName; got != "EnhDynTun101" {
			t.Fatalf("after update %d the server holds %q, want %q — the name is growing again", i+1, got, "EnhDynTun101")
		}
		if got := l.stateTunnelName(); got != "EnhDynTun1" {
			t.Fatalf("after update %d state holds %q, want %q", i+1, got, "EnhDynTun1")
		}
		if !l.planIsEmpty(config) {
			t.Fatalf("the plan after update %d is not empty: %v", i+1, l.plan(config))
		}
	}
}

/*
TestEnhancedDynamicTunnelNameRenames is bullets 4 and 5: a rename written in config must reach the
server, including the renames the old DiffSuppressFunc swallowed.

`strings.TrimSuffix(old, "01") == new || old == strings.TrimSuffix(new, "01")` is true for
(`EnhDynTun1`, `EnhDynTun101`) in both directions, so with suppression in place those two renames
produced no diff at all: Terraform reported no changes and the tunnel kept its old name. The
`dynamicTunnel01` case is the same shape as the example in this resource's own documentation.
*/
func TestEnhancedDynamicTunnelNameRenames(t *testing.T) {
	for _, tc := range []struct {
		name       string
		from       string
		to         string
		wantServer string
	}{
		{
			name: "an ordinary rename",
			from: "EnhDynTun1", to: "RenamedTun", wantServer: "RenamedTun01",
		},
		{
			name: "renaming to the old name plus 01 — suppressed by the old code",
			from: "EnhDynTun1", to: "EnhDynTun101", wantServer: "EnhDynTun10101",
		},
		{
			name: "renaming away from a name ending in 01 — also suppressed by the old code",
			from: "EnhDynTun101", to: "EnhDynTun1", wantServer: "EnhDynTun101",
		},
		{
			name: "a user's own name ending in 01 is sent verbatim",
			from: "EnhDynTun1", to: "dynamicTunnel01", wantServer: "dynamicTunnel0101",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := createDynamicTunnelLifecycle(t, testDynamicTunnelNameConfig(tc.from, "20s"))
			renamed := testDynamicTunnelNameConfig(tc.to, "20s")

			if l.planIsEmpty(renamed) {
				t.Fatalf("renaming %q to %q produced an empty plan — the rename would never be applied", tc.from, tc.to)
			}

			sent := l.update(renamed)
			if sent != tc.to {
				t.Errorf("update sent tunnel_name %q, want %q — the configured name must reach the server unmodified", sent, tc.to)
			}
			if got := l.server.tunnelName; got != tc.wantServer {
				t.Errorf("the server holds %q, want %q", got, tc.wantServer)
			}
			if got := l.stateTunnelName(); got != tc.to {
				t.Errorf("state holds %q, want %q", got, tc.to)
			}
			if !l.planIsEmpty(renamed) {
				t.Errorf("the plan after the rename is not empty: %v", l.plan(renamed))
			}
		})
	}
}

/*
TestEnhancedDynamicTunnelNameHasNoDiffSuppression states the structural half of the fix outright.

Read now records the configured name, so there is nothing left to suppress — and a DiffSuppressFunc
on this attribute is not merely redundant, it is how the defect worked: a suppressed diff leaves the
state value in place for the apply, so d.Get returns it during Update. Anyone reintroducing one here
should have to delete this test and read why first.
*/
func TestEnhancedDynamicTunnelNameHasNoDiffSuppression(t *testing.T) {
	if resourceEnhancedDynamicTunnel().Schema["tunnel_name"].DiffSuppressFunc != nil {
		t.Error("tunnel_name has a DiffSuppressFunc again. A suppressed diff is not a discarded one: " +
			"the SDK carries the suppressed state value into Update, which is exactly how the tunnel name " +
			"grew by two characters per apply. Reconcile in Read instead — see dynamicTunnelNameForState.")
	}
	// The static tunnel never had the problem: a live probe created `ProbeTun1` and the server
	// reported `ProbeTun1`, undecorated. It must not acquire this handling by imitation.
	if resourceEnhancedStaticTunnel().Schema["tunnel_name"].DiffSuppressFunc != nil {
		t.Error("the static tunnel's tunnel_name has grown a DiffSuppressFunc; the server does not decorate static tunnel names")
	}
}
