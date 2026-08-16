package checkpointsase

import (
	"encoding/json"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
These tests cover the EnhancedTunnel READ shape, which three call sites share:
resourceEnhancedStaticTunnelRead, resourceEnhancedDynamicTunnelRead and
dataSourceEnhancedTunnelsRead.

They exist because that shape was wrong for the whole v3 port and nothing
offline noticed. The vendor spec declared the tunnel's timing fields and phase
configs nested inside an `advancedSettings` object, plus no remotePublicIP,
remoteID or description at all. The server sends all of them at TOP LEVEL and
sends no `advancedSettings` object whatsoever, so the generated pointer was nil
on every response, every nil-safe getter returned "", and each refresh blanked
the user's configured values. SDK overlay A19 corrects the spec; these tests
are what make a repeat of it fail here, in seconds, rather than sixty minutes
into a live acceptance run.

The fixture below is the response body of a live
GET /v3/networks/enhanced/{networkId}/tunnels captured 2026-08-16 against a
real static tunnel, reproduced verbatim except that the pre-shared key is
replaced with an obviously-fake fixture value. No real credential or tenant
data is stored here.
*/
const enhancedTunnelLiveReadFixture = `{
  "id": "aVttJETcnB",
  "tunnelName": "ProbeTun1",
  "regionID": "KESYiSXGoi",
  "p81GatewaySubnets": ["0.0.0.0/0"],
  "remoteGatewaySubnets": ["0.0.0.0/0"],
  "remotePublicIP": "198.51.100.77",
  "remoteID": "198.51.100.77",
  "keyExchange": "ikev1",
  "ikeLifeTime": "9h",
  "lifetime": "2h",
  "dpdDelay": "20s",
  "dpdTimeout": "40s",
  "passphrase": "fake-fixture-psk",
  "authType": "psk",
  "phase1": {"auth": ["sha256"], "keyExchangeMethod": ["modp2048"], "encryption": ["3des"]},
  "phase2": {"auth": ["sha256"], "keyExchangeMethod": ["modp2048"], "encryption": ["3des"]},
  "description": "",
  "features": {
    "cloudSecurity": {"enabled": false},
    "symmetricInnerMesh": {"enabled": false},
    "DNSServices": {"redirectToResolver": {"enabled": true}}
  },
  "dpdAction": "restart",
  "haTunnelID": "aVttJETcnB",
  "isHA": false,
  "routingType": "route",
  "peakBandwidthMbps": 1000
}`

// decodeEnhancedTunnelFixture unmarshals a response body through the SDK's
// generated EnhancedTunnel decoder, which is where a required-property
// regression would surface.
func decodeEnhancedTunnelFixture(t *testing.T, body string) *perimeter81Sdk.EnhancedTunnel {
	t.Helper()
	var tunnel perimeter81Sdk.EnhancedTunnel
	if err := json.Unmarshal([]byte(body), &tunnel); err != nil {
		t.Fatalf("the SDK could not decode a real enhanced-tunnel response: %v", err)
	}
	return &tunnel
}

/*
TestEnhancedTunnelReadShapeDecodesTheLiveResponse is the direct regression test
for SDK overlay A19: it asserts that every field the provider reads off an
enhanced tunnel is actually reachable as a typed field after decoding a real
response. Before A19, IkeLifeTime/Lifetime/DpdDelay/DpdTimeout/Phase1/Phase2
did not exist on the model at all (they were reachable only through a nested
AdvancedSettings pointer the server never populates) and
RemotePublicIP/RemoteID/Description did not exist in any form.
*/
func TestEnhancedTunnelReadShapeDecodesTheLiveResponse(t *testing.T) {
	tunnel := decodeEnhancedTunnelFixture(t, enhancedTunnelLiveReadFixture)

	for _, tc := range []struct {
		field string
		got   string
		want  string
	}{
		{"ikeLifeTime", tunnel.GetIkeLifeTime(), "9h"},
		{"lifetime", tunnel.GetLifetime(), "2h"},
		{"dpdDelay", tunnel.GetDpdDelay(), "20s"},
		{"dpdTimeout", tunnel.GetDpdTimeout(), "40s"},
		{"remotePublicIP", tunnel.GetRemotePublicIP(), "198.51.100.77"},
		{"remoteID", tunnel.GetRemoteID(), "198.51.100.77"},
		{"tunnelName", tunnel.GetTunnelName(), "ProbeTun1"},
		{"regionID", tunnel.GetRegionID(), "KESYiSXGoi"},
		{"keyExchange", tunnel.GetKeyExchange(), "ikev1"},
		{"authType", tunnel.GetAuthType(), "psk"},
		{"dpdAction", tunnel.GetDpdAction(), "restart"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q — the read model no longer matches the shape the server sends (see SDK overlay A19)", tc.field, tc.got, tc.want)
		}
	}

	if !tunnel.HasPhase1() || !tunnel.HasPhase2() {
		t.Fatalf("phase1/phase2 missing from the decoded tunnel; they are top-level fields on the wire")
	}
	if got := tunnel.GetPhase1().Auth; !testComparableArraiesEq(got, []string{"sha256"}) {
		t.Errorf("phase1.auth = %q, want [sha256]", got)
	}
	if got := tunnel.GetPhase2().KeyExchangeMethod; !testComparableArraiesEq(got, []string{"modp2048"}) {
		t.Errorf("phase2.keyExchangeMethod = %q, want [modp2048]", got)
	}
	if got := tunnel.GetPeakBandwidthMbps(); got != 1000 {
		t.Errorf("peakBandwidthMbps = %d, want 1000", got)
	}
	if tunnel.GetIsHA() {
		t.Errorf("isHA = true, want false")
	}

	// `features` is deliberately NOT declared on the read model — the capture
	// abridged its contents, so its nested shape is unverified and declaring
	// it would add a strict-decode surface for a field no caller reads (see
	// A19's reason). This asserts the consequence of that decision is benign:
	// the object still decodes, into AdditionalProperties, rather than
	// failing or being dropped.
	if _, ok := tunnel.AdditionalProperties["features"]; !ok {
		t.Errorf("features did not land in AdditionalProperties; an undeclared response field must not be lost")
	}
}

/*
TestSetEnhancedTunnelIPSecStateWritesTopLevelFields drives the exact helper
both Read functions call, against both resources' real schemas, and asserts the
six shared IPSec attributes land in state. This is the test that fails if
anyone reroutes these reads back through a nested settings object: the
pre-A19 code path put "" in all six.
*/
func TestSetEnhancedTunnelIPSecStateWritesTopLevelFields(t *testing.T) {
	tunnel := decodeEnhancedTunnelFixture(t, enhancedTunnelLiveReadFixture)

	for _, tc := range []struct {
		name   string
		schema map[string]*schema.Schema
	}{
		{"static tunnel", resourceEnhancedStaticTunnel().Schema},
		{"dynamic tunnel", resourceEnhancedDynamicTunnel().Schema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, tc.schema, map[string]interface{}{})

			if err := setEnhancedTunnelIPSecState(d, tunnel); err != nil {
				t.Fatalf("setEnhancedTunnelIPSecState: %v", err)
			}

			for key, want := range map[string]string{
				"ike_life_time": "9h",
				"lifetime":      "2h",
				"dpd_delay":     "20s",
				"dpd_timeout":   "40s",
			} {
				if got := d.Get(key).(string); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}

			for _, key := range []string{"phase1", "phase2"} {
				list, ok := d.Get(key).([]interface{})
				if !ok || len(list) != 1 {
					t.Fatalf("%s = %v, want a one-element list", key, d.Get(key))
				}
				block, ok := list[0].(map[string]interface{})
				if !ok {
					t.Fatalf("%s[0] is %T, want map[string]interface{}", key, list[0])
				}
				auth, _ := block["auth"].([]interface{})
				if len(auth) != 1 || auth[0] != "sha256" {
					t.Errorf("%s.auth = %v, want [sha256]", key, block["auth"])
				}
			}
		})
	}
}

/*
TestSetEnhancedTunnelIPSecStatePreservesStateWhenTheServerOmitsFields is the
other half of the guard. Every write goes through setIfPresent / a Has* check
specifically so that a future recurrence of the A19 defect — the server, or the
spec, no longer producing these fields — degrades to "this refresh learned
nothing" instead of "the user's configuration was silently erased". Without the
guard this test would blank all four values.
*/
func TestSetEnhancedTunnelIPSecStatePreservesStateWhenTheServerOmitsFields(t *testing.T) {
	// A minimal but valid response: only the fields the read model requires.
	// None of the six IPSec attributes is present.
	tunnel := decodeEnhancedTunnelFixture(t, `{
	  "id": "aVttJETcnB",
	  "haTunnelID": "aVttJETcnB",
	  "dpdAction": "restart",
	  "tunnelName": "ProbeTun1",
	  "regionID": "KESYiSXGoi",
	  "p81GatewaySubnets": ["0.0.0.0/0"],
	  "remoteGatewaySubnets": ["0.0.0.0/0"],
	  "keyExchange": "ikev1",
	  "authType": "psk"
	}`)

	prior := map[string]interface{}{
		"ike_life_time": "9h",
		"lifetime":      "2h",
		"dpd_delay":     "20s",
		"dpd_timeout":   "40s",
	}
	d := schema.TestResourceDataRaw(t, resourceEnhancedStaticTunnel().Schema, prior)

	if err := setEnhancedTunnelIPSecState(d, tunnel); err != nil {
		t.Fatalf("setEnhancedTunnelIPSecState: %v", err)
	}

	for key, want := range prior {
		if got := d.Get(key).(string); got != want.(string) {
			t.Errorf("%s = %q, want %q (a field the server did not report must not blank the prior value)", key, got, want)
		}
	}
}

/*
TestSetEnhancedTunnelSharedSubnetStateWritesBothLists covers the group's shared settings.

resourceEnhancedDynamicTunnelRead never wrote p81_gateway_subnets or remote_gateway_subnets into
state at all, so neither could ever drift-detect: change either list in HCL and the plan came back
empty. (The dynamic acceptance test already recorded this as "present on the API response but
never d.Set by Read for this resource".) Both Reads now go through one helper, so the two cannot
diverge again.
*/
func TestSetEnhancedTunnelSharedSubnetStateWritesBothLists(t *testing.T) {
	tunnel := decodeEnhancedTunnelFixture(t, enhancedTunnelLiveReadFixture)

	for _, tc := range []struct {
		name   string
		schema map[string]*schema.Schema
	}{
		{"static tunnel", resourceEnhancedStaticTunnel().Schema},
		{"dynamic tunnel", resourceEnhancedDynamicTunnel().Schema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, tc.schema, map[string]interface{}{})

			if err := setEnhancedTunnelSharedSubnetState(d, tunnel); err != nil {
				t.Fatalf("setEnhancedTunnelSharedSubnetState: %v", err)
			}

			for _, key := range []string{"p81_gateway_subnets", "remote_gateway_subnets"} {
				list, ok := d.Get(key).([]interface{})
				if !ok || len(list) != 1 || list[0] != "0.0.0.0/0" {
					t.Errorf("%s = %v, want [0.0.0.0/0]", key, d.Get(key))
				}
			}
		})
	}
}

/*
TestSetEnhancedTunnelSharedSubnetStatePreservesStateWhenTheServerOmitsFields is the never-blank
half, matching the guard on the IPSec fields. Both attributes are Required in both schemas, so an
empty list is not a value the user could have configured — writing one back would only ever
destroy a real configuration, never record a real one.
*/
func TestSetEnhancedTunnelSharedSubnetStatePreservesStateWhenTheServerOmitsFields(t *testing.T) {
	tunnel := decodeEnhancedTunnelFixture(t, `{
	  "id": "aVttJETcnB",
	  "haTunnelID": "aVttJETcnB",
	  "dpdAction": "restart",
	  "tunnelName": "ProbeTun1",
	  "regionID": "KESYiSXGoi",
	  "p81GatewaySubnets": [],
	  "remoteGatewaySubnets": [],
	  "keyExchange": "ikev1",
	  "authType": "psk"
	}`)

	d := schema.TestResourceDataRaw(t, resourceEnhancedDynamicTunnel().Schema, map[string]interface{}{
		"p81_gateway_subnets":    []interface{}{"10.0.0.0/24"},
		"remote_gateway_subnets": []interface{}{"10.1.0.0/24"},
	})

	if err := setEnhancedTunnelSharedSubnetState(d, tunnel); err != nil {
		t.Fatalf("setEnhancedTunnelSharedSubnetState: %v", err)
	}

	for key, want := range map[string]string{
		"p81_gateway_subnets":    "10.0.0.0/24",
		"remote_gateway_subnets": "10.1.0.0/24",
	} {
		list, ok := d.Get(key).([]interface{})
		if !ok || len(list) != 1 || list[0] != want {
			t.Errorf("%s = %v, want [%s] (an empty list from the server must not blank a configured one)", key, d.Get(key), want)
		}
	}
}

/*
TestFlattenEnhancedTunnelsDataPopulatesEveryAttribute covers the third call
site. dataSourceEnhancedTunnelsRead used to hardcode "" for remote_public_ip,
remote_id and description, and read the four timing fields off the nil
AdvancedSettings pointer — six of its eighteen attributes were structurally
incapable of ever carrying a value. A data source has no prior state to
preserve, so unlike the resource Reads it writes unconditionally; what this
asserts is that none of the six is hardcoded or nil-sourced any more.
*/
func TestFlattenEnhancedTunnelsDataPopulatesEveryAttribute(t *testing.T) {
	tunnel := decodeEnhancedTunnelFixture(t, enhancedTunnelLiveReadFixture)

	out := flattenEnhancedTunnelsData([]perimeter81Sdk.EnhancedTunnel{*tunnel})
	if len(out) != 1 {
		t.Fatalf("got %d entries, want 1", len(out))
	}
	m, ok := out[0].(map[string]interface{})
	if !ok {
		t.Fatalf("entry is %T, want map[string]interface{}", out[0])
	}

	for key, want := range map[string]string{
		"id":               "aVttJETcnB",
		"tunnel_name":      "ProbeTun1",
		"region_id":        "KESYiSXGoi",
		"ha_tunnel_id":     "aVttJETcnB",
		"auth_type":        "psk",
		"key_exchange":     "ikev1",
		"ike_life_time":    "9h",
		"lifetime":         "2h",
		"dpd_delay":        "20s",
		"dpd_timeout":      "40s",
		"dpd_action":       "restart",
		"remote_public_ip": "198.51.100.77",
		"remote_id":        "198.51.100.77",
		"routing_type":     "route",
	} {
		got, ok := m[key].(string)
		if !ok {
			t.Fatalf("%s is %T, want string", key, m[key])
		}
		if got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got, ok := m["description"].(string); !ok || got != "" {
		t.Errorf("description = %v, want \"\" (the fixture's tunnel was created without one)", m["description"])
	}
	if got, ok := m["peak_bandwidth"].(int); !ok || got != 1000 {
		t.Errorf("peak_bandwidth = %v, want 1000", m["peak_bandwidth"])
	}

	// The pre-A19 implementation is the thing being regressed against: it
	// literally wrote "" for these three regardless of the response.
	for _, key := range []string{"remote_public_ip", "remote_id"} {
		if m[key] == "" {
			t.Errorf("%s is empty; the data source is hardcoding it again instead of reading the response", key)
		}
	}
}
