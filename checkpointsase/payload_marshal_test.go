package checkpointsase

import (
	"encoding/json"
	"reflect"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
This file closes a systemic gap found during a whole-branch review: nothing in this codebase
marshaled a request body before this file existed. Every other test asserts schema shape or
helper behaviour, which is exactly how two release blockers survived a per-task review and a
schema conformance suite —

  - firewall_policy: GranularFirewallPolicyRule.Sources/Destinations were left as the
    zero-value SourcesAndDestinations{} (a oneOf wrapper). Its MarshalJSON returns (nil, nil)
    when neither variant is set, and encoding/json treats that as an error, so Execute() failed
    in setBody before any request reached the wire — for every policy_rules block with at least
    one rule.
  - enhanced_dynamic_tunnel: flattenDynamicTunnelDetails never assigned RoutingType, so every
    create sent routingType: "" against a required enum that only admits "route"/"policy".

Both bugs were invisible to schema-shape tests because the schema was never wrong — only the
wire body was. These tests marshal the actual payload types (calling into the same production
code where it has been factored out for that purpose) and compare the result against a fixture
body, so a regression in the wire shape fails here first.

Comparison is semantic (unmarshal both sides into map[string]interface{} and reflect.DeepEqual)
rather than string-equality, so Go's non-deterministic map key ordering during encoding/json's
marshal can't make these tests flaky.

Fixture values (IDs, IPs, keys, ASNs) are all obviously fake and carry no real credentials or
tenant data.
*/

// assertMarshalsTo marshals payload with encoding/json, asserts that succeeds without error,
// then asserts the result is semantically equal to the want JSON fixture.
func assertMarshalsTo(t *testing.T, payload interface{}, want string) {
	t.Helper()

	got, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal returned an error: %v", err)
	}

	var gotMap map[string]interface{}
	if err := json.Unmarshal(got, &gotMap); err != nil {
		t.Fatalf("could not unmarshal actual body for comparison: %v\nbody: %s", err, got)
	}
	var wantMap map[string]interface{}
	if err := json.Unmarshal([]byte(want), &wantMap); err != nil {
		t.Fatalf("could not unmarshal expected body fixture: %v", err)
	}

	if !reflect.DeepEqual(gotMap, wantMap) {
		t.Errorf("marshaled body does not match expected.\ngot:  %s\nwant: %s", got, want)
	}
}

/*
TestPayloadMarshalGranularFirewallPolicy is the regression test for blocker 1. It calls
buildGranularFirewallPolicyRule — the exact function resourceFirewallPolicyUpdate uses to build
each rule's Sources/Destinations — so reverting that fix back to the zero-value
SourcesAndDestinations{} makes the "one rule" case below fail with a json.Marshal error, not just
a body mismatch. The "zero rules" case documents that a rule-less policy always marshaled fine
(PolicyRules is an empty slice either way), which is why the bug was easy to miss: it only
reproduces once a config has at least one rule.

The `{}` in the expected bodies is the second half of the same blocker and is the case to watch.
Wrapping an *empty* Addresses list also marshals cleanly, so it looked like a fix; it is a 400
(`policyRules.0.sources.addresses must contain at least 1 elements`, measured live 2026-08-19).
Only `{}` is accepted for an unrestricted rule, and nothing but a golden body catches the
difference offline — both shapes marshal without error. The same applies to `services`: the
"unrestricted rule, no services" case exists because `"services": []` is a 400 for exactly the
same reason, and the key must be absent rather than empty.
*/
func TestPayloadMarshalGranularFirewallPolicy(t *testing.T) {
	tests := []struct {
		name    string
		payload perimeter81Sdk.GranularFirewallPolicy
		want    string
	}{
		{
			name: "one rule",
			payload: func() perimeter81Sdk.GranularFirewallPolicy {
				rule := buildGranularFirewallPolicyRule(map[string]interface{}{
					"id":          "",
					"name":        "fake-allow-web",
					"enabled":     true,
					"allowed":     true,
					"log_enabled": false,
					"services":    []interface{}{"fake-svc-1", "fake-svc-2"},
				})
				policy := perimeter81Sdk.GranularFirewallPolicy{
					Id:          "fake-policy-1",
					Enabled:     true,
					Allowed:     true,
					PolicyRules: []perimeter81Sdk.GranularFirewallPolicyRule{rule},
				}
				policy.SetPolicyLoggingEnabled(true)
				return policy
			}(),
			want: `{
				"enabled": true,
				"allowed": true,
				"id": "fake-policy-1",
				"policyLoggingEnabled": true,
				"policyRules": [
					{
						"name": "fake-allow-web",
						"enabled": true,
						"allowed": true,
						"sources": {},
						"destinations": {},
						"services": ["fake-svc-1", "fake-svc-2"],
						"logEnabled": false
					}
				]
			}`,
		},
		{
			// A rule with neither sources, destinations nor services: the least
			// restricted rule the resource can express, and the one whose body has
			// the most keys that must be absent rather than empty.
			name: "unrestricted rule, no services",
			payload: func() perimeter81Sdk.GranularFirewallPolicy {
				rule := buildGranularFirewallPolicyRule(map[string]interface{}{
					"id":          "",
					"name":        "fake-allow-all",
					"enabled":     true,
					"allowed":     true,
					"log_enabled": true,
					// d.Get on an unset Optional TypeList returns an empty, non-nil
					// slice — not nil — which is exactly how `"services": []` used
					// to reach the wire.
					"services": []interface{}{},
				})
				policy := perimeter81Sdk.GranularFirewallPolicy{
					Id:          "fake-policy-3",
					Enabled:     true,
					Allowed:     true,
					PolicyRules: []perimeter81Sdk.GranularFirewallPolicyRule{rule},
				}
				policy.SetPolicyLoggingEnabled(false)
				return policy
			}(),
			want: `{
				"enabled": true,
				"allowed": true,
				"id": "fake-policy-3",
				"policyLoggingEnabled": false,
				"policyRules": [
					{
						"name": "fake-allow-all",
						"enabled": true,
						"allowed": true,
						"sources": {},
						"destinations": {},
						"logEnabled": true
					}
				]
			}`,
		},
		{
			// An addresses-scoped rule. Note the `users` and `groups` keys in the input:
			// d.Get hands over every attribute of a block, with empty lists for the ones
			// the user did not write, so the expand path has to distinguish "empty" from
			// "set" — and must emit no `users` key at all here, since `"users": []` is a
			// 400 exactly like `"addresses": []`.
			name: "addresses on both sides",
			payload: func() perimeter81Sdk.GranularFirewallPolicy {
				rule := buildGranularFirewallPolicyRule(map[string]interface{}{
					"id":          "fakeRuleAB",
					"name":        "fake-branch-to-db",
					"enabled":     true,
					"allowed":     true,
					"log_enabled": true,
					"services":    []interface{}{"fake-svc-1"},
					"sources": []interface{}{map[string]interface{}{
						"addresses": []interface{}{"fake-addr-1", "fake-addr-2"},
						"users":     []interface{}{},
						"groups":    []interface{}{},
					}},
					"destinations": []interface{}{map[string]interface{}{
						"addresses": []interface{}{"fake-addr-3"},
						"users":     []interface{}{},
						"groups":    []interface{}{},
					}},
				})
				policy := perimeter81Sdk.GranularFirewallPolicy{
					Id:          "fake-policy-4",
					Enabled:     true,
					Allowed:     false,
					PolicyRules: []perimeter81Sdk.GranularFirewallPolicyRule{rule},
				}
				policy.SetPolicyLoggingEnabled(true)
				return policy
			}(),
			want: `{
				"enabled": true,
				"allowed": false,
				"id": "fake-policy-4",
				"policyLoggingEnabled": true,
				"policyRules": [
					{
						"id": "fakeRuleAB",
						"name": "fake-branch-to-db",
						"enabled": true,
						"allowed": true,
						"sources": {"addresses": ["fake-addr-1", "fake-addr-2"]},
						"destinations": {"addresses": ["fake-addr-3"]},
						"services": ["fake-svc-1"],
						"logEnabled": true
					}
				]
			}`,
		},
		{
			// users and groups may coexist — they are the same oneOf variant. The
			// destinations side pairs a users+groups source with an addresses
			// destination, which is legal: the exclusion is per object, not per rule.
			name: "users and groups source, addresses destination",
			payload: func() perimeter81Sdk.GranularFirewallPolicy {
				rule := buildGranularFirewallPolicyRule(map[string]interface{}{
					"id":          "",
					"name":        "fake-contractors",
					"enabled":     true,
					"allowed":     false,
					"log_enabled": false,
					"services":    []interface{}{},
					"sources": []interface{}{map[string]interface{}{
						"addresses": []interface{}{},
						"users":     []interface{}{"fake-user-1", "fake-user-2"},
						"groups":    []interface{}{"fake-group-1"},
					}},
					"destinations": []interface{}{map[string]interface{}{
						"addresses": []interface{}{"fake-addr-9"},
						"users":     []interface{}{},
						"groups":    []interface{}{},
					}},
				})
				policy := perimeter81Sdk.GranularFirewallPolicy{
					Id:          "fake-policy-5",
					Enabled:     true,
					Allowed:     true,
					PolicyRules: []perimeter81Sdk.GranularFirewallPolicyRule{rule},
				}
				policy.SetPolicyLoggingEnabled(false)
				return policy
			}(),
			want: `{
				"enabled": true,
				"allowed": true,
				"id": "fake-policy-5",
				"policyLoggingEnabled": false,
				"policyRules": [
					{
						"name": "fake-contractors",
						"enabled": true,
						"allowed": false,
						"sources": {"users": ["fake-user-1", "fake-user-2"], "groups": ["fake-group-1"]},
						"destinations": {"addresses": ["fake-addr-9"]},
						"logEnabled": false
					}
				]
			}`,
		},
		{
			// A block written as `sources {}`, or one whose lists are all empty, is
			// the same request as no block at all. This is the case that would
			// silently widen a rule if the expand path guessed differently.
			name: "empty blocks are the unrestricted case",
			payload: func() perimeter81Sdk.GranularFirewallPolicy {
				rule := buildGranularFirewallPolicyRule(map[string]interface{}{
					"id":          "",
					"name":        "fake-empty-blocks",
					"enabled":     true,
					"allowed":     true,
					"log_enabled": false,
					"sources": []interface{}{map[string]interface{}{
						"addresses": []interface{}{},
						"users":     []interface{}{},
						"groups":    []interface{}{},
					}},
					"destinations": []interface{}{nil},
				})
				policy := perimeter81Sdk.GranularFirewallPolicy{
					Id:          "fake-policy-6",
					Enabled:     true,
					Allowed:     true,
					PolicyRules: []perimeter81Sdk.GranularFirewallPolicyRule{rule},
				}
				policy.SetPolicyLoggingEnabled(false)
				return policy
			}(),
			want: `{
				"enabled": true,
				"allowed": true,
				"id": "fake-policy-6",
				"policyLoggingEnabled": false,
				"policyRules": [
					{
						"name": "fake-empty-blocks",
						"enabled": true,
						"allowed": true,
						"sources": {},
						"destinations": {},
						"logEnabled": false
					}
				]
			}`,
		},
		{
			name: "zero rules",
			payload: func() perimeter81Sdk.GranularFirewallPolicy {
				policy := perimeter81Sdk.GranularFirewallPolicy{
					Id:          "fake-policy-2",
					Enabled:     false,
					Allowed:     false,
					PolicyRules: []perimeter81Sdk.GranularFirewallPolicyRule{},
				}
				policy.SetPolicyLoggingEnabled(false)
				return policy
			}(),
			want: `{
				"enabled": false,
				"allowed": false,
				"id": "fake-policy-2",
				"policyLoggingEnabled": false,
				"policyRules": []
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertMarshalsTo(t, tc.payload, tc.want)
		})
	}
}

/*
TestPayloadMarshalDynamicTunnelDetails is the regression test for blocker 2. It calls
flattenDynamicTunnelDetails — the exact function resourceEnhancedDynamicTunnelCreate uses to
build the Tunnels list — so reverting that fix (removing the RoutingType assignment) makes both
cases below fail: routingType comes back "" instead of "route".

The second case doubles as documentation of a known, deliberately-not-fixed issue: AuthType and
RemotePublicIP are required strings (not *string) on DynamicTunnelDetails, so when the user
leaves the corresponding Optional schema attributes unset, they still serialize as "" rather
than being omitted — same requiredness-driven behavior as StaticTunnelCreate below. RoutingType
must still come back "route" regardless, which is what this case is really asserting.
*/
func TestPayloadMarshalDynamicTunnelDetails(t *testing.T) {
	tests := []struct {
		name    string
		payload perimeter81Sdk.DynamicTunnelDetails
		want    string
	}{
		{
			name: "fields set",
			payload: flattenDynamicTunnelDetails([]interface{}{
				map[string]interface{}{
					"region_id":             "fake-region-1",
					"auth_type":             "psk",
					"passphrase":            "fake-passphrase-1",
					"customer_root_ca":      "",
					"remote_public_ip":      "203.0.113.10",
					"remote_id":             "",
					"remote_asn":            65010,
					"p81_gw_internal_ip":    "10.10.0.1",
					"remote_gw_internal_ip": "10.10.0.2",
				},
			})[0],
			want: `{
				"authType": "psk",
				"passphrase": "fake-passphrase-1",
				"regionID": "fake-region-1",
				"p81GWInternalIP": "10.10.0.1",
				"remoteGWInternalIP": "10.10.0.2",
				"remotePublicIP": "203.0.113.10",
				"remoteASN": 65010,
				"remoteID": "203.0.113.10",
				"routingType": "route"
			}`,
		},
		{
			name: "optional strings left unset — known issue: no omitempty, so they serialize as empty strings; routingType must still be route, never empty",
			payload: flattenDynamicTunnelDetails([]interface{}{
				map[string]interface{}{
					"region_id":             "fake-region-2",
					"auth_type":             "",
					"passphrase":            "",
					"customer_root_ca":      "",
					"remote_public_ip":      "",
					"remote_id":             "",
					"remote_asn":            65020,
					"p81_gw_internal_ip":    "10.20.0.1",
					"remote_gw_internal_ip": "10.20.0.2",
				},
			})[0],
			want: `{
				"authType": "",
				"regionID": "fake-region-2",
				"p81GWInternalIP": "10.20.0.1",
				"remoteGWInternalIP": "10.20.0.2",
				"remotePublicIP": "",
				"remoteASN": 65020,
				"remoteID": "",
				"routingType": "route"
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertMarshalsTo(t, tc.payload, tc.want)
			if tc.payload.RoutingType != perimeter81Sdk.ROUTINGTYPE_ROUTE {
				t.Errorf("RoutingType = %q, want %q (blocker 2 regression)", tc.payload.RoutingType, perimeter81Sdk.ROUTINGTYPE_ROUTE)
			}
		})
	}
}

/*
TestPayloadMarshalStaticTunnelCreate mirrors the StaticTunnelCreate payload construction in
resourceEnhancedStaticTunnelCreate (resource_enhanced_static_tunnel.go). It is not a regression
test — the static tunnel path already set RoutingType correctly — but it documents two known,
deliberately-not-fixed behaviors on the create path:

  - RemotePublicIP/RemoteID/AuthType lost omitempty under v3 (they're required strings, not
    *string), so a cert-auth tunnel that never sets remote_public_ip/remote_id still sends them
    as "" instead of omitting them.
  - Features is always NetworkFeaturesCreate{}, which serializes as three explicit
    "enabled": false leaves (cloudSecurity, symmetricInnerMesh, DNSServices.redirectToResolver)
    that v2.3 left at server default.
*/
func TestPayloadMarshalStaticTunnelCreate(t *testing.T) {
	phase1 := perimeter81Sdk.IPSecPhaseConfigV23{
		Auth:              []string{"sha256"},
		Encryption:        []string{"aes-cbc-256"},
		KeyExchangeMethod: []string{"modp2048"},
	}
	phase2 := perimeter81Sdk.IPSecPhaseConfigV23{
		Auth:              []string{"sha256"},
		Encryption:        []string{"aes-cbc-256"},
		KeyExchangeMethod: []string{"modp2048"},
	}

	tests := []struct {
		name    string
		payload perimeter81Sdk.StaticTunnelCreate
		want    string
	}{
		{
			name: "psk auth, all optional fields set",
			payload: func() perimeter81Sdk.StaticTunnelCreate {
				payload := perimeter81Sdk.StaticTunnelCreate{
					RegionID:             "fake-region-3",
					TunnelName:           "fake-tunnel-1",
					KeyExchange:          "ikev2",
					IkeLifeTime:          "28800s",
					Lifetime:             "3600s",
					DpdDelay:             "30s",
					DpdTimeout:           "30s",
					P81GatewaySubnets:    []string{"10.0.0.0/24"},
					RemoteGatewaySubnets: []string{"10.1.0.0/24"},
					Phase1:               phase1,
					Phase2:               phase2,
					RoutingType:          perimeter81Sdk.ROUTINGTYPE_ROUTE,
					Features:             perimeter81Sdk.NetworkFeaturesCreate{},
				}
				payload.AuthType = "psk"
				payload.RemotePublicIP = "203.0.113.20"
				payload.RemoteID = "203.0.113.20"
				passphrase := "fake-passphrase-2"
				payload.Passphrase = &passphrase
				description := "fake tunnel description"
				payload.Description = &description
				peakBandwidth := int32(500)
				payload.PeakBandwidthMbps = &peakBandwidth
				return payload
			}(),
			want: `{
				"authType": "psk",
				"passphrase": "fake-passphrase-2",
				"regionID": "fake-region-3",
				"tunnelName": "fake-tunnel-1",
				"p81GatewaySubnets": ["10.0.0.0/24"],
				"remoteGatewaySubnets": ["10.1.0.0/24"],
				"keyExchange": "ikev2",
				"ikeLifeTime": "28800s",
				"lifetime": "3600s",
				"dpdDelay": "30s",
				"dpdTimeout": "30s",
				"phase1": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "keyExchangeMethod": ["modp2048"]},
				"phase2": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "keyExchangeMethod": ["modp2048"]},
				"remotePublicIP": "203.0.113.20",
				"remoteID": "203.0.113.20",
				"description": "fake tunnel description",
				"features": {
					"cloudSecurity": {"enabled": false},
					"symmetricInnerMesh": {"enabled": false},
					"DNSServices": {"redirectToResolver": {"enabled": false}}
				},
				"routingType": "route",
				"peakBandwidthMbps": 500
			}`,
		},
		{
			name: "cert auth, remote_public_ip/remote_id left unset — known issue: serialize as empty strings, not omitted",
			payload: func() perimeter81Sdk.StaticTunnelCreate {
				payload := perimeter81Sdk.StaticTunnelCreate{
					RegionID:             "fake-region-4",
					TunnelName:           "fake-tunnel-2",
					KeyExchange:          "ikev1",
					IkeLifeTime:          "480m",
					Lifetime:             "60m",
					DpdDelay:             "10s",
					DpdTimeout:           "10s",
					P81GatewaySubnets:    []string{"10.2.0.0/24"},
					RemoteGatewaySubnets: []string{"10.3.0.0/24"},
					Phase1:               phase1,
					Phase2:               phase2,
					RoutingType:          perimeter81Sdk.ROUTINGTYPE_ROUTE,
					Features:             perimeter81Sdk.NetworkFeaturesCreate{},
				}
				payload.AuthType = "cert"
				rootCA := "fake-root-ca-pem"
				payload.CustomerRootCA = &rootCA
				// remote_public_ip and remote_id intentionally left unset (as if the user
				// never configured them for a cert-auth tunnel) — RemotePublicIP/RemoteID
				// stay at their Go zero value "" since d.GetOk's guard in the resource code
				// skips the assignment rather than defaulting to a pointer.
				return payload
			}(),
			want: `{
				"authType": "cert",
				"customerRootCA": "fake-root-ca-pem",
				"regionID": "fake-region-4",
				"tunnelName": "fake-tunnel-2",
				"p81GatewaySubnets": ["10.2.0.0/24"],
				"remoteGatewaySubnets": ["10.3.0.0/24"],
				"keyExchange": "ikev1",
				"ikeLifeTime": "480m",
				"lifetime": "60m",
				"dpdDelay": "10s",
				"dpdTimeout": "10s",
				"phase1": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "keyExchangeMethod": ["modp2048"]},
				"phase2": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "keyExchangeMethod": ["modp2048"]},
				"remotePublicIP": "",
				"remoteID": "",
				"features": {
					"cloudSecurity": {"enabled": false},
					"symmetricInnerMesh": {"enabled": false},
					"DNSServices": {"redirectToResolver": {"enabled": false}}
				},
				"routingType": "route"
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertMarshalsTo(t, tc.payload, tc.want)
		})
	}
}

/*
TestPayloadMarshalStaticTunnelUpdate mirrors the StaticTunnelUpdate payload construction in
resourceEnhancedStaticTunnelUpdate (resource_enhanced_static_tunnel.go). Every field on
StaticTunnelUpdate is a pointer/omitempty, and the Update path never sets Features or
RoutingType at all, so — unlike Create — Update never sends "features"/"routingType" regardless
of what the user configures. Documented here, not changed: peak_bandwidth has no field to update
in v3 at all (see the comment above UpdateStaticTunnel's call site), which is a separate,
already-flagged capability regression, not something this test asserts on.
*/
func TestPayloadMarshalStaticTunnelUpdate(t *testing.T) {
	tunnelName := "fake-tunnel-3"
	remotePublicIP := "203.0.113.30"
	remoteID := "203.0.113.30"
	authType := "psk"
	passphrase := "fake-passphrase-3"
	description := "updated fake tunnel"
	keyExchange := "ikev2"
	ikeLifeTime := "28800s"
	lifetime := "3600s"
	dpdDelay := "30s"
	dpdTimeout := "30s"
	phase1 := perimeter81Sdk.IPSecPhaseConfigV23{
		Auth:              []string{"sha256"},
		Encryption:        []string{"aes-cbc-256"},
		KeyExchangeMethod: []string{"modp2048"},
	}
	phase2 := perimeter81Sdk.IPSecPhaseConfigV23{
		Auth:              []string{"sha256"},
		Encryption:        []string{"aes-cbc-256"},
		KeyExchangeMethod: []string{"modp2048"},
	}

	payload := perimeter81Sdk.StaticTunnelUpdate{
		TunnelName:           &tunnelName,
		RemotePublicIP:       &remotePublicIP,
		RemoteID:             &remoteID,
		AuthType:             &authType,
		Passphrase:           &passphrase,
		Description:          &description,
		KeyExchange:          &keyExchange,
		IkeLifeTime:          &ikeLifeTime,
		Lifetime:             &lifetime,
		DpdDelay:             &dpdDelay,
		DpdTimeout:           &dpdTimeout,
		P81GatewaySubnets:    []string{"10.4.0.0/24"},
		RemoteGatewaySubnets: []string{"10.5.0.0/24"},
		Phase1:               &phase1,
		Phase2:               &phase2,
	}

	want := `{
		"authType": "psk",
		"passphrase": "fake-passphrase-3",
		"tunnelName": "fake-tunnel-3",
		"p81GatewaySubnets": ["10.4.0.0/24"],
		"remoteGatewaySubnets": ["10.5.0.0/24"],
		"keyExchange": "ikev2",
		"ikeLifeTime": "28800s",
		"lifetime": "3600s",
		"dpdDelay": "30s",
		"dpdTimeout": "30s",
		"phase1": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "keyExchangeMethod": ["modp2048"]},
		"phase2": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "keyExchangeMethod": ["modp2048"]},
		"remotePublicIP": "203.0.113.30",
		"remoteID": "203.0.113.30",
		"description": "updated fake tunnel"
	}`

	assertMarshalsTo(t, payload, want)
}

// testDynamicTunnelEndpointBlock returns one `tunnel` block, with every attribute set, as
// Terraform would hand it to the resource. Callers override individual keys to express "the
// same endpoint, edited".
func testDynamicTunnelEndpointBlock(regionID string, remotePublicIP string, remoteASN int) map[string]interface{} {
	return map[string]interface{}{
		"region_id":             regionID,
		"auth_type":             "psk",
		"passphrase":            "fake-passphrase-5",
		"customer_root_ca":      "",
		"remote_public_ip":      remotePublicIP,
		"remote_id":             remotePublicIP,
		"remote_asn":            remoteASN,
		"p81_gw_internal_ip":    "10.8.0.1",
		"remote_gw_internal_ip": "10.8.0.2",
	}
}

// testDynamicTunnelUpdateResourceData builds a ResourceData over the real
// checkpointsase_enhanced_dynamic_tunnel schema, holding the values
// buildDynamicTunnelUpdatePayload reads.
func testDynamicTunnelUpdateResourceData(t *testing.T) *schema.ResourceData {
	t.Helper()
	phase := []interface{}{map[string]interface{}{
		"auth":                []interface{}{"sha256"},
		"encryption":          []interface{}{"aes-cbc-256"},
		"key_exchange_method": []interface{}{"modp2048"},
	}}
	return schema.TestResourceDataRaw(t, resourceEnhancedDynamicTunnel().Schema, map[string]interface{}{
		"network_id":             "fake-network-1",
		"tunnel_name":            "fake-dyn-tun-1",
		"description":            "updated fake dynamic tunnel",
		"left_asn":               65000,
		"p81_gateway_subnets":    []interface{}{"10.6.0.0/24"},
		"remote_gateway_subnets": []interface{}{"10.7.0.0/24"},
		"peak_bandwidth":         500,
		"key_exchange":           "ikev2",
		"ike_life_time":          "28800s",
		"lifetime":               "3600s",
		"dpd_delay":              "30s",
		"dpd_timeout":            "30s",
		"phase1":                 phase,
		"phase2":                 phase,
		"tunnel": []interface{}{
			testDynamicTunnelEndpointBlock("fake-region-6", "203.0.113.50", 65010),
		},
	})
}

/*
TestPayloadMarshalDynamicTunnelUpdate is the regression test for the defect that this resource's
update body carried two of its fourteen mutable attributes — tunnelName and description — and
nothing else. Every other configurable value (the subnet lists, the IKE version, the four timing
fields and both phase configs) was accepted by Terraform, reported as applied, and never sent, so
the next plan showed the same diff forever.

It drives buildDynamicTunnelUpdatePayload, the exact function
resourceEnhancedDynamicTunnelUpdate calls, over the real resource schema, so dropping any of
those fields again fails here.

Two absences in the golden body are deliberate and are asserted by their absence:

  - no "features" inside sharedSettings. The only value the provider could send is
    NetworkFeaturesCreate{}, which serializes as explicit "enabled": false leaves; the live read
    capture in resource_enhanced_tunnel_read_test.go shows a real tunnel with
    DNSServices.redirectToResolver enabled, so sending it would switch off a feature nobody asked
    to change.
  - no "routingType". This resource exposes no routing_type attribute, the field is optional, and
    omitting it preserves whatever mode the group is in.

WIRE SHAPE UNVERIFIED: the nesting below (timing fields under advancedSettings, subnets under
sharedSettings) comes from the generated model and has not been confirmed against a live
response. The sibling read model was wrong in precisely this way until SDK overlay A19. If a
capture later shows the server wants these flat, this fixture is what changes.
*/
func TestPayloadMarshalDynamicTunnelUpdate(t *testing.T) {
	payload := buildDynamicTunnelUpdatePayload(testDynamicTunnelUpdateResourceData(t))

	want := `{
		"tunnelName": "fake-dyn-tun-1",
		"description": "updated fake dynamic tunnel",
		"sharedSettings": {
			"p81GatewaySubnets": ["10.6.0.0/24"],
			"remoteGatewaySubnets": ["10.7.0.0/24"]
		},
		"advancedSettings": {
			"keyExchange": "ikev2",
			"ikeLifeTime": "28800s",
			"lifetime": "3600s",
			"dpdDelay": "30s",
			"dpdTimeout": "30s",
			"phase1": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "keyExchangeMethod": ["modp2048"]},
			"phase2": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "keyExchangeMethod": ["modp2048"]}
		}
	}`

	assertMarshalsTo(t, payload, want)

	// The three endpoint collections must stay absent when the endpoint list did not change:
	// addTunnels/updateTunnels/removeTunnels are incremental, so an empty-but-present collection
	// is not the same request as an omitted one.
	if payload.AddTunnels != nil || payload.UpdateTunnels != nil || payload.RemoveTunnels != nil {
		t.Errorf("endpoint collections should be nil on a payload built from schema data alone; got add=%v update=%v remove=%v",
			payload.AddTunnels, payload.UpdateTunnels, payload.RemoveTunnels)
	}
}

/*
TestPayloadMarshalDynamicTunnelUpdateAddsEndpoints covers the one endpoint collection the
provider can populate correctly. addTunnels takes whole DynamicTunnelDetails objects, so a newly
written `tunnel` block needs no server-side id and can be sent verbatim — which is why adding an
endpoint is supported while editing or removing one is not (see
TestPlanDynamicTunnelEndpointChanges).
*/
func TestPayloadMarshalDynamicTunnelUpdateAddsEndpoints(t *testing.T) {
	existing := testDynamicTunnelEndpointBlock("fake-region-6", "203.0.113.50", 65010)
	added := testDynamicTunnelEndpointBlock("fake-region-7", "203.0.113.51", 65011)

	addTunnels, err := planDynamicTunnelEndpointChanges(
		[]interface{}{existing},
		[]interface{}{existing, added},
	)
	if err != nil {
		t.Fatalf("adding an endpoint must not error: %v", err)
	}

	payload := buildDynamicTunnelUpdatePayload(testDynamicTunnelUpdateResourceData(t))
	payload.AddTunnels = addTunnels

	want := `{
		"tunnelName": "fake-dyn-tun-1",
		"description": "updated fake dynamic tunnel",
		"sharedSettings": {
			"p81GatewaySubnets": ["10.6.0.0/24"],
			"remoteGatewaySubnets": ["10.7.0.0/24"]
		},
		"advancedSettings": {
			"keyExchange": "ikev2",
			"ikeLifeTime": "28800s",
			"lifetime": "3600s",
			"dpdDelay": "30s",
			"dpdTimeout": "30s",
			"phase1": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "keyExchangeMethod": ["modp2048"]},
			"phase2": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "keyExchangeMethod": ["modp2048"]}
		},
		"addTunnels": [
			{
				"authType": "psk",
				"passphrase": "fake-passphrase-5",
				"regionID": "fake-region-7",
				"p81GWInternalIP": "10.8.0.1",
				"remoteGWInternalIP": "10.8.0.2",
				"remotePublicIP": "203.0.113.51",
				"remoteASN": 65011,
				"remoteID": "203.0.113.51",
				"routingType": "route"
			}
		]
	}`

	assertMarshalsTo(t, payload, want)
}

/*
TestPlanDynamicTunnelEndpointChanges pins the rule that decides whether an endpoint change can be
expressed at all.

The asymmetry it encodes is not a simplification: addTunnels carries whole endpoint objects,
while updateTunnels and removeTunnels are keyed by a required server-assigned `id` that the
provider has no way to learn — the `tunnel` block has no id attribute, Read does not refresh the
block list, and EnhancedTunnel returns no remoteASN/p81GWInternalIP/remoteGWInternalIP to match a
returned endpoint back to the block that configured it. Guessing the pairing by list position or
by region_id would send one endpoint's pre-shared key to another endpoint, or delete the wrong
one.

The error cases below are therefore the point of the function, not a limitation to be worked
around later without new information: they turn "Terraform reported success and nothing happened"
into a failed apply that names what is missing.
*/
func TestPlanDynamicTunnelEndpointChanges(t *testing.T) {
	first := testDynamicTunnelEndpointBlock("fake-region-6", "203.0.113.50", 65010)
	second := testDynamicTunnelEndpointBlock("fake-region-7", "203.0.113.51", 65011)
	editedFirst := testDynamicTunnelEndpointBlock("fake-region-6", "203.0.113.52", 65010)

	rotatedFirst := testDynamicTunnelEndpointBlock("fake-region-6", "203.0.113.50", 65010)
	rotatedFirst["passphrase"] = "fake-passphrase-6"

	tests := []struct {
		name      string
		old       []interface{}
		updated   []interface{}
		wantAdded []string // regionID of each endpoint expected in addTunnels, in order
		wantErr   bool
	}{
		{
			name:    "unchanged endpoint list sends nothing",
			old:     []interface{}{first},
			updated: []interface{}{first},
		},
		{
			name:      "new endpoint appended",
			old:       []interface{}{first},
			updated:   []interface{}{first, second},
			wantAdded: []string{"fake-region-7"},
		},
		{
			name: "an empty prior list is refused, not treated as an add",
			// `tunnel` is Required, so a group Terraform created always has a block in
			// state. Reaching Update with none means the resource was imported, and the
			// endpoints already exist server-side — "adding" them would duplicate every
			// one of them on a live tunnel group. This case is the reason the function
			// checks cardinality before anything else.
			old:     []interface{}{},
			updated: []interface{}{first},
			wantErr: true,
		},
		{
			name: "reordering the same endpoints is not a change",
			old:  []interface{}{first, second},
			// Terraform sees a list, so a reorder is a diff; the server sees the same two
			// endpoints, so nothing needs sending. Position must not be treated as identity.
			updated: []interface{}{second, first},
		},
		{
			name:      "adding a duplicate of an existing endpoint adds exactly one",
			old:       []interface{}{first},
			updated:   []interface{}{first, first},
			wantAdded: []string{"fake-region-6"},
		},
		{
			name:    "editing an existing endpoint is refused",
			old:     []interface{}{first},
			updated: []interface{}{editedFirst},
			wantErr: true,
		},
		{
			name: "rotating an existing endpoint's passphrase is refused",
			old:  []interface{}{first},
			// A credential rotation looks like any other edit and needs the same missing id.
			// Treating it as an add would leave the old endpoint live with the old key.
			updated: []interface{}{rotatedFirst},
			wantErr: true,
		},
		{
			name:    "removing an endpoint is refused",
			old:     []interface{}{first, second},
			updated: []interface{}{first},
			wantErr: true,
		},
		{
			name:    "removing one of two identical endpoints is refused",
			old:     []interface{}{first, first},
			updated: []interface{}{first},
			wantErr: true,
		},
		{
			name:    "replacing an endpoint is refused, not split into an add plus a silent drop",
			old:     []interface{}{first},
			updated: []interface{}{second},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			added, err := planDynamicTunnelEndpointChanges(tc.old, tc.updated)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got addTunnels=%v — a change the update endpoint cannot express must fail the apply, not disappear", added)
				}
				if added != nil {
					t.Errorf("addTunnels must be nil on the error path, got %v", added)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(added) != len(tc.wantAdded) {
				t.Fatalf("addTunnels has %d entries, want %d: %v", len(added), len(tc.wantAdded), added)
			}
			for i, wantRegion := range tc.wantAdded {
				if added[i].RegionID != wantRegion {
					t.Errorf("addTunnels[%d].regionID = %q, want %q", i, added[i].RegionID, wantRegion)
				}
			}
		})
	}
}

/*
TestPayloadMarshalIPSecSingleCreate mirrors the CreateIPSecSinglePayload construction in
resourceIpsecSingleCreate (resource_ipsec_single.go). This is a v2.3-shaped payload — per the
v3-supersets-v2.3 relationship, ipsec_single hits an endpoint the v3 port left untouched — with
no known wire-body defects; it is covered here so a future change to this construction has a
golden body to regress against.
*/
func TestPayloadMarshalIPSecSingleCreate(t *testing.T) {
	payload := perimeter81Sdk.CreateIPSecSinglePayload{
		RegionID:             "fake-region-5",
		GatewayID:            "fake-gateway-1",
		TunnelName:           "fake-tunnel-4",
		KeyExchange:          "ikev2",
		RemotePublicIP:       "203.0.113.40",
		Lifetime:             "3600s",
		IkeLifeTime:          "28800s",
		Passphrase:           "fake-passphrase-4",
		DpdTimeout:           "30s",
		DpdDelay:             "30s",
		P81GatewaySubnets:    []string{"10.6.0.0/24"},
		RemoteGatewaySubnets: []string{"10.7.0.0/24"},
		Phase1: perimeter81Sdk.IPSecPhaseConfig{
			Auth:       []string{"sha256"},
			Encryption: []string{"aes-cbc-256"},
			Dh:         []int32{14},
		},
		Phase2: perimeter81Sdk.IPSecPhaseConfig{
			Auth:       []string{"sha256"},
			Encryption: []string{"aes-cbc-256"},
			Dh:         []int32{14},
		},
	}

	want := `{
		"regionID": "fake-region-5",
		"gatewayID": "fake-gateway-1",
		"tunnelName": "fake-tunnel-4",
		"p81GatewaySubnets": ["10.6.0.0/24"],
		"remoteGatewaySubnets": ["10.7.0.0/24"],
		"keyExchange": "ikev2",
		"ikeLifeTime": "28800s",
		"lifetime": "3600s",
		"dpdDelay": "30s",
		"dpdTimeout": "30s",
		"phase1": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "dh": [14]},
		"phase2": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "dh": [14]},
		"passphrase": "fake-passphrase-4",
		"remotePublicIP": "203.0.113.40"
	}`

	assertMarshalsTo(t, payload, want)
}

/*
TestPayloadMarshalIPSecRedundantCreate mirrors the CreateIPSecRedundantPayload construction in
resourceIpsecRedundantCreate (resource_ipsec_redundant.go), including the RemoteID oneOf-wrapper
handling via StringAsRemoteID. Note RemoteID is the same kind of oneOf wrapper as
SourcesAndDestinations (blocker 1) — it would hit the identical (nil, nil) MarshalJSON failure if
ever left as the zero-value RemoteID{}, but the provider always wraps a pointer to a string
variable (StringAsRemoteID(&remoteId)) even when that string is empty, so RemoteID.String is
never nil here and this path does not reproduce blocker 1's bug.
*/
func TestPayloadMarshalIPSecRedundantCreate(t *testing.T) {
	remoteID1 := "203.0.113.50"
	remoteID2 := "203.0.113.60"

	payload := perimeter81Sdk.CreateIPSecRedundantPayload{
		RegionID:   "fake-region-6",
		TunnelName: "fake-tunnel-5",
		Tunnel1: perimeter81Sdk.IPSecRedundantTunnelPayload{
			Passphrase:         "fake-passphrase-t1",
			GatewayID:          "fake-gateway-2",
			P81GWInternalIP:    "10.8.0.1",
			RemoteGWInternalIP: "10.8.0.2",
			RemotePublicIP:     "203.0.113.50",
			RemoteASN:          65030,
			RemoteID:           perimeter81Sdk.StringAsRemoteID(&remoteID1),
		},
		Tunnel2: perimeter81Sdk.IPSecRedundantTunnelPayload{
			Passphrase:         "fake-passphrase-t2",
			GatewayID:          "fake-gateway-3",
			P81GWInternalIP:    "10.9.0.1",
			RemoteGWInternalIP: "10.9.0.2",
			RemotePublicIP:     "203.0.113.60",
			RemoteASN:          65040,
			RemoteID:           perimeter81Sdk.StringAsRemoteID(&remoteID2),
		},
		SharedSettings: perimeter81Sdk.IPSecSharedSettingsCreate{
			P81GatewaySubnets:    []string{"10.10.0.0/24"},
			RemoteGatewaySubnets: []string{"10.11.0.0/24"},
			// P81ASN and Features intentionally omitted — see the comment above
			// SharedSettings in resourceIpsecRedundantCreate.
		},
		AdvancedSettings: perimeter81Sdk.IPSecAdvancedSettings{
			KeyExchange: "ikev2",
			IkeLifeTime: "28800s",
			Lifetime:    "3600s",
			DpdTimeout:  "30s",
			DpdDelay:    "30s",
			Phase1: perimeter81Sdk.IPSecPhaseConfig{
				Auth:       []string{"sha256"},
				Encryption: []string{"aes-cbc-256"},
				Dh:         []int32{14},
			},
			Phase2: perimeter81Sdk.IPSecPhaseConfig{
				Auth:       []string{"sha256"},
				Encryption: []string{"aes-cbc-256"},
				Dh:         []int32{14},
			},
		},
	}

	want := `{
		"tunnelName": "fake-tunnel-5",
		"regionID": "fake-region-6",
		"tunnel1": {
			"passphrase": "fake-passphrase-t1",
			"p81GWInternalIP": "10.8.0.1",
			"remoteGWInternalIP": "10.8.0.2",
			"remotePublicIP": "203.0.113.50",
			"remoteASN": 65030,
			"remoteID": "203.0.113.50",
			"gatewayID": "fake-gateway-2"
		},
		"tunnel2": {
			"passphrase": "fake-passphrase-t2",
			"p81GWInternalIP": "10.9.0.1",
			"remoteGWInternalIP": "10.9.0.2",
			"remotePublicIP": "203.0.113.60",
			"remoteASN": 65040,
			"remoteID": "203.0.113.60",
			"gatewayID": "fake-gateway-3"
		},
		"sharedSettings": {
			"p81GatewaySubnets": ["10.10.0.0/24"],
			"remoteGatewaySubnets": ["10.11.0.0/24"]
		},
		"advancedSettings": {
			"keyExchange": "ikev2",
			"ikeLifeTime": "28800s",
			"lifetime": "3600s",
			"dpdDelay": "30s",
			"dpdTimeout": "30s",
			"phase1": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "dh": [14]},
			"phase2": {"auth": ["sha256"], "encryption": ["aes-cbc-256"], "dh": [14]}
		}
	}`

	assertMarshalsTo(t, payload, want)
}

/*
TestPayloadMarshalApplicationCreate is the golden body for the application create request, and the
regression test for the first live application create failure (2026-08-19):

	Error: Unable to create Application
	{"data":{"errors":["users must contain at least 1 elements"]},
	 "message":"Bad Request Exception","messageCode":"BAD_REQUEST","status":400}

The interesting assertion in every case below is that `users` and `groups` are always present and
always arrays. None of the three Create models carries omitempty on either field, and all three
generated ToMap implementations write both keys unconditionally, so the provider cannot omit them —
and it must not try to, because the server's `users` is decorated @NotEquals(null) and would reject
a nil slice's `"users": null` outright. "Both keys, both arrays" is the only shape available, which
is why the both-empty case is refused before a request is built rather than reshaped here.

The `[]` in the "groups only" case is therefore deliberate and correct: the server's UsersMinSize
rule requires len(users) >= 1 only while `groups` is empty, so `"users": []` alongside a non-empty
`groups` is accepted. A test that asserted the key was absent would be pinning a shape the SDK
cannot produce and the API does not want.
*/
func TestPayloadMarshalApplicationCreate(t *testing.T) {
	tests := []struct {
		name    string
		appType string
		users   []string
		groups  []string
		want    string
	}{
		{
			name:    "http, users only",
			appType: "http",
			users:   []string{"fakeUser01", "fakeUser02"},
			groups:  []string{},
			want: `{
				"name": "fake-app",
				"type": "http",
				"network": "fakeNetwork01",
				"host": {"source": "fixed", "value": "app.fake.invalid"},
				"port": {"source": "fixed", "value": 8080},
				"users": ["fakeUser01", "fakeUser02"],
				"groups": [],
				"headers": {},
				"attributes": {}
			}`,
		},
		{
			// The shape that makes an application reachable by a group and no named user.
			// "users": [] is accepted here and only here — see the function comment.
			name:    "https, groups only",
			appType: "https",
			users:   []string{},
			groups:  []string{"fakeGroup01"},
			want: `{
				"name": "fake-app",
				"type": "https",
				"network": "fakeNetwork01",
				"host": {"source": "fixed", "value": "app.fake.invalid"},
				"port": {"source": "fixed", "value": 8080},
				"users": [],
				"groups": ["fakeGroup01"],
				"headers": {},
				"attributes": {}
			}`,
		},
		{
			// rdp has no headers and does carry auth, so it is the one variant whose key set
			// differs. Both access lists are populated to pin that they are independent.
			name:    "rdp, users and groups",
			appType: "rdp",
			users:   []string{"fakeUser01"},
			groups:  []string{"fakeGroup01"},
			want: `{
				"name": "fake-app",
				"type": "rdp",
				"network": "fakeNetwork01",
				"host": {"source": "fixed", "value": "app.fake.invalid"},
				"port": {"source": "fixed", "value": 8080},
				"users": ["fakeUser01"],
				"groups": ["fakeGroup01"],
				"attributes": {},
				"auth": {"authEnabled": false}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := buildCreateApplicationRequest(
				tt.appType, "fake-app", "fakeNetwork01", "app.fake.invalid", 8080, tt.users, tt.groups)
			if err != nil {
				t.Fatalf("buildCreateApplicationRequest returned an error: %v", err)
			}
			assertMarshalsTo(t, payload, tt.want)
		})
	}
}

/*
TestBuildCreateApplicationRequestRejectsUnknownType pins that the type switch has no silent fallback.
A oneOf CreateApplicationRequest with no variant set marshals to (nil, nil), which encoding/json
turns into "unexpected end of JSON input" — the same class of failure that made every firewall policy
rule unsendable. Returning an error keeps that out of the request path entirely.
*/
func TestBuildCreateApplicationRequestRejectsUnknownType(t *testing.T) {
	for _, appType := range []string{"", "ssh", "vnc", "HTTP"} {
		if _, err := buildCreateApplicationRequest(
			appType, "fake-app", "fakeNetwork01", "app.fake.invalid", 8080, []string{"fakeUser01"}, nil); err == nil {
			t.Errorf("buildCreateApplicationRequest(%q) returned no error; want one", appType)
		}
	}
}

/*
TestValidateApplicationAccessGrant covers the cross-field rule the schema cannot express. The cases
are chosen to match the server's UsersMinSize decorator rather than a plain min-size on `users`:
either list on its own is enough, and only the both-empty case is refused.
*/
func TestValidateApplicationAccessGrant(t *testing.T) {
	tests := []struct {
		name    string
		users   []interface{}
		groups  []interface{}
		wantErr bool
	}{
		{name: "users only", users: []interface{}{"fakeUser01"}, groups: []interface{}{}},
		{name: "groups only", users: []interface{}{}, groups: []interface{}{"fakeGroup01"}},
		{name: "both", users: []interface{}{"fakeUser01"}, groups: []interface{}{"fakeGroup01"}},
		// The two shapes an unset Optional TypeList takes: d.Get returns an empty non-nil
		// slice, and a type assertion that misses returns nil. Both mean "no members".
		{name: "both empty", users: []interface{}{}, groups: []interface{}{}, wantErr: true},
		{name: "both nil", users: nil, groups: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateApplicationAccessGrant(tt.users, tt.groups)
			if tt.wantErr && err == nil {
				t.Fatalf("validateApplicationAccessGrant returned no error; want one")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateApplicationAccessGrant returned an error: %v", err)
			}
		})
	}
}

/*
TestPayloadMarshalGranularFirewallPolicyClear is the golden body for the PUT that
resourceFirewallPolicyDelete sends, and the regression test for the destroy failure measured on
2026-08-19: the rules survived the destroy, and every object they referenced answered
`409 CONFLICT: This object cannot be edited or deleted because it is currently in use.`

Two properties are pinned that nothing else can see:

  - `"policyRules": []` — an array, not null. GranularFirewallPolicy.ToMap writes the key
    unconditionally, so building the payload with a nil slice would send `"policyRules": null` and
    fail the endpoint's @IsArray. Both variants compile and both marshal without error.
  - the three scalars carry the values the read returned, not defaults. The "not the new-network
    defaults" case exists so that a regression to hardcoded false/true/false fails here: it would
    still clear the rules, and the only visible symptom on a live tenant would be a policy whose
    switches were quietly rewritten during destroy.
*/
func TestPayloadMarshalGranularFirewallPolicyClear(t *testing.T) {
	tests := []struct {
		name string
		read perimeter81Sdk.GranularFirewallPolicy
		want string
	}{
		{
			name: "rules cleared, scalars echoed",
			read: perimeter81Sdk.GranularFirewallPolicy{
				Id:                   "fake-policy-1",
				Enabled:              true,
				Allowed:              false,
				PolicyLoggingEnabled: true,
				PolicyRules: []perimeter81Sdk.GranularFirewallPolicyRule{
					buildGranularFirewallPolicyRule(map[string]interface{}{
						"id":          "fakeRuleAB",
						"name":        "fake-allow-web",
						"enabled":     true,
						"allowed":     true,
						"log_enabled": false,
						"services":    []interface{}{"fake-svc-1"},
					}),
				},
			},
			want: `{
				"enabled": true,
				"allowed": false,
				"id": "fake-policy-1",
				"policyLoggingEnabled": true,
				"policyRules": []
			}`,
		},
		{
			// The pre-Terraform shape a freshly-created network's policy has, probed live on
			// 2026-08-19. Echoing it back is a true no-op.
			name: "already at new-network defaults",
			read: perimeter81Sdk.GranularFirewallPolicy{
				Id:                   "fake-policy-2",
				Enabled:              false,
				Allowed:              true,
				PolicyLoggingEnabled: false,
				PolicyRules:          []perimeter81Sdk.GranularFirewallPolicyRule{},
			},
			want: `{
				"enabled": false,
				"allowed": true,
				"id": "fake-policy-2",
				"policyLoggingEnabled": false,
				"policyRules": []
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read := tt.read
			assertMarshalsTo(t, buildGranularFirewallPolicyClear(&read), tt.want)
		})
	}
}

/*
TestObjectServicesICMPProtocolOptionsIsAsymmetric pins the shape difference
between the two directions of protocolOptions, which is the round-trip hazard
this attribute exists inside. The request takes a bare code — the SDK models it
as an int32 enum — while the response returns {code, description}, because the
server expands it through createProtocolOptions. A provider that wrote the
request value into state and read the response value back out of it would diff
forever; the same defect class as EnhancedTunnel's read shape in Phase 1.

Sending the object form, or sending valueType/value alongside icmp, is what a
naive port of the tcp/udp path would do. This test documents the SDK's existing
behaviour rather than driving a change to it: if it fails, the SDK does not model
ICMP the way this resource assumes.
*/
func TestObjectServicesICMPProtocolOptionsIsAsymmetric(t *testing.T) {
	t.Run("request carries the bare code", func(t *testing.T) {
		code := perimeter81Sdk.ObjectServiceProtocolOptionsICMPrequest(8)
		assertMarshalsTo(t, perimeter81Sdk.ObjectsServicesProtocolRequestObj{
			Protocol:        "icmp",
			ProtocolOptions: &code,
		}, `{"protocol":"icmp","protocolOptions":8}`)
	})

	t.Run("response carries the expanded object", func(t *testing.T) {
		codeValue := int32(8)
		description := "Echo"
		assertMarshalsTo(t, perimeter81Sdk.ObjectsServicesProtocolResponseObj{
			Protocol:        "icmp",
			ProtocolOptions: &perimeter81Sdk.ObjectServiceProtocolOptionsICMPresponse{Code: &codeValue, Description: &description},
		}, `{"protocol":"icmp","protocolOptions":{"code":8,"description":"Echo"}}`)
	})
}

/*
TestPayloadMarshalObjectServicesCreate is the golden body for both protocol
shapes, built through flattenProtocolsData — the exact function Create and Update
use — from the map shape d.Get("protocols") produces.

The cases that matter are the absences, and neither of them is visible in a
schema test because both shapes marshal without error:

  - an icmp entry must carry no valueType and no value. Sending them is not a
    400: CreateServicesTransformer rewrites valueType to "single" and drops
    value, and the read returns neither, so the entry would diff on every plan.
  - a tcp/udp entry must carry no protocolOptions, for the mirror-image reason —
    the server neither validates nor stores it for tcp, so it never comes back.

The `protocolOptions: 0` case is the one to watch. 0 is a legal ICMP code (Echo
Reply) and it is also the zero value of the SDK's int32 enum, so an
`omitempty`-by-value field would drop it from the body — after which the server
reads the code as absent and silently substitutes -1 ("Any"). It survives only
because ProtocolOptions is a pointer and ToMap tests the pointer, not the value.
*/
func TestPayloadMarshalObjectServicesCreate(t *testing.T) {
	description := "fake service"

	tests := []struct {
		name      string
		protocols []interface{}
		want      string
	}{
		{
			name: "tcp single port",
			protocols: []interface{}{
				map[string]interface{}{
					"protocol":         "tcp",
					"value_type":       "single",
					"value":            []interface{}{22},
					"protocol_options": 0,
				},
			},
			want: `{
				"name": "fake-svc",
				"description": "fake service",
				"protocols": [{"protocol": "tcp", "valueType": "single", "value": [22]}]
			}`,
		},
		{
			name: "icmp echo",
			protocols: []interface{}{
				map[string]interface{}{
					"protocol":         "icmp",
					"value_type":       "",
					"value":            []interface{}{},
					"protocol_options": 8,
				},
			},
			want: `{
				"name": "fake-svc",
				"description": "fake service",
				"protocols": [{"protocol": "icmp", "protocolOptions": 8}]
			}`,
		},
		{
			name: "icmp echo reply, whose code is the enum's zero value",
			protocols: []interface{}{
				map[string]interface{}{
					"protocol":         "icmp",
					"value_type":       "",
					"value":            []interface{}{},
					"protocol_options": 0,
				},
			},
			want: `{
				"name": "fake-svc",
				"description": "fake service",
				"protocols": [{"protocol": "icmp", "protocolOptions": 0}]
			}`,
		},
		{
			name: "icmp any",
			protocols: []interface{}{
				map[string]interface{}{
					"protocol":         "icmp",
					"value_type":       "",
					"value":            []interface{}{},
					"protocol_options": -1,
				},
			},
			want: `{
				"name": "fake-svc",
				"description": "fake service",
				"protocols": [{"protocol": "icmp", "protocolOptions": -1}]
			}`,
		},
		{
			// One object exercising both branches, in the order the user wrote
			// them: list position is preserved on the wire.
			name: "icmp alongside udp",
			protocols: []interface{}{
				map[string]interface{}{
					"protocol":         "icmp",
					"value_type":       "",
					"value":            []interface{}{},
					"protocol_options": 8,
				},
				map[string]interface{}{
					"protocol":         "udp",
					"value_type":       "range",
					"value":            []interface{}{5000, 5010},
					"protocol_options": 0,
				},
			},
			want: `{
				"name": "fake-svc",
				"description": "fake service",
				"protocols": [
					{"protocol": "icmp", "protocolOptions": 8},
					{"protocol": "udp", "valueType": "range", "value": [5000, 5010]}
				]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertMarshalsTo(t, perimeter81Sdk.ObjectsServicesRequestObj{
				Name:        "fake-svc",
				Description: &description,
				Protocols:   flattenProtocolsData(tt.protocols),
			}, tt.want)
		})
	}
}

/*
TestPayloadMarshalSupportOptions is the golden body for the account support
options PUT, built through buildSupportOptionsRequest — the exact function
resourceSupportOptionsUpdate uses — over the real resource schema.

The cases that matter are the absences, and neither is visible in a schema test
because both shapes marshal without error. Both were read against account-domain's
putCompanyBranding.schema.ts on 2026-08-19:

  - supportPhoneNumbers must be ABSENT, not [], when there are no custom numbers.
    The field is `type: ["array","null"]` with `minItems: 1`, so `[]` is a 400, and
    SupportOptionsRequest.ToMap writes the key on `o.SupportPhoneNumbers != nil` —
    a non-nil empty slice is present on the wire no matter what the struct tag
    says. This is the present-but-empty-array class that shipped three times in
    Phase 1.
  - liveChatCustomUrl must be ABSENT, not "", when there is no custom chat URL.
    The field carries minLength 8 and an `^https?://` pattern, so "" is a 400 as
    well. It survives only because the SDK models it as a *string and ToMap tests
    the pointer.

The `"userGuidesEnabled": false` case is the one to watch in the other direction.
It is a plain bool that ToMap writes unconditionally, which is what makes "disable
the user guides" expressible at all — an omitempty-by-value field would drop it
and the server would then reject the body for a missing required property.
*/
func TestPayloadMarshalSupportOptions(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]interface{}
		want string
	}{
		{
			// The shape an account gets by adopting the settings and changing
			// nothing but the user guides switch: three keys, and only three.
			name: "harmony sase defaults, both optional fields unset",
			raw: map[string]interface{}{
				"phone_support_type":  "harmonySaseDefault",
				"user_guides_enabled": true,
				"live_chat_type":      "harmonySaseDefault",
			},
			want: `{
				"phoneSupportType": "harmonySaseDefault",
				"userGuidesEnabled": true,
				"liveChatType": "harmonySaseDefault"
			}`,
		},
		{
			name: "hidden support, user guides off",
			raw: map[string]interface{}{
				"phone_support_type":  "hidden",
				"user_guides_enabled": false,
				"live_chat_type":      "hidden",
			},
			want: `{
				"phoneSupportType": "hidden",
				"userGuidesEnabled": false,
				"liveChatType": "hidden"
			}`,
		},
		{
			name: "custom, one phone number and a chat url",
			raw: map[string]interface{}{
				"phone_support_type":  "custom",
				"user_guides_enabled": true,
				"live_chat_type":      "custom",
				"support_phone_numbers": []interface{}{
					map[string]interface{}{"description": "US Support", "phone_number": "+1 555 0100"},
				},
				"live_chat_custom_url": "https://support.example.com/chat",
			},
			want: `{
				"phoneSupportType": "custom",
				"userGuidesEnabled": true,
				"liveChatType": "custom",
				"supportPhoneNumbers": [
					{"description": "US Support", "phoneNumber": "+1 555 0100"}
				],
				"liveChatCustomUrl": "https://support.example.com/chat"
			}`,
		},
		{
			// maxItems is 3, so this is the widest legal list, and list position
			// is preserved on the wire.
			name: "custom, the maximum three phone numbers",
			raw: map[string]interface{}{
				"phone_support_type":  "custom",
				"user_guides_enabled": true,
				"live_chat_type":      "hidden",
				"support_phone_numbers": []interface{}{
					map[string]interface{}{"description": "US Support", "phone_number": "+1 555 0100"},
					map[string]interface{}{"description": "EU Support", "phone_number": "+44 20 7000 0000"},
					map[string]interface{}{"description": "APAC Support", "phone_number": "+61 2 5550 0000"},
				},
			},
			want: `{
				"phoneSupportType": "custom",
				"userGuidesEnabled": true,
				"liveChatType": "hidden",
				"supportPhoneNumbers": [
					{"description": "US Support", "phoneNumber": "+1 555 0100"},
					{"description": "EU Support", "phoneNumber": "+44 20 7000 0000"},
					{"description": "APAC Support", "phoneNumber": "+61 2 5550 0000"}
				]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, resourceSupportOptions().Schema, tt.raw)
			assertMarshalsTo(t, buildSupportOptionsRequest(d), tt.want)
		})
	}
}

/*
TestSupportPhoneNumbersExpandOmitsRatherThanEmpties pins the nil that keeps
supportPhoneNumbers off the wire, at the one place a refactor would break it
without changing any golden body.

TestPayloadMarshalSupportOptions already fails if the key appears when it should
not, but only for a payload built from schema data. This asserts the contract
directly — expandSupportPhoneNumbers returns a nil slice, not an empty one, for
every input that carries no numbers — because "return an empty slice for an empty
input" is the obvious, idiomatic, and here wrong thing for someone to tidy this
function into. `[]` is a 400 (minItems 1, twice over: the request schema and the
stored document's own $jsonSchema).
*/
func TestSupportPhoneNumbersExpandOmitsRatherThanEmpties(t *testing.T) {
	for _, raw := range []struct {
		name  string
		input []interface{}
	}{
		{"nil", nil},
		{"empty", []interface{}{}},
		{"only unusable elements", []interface{}{"not a map", 7}},
	} {
		t.Run(raw.name, func(t *testing.T) {
			if got := expandSupportPhoneNumbers(raw.input); got != nil {
				t.Errorf("expandSupportPhoneNumbers(%#v) = %#v, want nil: a non-nil empty slice "+
					"reaches the wire as \"supportPhoneNumbers\": [], which the server refuses "+
					"(minItems 1)", raw.input, got)
			}
		})
	}

	// And the mirror-image contract on the read side: nil flattens to an empty
	// list, which is what an unset Optional list holds in state, so an account
	// with no custom numbers produces no diff.
	got := flattenSupportPhoneNumbers(nil)
	if got == nil || len(got) != 0 {
		t.Errorf("flattenSupportPhoneNumbers(nil) = %#v, want an empty non-nil list", got)
	}
}

/*
TestPayloadMarshalCustomDnsUpdate pins the private-DNS PUT body, whose shape the
corresponding GET cannot produce.

Measured 2026-08-26 and recorded as API-FINDINGS.md 1.31. Three neighbouring
bodies, one accepted and two refused:

	{"enabled":false,"attributes":{"servers":[],"searchDomains":[]}}   -> 202
	{"enabled":false}                                                  -> 422 VALIDATION_ERROR
	{"enabled":false,"attributes":{"searchDomains":[]}}                -> 400 "attributes.servers must be an array"

The 422 is the one that matters, because the second body is EXACTLY what
GET .../privateDNS returns for an unconfigured network -- no `attributes` key at
all. So the read body cannot be echoed back as a write, in either direction, and
`attributes` has to be synthesised on every PUT rather than carried over from the
read. Same trap as 1.17.

The two refusals cannot be asserted offline as HTTP responses, so they are pinned
as what the expander must never produce: `attributes` is always present, and
`attributes.servers` is always present inside it. Both are golden-body
assertions, because both bodies marshal without error and differ from the legal
one only by an absent key.

This calls expandCustomDnsUpdate rather than building the struct here, so a
regression that lets a nil slice through fails on this fixture and not only in
private_dns_test.go.
*/
func TestPayloadMarshalCustomDnsUpdate(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]interface{}
		want string
	}{
		{
			// VERIFIED 2026-08-26: this exact body returned 202. It is what a
			// config with `enabled = false` and no attributes block must send.
			name: "disable, no attributes block in the config",
			raw:  map[string]interface{}{"network_id": "fake-net-1", "enabled": false},
			want: `{"enabled": false, "attributes": {"servers": [], "searchDomains": []}}`,
		},
		{
			// The same body reached the other way: an explicitly emptied block.
			// `attributes { servers = [] search_domains = [] }` and an omitted
			// block are one configuration on the wire.
			name: "disable, attributes block present and emptied",
			raw: map[string]interface{}{
				"network_id": "fake-net-1",
				"enabled":    false,
				"attributes": []interface{}{map[string]interface{}{
					"servers":        []interface{}{},
					"search_domains": []interface{}{},
				}},
			},
			want: `{"enabled": false, "attributes": {"servers": [], "searchDomains": []}}`,
		},
		{
			// VERIFIED 2026-08-26: sent as written and returned byte-exactly,
			// including the non-alphabetical search-domain order and the
			// differing isTLS values. There is no canonicalisation here for a
			// flattener to reproduce (API-FINDINGS.md 1.31).
			name: "enabled, two servers and two search domains",
			raw: map[string]interface{}{
				"network_id": "fake-net-1",
				"enabled":    true,
				"attributes": []interface{}{map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{"address": "10.0.0.53", "is_tls": false},
						map[string]interface{}{"address": "10.0.1.53", "is_tls": true},
					},
					"search_domains": []interface{}{"b.example.com", "a.example.com"},
				}},
			},
			want: `{
				"enabled": true,
				"attributes": {
					"servers": [
						{"address": "10.0.0.53", "isTLS": false},
						{"address": "10.0.1.53", "isTLS": true}
					],
					"searchDomains": ["b.example.com", "a.example.com"]
				}
			}`,
		},
		{
			// NOT MEASURED, AND AUTHORED FOR THIS TEST. Every other row here is a
			// captured body; this one is not, and it is labelled so nobody reads
			// it as evidence about the API.
			//
			// It exists because the measured row above sends its two servers in
			// ASCENDING address order, so it passes just as well against an
			// expander that sorts -- proven by mutation on 2026-08-26: sorting the
			// `servers` array that expandCustomDnsUpdate sends left the whole
			// offline suite green. `servers` is priority-ordered, so reordering it
			// on the WRITE path changes which server the tenant consults first,
			// silently.
			//
			// Everything below is strictly DESCENDING, so a sort moves every
			// element of every array rather than one element of one. assertMarshalsTo
			// compares with reflect.DeepEqual over the decoded body, and DeepEqual
			// on a []interface{} is element-wise and ordered, so array order really
			// is asserted here and not merely set membership.
			name: "AUTHORED, NOT MEASURED: descending arrays must reach the wire descending",
			raw: map[string]interface{}{
				"network_id": "fake-net-1",
				"enabled":    true,
				"attributes": []interface{}{map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{"address": "10.0.2.53", "is_tls": true},
						map[string]interface{}{"address": "10.0.1.53", "is_tls": false},
						map[string]interface{}{"address": "10.0.0.53", "is_tls": true},
					},
					"search_domains": []interface{}{"c.example.com", "b.example.com", "a.example.com"},
					"dns_policy": []interface{}{map[string]interface{}{
						"public": []interface{}{map[string]interface{}{
							"domains": []interface{}{"z.example.com", "m.example.com", "a.example.com"},
						}},
						"private": []interface{}{map[string]interface{}{
							"mode":            "resolveAllViaPrivate",
							"public_fallback": false,
							"domains":         []interface{}{"z.corp.example.com", "a.corp.example.com"},
						}},
					}},
				}},
			},
			want: `{
				"enabled": true,
				"attributes": {
					"servers": [
						{"address": "10.0.2.53", "isTLS": true},
						{"address": "10.0.1.53", "isTLS": false},
						{"address": "10.0.0.53", "isTLS": true}
					],
					"searchDomains": ["c.example.com", "b.example.com", "a.example.com"],
					"dnsPolicy": {
						"public": {"domains": ["z.example.com", "m.example.com", "a.example.com"]},
						"private": {
							"mode": "resolveAllViaPrivate",
							"publicFallback": false,
							"domains": ["z.corp.example.com", "a.corp.example.com"]
						}
					}
				}
			}`,
		},
		{
			// dnsPolicy is *DnsPolicy with omitempty, so an absent block keeps
			// the key off the wire entirely -- which is what "any field omitted
			// from attributes is cleared, not preserved" means for a resource
			// whose config does not mention it.
			name: "enabled with a dns policy",
			raw: map[string]interface{}{
				"network_id": "fake-net-1",
				"enabled":    true,
				"attributes": []interface{}{map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{"address": "10.0.0.53", "is_tls": false},
					},
					"search_domains": []interface{}{"corp.example.com"},
					"dns_policy": []interface{}{map[string]interface{}{
						"public": []interface{}{map[string]interface{}{
							"domains": []interface{}{"public.example.com"},
						}},
						"private": []interface{}{map[string]interface{}{
							"mode":            "matchPattern",
							"public_fallback": true,
							"domains":         []interface{}{"private.example.com"},
						}},
					}},
				}},
			},
			want: `{
				"enabled": true,
				"attributes": {
					"servers": [{"address": "10.0.0.53", "isTLS": false}],
					"searchDomains": ["corp.example.com"],
					"dnsPolicy": {
						"public": {"domains": ["public.example.com"]},
						"private": {
							"mode": "matchPattern",
							"publicFallback": true,
							"domains": ["private.example.com"]
						}
					}
				}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, testPrivateDNSResourceSchema(), tt.raw)
			assertMarshalsTo(t, expandCustomDnsUpdate(d), tt.want)
		})
	}
}
