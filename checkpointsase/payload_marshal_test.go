package checkpointsase

import (
	"encoding/json"
	"reflect"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
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
						"sources": {"addresses": []},
						"destinations": {"addresses": []},
						"services": ["fake-svc-1", "fake-svc-2"],
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
