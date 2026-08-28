package checkpointsase

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
tunnelNameResources is EVERY resource carrying a `tunnel_name`, both network
families, because both were measured to enforce the same rule.

The standard four -- ipsec_single, ipsec_redundant, openvpn, wireguard -- take it
from the API's shared `TunnelName` schema (^[a-zA-Z0-9]*$, minLength 3, maxLength
15, swagger.yaml:7517), reached from `BaseTunnelValues`,
`CreateIPSecRedundantPayload` and `IPSecRedundantTunnels`.

The enhanced two are here ON EVIDENCE, NOT SYMMETRY, and the distinction is the
point: their payload schemas declare no constraint whatsoever
(`DynamicTunnelCreate` at swagger.yaml:4651, the static payload at
swagger.yaml:5059), so for one day they were deliberately excluded. An apply of
demo/enhanced_dynamic_tunnel on 2026-08-28 -- enhanced endpoints and nothing else
-- returned the same 422 at the same Joi path as the standard family. See the
comment on tunnelNamePattern and API-FINDINGS.md 1.33.

If a seventh tunnel resource ever appears, add it here; TestEveryTunnelNameIsGuarded
below is what notices that nobody did.
*/
var tunnelNameResources = []string{
	"checkpointsase_ipsec_single",
	"checkpointsase_ipsec_redundant",
	"checkpointsase_openvpn",
	"checkpointsase_wireguard",
	"checkpointsase_enhanced_static_tunnel",
	"checkpointsase_enhanced_dynamic_tunnel",
}

/*
tunnelNameValidateFunc pulls the live ValidateFunc off the REGISTERED resource
rather than calling validation.StringMatch(tunnelNamePattern, ...) directly.
Testing the pattern in isolation would pass just as well with the pattern wired
into none of the four resources, which is the defect this file exists to catch.

@return schema.SchemaValidateFunc
*/
func tunnelNameValidateFunc(t *testing.T, resourceType string) schema.SchemaValidateFunc {
	t.Helper()
	resource, ok := Provider().ResourcesMap[resourceType]
	if !ok {
		t.Fatalf("%s is not a registered resource", resourceType)
	}
	attr, ok := resource.Schema["tunnel_name"]
	if !ok {
		t.Fatalf("%s has no tunnel_name attribute", resourceType)
	}
	if attr.ValidateFunc == nil {
		t.Fatalf("%s.tunnel_name has no ValidateFunc, so every name reaches the server", resourceType)
	}
	return attr.ValidateFunc
}

/*
TestTunnelNameRejectsWhatTheServerRejects covers both halves of the
server's rule -- the character class and the 3-15 length -- because a caller
cannot tell which of the two they broke from the 422, and because
StringLenBetween(0, 15) got the bottom of the range wrong as well as the class.

"tf-p9-probe-wg" is the exact value measured in API-FINDINGS.md 1.33.
*/
func TestTunnelNameRejectsWhatTheServerRejects(t *testing.T) {
	rejected := []struct {
		name string
		why  string
	}{
		{"tf-p9-probe-wg", "hyphens -- the value measured in API-FINDINGS.md 1.33"},
		{"tf_probe", "underscore"},
		{"tf probe", "space"},
		{"tf.probe", "dot"},
		{"tfprobé", "a non-ASCII letter: the server's class is [a-zA-Z0-9], not Unicode"},
		{"", "empty -- the server's minLength is 3, and StringLenBetween(0, 15) allowed this"},
		{"ab", "two characters, below the server's minLength of 3"},
		{"abcdefghijklmnop", "sixteen characters, above the server's maxLength of 15"},
	}

	for _, resourceType := range tunnelNameResources {
		validate := tunnelNameValidateFunc(t, resourceType)
		for _, row := range rejected {
			_, errs := validate(row.name, "tunnel_name")
			if len(errs) == 0 {
				t.Errorf("%s: tunnel_name %q was accepted at plan time and must not be (%s)",
					resourceType, row.name, row.why)
			}
		}
	}
}

/*
TestTunnelNameAcceptsWhatTheServerAccepts is the other side of the gate.
A validator that refuses a name the server would have taken is WORSE than the
422 it replaces: the 422 arrives with a workaround, a plan-time refusal has
none. Every value here is inside pattern ^[a-zA-Z0-9]*$ with 3 <= length <= 15.
*/
func TestTunnelNameAcceptsWhatTheServerAccepts(t *testing.T) {
	accepted := []string{
		"tfp9probe",
		"abc",             // exactly minLength
		"abcdefghijklmno", // exactly maxLength, 15
		"Tunnel01",        // mixed case
		"0123",            // leading digit -- unlike passphrase, this class has no such rule
	}

	for _, resourceType := range tunnelNameResources {
		validate := tunnelNameValidateFunc(t, resourceType)
		for _, name := range accepted {
			_, errs := validate(name, "tunnel_name")
			if len(errs) > 0 {
				t.Errorf("%s: tunnel_name %q is valid for the server and was refused at plan time: %v",
					resourceType, name, errs)
			}
		}
	}
}

/*
TestEveryTunnelNameIsGuarded is the anti-omission check. tunnelNameResources is a
hand-written list, and a hand-written list is exactly what a seventh tunnel
resource would be added without. This walks the whole provider instead, so the
failure lands on the person who adds the resource rather than on whoever next
runs a live apply.
*/
func TestEveryTunnelNameIsGuarded(t *testing.T) {
	listed := map[string]bool{}
	for _, name := range tunnelNameResources {
		listed[name] = true
	}
	for name, resource := range Provider().ResourcesMap {
		if _, ok := resource.Schema["tunnel_name"]; !ok {
			continue
		}
		if !listed[name] {
			t.Errorf("%s has a tunnel_name and is not in tunnelNameResources, so nothing here "+
				"checks it. Add it -- and give it tunnelNamePattern unless the server has been "+
				"measured to disagree.", name)
		}
	}
}
