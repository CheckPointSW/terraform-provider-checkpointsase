package checkpointsase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// parseASNString converts a user-supplied ASN string (e.g. "65010") to an
// int32. Invalid input returns 0; the API validator catches out-of-range
// values. Used by resources whose HCL schema declares the ASN as a string
// (historical reasons) — newer resources use TypeInt directly.
func parseASNString(s string) int32 {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return int32(n)
}

// remoteIDAlphanumericPattern is the "alpha-numeric" half of the server's
// documented remote_id rule; the other half (IP address) is checked with
// net.ParseIP below so both IPv4 and IPv6 values are accepted.
var remoteIDAlphanumericPattern = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

// validateRemoteID is a schema.SchemaValidateFunc enforcing the server's
// documented remote_id rule, confirmed live against a 400 response reading
// `remoteID must be a valid remoteID ( alpha-numeric or IP)`. An empty
// string is let through here: remote_id is Optional (often Optional+
// Computed) everywhere it's used, and validation for a value the user never
// set is not this function's job.
func validateRemoteID(v interface{}, k string) (warns []string, errs []error) {
	s, ok := v.(string)
	if !ok {
		errs = append(errs, fmt.Errorf("expected type of %q to be string", k))
		return warns, errs
	}
	if s == "" {
		return warns, errs
	}
	if remoteIDAlphanumericPattern.MatchString(s) || net.ParseIP(s) != nil {
		return warns, errs
	}
	errs = append(errs, fmt.Errorf("%q must be alphanumeric or a valid IP address, got: %s", k, s))
	return warns, errs
}

/*
maxASN is the top of the 4-byte BGP autonomous-system range, RFC 6793.

DECLARED AS A TYPED int64, NOT LEFT UNTYPED. `validation.IntBetween` takes
`int`, and on the 32-bit targets `make release` builds -- GOARCH=386 and
GOARCH=arm -- `int` is 32 bits, so the untyped constant 4294967295 does not fit
and the build fails outright:

	cannot use 4294967295 (untyped int constant) as int value in argument
	to validation.IntBetween (overflows)

validateASN below compares in int64 instead, which is wide enough everywhere.
*/
const maxASN int64 = 4294967295

/*
validateASN enforces the 4-byte BGP ASN range on every platform.

WHY NOT validation.IntBetween(1, maxASN): see the constant above -- it does not
compile for 32-bit targets. Widening to int64 for the comparison is the whole
of the fix.

A LIMITATION THIS CANNOT REMOVE, only avoid crashing on: schema.TypeInt is
backed by Go's `int`, so a 32-bit build genuinely cannot represent an ASN above
2147483647 whatever this function says. Such a value never reaches here on
those platforms. Operators needing the top half of the ASN space on a 32-bit
build need a 64-bit build, or the attribute would have to become a string.

  - @param v interface{} - the configured value, an int from schema.TypeInt
  - @param k string - the attribute name, for the diagnostic

@return warns []string, errs []error
*/
func validateASN(v interface{}, k string) (warns []string, errs []error) {
	n, ok := v.(int)
	if !ok {
		errs = append(errs, fmt.Errorf("expected type of %q to be int", k))
		return warns, errs
	}
	if asn := int64(n); asn < 1 || asn > maxASN {
		errs = append(errs, fmt.Errorf(
			"%q must be a BGP autonomous-system number between 1 and %d, got: %d",
			k, maxASN, n))
	}
	return warns, errs
}

/*
tunnelNamePattern is the API's shared `TunnelName` schema -- pattern
^[a-zA-Z0-9]*$, minLength 3, maxLength 15 (swagger.yaml:7517) -- reached from
`BaseTunnelValues`, `CreateIPSecRedundantPayload` and `IPSecRedundantTunnels`,
which is to say the four standard-network tunnel resources.

{3,15} INSTEAD OF * PLUS A SEPARATE LENGTH CHECK. The server splits its rule
across `pattern` and `minLength`/`maxLength`; folding both into one Go pattern
gives the operator one message rather than two, and the quantifier applies to an
ASCII-only class so there is no rune-versus-byte disagreement of the kind
resource_group.go's name check had to unpick.

The rule matters more than it looks: the server does not store this value and
move on, it DERIVES the tunnel's `interfaceName` from it, and the 422 that
follows names only the derived field. See tunnelNameRuleMessage.

APPLIED TO THE ENHANCED-NETWORK TUNNELS TOO, ON EVIDENCE RATHER THAN SYMMETRY.
`DynamicTunnelCreate` (swagger.yaml:4651) and the static tunnel payload
(swagger.yaml:5059) declare `tunnelName` as a bare string with NO pattern and NO
length, so for one day this pattern covered only the standard four. Measured
2026-08-28: an apply of demo/enhanced_dynamic_tunnel -- which touches enhanced
endpoints and nothing else -- returned the SAME 422 as the standard family,
`"interfaceName" must only contain alpha-numeric characters`, and returned it at
the SAME Joi path, `regions[0].instances[0].attributes.tunnels[0]`. `instances`
appears in the public spec only on `NetworkRegion` (swagger.yaml:6326), the
STANDARD region model; there is no enhanced equivalent. The two families
therefore share one internal network document, and the spec's silence on the
enhanced side is a spec gap, not a looser server.

WHAT IS MEASURED FOR THE ENHANCED SIDE IS THE CHARACTER CLASS, not the bounds.
15 was already enforced there before this change and is left as it was; the
floor of 3 is carried over from the standard family's `minLength` and has not
been tested against an enhanced endpoint. A two-character enhanced tunnel name
is the one value this could refuse that the server might have taken.
*/
var tunnelNamePattern = regexp.MustCompile(`^[a-zA-Z0-9]{3,15}$`)

/*
tunnelNameRuleMessage states the RULE and stops there.

An earlier version went on to explain that the server derives `interfaceName`
from this value and quoted the 422 that results, on the reasoning that an
operator who had already hit the server error would need the two connected.
Trimmed on request: validation.StringMatch wraps this in "invalid value for %s
(%s)", so anything past the rule itself lands in a parenthetical the reader
cannot skim. The derivation and the measurement live in the attribute
Description of all six tunnel resources and in API-FINDINGS.md 1.33, which is
where someone looking for the WHY will be.

validation.StringMatch passes this as an ARGUMENT to %s rather than as a format
string, so a literal per-cent sign would be written once; there is none here.
*/
const tunnelNameRuleMessage = "must be 3-15 characters using only letters and digits: " +
	"no hyphens, underscores, dots or spaces"

/*
p81GatewaySubnetsEnhancedRule is the server's own restriction on
p81_gateway_subnets for the enhanced-network tunnel endpoints, carried in the
attribute Description so a reader can tell it is the API's rule and not the
provider's.

Measured live 2026-08-17. Creating an enhanced static tunnel
(POST /v3/networks/enhanced/{networkId}/tunnels/ipsec/static) with
p81GatewaySubnets set to an arbitrary CIDR is refused:

	409 {"message":"The list of Harmony SASE Subnets can only be \"0.0.0.0/0\"
	     or the network Subnet","messageCode":"CONFLICT"}

So the permitted values are exactly two: the default route, or the enclosing
network's own subnet.

WHY THAT FULL RULE IS NOT ENFORCED AT PLAN TIME — deliberate, do not "fix" it.
The permitted non-default value is another resource's attribute,
checkpointsase_enhanced_network.subnet. A resource's CustomizeDiff sees only
its own configuration and state; it cannot read a sibling resource, and the
sibling is usually being created in the same apply, so its subnet is an unknown
value during plan (network_id itself commonly is too). Anything written here
would therefore have to guess. Guessing has one plausible shape — allow only
"0.0.0.0/0" — and it would fail every configuration that correctly names its
network's subnet, which is the other half of what the server allows. A plan
that refuses a valid config is worse than the 409 the server already returns
for an invalid one, so the rule is documented and the server keeps enforcing
it.

What IS enforced is the part that needs no outside knowledge: every element
parses as a CIDR (validation.IsCIDR on the element schema). That turns a typo
into a plan-time failure instead of an apply-time one, without overclaiming.

Not measured: whether the dynamic-tunnel endpoint
(.../tunnels/ipsec/dynamic) applies the same restriction — only the static
endpoint was exercised — and whether the standard-network endpoints
(/v3/networks/standard/...) do. See those resources' descriptions.
*/
const p81GatewaySubnetsEnhancedRule = "Server-enforced: the list can hold only " +
	"`0.0.0.0/0` or the parent `checkpointsase_enhanced_network`'s own `subnet`; " +
	"any other CIDR is refused at apply time with " +
	"`409 The list of Harmony SASE Subnets can only be \"0.0.0.0/0\" or the network Subnet`. " +
	"The plan-time validator checks CIDR format only — the permitted subnet lives on " +
	"another resource and is usually unknown while planning, so the allowed-value half " +
	"of the rule cannot be checked before apply."

/*
setIfPresent writes value to the ResourceData attribute key only when present
is true. present is expected to be the SDK model's nil-safety check for the
field being written (e.g. tunnel.HasSecretAccessKey()) — a no-op otherwise.

Several credential-bearing attributes across this provider (OpenVPN's
access_key_id/secret_access_key, IPSec's passphrase) are write-once: the v3
API returns them on create or rotation but omits them on a plain read. The
SDK's nil-safe Get*() getters turn that omission into a zero value ("") with
no way for a caller to tell "the API sent an empty string" apart from "the
API sent nothing" — so an unconditional d.Set(key, tunnel.GetX()) after a
plain read would overwrite the terraform state's only durable copy of the
value with "". setIfPresent exists so Read functions can't do that by
accident: when present is false, this is a no-op and whatever is already in
state is left untouched.

The same guard is used beyond credentials, for any optional read-model field
where blanking state is worse than missing one refresh — see
setEnhancedTunnelIPSecState in resource_enhanced_static_tunnel.go, which
routes the enhanced tunnel's timing and remote-endpoint fields through here
precisely because a spec defect that made them read back as "" is what caused
the bug it was written to fix.
  - @param d *schema.ResourceData - the terraform resource data
  - @param key string - the schema attribute to (maybe) write
  - @param value string - the value to write when present
  - @param present bool - whether the API actually returned a value for key

@return error - any error from the underlying d.Set
*/
func setIfPresent(d *schema.ResourceData, key string, value string, present bool) error {
	// `present` comes from the SDK's generated HasX(), which only reports whether
	// the JSON field was non-nil -- it is true for a field the server sent as "".
	// That is not good enough for write-once credentials: the API returns
	// secretAccessKey exactly once, on create/rotation, and thereafter sends the
	// key back as an empty string rather than omitting it. Treating that as
	// "present" made Read overwrite the stored credential with "", which is the
	// value the resource description explicitly promises to preserve.
	//
	// So an empty value never overwrites state here. The only way to clear one of
	// these attributes is to destroy the resource.
	if !present || value == "" {
		return nil
	}
	return d.Set(key, value)
}

/*
setStringListIfPresent is the []string counterpart of setIfPresent, for
list-typed attributes whose SDK field is a plain slice with no generated
HasX() to consult.

The reasoning is the one written out above setIfPresent, applied to a slice: a
response that carries no entries for the field is indistinguishable, after
decoding, from a response that omitted the field entirely, and writing the
resulting empty slice into state would erase a list the user configured. An
empty slice therefore leaves state alone. As with setIfPresent, that makes the
worst case "this refresh learned nothing" rather than "the configuration was
silently erased" — and it costs nothing real, because every attribute this is
used for is Required in the schema, so an empty list was never a legal
configured value to preserve in the first place.
  - @param d *schema.ResourceData - the terraform resource data
  - @param key string - the schema attribute to (maybe) write
  - @param values []string - the values to write when non-empty

@return error - any error from the underlying d.Set
*/
func setStringListIfPresent(d *schema.ResourceData, key string, values []string) error {
	if len(values) == 0 {
		return nil
	}
	return d.Set(key, values)
}

/*
flattenStringsArrayData flatten string array data
  - @param strs []interface{} - the strings that need to be flattened

@return []string - the flattened strings
*/
func flattenStringsArrayData(strs []interface{}) []string {
	strsData := make([]string, len(strs))
	for index, str := range strs {
		strsData[index] = fmt.Sprint(str)
	}
	return strsData
}

/*
flattenIntsArrayData flatten ints array data
  - @param ints []interface{} - the ints that need to be flattened

@return []int32 - the flattened ints
*/
func flattenIntsArrayData(ints []interface{}) []int32 {
	intsData := make([]int32, len(ints))
	for index, ele := range ints {
		intsData[index] = int32(ele.(int))
	}
	return intsData
}

/*
getIdFromUrl split the url and get the last element(id)
  - @param url string - the url that need to be splited to get the id

@return string - the id
*/
func getIdFromUrl(url string) string {
	urlSplited := strings.Split(url, "/")
	return urlSplited[len(urlSplited)-1]
}

/*
flattenRegions flatten regions data
  - @param regionsDate []perimeter81Sdk.Region - the regions that need to be flattened

@return []interface{} - the flattened regions
*/
func flattenRegions(regionsDate []perimeter81Sdk.Region) []interface{} {
	if regionsDate != nil {
		regions := make([]interface{}, len(regionsDate))

		for i, regionData := range regionsDate {
			region := make(map[string]interface{})

			region["country_code"] = regionData.GetCountryCode()
			region["continent_code"] = regionData.GetContinentCode()
			region["display_name"] = regionData.GetDisplayName()
			region["name"] = regionData.GetName()
			region["class_name"] = regionData.GetClassName()
			region["object_id"] = regionData.GetId()
			region["id"] = regionData.GetId()
			regions[i] = region
		}

		return regions
	}

	return make([]interface{}, 0)
}

/*
flattenRegionsData flatten regions data
  - @param regionItems []interface{} - the regions that need to be flattened

@return []perimeter81Sdk.StandardNetworkRegionConfig - the flattened regions
*/
func flattenRegionsData(regionItems []interface{}) []StandardNetworkRegionConfig {
	if regionItems != nil {
		regions := make([]StandardNetworkRegionConfig, len(regionItems))

		for i, regionItem := range regionItems {
			region := StandardNetworkRegionConfig{}

			region.CpRegionId = regionItem.(map[string]interface{})["cpregion_id"].(string)
			region.Idle = regionItem.(map[string]interface{})["idle"].(bool)
			region_id := regionItem.(map[string]interface{})["region_id"]
			if region_id != nil {
				region.RegionID = region_id.(string)
			}
			regions[i] = region
		}

		return regions
	}

	return make([]StandardNetworkRegionConfig, 0)
}

/*
flattenProtocolsData flatten Protocols data
  - @param protocolItems []interface{} - the protocols that need to be flattened

@return []perimeter81Sdk.ObjectsServicesProtocolRequestObj - the flattened protocols
*/
func flattenProtocolsData(protocolItems []interface{}) []perimeter81Sdk.ObjectsServicesProtocolRequestObj {
	if protocolItems == nil {
		return make([]perimeter81Sdk.ObjectsServicesProtocolRequestObj, 0)
	}
	protocols := make([]perimeter81Sdk.ObjectsServicesProtocolRequestObj, len(protocolItems))
	for i, protocolItem := range protocolItems {
		m, _ := protocolItem.(map[string]interface{})
		protocol, _ := m["protocol"].(string)

		if protocol == "icmp" {
			// An icmp entry carries the message type and no ports, and the two
			// halves are exclusive on the wire rather than merely optional: the
			// server's CreateServicesTransformer overwrites valueType with
			// "single" and drops value for icmp, so a body carrying both reads
			// back different from what was sent. protocol_options is required
			// for icmp by resourceObjectServicesCustomizeDiff, so a zero here
			// is a configured code 0 (Echo Reply) and not an omission — an
			// omission would have to be sent as something, and whatever we
			// chose would be an ICMP type the user never asked for.
			code, _ := m["protocol_options"].(int)
			options := perimeter81Sdk.ObjectServiceProtocolOptionsICMPrequest(int32(code))
			protocols[i] = perimeter81Sdk.ObjectsServicesProtocolRequestObj{
				Protocol:        protocol,
				ProtocolOptions: &options,
			}
			continue
		}

		// v3 flipped ValueType to *string; take the address of a local
		// rather than the (non-addressable) map-index type assertion.
		valueType, _ := m["value_type"].(string)
		value, _ := m["value"].([]interface{})
		entry := perimeter81Sdk.ObjectsServicesProtocolRequestObj{
			Protocol:  protocol,
			ValueType: &valueType,
			Value:     flattenIntsArrayData(value),
		}
		protocols[i] = entry
	}
	return protocols
}

// StandardNetworkRegionConfig holds the internal representation of a standard network region
// used for tracking region create/delete operations.
type StandardNetworkRegionConfig struct {
	// CpRegionId is the region ID used in the get-regions endpoint (cpregion / harmony-sase region id).
	CpRegionId string
	// RegionID is the ID of the created region inside the network.
	RegionID string
	// Idle indicates whether the gateway should be created as disabled.
	Idle bool
	// Name is the display name of the region.
	Name string
	// Dns is the DNS of the region.
	Dns string
	// DefaultGatewayIp is the IP of the default gateway.
	DefaultGatewayIp string
}

/*
flattenNetworkData flatten network data
  - @param networkItems []perimeter81Sdk.CreateNetworkPayload - the network data that need to be flattened

@return []interface{} - the flattened network data
*/
func flattenNetworkData(networkItems []perimeter81Sdk.CreateNetworkPayload) []interface{} {
	if networkItems != nil {
		networks := make([]interface{}, len(networkItems))

		for i, networkItem := range networkItems {
			network := make(map[string]interface{})

			network["name"] = networkItem.Name
			network["tags"] = networkItem.Tags
			network["subnet"] = networkItem.GetSubnet()
			networks[i] = network
		}

		return networks
	}

	return make([]interface{}, 0)
}

/*
flattenNetworkRegions flatten network regions
  - @param regionItems []StandardNetworkRegionConfig - the network regions that need to be flattened

@return []interface{} - the flattened  network regions
*/
func flattenNetworkRegions(regionItems []StandardNetworkRegionConfig) []interface{} {
	if regionItems != nil {
		regions := make([]interface{}, len(regionItems))

		for i, regionItem := range regionItems {
			region := make(map[string]interface{})

			region["cpregion_id"] = regionItem.CpRegionId
			region["region_id"] = regionItem.RegionID
			region["idle"] = regionItem.Idle
			region["name"] = regionItem.Name
			region["dns"] = regionItem.Dns
			region["default_gateway_ip"] = regionItem.DefaultGatewayIp
			regions[i] = region
		}

		return regions
	}

	return make([]interface{}, 0)
}

/*
flattenObjectServicesProtocols flatten object services protocols
  - @param protocolItems []perimeter81Sdk.ObjectsServicesProtocolResponseObj - the object services protocols that need to be flattened

@return []interface{} - the flattened  network regions
*/
func flattenObjectServicesProtocols(protocolItems []perimeter81Sdk.ObjectsServicesProtocolResponseObj) []interface{} {
	if protocolItems == nil {
		return make([]interface{}, 0)
	}
	protocols := make([]interface{}, len(protocolItems))
	for i, protocolItem := range protocolItems {
		protocols[i] = map[string]interface{}{
			"protocol": protocolItem.Protocol,
			// ValueType is *string in v3; GetValueType() nil-checks the
			// receiver and returns the zero value, so it's safe under
			// omitempty absence. Assigning the pointer directly would
			// store the pointer, not the string, in the flattened map.
			"value_type": protocolItem.GetValueType(),
			"value":      protocolItem.Value,
			// protocolOptions is asymmetric: the request takes the bare ICMP
			// code, the response wraps it as {code, description} because the
			// server expands it through createProtocolOptions. Read the code
			// back, never the description — the description is derived from the
			// code, so a state attribute holding it would have no behaviour
			// except to drift. GetCode is nil-safe on a nil receiver, so a
			// tcp/udp entry reads back 0, which is what an unset TypeInt holds
			// and therefore does not diff.
			"protocol_options": int(protocolItem.ProtocolOptions.GetCode()),
		}
	}
	return protocols
}

/*
flattenRegionData flatten network
  - @param networkItems []perimeter81Sdk.CreateNetworkPayload - the network that need to be flattened

@return []interface{} - the flattened  network data
*/
func flattenRegionData(networkItems []perimeter81Sdk.CreateNetworkPayload) []interface{} {
	if networkItems != nil {
		networks := make([]interface{}, len(networkItems))

		for i, networkItem := range networkItems {
			network := make(map[string]interface{})

			network["name"] = networkItem.Name
			network["tags"] = networkItem.Tags
			network["subnet"] = networkItem.GetSubnet()
			networks[i] = network
		}

		return networks
	}

	return make([]interface{}, 0)
}

/*
flattenNetworksData flatten networks data
  - @param networkItems []perimeter81Sdk.Network - the networks that need to be flattened

@return []interface{} - the flattened  networks data
*/
func flattenNetworksData(networkItems []perimeter81Sdk.Network) []interface{} {
	if networkItems != nil {
		networks := make([]interface{}, len(networkItems))
		for i, serverItem := range networkItems {
			network := make(map[string]interface{})
			network["name"] = serverItem.Name
			network["id"] = serverItem.Id
			network["tags"] = serverItem.Tags
			network["subnet"] = serverItem.Subnet
			network["dns"] = serverItem.Dns
			network["accesstype"] = serverItem.AccessType
			network["isdefault"] = serverItem.IsDefault
			network["tenantid"] = serverItem.TenantId
			network["createdat"] = serverItem.CreatedAt.String()
			if serverItem.UpdatedAt != nil {
				network["updatedat"] = serverItem.UpdatedAt.String()
			} else {
				network["updatedat"] = ""
			}
			network["regions"] = flattenNetworkRegionsData(serverItem.Regions)
			networks[i] = network
		}
		return networks
	}
	return make([]interface{}, 0)
}

/*
flattenNetworkRegionsData flatten network regions data
  - @param regionItems []perimeter81Sdk.NetworkRegion - the network regions that need to be flattened

@return []interface{} - the flattened  network regions data
*/
func flattenNetworkRegionsData(regionItems []perimeter81Sdk.NetworkRegion) []interface{} {
	if regionItems != nil {
		regions := make([]interface{}, len(regionItems))
		for i, regionItem := range regionItems {
			region := make(map[string]interface{})
			region["network"] = regionItem.Network
			region["dns"] = regionItem.Dns
			region["name"] = regionItem.Name
			region["tenantid"] = regionItem.TenantId
			region["createdat"] = regionItem.CreatedAt.String()
			if regionItem.UpdatedAt != nil {
				region["updatedat"] = regionItem.UpdatedAt.String()
			} else {
				region["updatedat"] = ""
			}
			region["id"] = regionItem.Id
			region["instances"] = flattenNetworkInstancesData(regionItem.Instances)
			regions[i] = region
		}
		return regions
	}
	return make([]interface{}, 0)
}

/*
flattenNetworkInstancesData flatten network instances data
  - @param instanceItems []perimeter81Sdk.NetworkInstance - the network instances that need to be flattened

@return []interface{} - the flattened  network instances data
*/
func flattenNetworkInstancesData(instanceItems []perimeter81Sdk.NetworkInstance) []interface{} {
	if instanceItems != nil {
		instances := make([]interface{}, len(instanceItems))
		for i, instanceItem := range instanceItems {
			instance := make(map[string]interface{})
			instance["network"] = instanceItem.Network
			instance["dns"] = instanceItem.Dns
			instance["tenantid"] = instanceItem.TenantId
			instance["createdat"] = instanceItem.CreatedAt.String()
			if instanceItem.UpdatedAt != nil {
				instance["updatedat"] = instanceItem.UpdatedAt.String()
			} else {
				instance["updatedat"] = ""
			}
			instance["ip"] = instanceItem.Ip
			instance["id"] = instanceItem.Id
			instance["imageversion"] = instanceItem.ImageVersion
			instance["imagetype"] = instanceItem.ImageType
			instance["region"] = instanceItem.Region
			instance["instancetype"] = instanceItem.InstanceType
			instance["tunnels"] = flattenNetworkTunnelsData(instanceItem.Tunnels)
			instances[i] = instance
		}
		return instances
	}

	return make([]interface{}, 0)
}

/*
flattenNetworkTunnelsData flatten network tunnels data
  - @param tunnelItems []perimeter81Sdk.NetworkTunnel - the network tunnels that need to be flattened

@return []interface{} - the flattened  network tunnels data
*/
func flattenNetworkTunnelsData(tunnelItems []perimeter81Sdk.NetworkTunnel) []interface{} {
	if tunnelItems != nil {
		tunnels := make([]interface{}, len(tunnelItems))
		for i, tunnelItem := range tunnelItems {
			tunnel := make(map[string]interface{})
			// NetworkTunnel is a union type - extract base fields from whichever variant is set
			if tunnelItem.NetworkTunnelWireguard != nil {
				wg := tunnelItem.NetworkTunnelWireguard
				tunnel["instance"] = wg.Instance
				tunnel["interfacename"] = wg.InterfaceName
				tunnel["leftallowedip"] = wg.LeftAllowedIP
				tunnel["leftendpoint"] = wg.LeftEndpoint
				tunnel["network"] = wg.Network
				tunnel["region"] = wg.Region
				tunnel["requestconfigtoken"] = wg.RequestConfigToken
				tunnel["type"] = wg.Type
				tunnel["id"] = wg.Id
				tunnel["tenantid"] = wg.TenantId
				tunnel["createdat"] = wg.CreatedAt.String()
				if wg.UpdatedAt != nil {
					tunnel["updatedat"] = wg.UpdatedAt.String()
				} else {
					tunnel["updatedat"] = ""
				}
			} else if tunnelItem.NetworkTunnelIpsecSingle != nil {
				t := tunnelItem.NetworkTunnelIpsecSingle
				tunnel["instance"] = t.Instance
				tunnel["interfacename"] = t.InterfaceName
				tunnel["leftallowedip"] = []string{}
				tunnel["leftendpoint"] = ""
				tunnel["network"] = t.Network
				tunnel["region"] = t.Region
				tunnel["requestconfigtoken"] = ""
				tunnel["type"] = t.Type
				tunnel["id"] = t.Id
				tunnel["tenantid"] = t.TenantId
				tunnel["createdat"] = t.CreatedAt.String()
				if t.UpdatedAt != nil {
					tunnel["updatedat"] = t.UpdatedAt.String()
				} else {
					tunnel["updatedat"] = ""
				}
			} else if tunnelItem.NetworkTunnelIpsecRedundant != nil {
				t := tunnelItem.NetworkTunnelIpsecRedundant
				tunnel["instance"] = t.Instance
				tunnel["interfacename"] = t.InterfaceName
				tunnel["leftallowedip"] = []string{}
				tunnel["leftendpoint"] = ""
				tunnel["network"] = t.Network
				tunnel["region"] = t.Region
				tunnel["requestconfigtoken"] = ""
				tunnel["type"] = t.Type
				tunnel["id"] = t.Id
				tunnel["tenantid"] = t.TenantId
				tunnel["createdat"] = t.CreatedAt.String()
				if t.UpdatedAt != nil {
					tunnel["updatedat"] = t.UpdatedAt.String()
				} else {
					tunnel["updatedat"] = ""
				}
			} else if tunnelItem.NetworkTunnelOpenvpn != nil {
				t := tunnelItem.NetworkTunnelOpenvpn
				tunnel["instance"] = t.Instance
				tunnel["interfacename"] = t.InterfaceName
				tunnel["leftallowedip"] = []string{}
				tunnel["leftendpoint"] = ""
				tunnel["network"] = t.Network
				tunnel["region"] = t.Region
				tunnel["requestconfigtoken"] = ""
				tunnel["type"] = t.Type
				tunnel["id"] = t.Id
				tunnel["tenantid"] = t.TenantId
				tunnel["createdat"] = t.CreatedAt.String()
				if t.UpdatedAt != nil {
					tunnel["updatedat"] = t.UpdatedAt.String()
				} else {
					tunnel["updatedat"] = ""
				}
			}
			tunnels[i] = tunnel
		}
		return tunnels
	}

	return make([]interface{}, 0)
}

/*
flattenPhasesData flatten Phases date
  - @param phasesItem *perimeter81Sdk.IPSecPhaseConfig - the phase config that need to be flattened

@return []interface{} - the flattened  phases data
*/
func flattenPhasesData(phasesItem *perimeter81Sdk.IPSecPhaseConfig) []interface{} {
	if phasesItem != nil {
		phase := make([]interface{}, 1)
		phaseData := make(map[string]interface{})
		phaseData["auth"] = phasesItem.Auth
		phaseData["encryption"] = phasesItem.Encryption
		phaseData["dh"] = phasesItem.Dh
		phase[0] = phaseData
		return phase
	}

	return make([]interface{}, 0)
}

/*
flattenAdvancedSettingsData flatten Advanced Settings date
  - @param advancedSettingsItem *IPSecAdvancedSettings - the advanced settings that need to be flattened

@return []interface{} - the flattened advanced settings data
*/
func flattenAdvancedSettingsData(advancedSettingsItem *perimeter81Sdk.IPSecAdvancedSettings) []interface{} {
	if advancedSettingsItem != nil {
		advancedSettings := make([]interface{}, 1)
		advancedSettingsData := make(map[string]interface{})
		advancedSettingsData["key_exchange"] = advancedSettingsItem.KeyExchange
		advancedSettingsData["ike_life_time"] = advancedSettingsItem.IkeLifeTime
		advancedSettingsData["lifetime"] = advancedSettingsItem.Lifetime
		advancedSettingsData["dpd_delay"] = advancedSettingsItem.DpdDelay
		advancedSettingsData["dpd_timeout"] = advancedSettingsItem.DpdTimeout
		phase1 := advancedSettingsItem.Phase1
		phase2 := advancedSettingsItem.Phase2
		advancedSettingsData["phase1"] = flattenPhasesData(&phase1)
		advancedSettingsData["phase2"] = flattenPhasesData(&phase2)
		advancedSettings[0] = advancedSettingsData
		return advancedSettings
	}

	return make([]interface{}, 0)
}

/*
flattenSharedSettingsData flatten Shared Settings date
  - @param sharedSettingsItem *IpSecSharedSettings - the Ip-Sec Shared settings that need to be flattened
  - @param priorSharedSettings []interface{} - the previous value of the "shared_settings"
    attribute (i.e. d.Get("shared_settings") from BEFORE this Read call overwrites it), used to
    preserve peak_bandwidth across reads — see comment below. Callers MUST pass the prior value;
    passing nil/empty silently loses any previously-configured peak_bandwidth. Preservation is
    threaded through the signature (rather than left to the caller to remember at the d.Set call
    site) specifically so it can't be forgotten by a future call site.

@return []interface{} - the flattened Ip-Sec Shared settings data
*/
func flattenSharedSettingsData(sharedSettingsItem *perimeter81Sdk.IPSecSharedSettings, priorSharedSettings []interface{}) []interface{} {
	if sharedSettingsItem != nil {
		sharedSettings := make([]interface{}, 1)
		sharedSettingsData := make(map[string]interface{})
		sharedSettingsData["p81_gateway_subnets"] = sharedSettingsItem.P81GatewaySubnets
		sharedSettingsData["remote_gateway_subnets"] = sharedSettingsItem.RemoteGatewaySubnets
		// v3 dropped the bandwidth field entirely from IPSecSharedSettings —
		// verified against the SDK: no field of any name carries it anymore,
		// and nothing on the redundant-tunnel read/create/update surface
		// replaces it. This flatten helper can no longer populate
		// "peak_bandwidth" from the API response, so carry forward whatever
		// was already in state instead of blanking it — same
		// preserve-prior-state precedent as resourceGatewayRead's
		// `name`/`idle` handling in resource_gateway.go. A tunnel whose
		// state never had peak_bandwidth set (e.g. imported outside
		// Terraform) has nothing to carry forward and falls back to the
		// schema default via Terraform's normal Default handling.
		//
		// The corresponding schema attribute
		// (checkpointsase_ipsec_redundant's shared_settings.peak_bandwidth,
		// resource_ipsec_redundant.go) is effectively inert under v3: HCL
		// can still set it, and it round-trips in state via this
		// preservation, but it is never transmitted to the API —
		// IPSecSharedSettingsCreate (and every other IPSecSharedSettings-
		// family type) dropped the field entirely, with no replacement
		// anywhere on the redundant-tunnel create/update surface. See the
		// schema comment on that attribute for the user-facing note.
		if len(priorSharedSettings) > 0 {
			if priorMap, ok := priorSharedSettings[0].(map[string]interface{}); ok {
				if pb, ok := priorMap["peak_bandwidth"].(int); ok {
					sharedSettingsData["peak_bandwidth"] = pb
				}
			}
		}
		sharedSettings[0] = sharedSettingsData
		return sharedSettings
	}

	return make([]interface{}, 0)
}

/*
flattenTunnelData flatten Tunnel date
  - @param tunnelItem *IPSecRedundantTunnel - the tunnel that need to be flattened
  - @param priorTunnelData []interface{} - the previous value of the "tunnel1"/"tunnel2"
    attribute (i.e. d.Get("tunnel1") / d.Get("tunnel2") from BEFORE this Read call overwrites
    it). passphrase is a write-once credential — same pattern as OpenVPN's secret_access_key
    (see setIfPresent above): v3 does not return the pre-shared key on a plain read, and this
    resource has no in-place update path (tunnel1/tunnel2 are ForceNew), so blanking passphrase
    here would surface as a diff on a ForceNew field and force a destroy/recreate of a live
    tunnel pair on every refresh. When tunnelItem carries no passphrase, carry forward whatever
    was already in state instead — same preserve-prior-state precedent as
    flattenSharedSettingsData's peak_bandwidth handling below. Callers MUST pass the prior
    value; passing nil/empty degrades to "" for a tunnel the API never reported a passphrase
    for (e.g. straight after import).

@return []interface{} - the flattened tunnel data
*/
func flattenTunnelData(tunnelItem *perimeter81Sdk.IPSecRedundantTunnel, priorTunnelData []interface{}) []interface{} {
	if tunnelItem != nil {
		tunnel := make([]interface{}, 1)
		tunnelData := make(map[string]interface{})
		tunnelData["passphrase"] = ""
		if tunnelItem.HasPassphrase() {
			tunnelData["passphrase"] = tunnelItem.GetPassphrase()
		} else if len(priorTunnelData) > 0 {
			if priorMap, ok := priorTunnelData[0].(map[string]interface{}); ok {
				if prior, ok := priorMap["passphrase"].(string); ok {
					tunnelData["passphrase"] = prior
				}
			}
		}
		tunnelData["gateway_id"] = tunnelItem.GatewayID
		// RemoteID is a union type wrapping an optional string
		if tunnelItem.RemoteID != nil && tunnelItem.RemoteID.String != nil {
			tunnelData["remote_id"] = *tunnelItem.RemoteID.String
		} else {
			tunnelData["remote_id"] = ""
		}
		tunnelData["p81_gwinternal_ip"] = tunnelItem.P81GWInternalIP
		tunnelData["remote_gwinternal_ip"] = tunnelItem.RemoteGWInternalIP
		tunnelData["remote_public_ip"] = tunnelItem.RemotePublicIP
		tunnelData["remote_asn"] = fmt.Sprintf("%d", int32(tunnelItem.RemoteASN))
		if tunnelItem.TunnelID != nil {
			tunnelData["tunnel_id"] = *tunnelItem.TunnelID
		} else {
			tunnelData["tunnel_id"] = ""
		}
		tunnel[0] = tunnelData
		return tunnel
	}

	return make([]interface{}, 0)
}

/*
getTunnelId get the tunnel id
  - @param ctx context.Context - the context
  - @param networkId string - the network id
  - @param tunnelBody perimeter81Sdk.BaseTunnelValues - the tunnel body
  - @param client perimeter81Sdk.APIClient - the client
  - @param diags diag.Diagnostics - the diagnostics

@return string - the tunnel id, diag.Diagnostics - the diagnostics
*/
func getTunnelId(ctx context.Context, networkId string, tunnelBody perimeter81Sdk.BaseTunnelValues, client perimeter81Sdk.APIClient, diags diag.Diagnostics) (string, diag.Diagnostics) {
	network, _, err := client.StandardNetworksAPI.StandardNetworksControllerV2NetworkFind(ctx, networkId).Execute()
	if err != nil {
		diags = appendErrorDiags(diags, "Unable to fetch network", err)
		return "", diags
	}
	// find the tunnel id based on that tunnel name is unique
	for _, region := range network.Regions {
		if region.Id == tunnelBody.RegionID {
			for _, gateway := range region.Instances {
				if gateway.Id == tunnelBody.GatewayID {
					for _, tunnel := range gateway.Tunnels {
						ifName := getNetworkTunnelInterfaceName(tunnel)
						if ifName == tunnelBody.TunnelName {
							return getNetworkTunnelId(tunnel), diags
						}
					}
				}

			}
		}
	}
	diags = appendErrorDiags(diags, "Unable to find tunnel", fmt.Errorf("check tunnel fields there might be overlap error"))
	return "", diags
}

/*
getNetworkTunnelInterfaceName extract the interface name from a NetworkTunnel union type.
*/
func getNetworkTunnelInterfaceName(tunnel perimeter81Sdk.NetworkTunnel) string {
	if tunnel.NetworkTunnelWireguard != nil {
		return tunnel.NetworkTunnelWireguard.InterfaceName
	}
	if tunnel.NetworkTunnelIpsecSingle != nil {
		return tunnel.NetworkTunnelIpsecSingle.InterfaceName
	}
	if tunnel.NetworkTunnelIpsecRedundant != nil {
		return tunnel.NetworkTunnelIpsecRedundant.InterfaceName
	}
	if tunnel.NetworkTunnelOpenvpn != nil {
		return tunnel.NetworkTunnelOpenvpn.InterfaceName
	}
	return ""
}

/*
getNetworkTunnelId extract the id from a NetworkTunnel union type.
*/
func getNetworkTunnelId(tunnel perimeter81Sdk.NetworkTunnel) string {
	if tunnel.NetworkTunnelWireguard != nil {
		return tunnel.NetworkTunnelWireguard.Id
	}
	if tunnel.NetworkTunnelIpsecSingle != nil {
		return tunnel.NetworkTunnelIpsecSingle.Id
	}
	if tunnel.NetworkTunnelIpsecRedundant != nil {
		return tunnel.NetworkTunnelIpsecRedundant.Id
	}
	if tunnel.NetworkTunnelOpenvpn != nil {
		return tunnel.NetworkTunnelOpenvpn.Id
	}
	return ""
}

/*
getNetworkTunnelHaTunnelId extract the HaTunnelID from a NetworkTunnel union type (for redundant tunnels).
*/
func getNetworkTunnelHaTunnelId(tunnel perimeter81Sdk.NetworkTunnel) string {
	if tunnel.NetworkTunnelIpsecRedundant != nil {
		return tunnel.NetworkTunnelIpsecRedundant.HaTunnelID.Id
	}
	return ""
}

/*
getRedundantTunnelId get the redundant tunnel id
  - @param ctx context.Context - the context
  - @param networkId string - the network id
  - @param tunnelBody perimeter81Sdk.BaseTunnelValues - the tunnel body
  - @param client perimeter81Sdk.APIClient - the client
  - @param diags diag.Diagnostics - the diagnostics

@return string - the redundant tunnel id, diag.Diagnostics - the diagnostics
*/
func getRedundantTunnelId(ctx context.Context, networkId string, tunnelBody perimeter81Sdk.BaseTunnelValues, client perimeter81Sdk.APIClient, diags diag.Diagnostics) (string, diag.Diagnostics) {
	network, _, err := client.StandardNetworksAPI.StandardNetworksControllerV2NetworkFind(ctx, networkId).Execute()
	if err != nil {
		diags = appendErrorDiags(diags, "Unable to fetch network", err)
		return "", diags
	}
	// Find the redundant tunnel by walking ALL gateways in the target region.
	// The wire response for the network-find endpoint does NOT include
	// haTunnelID per-tunnel — instead, redundant tunnel members are returned
	// as type="ipsec" with isHA=true and a per-tunnel id. The SDK's NetworkTunnel
	// union dispatcher falls back to NetworkTunnelBase for these (because the
	// NetworkTunnelIpsecRedundant schema requires haTunnelID which is absent
	// from this endpoint's response). We use the base tunnel's Id as the
	// haTunnelId — the API's GET /tunnels/ipsec/redundant/{id} accepts either
	// member of the pair and returns the full redundant tunnel pair.
	for _, region := range network.Regions {
		if region.Id != tunnelBody.RegionID {
			continue
		}
		for _, gateway := range region.Instances {
			for _, tunnel := range gateway.Tunnels {
				ifName := getNetworkTunnelInterfaceName(tunnel)
				if ifName != tunnelBody.TunnelName+"01" && ifName != tunnelBody.TunnelName+"02" {
					continue
				}
				// Prefer haTunnelID from the redundant-specific variant if present;
				// otherwise fall back to the base/single-routed tunnel id —
				// the API's redundant GET endpoint accepts either pair member's
				// id. The wire structure for redundant tunnel members is
				// identical to a single ipsec tunnel (type:"ipsec" + isHA:true),
				// so the SDK union dispatcher routes redundant pair members
				// into NetworkTunnelIpsecSingle.
				if id := getNetworkTunnelHaTunnelId(tunnel); id != "" {
					return id, diags
				}
				if tunnel.NetworkTunnelIpsecSingle != nil && tunnel.NetworkTunnelIpsecSingle.Id != "" {
					return tunnel.NetworkTunnelIpsecSingle.Id, diags
				}
				if tunnel.NetworkTunnelBase != nil && tunnel.NetworkTunnelBase.Id != "" {
					return tunnel.NetworkTunnelBase.Id, diags
				}
			}
		}
	}
	diags = appendErrorDiags(diags, "Unable to find tunnel",
		fmt.Errorf("no tunnel matched name=%s in region=%s; check tunnel fields or naming convention", tunnelBody.TunnelName, tunnelBody.RegionID))
	return "", diags
}

/*
setNetworkRegionInfos set the network region infos
  - @param regionsData []perimeter81Sdk.Region - the regions data
  - @param networkData *perimeter81Sdk.Network - the network data
  - @param regions []StandardNetworkRegionConfig - the regions

@return void
*/
func setNetworkRegionInfos(regionsData []perimeter81Sdk.Region, networkData *perimeter81Sdk.Network, regions []StandardNetworkRegionConfig) {
	newRegionsData := make([]StandardNetworkRegionConfig, 0)
	for _, networkRegions := range networkData.Regions {
		for _, regionData := range regionsData {
			if networkRegions.Name == regionData.GetDisplayName() {
				newRegionsData = append(newRegionsData, StandardNetworkRegionConfig{RegionID: networkRegions.Id, CpRegionId: regionData.GetId(), Dns: networkRegions.Dns, Name: networkRegions.Name})
			}
		}
	}
	for index, regionData := range regions {
		for _, networkRegions := range newRegionsData {
			if regionData.CpRegionId == networkRegions.CpRegionId {
				regions[index].RegionID = networkRegions.RegionID
				regions[index].Dns = networkRegions.Dns
				regions[index].Name = networkRegions.Name
			}
		}
	}
}

/*
appendErrorDiags append the error diagnostics
  - @param diags diag.Diagnostics - the diagnostics
  - @param summary string - the summary
  - @param err error - the error

@return diag.Diagnostics - the diagnostics
*/
func appendErrorDiags(diags diag.Diagnostics, summary string, err error) diag.Diagnostics {
	var errMsg string
	// errors.As rather than a bare type assertion. The SDK's error carries the
	// server's message body -- `"fromDefault" is not allowed`, `VALIDATION_WEB_
	// RULES_REQUIRED` -- and Error() carries only `422 Unprocessable Entity`.
	// A direct assertion fails the moment anything wraps the error with %w, and
	// something already does (async.go's withStatusID), so this was silently
	// discarding the only useful half of the diagnostic on that path.
	var apiErr *perimeter81Sdk.GenericOpenAPIError
	if errors.As(err, &apiErr) {
		errMsg = string(apiErr.Body())
		if errMsg == "" {
			errMsg = apiErr.Error()
		}
	} else {
		errMsg = err.Error()
	}
	diags = append(diags, diag.Diagnostic{
		Severity: diag.Error,
		Summary:  summary,
		Detail:   errMsg,
	})
	return diags
}

/*
appendErrorDiagsWithGuidance is appendErrorDiags for the errors that have to
carry an INSTRUCTION as well as a cause.

WHY IT EXISTS. appendErrorDiags promotes the server's response body into Detail
whenever errors.As finds a GenericOpenAPIError, and that is right: the body
(`VALIDATION_WEB_RULES_REQUIRED`, `"fromDefault" is not allowed`) is normally the
only useful part. The cost is that everything the caller wrapped the error with
is discarded. For an ordinary failure that costs nothing. Measured on the SWG
policies, where the wrapper is the entire "what to do about it" half of the
message, the whole diagnostic an operator saw for a failed read-back was:

	The web access policy was written but could not be read back
	{"message":"re-read failed"}

-- with policyWrittenNotReadBack's "the tenant is now enforcing it" and all of
reapplyToResync, including the `terraform untaint` warning that stops an operator
DESTROYING a whole-policy resource and emptying the tenant's policy with it,
reaching nobody.

The guidance goes in Detail rather than Summary because Terraform prints Summary
as a one-line heading, and it is skipped when the Detail already contains it --
which is the non-API-error branch, where err.Error() carries the wrapper
verbatim and appending it again would print the same paragraph twice.

  - @param diags diag.Diagnostics - the diagnostics
  - @param summary string - the one-line heading
  - @param guidance string - the instruction, which must survive whichever branch appendErrorDiags takes
  - @param err error - the error

@return diag.Diagnostics - the diagnostics
*/
func appendErrorDiagsWithGuidance(diags diag.Diagnostics, summary, guidance string,
	err error) diag.Diagnostics {
	diags = appendErrorDiags(diags, summary, err)
	last := &diags[len(diags)-1]
	if !strings.Contains(last.Detail, guidance) {
		last.Detail = strings.TrimSpace(last.Detail) + "\n\n" + guidance
	}
	return diags
}

/*
appendWarningDiags append a warning diagnostic
  - @param diags diag.Diagnostics - the diagnostics
  - @param summary string - the summary
  - @param detail string - the detail

@return diag.Diagnostics - the diagnostics
*/
func appendWarningDiags(diags diag.Diagnostics, summary string, detail string) diag.Diagnostics {
	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  summary,
		Detail:   detail,
	})
	return diags
}

/*
testComparableArraiesEq test if the arraies are equal
  - @param a []Type - the a
  - @param b []Type - the b

@return bool - the result
*/
func testComparableArraiesEq[Type comparable](a, b []Type) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

/*
randStringBytesRmndr generate random string

@return string - the random string
*/
func randStringBytesRmndr() string {
	str := make([]byte, 10)
	for i := range str {
		str[i] = letterBytes[seededRand.Intn(len(letterBytes))]
	}
	return string(str)
}

/*
regionExistsInArray check if region exists in array
  - @param regionId string - the region id
  - @param regions []StandardNetworkRegionConfig - the regions

@return bool - the result
*/
func regionExistsInArray(regionId string, regions []StandardNetworkRegionConfig) bool {
	for _, region := range regions {
		if region.CpRegionId == regionId {
			return true
		}
	}
	return false
}

/*
regionClonsInArray get the region clons in array
  - @param regionId string - the region id
  - @param regions []StandardNetworkRegionConfig - the regions

@return []StandardNetworkRegionConfig - the result
*/
func regionClonsInArray(regionId string, regions []StandardNetworkRegionConfig) []StandardNetworkRegionConfig {
	clons := make([]StandardNetworkRegionConfig, 0)
	for _, region := range regions {
		if region.CpRegionId == regionId {
			clons = append(clons, region)
		}
	}
	return clons
}

/*
importRegions import the manually added regions
  - @param networkData *perimeter81Sdk.Network - the network data
  - @param regionsData []perimeter81Sdk.Region - the regions date list
  - @param regions []StandardNetworkRegionConfig - the regions inside the configuration file if exists

@return []StandardNetworkRegionConfig - the result
*/
func importRegions(networkData *perimeter81Sdk.Network, regionsData []perimeter81Sdk.Region, regions []StandardNetworkRegionConfig) []StandardNetworkRegionConfig {
	if len(regions) == 0 {
		regions = make([]StandardNetworkRegionConfig, len(networkData.Regions))
		for i, regionItem := range networkData.Regions {
			region := StandardNetworkRegionConfig{}
			region.Idle = networkData.IsDefault
			region.RegionID = regionItem.Id
			region.Name = regionItem.Name
			region.Dns = regionItem.Dns
			for _, regionInfo := range regionsData {
				if regionInfo.GetDisplayName() == regionItem.Name {
					region.CpRegionId = regionInfo.GetId()
					break
				}
			}
			if region.CpRegionId == "" {
				for _, regionInfo := range regionsData {
					if regionInfo.GetName() == regionItem.Name {
						region.CpRegionId = regionInfo.GetId()
						break
					}
				}
			}
			regions[i] = region
		}
	}
	return regions
}

/*
getGatewaysInArray get the manually added gateways inside a specific region inside a given network
  - @param regionId string - the region id
  - @param network *perimeter81Sdk.Network - the network that has the gateways

@return []perimeter81Sdk.NetworkInstance - the result
*/
func getGatewaysInArray(regionId string, network *perimeter81Sdk.Network) []perimeter81Sdk.NetworkInstance {
	clons := make([]perimeter81Sdk.NetworkInstance, 0)

	// A NIL NETWORK IS A CALLER BUG THAT USED TO CRASH THE WHOLE PROVIDER.
	//
	// The gateway importer called this after a failed network read, having
	// recorded the error in a diagnostics slice it did not return yet, so
	// `network` was nil and the range below panicked -- SIGSEGV, plugin dead,
	// "The terraform-provider-checkpointsase plugin crashed!" rather than a
	// diagnostic. The importer is fixed, but the guard belongs here too: the
	// next caller to make the same mistake should get an empty result, not a
	// stack trace. Measured 2026-09-09 (P81-144756).
	if network == nil {
		return clons
	}

	for _, region := range network.Regions {
		if region.Id == regionId {
			clons = append(clons, region.Instances...)
			break
		}
	}
	return clons
}

/*
getCurrentObjectServicesInArray get the current object services from all the services by name.
The list API does not return IDs, so matching is done by name.
  - @param objectsServices *perimeter81Sdk.ObjectsServicesResponse - the objects services in the system
  - @param objectServicesName string - the object services name

@return *perimeter81Sdk.ObjectsServicesResponseObj - the result
*/
func getCurrentObjectServicesInArray(objectsServices *perimeter81Sdk.ObjectsServicesResponse, objectServicesName string) *perimeter81Sdk.ObjectsServicesResponseObj {
	for i, service := range objectsServices.Data {
		if service.Name == objectServicesName {
			return &objectsServices.Data[i]
		}
	}
	return nil
}

/*
getTunnelFromNetwork get the wireguard tunnel configs
  - @param tunnelId string - the tunnel id
  - @param network perimeter81Sdk.NetworkInstance - the network instance that has the configs

@return string,string - the result
*/
func getWireguardConfigsFromNetwork(tunnelId string, instances perimeter81Sdk.NetworkInstance) (string, string) {

	for _, tunnel := range instances.Tunnels {
		if tunnel.NetworkTunnelWireguard != nil && tunnel.NetworkTunnelWireguard.Id == tunnelId {
			return tunnel.NetworkTunnelWireguard.RequestConfigToken, tunnel.NetworkTunnelWireguard.Vault
		}
	}
	return "", ""
}

/*
getInstanceFromInstances get the gateway of gateways array
  - @param tunnelId string - the tunnel id
  - @param network []perimeter81Sdk.NetworkInstance - the network that has the gateways

@return perimeter81Sdk.NetworkInstance - the result
*/
func getInstanceFromInstances(gatewayId string, instances []perimeter81Sdk.NetworkInstance) *perimeter81Sdk.NetworkInstance {

	for _, instance := range instances {
		if instance.Id == gatewayId {
			return &instance
		}
	}
	return nil
}

/*
setDefaultGatewayIpForRegions set the default gateway ip for regions
  - @param regions []StandardNetworkRegionConfig - the region list
  - @param networkData *perimeter81Sdk.Network - the network data

@return []StandardNetworkRegionConfig - the result
*/
func setDefaultGatewayIpForRegions(regions []StandardNetworkRegionConfig, networkData *perimeter81Sdk.Network) []StandardNetworkRegionConfig {

	for index, region := range regions {
		gateways := getGatewaysInArray(region.RegionID, networkData)
		if len(gateways) > 0 {
			regions[index].DefaultGatewayIp = gateways[0].Ip
		}
	}
	return regions
}

/*
flattenObjectServicesDataSource flatten object Services data
  - @param objectServicesItems []perimeter81Sdk.ObjectsServicesResponseObj - the object services that need to be flattened

@return []interface{} - the flattened object services data
*/
func flattenObjectServicesData(objectServicesItems []perimeter81Sdk.ObjectsServicesResponseObj) []interface{} {
	if objectServicesItems != nil {
		objectServices := make([]interface{}, len(objectServicesItems))
		for i, objectServicesItem := range objectServicesItems {
			objectService := make(map[string]interface{})
			if objectServicesItem.Id != nil {
				objectService["id"] = *objectServicesItem.Id
			}
			objectService["name"] = objectServicesItem.Name
			if objectServicesItem.Description != nil {
				objectService["description"] = *objectServicesItem.Description
			}
			objectService["protocols"] = flattenProtocolsDataSourceData(objectServicesItem.Protocols)
			objectServices[i] = objectService
		}
		return objectServices
	}
	return make([]interface{}, 0)
}

/*
flattenProtocolsDataSourceData flatten protocols data
  - @param objectServicesItems []perimeter81Sdk.ObjectsServicesProtocolResponseObj - the object services that need to be flattened

@return []interface{} - the flattened object services data
*/
func flattenProtocolsDataSourceData(protocolItems []perimeter81Sdk.ObjectsServicesProtocolResponseObj) []interface{} {
	if protocolItems == nil {
		return make([]interface{}, 0)
	}
	protocols := make([]interface{}, len(protocolItems))
	for i, protocolItem := range protocolItems {
		protocols[i] = map[string]interface{}{
			"protocol": protocolItem.Protocol,
			// ValueType is *string in v3; GetValueType() nil-checks the
			// receiver and returns the zero value, so it's safe under
			// omitempty absence. Assigning the pointer directly would
			// store the pointer, not the string, in the flattened map.
			"value_type": protocolItem.GetValueType(),
			"value":      protocolItem.Value,
			// The code only, matching the resource attribute of the same name:
			// the response wraps it as {code, description}, and the description
			// is derived from the code rather than being information of its own.
			// GetCode is nil-safe on a nil receiver, so a tcp/udp entry — which
			// the server never gives protocolOptions — reads back 0.
			"protocol_options": int(protocolItem.ProtocolOptions.GetCode()),
		}
	}
	return protocols
}

/*
getCurrentObjectAddressesInArray get the current object addresses from all the addresses
  - @param objectsAddresses perimeter81Sdk.AddressList - the objects addresses in the system
  - @param objectAddressesId string - the object addresses id

@return *perimeter81Sdk.Address - the result
*/
func getCurrentObjectAddressesInArray(objectsAddresses *perimeter81Sdk.AddressList, objectAddressesId string) *perimeter81Sdk.Address {
	for i, address := range objectsAddresses.Data {
		if address.GetId() == objectAddressesId {
			return &objectsAddresses.Data[i]
		}
	}
	return nil
}

/*
flattenObjectAddressesData flatten ObjectAddresses data
  - @param objectAddressesItems []perimeter81Sdk.Address - the object services that need to be flattened

@return []interface{} - the flattened object addressess data
*/
func flattenObjectAddressesData(objectAddressesItems []perimeter81Sdk.Address) []interface{} {
	if objectAddressesItems != nil {
		objectAddresses := make([]interface{}, len(objectAddressesItems))
		for i, objectAddressesItem := range objectAddressesItems {
			objectAddress := make(map[string]interface{})
			if objectAddressesItem.Id != nil {
				objectAddress["id"] = *objectAddressesItem.Id
			}
			// v3 flipped Name/ValueType from required string to *string;
			// use the Get* accessors (nil-safe) rather than assigning the
			// pointer itself, which would break d.Set.
			objectAddress["name"] = objectAddressesItem.GetName()
			if objectAddressesItem.Description != nil {
				objectAddress["description"] = *objectAddressesItem.Description
			}
			objectAddress["value_type"] = objectAddressesItem.GetValueType()
			objectAddress["value"] = objectAddressesItem.Value
			objectAddresses[i] = objectAddress
		}
		return objectAddresses
	}
	return make([]interface{}, 0)
}

/*
readByIDFromList finds one element of a collection by exact ID match, for the v3
surfaces that expose no GET-by-id. /v3/users and /v3/groups are the first two;
Phase 4's SWG rule lists are the next.

MATCHING IS EXACT EQUALITY AND MUST STAY THAT WAY. A prefix or name match here
would hand one resource another resource's attributes, and Terraform would then
write that to state as a successful Read -- silent, and indistinguishable from
correct behaviour until two resources' ids happen to share a prefix.

An empty id never matches, even against an element whose own id is empty. That
case is reachable rather than theoretical: overlay entries A21a/A22a declare
`id` OPTIONAL on User and Group, so idOf can legitimately return "".

Returns found=false when the object is absent, so callers apply the provider's
drift convention (d.SetId("")) rather than reporting an error.

  - @param items []T - the collection as the list endpoint returned it
  - @param id string - the id held in Terraform state
  - @param idOf func(T) string - extracts one element's id

@return (T, bool) - the matching element (or T's zero value) and whether it was found
*/
func readByIDFromList[T any](items []T, id string, idOf func(T) string) (T, bool) {
	var zero T
	if id == "" {
		return zero, false
	}
	for i := range items {
		if idOf(items[i]) == id {
			return items[i], true
		}
	}
	return zero, false
}

/*
expandUserProfile builds a UserProfileDto from the profile_data block.

Returns nil when no field was actually set, which is what keeps `profileData` out
of the request body entirely. That matters: CreateUserDto.profileData is
@IsOptional, and sending a present-but-empty object is a different request from
omitting the key.

The emptiness test is "did any field get a value", NOT "is the block present".
A bare `profile_data {}` in HCL yields a non-nil map of empty strings, so
guarding on block presence alone would set every pointer to nil and then send
`"profileData": {}` -- the exact request this comment claims to avoid.

  - @param profileItems []interface{} - the profile_data block as Terraform holds it

@return *perimeter81Sdk.UserProfileDto - nil when no profile field was configured
*/
func expandUserProfile(profileItems []interface{}) *perimeter81Sdk.UserProfileDto {
	if len(profileItems) == 0 || profileItems[0] == nil {
		return nil
	}
	item, ok := profileItems[0].(map[string]interface{})
	if !ok {
		return nil
	}
	profile := perimeter81Sdk.UserProfileDto{}
	set := false
	for key, target := range map[string]**string{
		"first_name": &profile.FirstName,
		"last_name":  &profile.LastName,
		"role_name":  &profile.RoleName,
		"phone":      &profile.Phone,
	} {
		if v, ok := item[key].(string); ok && v != "" {
			value := v
			*target = &value
			set = true
		}
	}
	if !set {
		return nil
	}
	return &profile
}

/*
suppressDiffOnEmptyOldValue suppresses the diff for a write-only attribute on a
resource that already exists but has no value for it in state.

The case this exists for is import. A write-only attribute -- one the server
either does not return or must not be read back from -- is absent from an
imported resource's state, so the first plan after an import sees "" -> the
configured value. On a ForceNew attribute that plans a REPLACEMENT: import a
user, apply the configuration that describes her, and she is deleted and
re-invited.

THE `d.Id() != ""` CONDITION IS NOT OPTIONAL. Keyed on `old == ""` alone, this
function breaks create instead. A create diffs against no state, so `old` is ""
for every attribute; schemaMap.diff DROPS a suppressed attribute from the diff
(it only converts it to a no-op when called with all=true, which the real plan
path never does), the ResourceData a CreateContext receives is built from that
diff, and d.Get on the attribute returns "". Measured, not theorised: with the
condition removed, d.Get("invite_message") is "" for a configuration that sets
it, and the provider POSTs an empty invitation message. A non-empty Id is what
distinguishes "state has no value because the resource does not exist yet" from
"state has no value because the resource was imported".

What it does NOT do is mask a real change on a resource this provider created:
such a resource has the operator's own value in state, so `old` is non-empty.
The one accepted blind spot is an imported resource, whose state stays empty for
the attribute -- a later edit to it plans clean instead of replacing. That is the
lesser harm by a wide margin, and for these attributes it is nearly moot: there
is no update endpoint, so "changing" one means deleting the account either way.

  - @param k string - the attribute key (unused; the SDK passes it for logging)
  - @param old string - the value in state
  - @param new string - the value in configuration (unused)
  - @param d *schema.ResourceData - the prior state, consulted for the resource id

@return bool - true to suppress the diff
*/
func suppressDiffOnEmptyOldValue(_, old, _ string, d *schema.ResourceData) bool {
	return old == "" && d != nil && d.Id() != ""
}

/*
validateSortDirections rejects a sort map whose values are not asc/desc.

The API's `sort` parameter on GET /v3/users is an object of enum strings, and the
enum is the whole of its validation -- a typo like {email = "ascending"} is
otherwise a request the server rejects after Terraform has already reported a
valid plan.

Only checkpointsase_users can be validated this way. GET /v3/groups declares its
`sort` as a bare string with no documented grammar, so its schema entry carries
no ValidateFunc at all; see the comment there.

  - @param v interface{} - the configured map, which schemaMap.validateMap passes as map[string]interface{}
  - @param p cty.Path - the attribute path, so a diagnostic points at the right argument

@return diag.Diagnostics
*/
func validateSortDirections(v interface{}, p cty.Path) diag.Diagnostics {
	var diags diag.Diagnostics
	raw, ok := v.(map[string]interface{})
	if !ok {
		// schemaMap.validateMap only reaches validateFunc with a
		// map[string]interface{}, so this is unreachable through Terraform. It
		// is here so a direct caller (a test, or a later refactor that moves the
		// attribute) gets a diagnostic instead of a panic.
		return append(diags, diag.Diagnostic{
			Severity:      diag.Error,
			Summary:       "Invalid sort",
			Detail:        fmt.Sprintf("sort must be a map of field to direction, got %T.", v),
			AttributePath: p,
		})
	}
	// Sorted so a map with two bad entries always reports them in the same
	// order; a diagnostic whose wording depends on Go's map iteration is a
	// flaky test waiting to happen.
	for _, field := range sortedMapKeys(raw) {
		s, _ := raw[field].(string)
		if s != "asc" && s != "desc" {
			diags = append(diags, diag.Diagnostic{
				Severity:      diag.Error,
				Summary:       "Invalid sort direction",
				Detail:        fmt.Sprintf("sort[%s] is %q; it must be \"asc\" or \"desc\".", field, s),
				AttributePath: p,
			})
		}
	}
	return diags
}

/*
expandSortDirections converts a configured TypeMap into the map[string]string the
generated Sort builder takes.

  - @param raw interface{} - the value d.Get returned for a TypeMap attribute

@return map[string]string - empty (not nil) when nothing was configured
*/
func expandSortDirections(raw interface{}) map[string]string {
	configured, ok := raw.(map[string]interface{})
	if !ok {
		return map[string]string{}
	}
	sortOrder := make(map[string]string, len(configured))
	for field, direction := range configured {
		s, _ := direction.(string)
		sortOrder[field] = s
	}
	return sortOrder
}

/*
canonicalSortDirections renders a sort map as one deterministic string, for use in
a data source's derived ID. Map iteration order is random in Go, so joining the
pairs unsorted would give the same configuration a different ID on every process.
*/
func canonicalSortDirections(sortOrder map[string]string) string {
	pairs := make([]string, 0, len(sortOrder))
	for _, field := range sortedMapKeys(sortOrder) {
		pairs = append(pairs, field+":"+sortOrder[field])
	}
	return strings.Join(pairs, ",")
}

/*
sortedMapKeys returns a map's keys in sorted order. Generic over the value type so
it serves both map[string]string and map[string]interface{}.
*/
func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

/*
dataSourceArgumentDigest builds the short, stable suffix a parameterised data
source appends to its base ID.

THIS IS AN IDENTITY KEY, NOT AN INTEGRITY CHECK. Nothing here is a security
boundary: the digest exists so that two instances of one data source with
different arguments do not share a Terraform address, and a practitioner who
forces a collision has given two instances one id string, not access to another
instance's data. Do not cite it as evidence of anything else.

WHAT IS ACTUALLY GUARANTEED: the same arguments always produce the same suffix,
in this process and the next. That is the property the derived ID needs and the
one L16c is about, and it holds because every caller renders its arguments
deterministically -- `canonicalSortDirections` sorts the map's keys before
joining, so Go's randomised map iteration cannot leak into the digest.

WHAT IS NOT GUARANTEED, corrected 2026-08-20: an earlier version of this comment
claimed the newline separator made a collision by concatenation IMPOSSIBLE,
"because a newline cannot appear in any of the parts". That is false and a
reviewer built the counter-example: `where` is a free-form pass-through and
validateSortDirections constrains sort DIRECTIONS but not sort KEYS, so both can
carry a newline, and a crafted key can be made to produce the same joined string
as a crafted `where`. Each part is therefore length-prefixed, which does make the
encoding unambiguous -- but the honest claim is the narrow one: the encoding
separates the arguments these data sources can realistically carry, and truncating
to six bytes trades collision headroom for a readable id, which is the right trade
for the handful of instances one configuration holds.

Same construction as updatableObjectsDataSourceID, which predates it; that
function is left as it is rather than rewritten in terms of this one, because it
carries its own base-name special case and is covered by its own tests.
*/
func dataSourceArgumentDigest(parts ...string) string {
	// Length-prefixed rather than newline-joined: "3:abc" cannot be read as any
	// other sequence of parts, whatever the parts contain.
	var canonical strings.Builder
	for _, part := range parts {
		canonical.WriteString(strconv.Itoa(len(part)))
		canonical.WriteString(":")
		canonical.WriteString(part)
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:6])
}

/*
coerceNilStringsToEmpty returns an empty slice in place of a nil one.

BELT-AND-BRACES, NOT LOAD-BEARING. Measured 2026-08-20:
schema.ResourceData.Set already normalises a nil slice to an empty list, including
for a list nested inside a list element, so state holds [] either way. This exists
so that a flatten function handling four optional lists says once, legibly, that
nil is the routine case rather than repeating a four-line if. Do not write a
comment claiming state would hold a null without it, and do not write a test
asserting that -- such a test cannot fail.
*/
func coerceNilStringsToEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
