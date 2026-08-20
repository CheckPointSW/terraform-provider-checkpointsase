package checkpointsase

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

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

// GatewayConfig holds the internal representation of a gateway.
type GatewayConfig struct {
	Name string
	Idle bool
	Id   string
	Dns  string
	Ip   string
}

/*
flattenGatewaysData flatten gateways data
  - @param gatewaysItems []interface{} - the gateways data that need to be flattened

@return []GatewayConfig - the flattened gateways
*/
func flattenGatewaysData(gatewaysItems []interface{}) []GatewayConfig {
	if gatewaysItems != nil {
		gateways := make([]GatewayConfig, len(gatewaysItems))

		for i, gatewayItem := range gatewaysItems {
			gateway := GatewayConfig{}

			gateway.Name = gatewayItem.(map[string]interface{})["name"].(string)
			gateway.Idle = gatewayItem.(map[string]interface{})["idle"].(bool)
			id := gatewayItem.(map[string]interface{})["id"]
			if id != nil {
				gateway.Id = id.(string)
			}
			gateways[i] = gateway
		}

		return gateways
	}

	return make([]GatewayConfig, 0)
}

/*
flattenGateways flatten gateways data
  - @param gatewaysItems []GatewayConfig - the gateways that need to be flattened

@return []interface{} - the flattened gateways data
*/
func flattenGateways(gatewaysItems []GatewayConfig) []interface{} {
	if gatewaysItems != nil {
		gateways := make([]interface{}, len(gatewaysItems))

		for i, gatewayItems := range gatewaysItems {
			gateway := make(map[string]interface{})

			gateway["name"] = gatewayItems.Name
			gateway["idle"] = gatewayItems.Idle
			gateway["id"] = gatewayItems.Id
			gateway["dns"] = gatewayItems.Dns
			gateway["ip"] = gatewayItems.Ip
			gateways[i] = gateway
		}
		return gateways
	}
	return make([]interface{}, 0)
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
getGatewayInfo get the gateway info
  - @param ctx context.Context - the context
  - @param networkId string - the network id
  - @param regionId string - the region id
  - @param client perimeter81Sdk.APIClient - the client
  - @param diags diag.Diagnostics - the diagnostics

@return string - the gateway id, the gateway dns, the gateway ip,  diag.Diagnostics - the diagnostics
*/
func getGatewayInfo(ctx context.Context, networkId string, regionId string, client perimeter81Sdk.APIClient, diags diag.Diagnostics) (string, string, string, diag.Diagnostics) {
	network, _, err := client.StandardNetworksAPI.StandardNetworksControllerV2NetworkFind(ctx, networkId).Execute()
	if err != nil {
		diags = appendErrorDiags(diags, "Unable to fetch network", err)
		return "", "", "", diags
	}
	// find the gateway id based on that least recently created gateway
	var gatewayId string
	var gatewayDns string
	var gatewayIp string
	for _, region := range network.Regions {
		if region.Id == regionId {
			latest := region.Instances[0].CreatedAt
			for _, gateway := range region.Instances {
				currentTime := gateway.CreatedAt
				gatewayId = gateway.Id
				if currentTime.After(latest) {
					latest = currentTime
					gatewayId = gateway.Id
					gatewayDns = gateway.Dns
					gatewayIp = gateway.Ip
				}
			}
		}
	}
	return gatewayId, gatewayDns, gatewayIp, diags
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
addGatewayToRegion add the gateway to region
  - @param ctx context.Context - the context
  - @param client *perimeter81Sdk.APIClient - the client
  - @param gateways []GatewayConfig - the gateways
  - @param network_id string - the network id
  - @param region_id string - the region id
  - @param diags diag.Diagnostics - the diagnostics

@return diag.Diagnostics, error - the diagnostics, the error
*/
func addGatewayToRegion(ctx context.Context, client *perimeter81Sdk.APIClient, gateways []GatewayConfig, network_id string, region_id string, diags diag.Diagnostics) (diag.Diagnostics, error) {
	if len(gateways) == 0 {
		return diags, nil
	}
	for index, gateway := range gateways {
		gatewayPayload := perimeter81Sdk.CreateInstancesInNetworkPayload{
			RegionId: region_id,
			Idle:     gateway.Idle,
		}
		status, _, err := client.StandardNetworksAPI.StandardNetworksControllerV2AddNetworkInstance(ctx, network_id).CreateInstancesInNetworkPayload(gatewayPayload).Execute()
		if err != nil {
			diags = appendErrorDiags(diags, "Unable to create gateway", err)
			return diags, err
		}
		statusId := getIdFromUrl(status.GetStatusUrl())
		var gatewayId string
		var gatewayDns string
		var gatewayIp string
		if err := pollStandardNetworkStatus(ctx, client, statusId, standardNetworkPollInterval); err != nil {
			diags = appendErrorDiags(diags, "Unable to create gateway", err)
			return diags, err
		}
		gatewayId, gatewayDns, gatewayIp, diags = getGatewayInfo(ctx, network_id, region_id, *client, diags)
		gateways[index].Id = gatewayId
		gateways[index].Dns = gatewayDns
		gateways[index].Ip = gatewayIp
	}
	return diags, nil
}

/*
deleteGatewayFromRegion delete the gateway from region
  - @param ctx context.Context - the context
  - @param client *perimeter81Sdk.APIClient - the client
  - @param gateways []GatewayConfig - the gateways
  - @param network_id string - the network id
  - @param region_id string - the region id
  - @param diags diag.Diagnostics - the diagnostics

@return diag.Diagnostics, error - the diagnostics, the error
*/
func deleteGatewayFromRegion(ctx context.Context, client *perimeter81Sdk.APIClient, gateways []GatewayConfig, network_id string, region_id string, diags diag.Diagnostics) (diag.Diagnostics, error) {
	if len(gateways) == 0 {
		return diags, nil
	}
	gatewaysForDelete := perimeter81Sdk.RemoveRegionInstance{
		Regions: []perimeter81Sdk.RemoveRegionPayload{
			{
				RegionId:  &region_id,
				Instances: []perimeter81Sdk.RemoveInstancePayload{},
			},
		},
	}

	removedIds := make(map[string]bool, len(gateways))
	for _, gateway := range gateways {
		id := gateway.Id
		removedIds[id] = true
		gatewaysForDelete.Regions[0].Instances = append(gatewaysForDelete.Regions[0].Instances, perimeter81Sdk.RemoveInstancePayload{
			Id: &id,
		})
	}
	// DeleteNetworkInstance returns its AsyncOperationResult inline — there is
	// no status URL to poll — so a non-2xx result.statusCode is the only
	// signal that the delete was rejected.
	result, _, err := client.StandardNetworksAPI.StandardNetworksControllerV2DeleteNetworkInstance(ctx, network_id).RemoveRegionInstance(gatewaysForDelete).Execute()
	if err != nil {
		diags = appendErrorDiags(diags, "Unable to delete gateways", err)
		return diags, err
	}
	if !isSuccessStatus(int(result.GetStatusCode())) {
		err := &asyncFailedError{StatusCode: int(result.GetStatusCode()), Reasons: result.GetReason()}
		diags = appendErrorDiags(diags, "Unable to delete gateways", err)
		return diags, err
	}

	// The delete responded 2xx, but the gateway can still be listed in the
	// network for a moment afterwards: it is eventually consistent. Callers
	// read the network right after this function returns, so wait until none
	// of the removed gateway ids are listed under this region any more —
	// otherwise Read observes stale state.
	what := fmt.Sprintf("gateway removal to take effect in region %s of network %s", region_id, network_id)
	if pollErr := pollUntilConverged(ctx, func(ctx context.Context) (bool, *http.Response, error) {
		network, resp, err := client.StandardNetworksAPI.StandardNetworksControllerV2NetworkFind(ctx, network_id).Execute()
		if err != nil {
			return false, resp, err
		}
		for _, region := range network.Regions {
			if region.Id != region_id {
				continue
			}
			for _, instance := range region.Instances {
				if removedIds[instance.Id] {
					return false, resp, nil
				}
			}
		}
		return true, resp, nil
	}, convergencePollInterval, convergenceTransientBudget, what); pollErr != nil {
		diags = appendErrorDiags(diags, "Unable to delete gateways", pollErr)
		return diags, pollErr
	}
	return diags, nil
}

/*
getNewGateway get the new gateway
  - @param oldGateways []GatewayConfig - the old gateways
  - @param newGateways []GatewayConfig - the new gateways

@return []GatewayConfig - the new gateways
*/
func getNewGateway(oldGateways []GatewayConfig, newGateways []GatewayConfig) []GatewayConfig {
	var gateways []GatewayConfig
	for _, newGateway := range newGateways {
		if !gatewayExistsInArray(newGateway.Name, oldGateways) {
			gateways = append(gateways, newGateway)
		}
	}
	return gateways
}

/*
getGatewayToBeDeleted get the gateway to be deleted
  - @param oldGateways []GatewayConfig - the old gateways
  - @param newGateways []GatewayConfig - the new gateways

@return []GatewayConfig - the gateways
*/
func getGatewayToBeDeleted(oldGateways []GatewayConfig, newGateways []GatewayConfig) []GatewayConfig {
	var gateways []GatewayConfig
	for _, oldGateway := range oldGateways {
		if !gatewayExistsInArray(oldGateway.Name, newGateways) {
			gateways = append(gateways, oldGateway)
		}
	}
	return gateways
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
	if apiErr, ok := err.(*perimeter81Sdk.GenericOpenAPIError); ok {
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
gatewayExistsInArray check if gateway exists in array
  - @param gateway_name string - the gateway name
  - @param gateways []GatewayConfig - the gateways

@return bool - the result
*/
func gatewayExistsInArray(gateway_name string, gateways []GatewayConfig) bool {
	for _, gateway := range gateways {
		if gateway.Name == gateway_name {
			return true
		}
	}
	return false
}

/*
checkGatewayDuplicatesInArray check if gateway duplicates in array
  - @param gateways []GatewayConfig - the gateways

@return bool - the result, string - the gateway name
*/
func checkGatewayDuplicatesInArray(gateways []GatewayConfig) (bool, string) {
	for _, gatewayToCheck := range gateways {

		var count int
		for _, currentGateway := range gateways {
			if gatewayToCheck.Name == currentGateway.Name {
				count++
			}
		}
		if count > 1 {
			return true, gatewayToCheck.Name
		}
	}

	return false, ""
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
