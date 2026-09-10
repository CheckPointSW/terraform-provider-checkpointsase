package checkpointsase

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
resourceIpsecRedundant Setup the IpSec-Redundant Resource CRUD operations

@return &schema.Resource
*/
/*
ipsecRedundantCannotBeManaged is the whole explanation, not "invalid value",
because nothing the user wrote is wrong. The API cannot return the identifier
this resource needs, so no configuration can succeed.

MEASURED 2026-08-27 on a live HA pair (API-FINDINGS.md 1.39). The read, update
and delete routes all live at
/v3/networks/standard/{networkId}/tunnels/ipsec/redundant/{haTunnelId}, and
haTunnelID is returned by NO endpoint on this API: not the network detail, not
the network list, not the gateway or region reads, not the single-tunnel read,
and there is no redundant collection route to list it from. The redundant GET
was tested with BOTH member ids and answered 404 to each.

WHY THIS REFUSES RATHER THAN LETTING THE APPLY RUN. Create SUCCEEDS -- the
tunnels are really built -- and the failure lands on the read immediately after.
So every attempt left a live HA pair the provider could not read, update or
delete, on two gateways that had to be removed by hand. Refusing at plan time is
the difference between a clear message and orphaned infrastructure.

This mirrors the same class of reason (1.1) that closed checkpointsase_enhanced_route_table.
One difference is worth knowing: there, create FAILS, so refusing early only
improves the message. Here create WORKS, so refusing early prevents real damage.

Delete this function and the CustomizeDiff registration when the API returns
haTunnelID -- one field on the network-find tunnel objects would restore read,
update and delete together.
*/
const ipsecRedundantCannotBeManaged = `checkpointsase_ipsec_redundant cannot be managed on the v3 API.

The read, update and delete endpoints are all addressed by an "haTunnelId" -- the
identifier of the HA PAIR -- and the API returns that value from no endpoint. It
is absent from the network read, the network list, the gateway and region reads,
and the single-tunnel read, and there is no collection route that lists it. The
pair endpoint was tested with each member tunnel's own id and returned 404 for
both.

This is refused at plan time on purpose. Creating the pair SUCCEEDS, so without
this refusal an apply builds two real tunnels and then fails on the read that
follows, leaving infrastructure this provider can neither manage nor destroy.

Until the API exposes haTunnelID, use the Harmony SASE console for redundant
IPsec tunnels. checkpointsase_ipsec_single is unaffected and works normally.

Measured and recorded in API-FINDINGS.md section 1.39.`

/*
resourceIpsecRedundantCustomizeDiff refuses every configuration.

See ipsecRedundantCannotBeManaged for why. Destroy plans do not reach
CustomizeDiff in SDKv2, which is deliberate: anyone already holding a pair in
state can still remove it from state.
*/
func resourceIpsecRedundantCustomizeDiff(_ context.Context, _ *schema.ResourceDiff, _ interface{}) error {
	return errors.New(ipsecRedundantCannotBeManaged)
}

func resourceIpsecRedundant() *schema.Resource {
	return &schema.Resource{
		CustomizeDiff: resourceIpsecRedundantCustomizeDiff,
		Description: "**UNAVAILABLE ON THE v3 API — every configuration is refused at " +
			"plan time.** The read, update and delete endpoints are all addressed by an " +
			"`haTunnelId` (the id of the HA *pair*), and the API returns that value from " +
			"no endpoint: not the network read or list, not the gateway or region reads, " +
			"not the single-tunnel read, and there is no collection route that lists it. " +
			"The pair endpoint answers 404 to each member tunnel's own id. Creating the " +
			"pair *succeeds*, so this resource refuses at plan time rather than building " +
			"two real tunnels it could neither manage nor destroy. Use the Harmony SASE " +
			"console until the API exposes `haTunnelID`; `checkpointsase_ipsec_single` is " +
			"unaffected. Measured in API-FINDINGS.md §1.39. " +
			"Manages an active/standby IPsec redundant tunnel pair for a " +
			"`checkpointsase_network`. Two tunnels (`tunnel1` + `tunnel2`) terminate at " +
			"distinct remote endpoints for failover; `shared_settings` (gateway subnets) " +
			"and `advanced_settings` (IKE/IPSec parameters, phase1/phase2 proposals) " +
			"apply to both tunnels uniformly. " +
			"**This resource has no in-place update path.** `region_id`, `network_id` and " +
			"`tunnel_name` are `ForceNew`, so changing one of those plans a full " +
			"replacement (destroy + recreate). **Changing anything else fails the apply " +
			"instead**, with `ipsec-redundant tunnel update is not available yet` — this " +
			"resource's Update handler makes no API call at all. That covers " +
			"`last_updated` and, more importantly, every field nested inside " +
			"`tunnel1`, `tunnel2`, `shared_settings` and `advanced_settings`: those four " +
			"blocks are marked `ForceNew`, but the SDK does not propagate `ForceNew` from " +
			"a list into the schema of its element object, so editing a passphrase or an " +
			"IKE lifetime produces an in-place plan that then errors. **To change any of " +
			"them, taint or replace the resource explicitly** (`terraform apply " +
			"-replace=...`). A `PUT` for this tunnel type does exist in the API and is " +
			"simply not wired up here. Updating in place will be supported in a future " +
			"version.",
		CreateContext: resourceIpsecRedundantCreate,
		ReadContext:   resourceIpsecRedundantRead,
		UpdateContext: resourceIpsecRedundantUpdate,
		DeleteContext: resourceIpsecRedundantDelete,
		Schema: map[string]*schema.Schema{
			"last_updated": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Timestamp of the last update to this resource.",
			},
			"region_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The ID of the network's region. Returned by `checkpointsase_network.region.region_id`.",
			},
			"network_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The ID of the standard network the tunnel pair belongs to.",
			},
			"tunnel_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "Display name for the redundant tunnel pair. 3-15 characters, letters and " +
					"digits only. The server derives each member's `interfaceName` from this value " +
					"(`<name>01` and `<name>02`) and rejects hyphens, underscores, dots and spaces " +
					"with a 422 that names only the derived field.",
				ValidateFunc: validation.StringMatch(tunnelNamePattern, tunnelNameRuleMessage),
			},
			"advanced_settings": {
				Type:        schema.TypeList,
				Required:    true,
				ForceNew:    true,
				Description: "IKE/IPSec parameters and phase1/phase2 proposals shared by both tunnels.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"key_exchange": {
							Type:         schema.TypeString,
							Required:     true,
							Description:  "IKE version for key exchange. Must be `ikev1` or `ikev2`.",
							ValidateFunc: validation.StringInSlice([]string{"ikev1", "ikev2"}, false),
						},
						"ike_life_time": {
							Type:     schema.TypeString,
							Required: true,
							Description: "IKE lifetime as a `<int><unit>` duration string, e.g. `28800s`, `480m`, or `8h`. " +
								"Server-enforced ranges: `s` 10–86400, `m` 1–1440, `h` 1–24.",
							ValidateFunc: validation.StringMatch(regexp.MustCompile(`^\d+[smh]$`),
								"must be a duration with unit `s`, `m`, or `h` (e.g. `28800s`, `480m`, `8h`)"),
						},
						"lifetime": {
							Type:     schema.TypeString,
							Required: true,
							Description: "IPSec SA lifetime as a `<int><unit>` duration string, e.g. `3600s`, `60m`, or `1h`. " +
								"Server-enforced ranges: `s` 10–86400, `m` 1–1440, `h` 1–24.",
							ValidateFunc: validation.StringMatch(regexp.MustCompile(`^\d+[smh]$`),
								"must be a duration with unit `s`, `m`, or `h` (e.g. `3600s`, `60m`, `1h`)"),
						},
						"dpd_delay": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Dead peer detection delay interval, formatted `<int>s`. Allowed range is `5s`–`60s`.",
							ValidateFunc: validation.StringMatch(regexp.MustCompile(`^([5-9]|[1-5]\d|60)s$`),
								"must be a duration like `5s`–`60s`"),
						},
						"dpd_timeout": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Dead peer detection timeout, formatted `<int>s`. Allowed range is `5s`–`60s`.",
							ValidateFunc: validation.StringMatch(regexp.MustCompile(`^([5-9]|[1-5]\d|60)s$`),
								"must be a duration like `5s`–`60s`"),
						},
						"phase1": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "Phase 1 (IKE) IPSec proposal lists.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"auth": {
										Type:        schema.TypeList,
										Required:    true,
										MinItems:    1,
										Description: "List of phase 1 authentication algorithms (e.g. `[\"sha256\"]`).",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"encryption": {
										Type:        schema.TypeList,
										Required:    true,
										MinItems:    1,
										Description: "List of phase 1 encryption algorithms (e.g. `[\"aes-cbc-256\"]`).",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"dh": {
										Type:        schema.TypeList,
										Required:    true,
										Description: "List of phase 1 Diffie-Hellman group numbers (e.g. `[14]` for MODP2048).",
										Elem: &schema.Schema{
											Type: schema.TypeInt,
										},
									},
								}},
						},
						"phase2": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "Phase 2 (ESP/IPSec) proposal lists.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"auth": {
										Type:        schema.TypeList,
										Required:    true,
										MinItems:    1,
										Description: "List of phase 2 authentication algorithms.",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"encryption": {
										Type:        schema.TypeList,
										Required:    true,
										MinItems:    1,
										Description: "List of phase 2 encryption algorithms.",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"dh": {
										Type:        schema.TypeList,
										Required:    true,
										Description: "List of phase 2 Diffie-Hellman group numbers.",
										Elem: &schema.Schema{
											Type: schema.TypeInt,
										},
									},
								}},
						},
					}},
			},
			"shared_settings": {
				Type:        schema.TypeList,
				Required:    true,
				ForceNew:    true,
				Description: "Subnet routing settings shared by both tunnels.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"p81_gateway_subnets": {
							Type:     schema.TypeList,
							Required: true,
							Description: "Check Point SASE gateway subnet CIDR blocks reachable through either tunnel. " +
								"The enhanced-network tunnel endpoints restrict this list to `0.0.0.0/0` or the " +
								"network's own subnet; whether `/v3/networks/standard/...` applies the same rule " +
								"has not been measured. The plan-time validator checks CIDR format only.",
							// Same reasoning as checkpointsase_ipsec_single: standard
							// networks are a different endpoint family from the enhanced
							// tunnels where the "0.0.0.0/0 or the network Subnet" 409 was
							// measured (see p81GatewaySubnetsEnhancedRule in utils.go), so
							// only the CIDR format check is applied here.
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: validation.IsCIDR,
							},
						},
						"remote_gateway_subnets": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "Remote-side subnet CIDR blocks reachable through either tunnel.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						// v3 migration note (Task 12A): this attribute can still be set in
						// HCL and round-trips in state (see flattenSharedSettingsData's
						// preserve-prior-state handling in utils.go), but it is never
						// transmitted to the v3 API. IPSecSharedSettingsCreate — and
						// every other IPSecSharedSettings-family type — dropped the
						// bandwidth field entirely in v3, with no replacement anywhere
						// on the redundant-tunnel create/update surface. Per the
						// project's release notes this attribute originally existed
						// because the downstream service required it; under v3 that
						// requirement is either defaulted server-side or no longer
						// enforced. Users setting peak_bandwidth on
						// checkpointsase_ipsec_redundant will find it has no effect
						// under v3. Marked Deprecated below rather than removed, since
						// removing it would be a breaking schema change; ForceNew is
						// intentionally not added because replacement would not send
						// the value either, making it destructive for no benefit.
						"peak_bandwidth": {
							Type:        schema.TypeInt,
							Optional:    true,
							Default:     1000,
							Deprecated:  "Has no effect on this resource in v3. Retained only for configuration compatibility.",
							Description: "Expected peak throughput of the tunnel pair in Mbps. Defaults to 1000. Not sent to the v3 server — the value is retained only for configuration compatibility with prior provider versions.",
						},
					}},
			},
			"tunnel1": {
				Type:        schema.TypeList,
				Required:    true,
				ForceNew:    true,
				Description: "Primary tunnel endpoint configuration.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"passphrase": {
							Type:        schema.TypeString,
							Sensitive:   true,
							Required:    true,
							Description: "Pre-shared key for this tunnel. The public-api regex disallows hyphens; allowed characters are letters, digits, `.` and `_` (8-64 chars).",
							ValidateFunc: validation.StringMatch(
								regexp.MustCompile(`^[a-zA-Z1-9._][a-zA-Z0-9._]{7,63}$`),
								"must be 8-64 characters using only letters, digits, '.', and '_' (the first character cannot be '0')",
							),
						},
						"gateway_id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The ID of the SASE gateway that terminates this tunnel locally.",
						},
						"remote_id": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							Description:  "Optional remote tunnel ID. Computed if not supplied. Must be alphanumeric or a valid IP address.",
							ValidateFunc: validateRemoteID,
						},
						"tunnel_id": {
							Type:        schema.TypeString,
							Optional:    true,
							Computed:    true,
							Description: "The server-assigned tunnel ID. Computed.",
						},
						"p81_gwinternal_ip": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The Check Point SASE gateway internal IP on this tunnel.",
						},
						"remote_gwinternal_ip": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The remote gateway internal IP on this tunnel.",
						},
						"remote_public_ip": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The remote gateway public IP on this tunnel.",
						},
						"remote_asn": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The remote peer's BGP ASN as a string (e.g. `\"65010\"`).",
						},
					}},
			},
			"tunnel2": {
				Type:        schema.TypeList,
				Required:    true,
				ForceNew:    true,
				Description: "Standby tunnel endpoint configuration. Same shape as `tunnel1`.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"passphrase": {
							Type:        schema.TypeString,
							Sensitive:   true,
							Required:    true,
							Description: "Pre-shared key for this tunnel. The public-api regex disallows hyphens; allowed characters are letters, digits, `.` and `_` (8-64 chars).",
							ValidateFunc: validation.StringMatch(
								regexp.MustCompile(`^[a-zA-Z1-9._][a-zA-Z0-9._]{7,63}$`),
								"must be 8-64 characters using only letters, digits, '.', and '_' (the first character cannot be '0')",
							),
						},
						"tunnel_id": {
							Type:        schema.TypeString,
							Optional:    true,
							Computed:    true,
							Description: "The server-assigned tunnel ID. Computed.",
						},
						"gateway_id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The ID of the SASE gateway that terminates this tunnel locally.",
						},
						"remote_id": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							Description:  "Optional remote tunnel ID. Computed if not supplied. Must be alphanumeric or a valid IP address.",
							ValidateFunc: validateRemoteID,
						},
						"p81_gwinternal_ip": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The Check Point SASE gateway internal IP on this tunnel.",
						},
						"remote_gwinternal_ip": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The remote gateway internal IP on this tunnel.",
						},
						"remote_public_ip": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The remote gateway public IP on this tunnel.",
						},
						"remote_asn": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The remote peer's BGP ASN as a string (e.g. `\"65010\"`).",
						},
					}},
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceIpsecRedundantImportState,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(asyncResourceTimeout),
			Update: schema.DefaultTimeout(asyncResourceTimeout),
			Delete: schema.DefaultTimeout(asyncResourceTimeout),
		},
	}
}

/*
resourceIpsecRedundantImportState Import an ipsec-redundant tunnel by its ID
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceIpsecRedundantImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	// get the network and tunnel id and validate
	if len(strings.Split(d.Id(), "-")) != 2 {
		return nil, fmt.Errorf("could not import tunnel without provider the network_id and the tunnel_id in format network_id-tunnel_id\n")
	}

	diagnostics := resourceIpsecRedundantRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import ipsec redundant tunnel: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}

/*
resourceIpsecRedundantCreate Create a Ipsec Redundant Tunnel
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/

func resourceIpsecRedundantCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// intialize the client and the context if not exists
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// get the tunnel data from the terraform resource and flatten what need to be flattened for the api
	networkId := d.Get("network_id").(string)
	regionId := d.Get("region_id").(string)
	tunnelName := d.Get("tunnel_name").(string)
	tunnel1Data := d.Get("tunnel1").([]interface{})[0].(map[string]interface{})
	tunnel2Data := d.Get("tunnel2").([]interface{})[0].(map[string]interface{})
	gatewayId1 := tunnel1Data["gateway_id"].(string)
	passphrase1 := tunnel1Data["passphrase"].(string)
	p81GWinternalIP1 := tunnel1Data["p81_gwinternal_ip"].(string)
	remoteGWinernalIP1 := tunnel1Data["remote_gwinternal_ip"].(string)
	remotePublicIP1 := tunnel1Data["remote_public_ip"].(string)
	remoteId1 := tunnel1Data["remote_id"].(string)
	remoteAsn1 := parseASNString(tunnel1Data["remote_asn"].(string))
	gatewayId2 := tunnel2Data["gateway_id"].(string)
	passphrase2 := tunnel2Data["passphrase"].(string)
	p81GWinternalIP2 := tunnel2Data["p81_gwinternal_ip"].(string)
	remoteGWinernalIP2 := tunnel2Data["remote_gwinternal_ip"].(string)
	remotePublicIP2 := tunnel2Data["remote_public_ip"].(string)
	remoteId2 := tunnel2Data["remote_id"].(string)
	remoteAsn2 := parseASNString(tunnel2Data["remote_asn"].(string))
	sharedSettingsData := d.Get("shared_settings").([]interface{})[0].(map[string]interface{})
	p81GatewaySubnets := flattenStringsArrayData(sharedSettingsData["p81_gateway_subnets"].([]interface{}))
	remoteGatewaySubnets := flattenStringsArrayData(sharedSettingsData["remote_gateway_subnets"].([]interface{}))
	// peak_bandwidth is intentionally not read into the create payload here.
	// v3 removed the bandwidth field entirely from IPSecSharedSettingsCreate
	// (and every other IPSecSharedSettings-family type) — see the schema
	// comment above and flattenSharedSettingsData in utils.go for the
	// read-side preserve-prior-state handling this pairs with.
	// peakBandwidth := int32(sharedSettingsData["peak_bandwidth"].(int))
	advancedSettingsData := d.Get("advanced_settings").([]interface{})[0].(map[string]interface{})
	keyExchange := advancedSettingsData["key_exchange"].(string)
	dpdTimeout := advancedSettingsData["dpd_timeout"].(string)
	dpdDelay := advancedSettingsData["dpd_delay"].(string)
	lifetime := advancedSettingsData["lifetime"].(string)
	ikeLifeTime := advancedSettingsData["ike_life_time"].(string)
	phase1Data := advancedSettingsData["phase1"].([]interface{})[0].(map[string]interface{})
	phase2Data := advancedSettingsData["phase2"].([]interface{})[0].(map[string]interface{})
	authPhase1 := flattenStringsArrayData(phase1Data["auth"].([]interface{}))
	authPhase2 := flattenStringsArrayData(phase2Data["auth"].([]interface{}))
	encryptionPhase1 := flattenStringsArrayData(phase1Data["encryption"].([]interface{}))
	encryptionPhase2 := flattenStringsArrayData(phase2Data["encryption"].([]interface{}))
	dhPhase1 := flattenIntsArrayData(phase1Data["dh"].([]interface{}))
	dhPhase2 := flattenIntsArrayData(phase2Data["dh"].([]interface{}))

	// create the payload for the api
	remoteId1Value := perimeter81Sdk.StringAsRemoteID(&remoteId1)
	remoteId2Value := perimeter81Sdk.StringAsRemoteID(&remoteId2)
	ipSecRedundantBody := perimeter81Sdk.CreateIPSecRedundantPayload{
		RegionID:   regionId,
		TunnelName: tunnelName,
		Tunnel1: perimeter81Sdk.IPSecRedundantTunnelPayload{
			Passphrase:         passphrase1,
			GatewayID:          gatewayId1,
			P81GWInternalIP:    p81GWinternalIP1,
			RemoteGWInternalIP: remoteGWinernalIP1,
			RemotePublicIP:     remotePublicIP1,
			RemoteASN:          remoteAsn1,
			RemoteID:           remoteId1Value,
		},
		Tunnel2: perimeter81Sdk.IPSecRedundantTunnelPayload{
			Passphrase:         passphrase2,
			GatewayID:          gatewayId2,
			P81GWInternalIP:    p81GWinternalIP2,
			RemoteGWInternalIP: remoteGWinernalIP2,
			RemotePublicIP:     remotePublicIP2,
			RemoteASN:          remoteAsn2,
			RemoteID:           remoteId2Value,
		},
		SharedSettings: perimeter81Sdk.IPSecSharedSettingsCreate{
			P81GatewaySubnets:    p81GatewaySubnets,
			RemoteGatewaySubnets: remoteGatewaySubnets,
			// PeakBandwidth omitted; v3 removed this field entirely from
			// IPSecSharedSettingsCreate (see comment on the peakBandwidth
			// read above). There is no replacement field to send it on.
			// P81ASN omitted; public-api DTO marks it @IsOptional on both
			// v2.1 and v2.2 redundant-tunnel paths (BUG-26 / P81-124405).
			// Adding an HCL surface for it is tracked as a follow-up.
		},
		AdvancedSettings: perimeter81Sdk.IPSecAdvancedSettings{
			KeyExchange: keyExchange,
			IkeLifeTime: ikeLifeTime,
			Lifetime:    lifetime,
			DpdTimeout:  dpdTimeout,
			DpdDelay:    dpdDelay,
			Phase1: perimeter81Sdk.IPSecPhaseConfig{
				Auth:       authPhase1,
				Encryption: encryptionPhase1,
				Dh:         dhPhase1,
			},
			Phase2: perimeter81Sdk.IPSecPhaseConfig{
				Auth:       authPhase2,
				Encryption: encryptionPhase2,
				Dh:         dhPhase2,
			},
		},
	}
	// create the ipsec-redundant tunnel using the client sdk and check for errors
	status, _, err := client.StandardTunnelsAPI.StandardCreateIPSecRedundantTunnel(ctx, networkId).CreateIPSecRedundantPayload(ipSecRedundantBody).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create ipsec-redundant tunnel", err)
	}

	// get the status id of the ipsec-redundant tunnel creation
	var ipSecRedundantTunnelId string
	statusId := getIdFromUrl(status.GetStatusUrl())

	// check the status of the network that contains the ipsec-redundant tunnel and check for errors
	if err := pollStandardNetworkStatus(ctx, client, statusId, standardTunnelPollInterval); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create ipsec-redundant tunnel", err)
	}
	// get the ipsec-redundant tunnel id
	baseTunnelBody := perimeter81Sdk.BaseTunnelValues{
		RegionID:   regionId,
		GatewayID:  gatewayId1,
		TunnelName: tunnelName,
	}
	ipSecRedundantTunnelId, diags = getRedundantTunnelId(ctx, networkId, baseTunnelBody, *client, diags)
	if ipSecRedundantTunnelId == "" {
		return diags
	}
	d.SetId(ipSecRedundantTunnelId)

	return resourceIpsecRedundantRead(ctx, d, m)
}

/*
resourceIpsecRedundantRead Read a Ipsec Redundant Tunnel
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceIpsecRedundantRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// intialize the client and the context if not exists
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// get the ipsec-redundant tunnel id and the network id from the terraform resource data
	ids := strings.Split(d.Id(), "-")
	var networkId string
	var tunnelId string
	if len(ids) == 1 {
		tunnelId = d.Id()
		networkId = d.Get("network_id").(string)
	} else {
		networkId = ids[0]
		tunnelId = ids[1]
	}
	// get the ipsec-redundant tunnel using the client sdk and check for errors
	tunnel, _, err := client.StandardTunnelsAPI.StandardGetIPSecRedundantTunnel(ctx, networkId, tunnelId).Execute()

	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read ipsec-redundant tunnel", err)
	}
	if err := d.Set("network_id", networkId); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set networkId", err)
	}
	if err := d.Set("region_id", tunnel.GetRegionID()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set regionId", err)
	}
	if err := d.Set("tunnel_name", tunnel.GetTunnelName()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set tunnel name", err)
	}
	if err := d.Set("advanced_settings", flattenAdvancedSettingsData(tunnel.AdvancedSettings)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set advanced settings", err)
	}
	// Pass the prior "shared_settings" value (before this Set overwrites it)
	// so flattenSharedSettingsData can carry forward peak_bandwidth, which
	// v3 no longer returns on read — see the comment in that function
	// (utils.go) and on the peak_bandwidth schema attribute below.
	priorSharedSettings, _ := d.Get("shared_settings").([]interface{})
	if err := d.Set("shared_settings", flattenSharedSettingsData(tunnel.SharedSettings, priorSharedSettings)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set shared settings", err)
	}
	// Pass the prior "tunnel1"/"tunnel2" value (before this Set overwrites it) so
	// flattenTunnelData can carry forward passphrase, which v3 does not return on
	// a plain read — see the comment on flattenTunnelData (utils.go) and on
	// setIfPresent, which guards the analogous OpenVPN credential fields.
	priorTunnel1, _ := d.Get("tunnel1").([]interface{})
	if err := d.Set("tunnel1", flattenTunnelData(tunnel.Tunnel1, priorTunnel1)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set tunnel1", err)
	}
	priorTunnel2, _ := d.Get("tunnel2").([]interface{})
	if err := d.Set("tunnel2", flattenTunnelData(tunnel.Tunnel2, priorTunnel2)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set tunnel2", err)
	}
	d.SetId(tunnelId)
	return diags
}

/*
resourceIpsecRedundantUpdate Update a Ipsec Redundant Tunnel
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceIpsecRedundantUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	// THIS IS REACHABLE. An earlier reading called it dead code on the grounds
	// that every top-level attribute is ForceNew, and that reading was wrong
	// twice over. `last_updated` is Optional+Computed and NOT ForceNew; and
	// helper/schema's diffList propagates the parent's ForceNew only for
	// `Elem: *Schema` and for the synthetic `<key>.#` count -- for
	// `Elem: *Resource` it diffs each nested field against that field's OWN
	// schema, none of which sets ForceNew. Measured against
	// terraform-plugin-sdk/v2 v2.26.1 on 2026-08-26: changing
	// tunnel1.0.passphrase on a ForceNew TypeList yields RequiresNew=false, so
	// Terraform plans an update and lands here. The summary said "Unable to
	// delete" until then -- a copy-paste from Delete that told an operator
	// changing a passphrase that the provider could not destroy their tunnel.
	return appendErrorDiags(diags, "Unable to update ipsec-redundant tunnel", fmt.Errorf("ipsec-redundant tunnel update is not available yet"))
}

/*
resourceIpsecRedundantDelete Delete a Ipsec Redundant Tunnel
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceIpsecRedundantDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// intialize the client and the context if not exists
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// get the ipsec-redundant tunnel id and the network id from the terraform resource data
	tunnelId := d.Id()
	networkId := d.Get("network_id").(string)

	// delete the ipsec-redundant tunnel using the client sdk and check for errors
	status, _, err := client.StandardTunnelsAPI.StandardDeleteIPSecRedundantTunnel(ctx, networkId, tunnelId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete ipsec-redundant tunnel", err)
	}

	// get the status id of the ipsec-redundant tunnel deletion
	statusId := getIdFromUrl(status.GetStatusUrl())
	// check the status of the network that contains the ipsec-redundant tunnel and check for errors
	if err := pollStandardNetworkStatus(ctx, client, statusId, standardTunnelPollInterval); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete ipsec-redundant tunnel", err)
	}
	d.SetId("")
	return diags
}
