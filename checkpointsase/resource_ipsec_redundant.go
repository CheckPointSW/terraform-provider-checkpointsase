package checkpointsase

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
resourceIpsecRedundant Setup the IpSec-Redundant Resource CRUD operations

@return &schema.Resource
*/
func resourceIpsecRedundant() *schema.Resource {
	return &schema.Resource{
		Description: "Manages an active/standby IPsec redundant tunnel pair for a " +
			"`checkpointsase_network`. Two tunnels (`tunnel1` + `tunnel2`) terminate at " +
			"distinct remote endpoints for failover; `shared_settings` (gateway subnets) " +
			"and `advanced_settings` (IKE/IPSec parameters, phase1/phase2 proposals) " +
			"apply to both tunnels uniformly. " +
			"The resource id is the HA *pair* id (`haTunnelId`), which read, update and " +
			"delete are all addressed by. It is not returned by the network read, the " +
			"network list, the gateway or region reads, or the single-tunnel read, and " +
			"there is no collection route that lists it — the pair endpoint answers 404 " +
			"to each member tunnel's own id. It is taken instead from the asynchronous " +
			"create status (`result.resource`), which is why Create must harvest it " +
			"rather than search for the pair by name. " +
			"`region_id`, `network_id` and `tunnel_name` are `ForceNew`; everything else " +
			"is updated in place through `PUT`.",
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

	statusId := getIdFromUrl(status.GetStatusUrl())

	// The pair id lives only in the async status's result.resource. There is no
	// searching for it afterwards: the pair route 404s for either member's own id,
	// and no read endpoint returns haTunnelID, so an id guessed from network-find
	// would be a member id and every later read, update and delete would 404.
	resource, err := pollStandardNetworkStatusForResource(ctx, client, statusId, standardTunnelPollInterval)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create ipsec-redundant tunnel", err)
	}
	haTunnelId := getIdFromUrl(resource)
	if haTunnelId == "" {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to extract ipsec-redundant pair id post-Create",
			fmt.Errorf("async status completed but result.resource was empty; the pair exists on network %s under tunnel_name=%s and must be removed by hand", networkId, tunnelName))
	}
	d.SetId(haTunnelId)

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
	client := m.(*perimeter81Sdk.APIClient)

	if d.HasChanges("tunnel1", "tunnel2", "shared_settings", "advanced_settings") {
		haTunnelId := d.Id()
		networkId := d.Get("network_id").(string)

		tunnel1Data := d.Get("tunnel1").([]interface{})[0].(map[string]interface{})
		tunnel2Data := d.Get("tunnel2").([]interface{})[0].(map[string]interface{})
		// The update payload needs each member's own id alongside the pair id.
		// It is never in the config: Read persists it from the pair read into the
		// Computed tunnelN.tunnel_id, so an update before a successful read has
		// nothing to send.
		tunnel1, err := expandRedundantTunnelUpdate(tunnel1Data)
		if err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to update ipsec-redundant tunnel", fmt.Errorf("tunnel1: %w", err))
		}
		tunnel2, err := expandRedundantTunnelUpdate(tunnel2Data)
		if err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to update ipsec-redundant tunnel", fmt.Errorf("tunnel2: %w", err))
		}

		sharedSettingsData := d.Get("shared_settings").([]interface{})[0].(map[string]interface{})
		advancedSettingsData := d.Get("advanced_settings").([]interface{})[0].(map[string]interface{})
		phase1Data := advancedSettingsData["phase1"].([]interface{})[0].(map[string]interface{})
		phase2Data := advancedSettingsData["phase2"].([]interface{})[0].(map[string]interface{})

		ipSecRedundantBody := perimeter81Sdk.UpdateIPSecRedundantPayload{
			Tunnel1: tunnel1,
			Tunnel2: tunnel2,
			SharedSettings: perimeter81Sdk.IPSecSharedSettings{
				// peak_bandwidth is not sent: v3 removed the field from every
				// IPSecSharedSettings-family type, update included.
				P81GatewaySubnets:    flattenStringsArrayData(sharedSettingsData["p81_gateway_subnets"].([]interface{})),
				RemoteGatewaySubnets: flattenStringsArrayData(sharedSettingsData["remote_gateway_subnets"].([]interface{})),
			},
			AdvancedSettings: perimeter81Sdk.IPSecAdvancedSettings{
				KeyExchange: advancedSettingsData["key_exchange"].(string),
				IkeLifeTime: advancedSettingsData["ike_life_time"].(string),
				Lifetime:    advancedSettingsData["lifetime"].(string),
				DpdTimeout:  advancedSettingsData["dpd_timeout"].(string),
				DpdDelay:    advancedSettingsData["dpd_delay"].(string),
				Phase1: perimeter81Sdk.IPSecPhaseConfig{
					Auth:       flattenStringsArrayData(phase1Data["auth"].([]interface{})),
					Encryption: flattenStringsArrayData(phase1Data["encryption"].([]interface{})),
					Dh:         flattenIntsArrayData(phase1Data["dh"].([]interface{})),
				},
				Phase2: perimeter81Sdk.IPSecPhaseConfig{
					Auth:       flattenStringsArrayData(phase2Data["auth"].([]interface{})),
					Encryption: flattenStringsArrayData(phase2Data["encryption"].([]interface{})),
					Dh:         flattenIntsArrayData(phase2Data["dh"].([]interface{})),
				},
			},
		}

		status, _, err := client.StandardTunnelsAPI.StandardUpdateIPSecRedundantTunnel(ctx, networkId, haTunnelId).UpdateIPSecRedundantPayload(ipSecRedundantBody).Execute()
		if err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to update ipsec-redundant tunnel", err)
		}

		statusId := getIdFromUrl(status.GetStatusUrl())
		if err := pollStandardNetworkStatus(ctx, client, statusId, standardTunnelPollInterval); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to update ipsec-redundant tunnel", err)
		}
		if err := d.Set("last_updated", time.Now().Format(time.RFC850)); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set last_updated", err)
		}
	}

	return resourceIpsecRedundantRead(ctx, d, m)
}

/*
expandRedundantTunnelUpdate builds one member's update payload from its state.

The read returns the member id as "tunnelID" and the update sends it as
"tunnelId"; the two tags differ by one character, so they are easy to cross.
*/
func expandRedundantTunnelUpdate(tunnelData map[string]interface{}) (*perimeter81Sdk.IPSecRedundantTunnelUpdatePayload, error) {
	tunnelId := tunnelData["tunnel_id"].(string)
	if tunnelId == "" {
		return nil, fmt.Errorf("tunnel_id is empty in state, so the member this update addresses is unknown; refresh the resource before changing it")
	}
	remoteId := tunnelData["remote_id"].(string)
	return &perimeter81Sdk.IPSecRedundantTunnelUpdatePayload{
		TunnelId:           tunnelId,
		Passphrase:         tunnelData["passphrase"].(string),
		GatewayID:          tunnelData["gateway_id"].(string),
		P81GWInternalIP:    tunnelData["p81_gwinternal_ip"].(string),
		RemoteGWInternalIP: tunnelData["remote_gwinternal_ip"].(string),
		RemotePublicIP:     tunnelData["remote_public_ip"].(string),
		RemoteASN:          parseASNString(tunnelData["remote_asn"].(string)),
		RemoteID:           perimeter81Sdk.StringAsRemoteID(&remoteId),
	}, nil
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
