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
resourceEnhancedDynamicTunnel Setup the Enhanced Dynamic Tunnel Resource CRUD operations

@return &schema.Resource
*/
func resourceEnhancedDynamicTunnel() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a dynamic (BGP-routed) IPsec tunnel attached to a " +
			"`checkpointsase_enhanced_network`. A dynamic tunnel can span multiple " +
			"regions: each `tunnel` block declares one endpoint, and shared phase1 / " +
			"phase2 / lifetime parameters apply to all of them. " +
			"Use `checkpointsase_enhanced_route_table` with `type = \"dynamic\"` to " +
			"attach routes to the resulting tunnel group. " +
			"**`network_id` is immutable** — changing it forces resource replacement.",
		CreateContext: resourceEnhancedDynamicTunnelCreate,
		ReadContext:   resourceEnhancedDynamicTunnelRead,
		UpdateContext: resourceEnhancedDynamicTunnelUpdate,
		DeleteContext: resourceEnhancedDynamicTunnelDelete,
		Schema: map[string]*schema.Schema{
			"last_updated": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Timestamp of the last update to this resource.",
			},
			"network_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The ID of the enhanced network this dynamic tunnel belongs to.",
			},
			"tunnel_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the dynamic IPSec tunnel. Must be 15 characters or fewer.",
				// The upstream model auto-suffixes the user's tunnel name
				// with `01` (createIPSecRedundant.transform.ts:113 —
				// `interfaceName: ${tunnelName}0${i+1}`). Suppress the
				// resulting drift so plan stays idempotent post-Create.
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					return strings.TrimSuffix(oldValue, "01") == newValue || oldValue == strings.TrimSuffix(newValue, "01")
				},
				ValidateFunc: validation.StringLenBetween(0, 15),
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional description for the dynamic tunnel.",
			},
			"left_asn": {
				Type:         schema.TypeInt,
				Required:     true,
				Description:  "The local (Check Point SASE) BGP autonomous-system number for this dynamic tunnel. Required by the API; valid ranges per IsValidASN.",
				ValidateFunc: validation.IntBetween(1, 4294967295),
			},
			"tunnel": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "The list of individual tunnel endpoints for this dynamic tunnel group.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"region_id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The enhanced region ID for this tunnel endpoint.",
						},
						"auth_type": {
							Type:         schema.TypeString,
							Optional:     true,
							Description:  "Authentication type for this tunnel endpoint. Must be `psk` or `cert`.",
							ValidateFunc: validation.StringInSlice([]string{"psk", "cert"}, false),
						},
						"passphrase": {
							Type:        schema.TypeString,
							Optional:    true,
							Sensitive:   true,
							Description: "Pre-shared key for tunnel authentication. The public-api regex disallows hyphens; allowed characters are letters, digits, `.` and `_` (8-64 chars).",
							ValidateFunc: validation.StringMatch(
								regexp.MustCompile(`^[a-zA-Z1-9._][a-zA-Z0-9._]{7,63}$`),
								"must be 8-64 characters using only letters, digits, '.', and '_' (the first character cannot be '0')",
							),
						},
						"customer_root_ca": {
							Type:        schema.TypeString,
							Optional:    true,
							Sensitive:   true,
							Description: "Customer root certificate authority. Required when auth_type is 'cert'.",
						},
						"remote_public_ip": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The remote gateway public IP address.",
						},
						"remote_id": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							Description:  "The remote gateway ID. Server defaults to `remote_public_ip` when omitted. Must be alphanumeric or a valid IP address.",
							ValidateFunc: validateRemoteID,
						},
						"remote_asn": {
							Type:         schema.TypeInt,
							Required:     true,
							Description:  "BGP autonomous-system number for the remote endpoint. Required by the API.",
							ValidateFunc: validation.IntBetween(1, 4294967295),
						},
						"p81_gw_internal_ip": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The Check Point SASE gateway internal IP address (BGP peer local).",
						},
						"remote_gw_internal_ip": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The remote gateway internal IP address (BGP peer remote).",
						},
					},
				},
			},
			"p81_gateway_subnets": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "List of Check Point SASE gateway subnet CIDR blocks (shared settings).",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"remote_gateway_subnets": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "List of remote gateway subnet CIDR blocks (shared settings).",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"peak_bandwidth": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      1000,
				Deprecated:   "Has no effect on this resource in v3. Retained only for configuration compatibility.",
				Description:  "Expected peak throughput of the tunnel communication in Mbps. Allowed range is 10–8000. Defaults to 1000. Not sent to the v3 server — the value is retained only for configuration compatibility with prior provider versions.",
				ValidateFunc: validation.IntBetween(10, 8000),
			},
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
				MaxItems:    1,
				Description: "Phase 1 (IKE) IPSec configuration.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"auth": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "List of phase 1 authentication algorithms.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"encryption": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "List of phase 1 encryption algorithms.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"key_exchange_method": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "List of phase 1 key exchange methods (Diffie-Hellman groups).",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
			"phase2": {
				Type:        schema.TypeList,
				Required:    true,
				MaxItems:    1,
				Description: "Phase 2 (ESP/IPSec) configuration.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"auth": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "List of phase 2 authentication algorithms.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"encryption": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "List of phase 2 encryption algorithms.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"key_exchange_method": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "List of phase 2 key exchange methods (Diffie-Hellman groups).",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceEnhancedDynamicTunnelImportState,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(asyncResourceTimeout),
			Update: schema.DefaultTimeout(asyncResourceTimeout),
			Delete: schema.DefaultTimeout(asyncResourceTimeout),
		},
	}
}

/*
resourceEnhancedDynamicTunnelImportState Import an enhanced dynamic tunnel by its ID.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceEnhancedDynamicTunnelImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	// Read needs both network_id (URL path) and tunnel_id (d.Id()) — the
	// import handler must split the composite ID `<network_id>-<tunnel_id>`
	// before delegating. Same pattern as static tunnel + gateway + enhanced
	// region importers.
	ids := strings.SplitN(d.Id(), "-", 2)
	if len(ids) != 2 || ids[0] == "" || ids[1] == "" {
		return nil, fmt.Errorf("could not import enhanced_dynamic_tunnel: expected composite ID in the form <network_id>-<tunnel_id>, got %q", d.Id())
	}
	if err := d.Set("network_id", ids[0]); err != nil {
		return nil, fmt.Errorf("could not import enhanced_dynamic_tunnel: failed to set network_id: %w", err)
	}
	d.SetId(ids[1])

	diagnostics := resourceEnhancedDynamicTunnelRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import enhanced dynamic tunnel: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}

/*
flattenDynamicTunnelDetails converts a list of tunnel schema blocks into []DynamicTunnelDetails SDK models.
*/
func flattenDynamicTunnelDetails(tunnelItems []interface{}) []perimeter81Sdk.DynamicTunnelDetails {
	tunnels := make([]perimeter81Sdk.DynamicTunnelDetails, len(tunnelItems))
	for i, item := range tunnelItems {
		tunnelMap := item.(map[string]interface{})
		regionId := tunnelMap["region_id"].(string)
		detail := perimeter81Sdk.DynamicTunnelDetails{
			RegionID: regionId,
		}
		detail.RemoteASN = int32(tunnelMap["remote_asn"].(int))
		// v3: AuthType and RemotePublicIP are required strings (not
		// *string) on DynamicTunnelDetails — Passphrase/CustomerRootCA
		// remain pointers. Same behavioral implication as
		// StaticTunnelCreate's RemotePublicIP/RemoteID/AuthType (see
		// resource_enhanced_static_tunnel.go's Create and Defect #3 in the
		// Task 12A report): when the user leaves auth_type/remote_public_ip
		// unset in HCL, the `ok && v != ""` guard below simply skips the
		// assignment, so these required fields still serialize as "" rather
		// than being omitted from the request. Inherent to v3's
		// requiredness, not introduced here, and not fixed per Phase 1
		// scope (endpoint-only port).
		if v, ok := tunnelMap["auth_type"].(string); ok && v != "" {
			detail.AuthType = v
		}
		if v, ok := tunnelMap["passphrase"].(string); ok && v != "" {
			detail.Passphrase = &v
		}
		if v, ok := tunnelMap["customer_root_ca"].(string); ok && v != "" {
			detail.CustomerRootCA = &v
		}
		if v, ok := tunnelMap["remote_public_ip"].(string); ok && v != "" {
			detail.RemotePublicIP = v
		}
		// OPEN-02: the v2.3 API rejects an empty remoteID with
		// `tunnels.0.remoteID must be a string`, even though the field is
		// schema-Optional and the description claims the server defaults
		// it from remote_public_ip. Mirror that documented default
		// client-side when the user leaves remote_id empty.
		remoteId, _ := tunnelMap["remote_id"].(string)
		if remoteId == "" {
			if v, ok := tunnelMap["remote_public_ip"].(string); ok {
				remoteId = v
			}
		}
		// v3: RemoteID, P81GWInternalIP and RemoteGWInternalIP are also
		// required strings (not *string) on DynamicTunnelDetails.
		if remoteId != "" {
			detail.RemoteID = remoteId
		}
		if v, ok := tunnelMap["p81_gw_internal_ip"].(string); ok && v != "" {
			detail.P81GWInternalIP = v
		}
		if v, ok := tunnelMap["remote_gw_internal_ip"].(string); ok && v != "" {
			detail.RemoteGWInternalIP = v
		}
		// Public-api requires `routingType` on every dynamic tunnel detail —
		// see model_dynamic_tunnel_details.go: RoutingType is a value type
		// (not a pointer), no omitempty, and the enum admits only
		// ROUTINGTYPE_ROUTE/ROUTINGTYPE_POLICY, so leaving it unset serializes
		// as "" and the server rejects the create outright. There is no
		// routing_type schema attribute for dynamic tunnels, so default to
		// route — the same default the static tunnel path uses (see
		// resource_enhanced_static_tunnel.go's Create) when the user sets
		// nothing.
		detail.RoutingType = perimeter81Sdk.ROUTINGTYPE_ROUTE
		tunnels[i] = detail
	}
	return tunnels
}

/*
resourceEnhancedDynamicTunnelCreate Create an Enhanced Dynamic IPSec Tunnel.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedDynamicTunnelCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	tunnelName := d.Get("tunnel_name").(string)
	p81GatewaySubnets := flattenStringsArrayData(d.Get("p81_gateway_subnets").([]interface{}))
	remoteGatewaySubnets := flattenStringsArrayData(d.Get("remote_gateway_subnets").([]interface{}))
	keyExchange := d.Get("key_exchange").(string)
	ikeLifeTime := d.Get("ike_life_time").(string)
	lifetime := d.Get("lifetime").(string)
	dpdDelay := d.Get("dpd_delay").(string)
	dpdTimeout := d.Get("dpd_timeout").(string)
	phase1 := flattenIPSecPhaseConfigV23(d.Get("phase1").([]interface{}))
	phase2 := flattenIPSecPhaseConfigV23(d.Get("phase2").([]interface{}))
	tunnels := flattenDynamicTunnelDetails(d.Get("tunnel").([]interface{}))

	leftASN := int32(d.Get("left_asn").(int))
	// v3 dropped the bandwidth field entirely from every IPSecSharedSettings-
	// family type — verified against the SDK: EnhancedIPSecSharedSettingsCreate,
	// IPSecSharedSettings, IPSecSharedSettingsCreate and
	// EnhancedIPSecSharedSettingsUpdate all lack it, and DynamicTunnelCreate
	// has no top-level replacement either. There is nowhere left to send
	// peak_bandwidth for a dynamic tunnel create in v3; the schema attribute
	// is preserved (Phase 1 does not touch schema) but its value can no
	// longer reach the API. Flagged as a capability regression for a later
	// phase — see the Task 12A report.
	sharedSettings := perimeter81Sdk.EnhancedIPSecSharedSettingsCreate{
		P81GatewaySubnets:    p81GatewaySubnets,
		RemoteGatewaySubnets: remoteGatewaySubnets,
		Features:             perimeter81Sdk.NetworkFeaturesCreate{},
		LeftASN:              leftASN,
	}

	advancedSettings := perimeter81Sdk.IPSecAdvancedSettingsV23{
		KeyExchange: keyExchange,
		IkeLifeTime: ikeLifeTime,
		Lifetime:    lifetime,
		DpdDelay:    dpdDelay,
		DpdTimeout:  dpdTimeout,
		Phase1:      phase1,
		Phase2:      phase2,
	}

	payload := perimeter81Sdk.DynamicTunnelCreate{
		TunnelName:       tunnelName,
		Tunnels:          tunnels,
		SharedSettings:   sharedSettings,
		AdvancedSettings: advancedSettings,
	}

	if v, ok := d.GetOk("description"); ok {
		s := v.(string)
		payload.Description = &s
	}

	status, _, err := client.EnhancedTunnelsAPI.CreateDynamicTunnel(ctx, networkId).DynamicTunnelCreate(payload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Enhanced Dynamic Tunnel", err)
	}

	statusId := getIdFromUrl(status.GetStatusUrl())
	resource, err := pollStandardNetworkStatusForResource(ctx, client, statusId, standardNetworkPollInterval)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Enhanced Dynamic Tunnel", err)
	}
	dynamicTunnelId := getIdFromUrl(resource)
	if dynamicTunnelId == "" {
		// Async result didn't carry a resource URL. Fall back to
		// listing tunnels and finding by tunnel_name.
		resp, _, lerr := client.EnhancedTunnelsAPI.GetEnhancedRegionTunnelsPerNetwork(ctx, networkId).Execute()
		if lerr == nil && resp != nil {
			for _, t := range resp.Data {
				if t.TunnelName == tunnelName {
					dynamicTunnelId = t.Id
					break
				}
			}
		}
		if dynamicTunnelId == "" {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to extract Enhanced Dynamic Tunnel id post-Create",
				fmt.Errorf("async status completed but result.resource was empty and list-by-name found no match for tunnel_name=%s", tunnelName))
		}
	}

	d.SetId(dynamicTunnelId)
	return resourceEnhancedDynamicTunnelRead(ctx, d, m)
}

/*
resourceEnhancedDynamicTunnelRead Read an Enhanced Dynamic IPSec Tunnel.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedDynamicTunnelRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	dynamicTunnelId := d.Id()

	tunnelsData, _, err := client.EnhancedTunnelsAPI.GetDynamicTunnel(ctx, networkId, dynamicTunnelId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to find Enhanced Dynamic Tunnel", err)
	}

	if len(tunnelsData) > 0 {
		tunnel := tunnelsData[0]
		if err := d.Set("tunnel_name", tunnel.TunnelName); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set Enhanced Dynamic Tunnel tunnel_name", err)
		}
		if err := d.Set("key_exchange", tunnel.KeyExchange); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set Enhanced Dynamic Tunnel key_exchange", err)
		}
		// ike_life_time / lifetime / dpd_delay / dpd_timeout / phase1 / phase2
		// come back at the top level of each returned endpoint, not inside an
		// `advancedSettings` object — see setEnhancedTunnelIPSecState
		// (resource_enhanced_static_tunnel.go) and SDK overlay A19. These are
		// the dynamic tunnel group's shared settings, identical across every
		// endpoint the group returns, so reading them from endpoint 0 is
		// correct.
		if err := setEnhancedTunnelIPSecState(d, &tunnel); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set Enhanced Dynamic Tunnel IPSec settings", err)
		}
	}

	// The per-endpoint `tunnel` blocks are deliberately NOT refreshed here,
	// even though each returned EnhancedTunnel now carries that endpoint's
	// remotePublicIP and remoteID (overlay A19). Two things would have to be
	// established first, and neither is:
	//
	//   1. EnhancedTunnel carries no remoteASN, p81GWInternalIP or
	//      remoteGWInternalIP, so rebuilding the `tunnel` list from the
	//      response would blank three Required attributes — a worse version
	//      of the bug this change fixes. A correct implementation has to
	//      merge into the existing list rather than replace it.
	//   2. That merge needs a reliable endpoint identity. Pairing
	//      tunnelsData[i] with tunnel[i] assumes the server returns endpoints
	//      in the order they were configured, which nothing verifies; if it
	//      does not, endpoint B's remote_id lands on endpoint A. region_id is
	//      not a key either — nothing stops two endpoints sharing a region.
	//
	// Populating these needs a live capture of a multi-endpoint dynamic tunnel
	// to settle the ordering question. Until then the static tunnel gets
	// remote_public_ip/remote_id drift detection and this resource does not.

	return diags
}

/*
resourceEnhancedDynamicTunnelUpdate Update an Enhanced Dynamic IPSec Tunnel.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedDynamicTunnelUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	dynamicTunnelId := d.Id()
	tunnelName := d.Get("tunnel_name").(string)

	payload := perimeter81Sdk.DynamicTunnelUpdate{
		TunnelName: tunnelName,
	}

	if v, ok := d.GetOk("description"); ok {
		s := v.(string)
		payload.Description = &s
	}

	_, _, err := client.EnhancedTunnelsAPI.UpdateDynamicTunnel(ctx, networkId, dynamicTunnelId).DynamicTunnelUpdate(payload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to update Enhanced Dynamic Tunnel", err)
	}
	d.Set("last_updated", time.Now().Format(time.RFC850))

	return resourceEnhancedDynamicTunnelRead(ctx, d, m)
}

/*
resourceEnhancedDynamicTunnelDelete Delete an Enhanced Dynamic IPSec Tunnel.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedDynamicTunnelDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	dynamicTunnelId := d.Id()

	status, _, err := client.EnhancedTunnelsAPI.DeleteDynamicTunnel(ctx, networkId, dynamicTunnelId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete Enhanced Dynamic Tunnel", err)
	}

	statusId := getIdFromUrl(status.GetStatusUrl())
	if err := pollStandardNetworkStatus(ctx, client, statusId, standardNetworkPollInterval); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete Enhanced Dynamic Tunnel", err)
	}

	d.SetId("")
	return diags
}
