package checkpointsase

import (
	"context"
	"strconv"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
dataSourceEnhancedTunnels Query all tunnels in an enhanced network

@return &schema.Resource
*/
func dataSourceEnhancedTunnels() *schema.Resource {
	return &schema.Resource{
		Description: "List all IPsec tunnels (static and dynamic) attached to a single " +
			"`checkpointsase_enhanced_network`. Returns paginated results with " +
			"`items_total`, `page`, and `total_page` metadata.",
		ReadContext: dataSourceEnhancedTunnelsRead,
		Schema: map[string]*schema.Schema{
			"network_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The ID of the enhanced network to retrieve tunnels for.",
			},
			"items_total": {
				Type:        schema.TypeFloat,
				Computed:    true,
				Description: "The total number of tunnels in the enhanced network.",
			},
			"page": {
				Type:        schema.TypeFloat,
				Computed:    true,
				Description: "The current page number of the paginated result.",
			},
			"total_page": {
				Type:        schema.TypeFloat,
				Computed:    true,
				Description: "The total number of pages in the paginated result.",
			},
			"tunnels": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The list of tunnels in the enhanced network.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The unique ID of the enhanced tunnel.",
						},
						"tunnel_name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The name of the tunnel.",
						},
						"region_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The ID of the target region for this tunnel.",
						},
						"ha_tunnel_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The enhanced dynamic tunnel group ID (or tunnel ID for static tunnels).",
						},
						"auth_type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The authentication type for the tunnel ('psk' for pre-shared key, 'cert' for certificate).",
						},
						"key_exchange": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The IKE version used for key exchange.",
						},
						"ike_life_time": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The IKE phase 1 lifetime.",
						},
						"lifetime": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The IKE phase 2 lifetime.",
						},
						"dpd_delay": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The Dead Peer Detection delay interval.",
						},
						"dpd_timeout": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The Dead Peer Detection timeout.",
						},
						"dpd_action": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The action taken when Dead Peer Detection triggers.",
						},
						"remote_public_ip": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The remote gateway's public IP address.",
						},
						"remote_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The remote gateway ID.",
						},
						"description": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "An optional description for the tunnel.",
						},
						"routing_type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The routing type for the tunnel.",
						},
						"peak_bandwidth": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "The expected peak throughput of the tunnel communication in Mbps.",
						},
						"p81_gateway_subnets": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "The list of Check Point SASE gateway subnets.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"remote_gateway_subnets": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "The list of remote gateway subnets.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
		},
	}
}

/*
dataSourceEnhancedTunnelsRead Use the SDK to query all tunnels in an enhanced network.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func dataSourceEnhancedTunnelsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)
	ctx = context.Background()

	networkId := d.Get("network_id").(string)

	response, _, err := client.EnhancedTunnelsAPI.GetEnhancedRegionTunnelsPerNetwork(ctx, networkId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to get Enhanced Tunnels", err)
	}

	if err := d.Set("items_total", float64(response.GetItemsTotal())); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Tunnels items_total", err)
	}
	if err := d.Set("page", float64(response.GetPage())); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Tunnels page", err)
	}
	if err := d.Set("total_page", float64(response.GetTotalPage())); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Tunnels total_page", err)
	}

	// v3's read shape (EnhancedTunnel) dropped remote_public_ip, remote_id
	// and description entirely — see flattenEnhancedTunnelsData below.
	// Preserve whatever this data source last saw per tunnel id instead of
	// blanking those three fields.
	priorTunnels, _ := d.Get("tunnels").([]interface{})
	tunnels := flattenEnhancedTunnelsData(response.GetData(), priorTunnels)
	if err := d.Set("tunnels", tunnels); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Tunnels data", err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))
	return diags
}

/*
flattenEnhancedTunnelsData flattens a list of EnhancedTunnel SDK models to a Terraform-compatible list.
  - @param tunnels []perimeter81Sdk.EnhancedTunnel - the tunnels to flatten
  - @param priorTunnels []interface{} - the previous value of the "tunnels" attribute (from
    d.Get), used to preserve remote_public_ip/remote_id/description across reads — see comment
    below.

@return []interface{} - the flattened tunnels
*/
func flattenEnhancedTunnelsData(tunnels []perimeter81Sdk.EnhancedTunnel, priorTunnels []interface{}) []interface{} {
	if tunnels == nil {
		return make([]interface{}, 0)
	}

	// v3: remote_public_ip, remote_id and description were dropped from
	// EnhancedTunnel (the v3 read shape) — they only still exist on the
	// write-side types (StaticTunnelCreate/StaticTunnelUpdate/
	// DynamicTunnelDetails/DynamicTunnelUpdate). This data source has no
	// prior Terraform config to fall back to (everything here is Computed),
	// so the best available substitute is whatever this data source itself
	// last observed for the same tunnel id — same preserve-prior-state
	// rationale as resourceGatewayRead's `name`/`idle` handling in
	// resource_gateway.go. Drift detection on these three fields is
	// impossible under v3: a tunnel seen here for the first time has no
	// prior value to carry forward and reads back as "".
	type priorFields struct {
		remotePublicIP string
		remoteID       string
		description    string
	}
	priorByID := make(map[string]priorFields, len(priorTunnels))
	for _, p := range priorTunnels {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := pm["id"].(string)
		if id == "" {
			continue
		}
		var pf priorFields
		pf.remotePublicIP, _ = pm["remote_public_ip"].(string)
		pf.remoteID, _ = pm["remote_id"].(string)
		pf.description, _ = pm["description"].(string)
		priorByID[id] = pf
	}

	result := make([]interface{}, len(tunnels))
	for i, tunnel := range tunnels {
		id := tunnel.GetId()
		prior := priorByID[id]
		tunnelMap := map[string]interface{}{
			"id":           id,
			"tunnel_name":  tunnel.GetTunnelName(),
			"region_id":    tunnel.GetRegionID(),
			"ha_tunnel_id": tunnel.GetHaTunnelID(),
			"auth_type":    tunnel.GetAuthType(),
			"key_exchange": tunnel.GetKeyExchange(),
			// v3: IkeLifeTime/Lifetime/DpdDelay/DpdTimeout moved off
			// EnhancedTunnel and onto its nested *IPSecAdvancedSettingsV23
			// (AdvancedSettings is a pointer, but IPSecAdvancedSettingsV23's
			// Get* accessors are nil-safe, so no manual nil-check is needed).
			"ike_life_time":          tunnel.AdvancedSettings.GetIkeLifeTime(),
			"lifetime":               tunnel.AdvancedSettings.GetLifetime(),
			"dpd_delay":              tunnel.AdvancedSettings.GetDpdDelay(),
			"dpd_timeout":            tunnel.AdvancedSettings.GetDpdTimeout(),
			"dpd_action":             tunnel.GetDpdAction(),
			"remote_public_ip":       prior.remotePublicIP,
			"remote_id":              prior.remoteID,
			"description":            prior.description,
			"routing_type":           string(tunnel.GetRoutingType()),
			"peak_bandwidth":         int(tunnel.GetPeakBandwidthMbps()),
			"p81_gateway_subnets":    tunnel.GetP81GatewaySubnets(),
			"remote_gateway_subnets": tunnel.GetRemoteGatewaySubnets(),
		}
		result[i] = tunnelMap
	}
	return result
}
