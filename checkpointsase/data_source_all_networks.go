package checkpointsase

import (
	"context"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
dataSourceAllNetworks Query all networks (both standard and enhanced) by merging the v3
/networks/standard and /networks/enhanced list endpoints client-side.

@return &schema.Resource
*/
func dataSourceAllNetworks() *schema.Resource {
	return &schema.Resource{
		Description: "List all networks (both standard and enhanced) in Check Point SASE. The v3 API has no combined networks endpoint, so this data source merges GET /v3/networks/standard and GET /v3/networks/enhanced.",
		ReadContext: dataSourceAllNetworksRead,
		Schema: map[string]*schema.Schema{
			"networks": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The list of all networks (standard and enhanced).",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The unique identifier of the network.",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The name of the network.",
						},
						"tags": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "Tags associated with the network.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"dns": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The DNS name of the network.",
						},
						"subnet": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The subnet CIDR block of the network.",
						},
						"access_type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The access type of the network.",
						},
						"is_default": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Whether this is the default network.",
						},
						"tenant_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The tenant ID that owns this network.",
						},
						"created_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The creation timestamp.",
						},
						"updated_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The last update timestamp.",
						},
						"network_kind": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Which list this network came from: standard or enhanced. Added in v3, where the combined /networks endpoint no longer exists.",
						},
					},
				},
			},
		},
	}
}

// allNetworkRow is the common projection of a standard or enhanced network,
// decoupling the flatten logic from the two different SDK response types so it
// can be unit-tested without an API.
type allNetworkRow struct {
	ID         string
	Name       string
	Tags       []string
	DNS        string
	Subnet     string
	AccessType string
	IsDefault  bool
	TenantID   string
	CreatedAt  string
	UpdatedAt  string
}

// flattenAllNetworks merges the standard and enhanced lists into the flat shape
// this data source has always exposed, tagging each row with its origin.
func flattenAllNetworks(standard, enhanced []allNetworkRow) []interface{} {
	out := make([]interface{}, 0, len(standard)+len(enhanced))
	for _, group := range []struct {
		kind string
		rows []allNetworkRow
	}{{"standard", standard}, {"enhanced", enhanced}} {
		for _, r := range group.rows {
			tags := r.Tags
			if tags == nil {
				tags = []string{}
			}
			out = append(out, map[string]interface{}{
				"id":           r.ID,
				"name":         r.Name,
				"tags":         tags,
				"dns":          r.DNS,
				"subnet":       r.Subnet,
				"access_type":  r.AccessType,
				"is_default":   r.IsDefault,
				"tenant_id":    r.TenantID,
				"created_at":   r.CreatedAt,
				"updated_at":   r.UpdatedAt,
				"network_kind": group.kind,
			})
		}
	}
	return out
}

func dataSourceAllNetworksRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// v3 deletes GET /networks (the combined list), so this data source fans out
	// to the two surviving list endpoints and merges them, preserving the HCL
	// contract customers already depend on.
	standardNetworks, _, err := client.StandardNetworksAPI.StandardGetNetworks(ctx).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to list standard networks", err)
	}
	enhancedNetworks, _, err := client.EnhancedNetworksAPI.GetEnhancedNetworks(ctx).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to list enhanced networks", err)
	}

	standardRows := make([]allNetworkRow, 0, len(standardNetworks))
	for _, n := range standardNetworks {
		standardRows = append(standardRows, allNetworkRow{
			ID: n.GetId(), Name: n.GetName(), Tags: n.GetTags(), DNS: n.GetDns(),
			Subnet: n.GetSubnet(), AccessType: n.GetAccessType(),
			IsDefault: n.GetIsDefault(), TenantID: n.GetTenantId(),
			CreatedAt: n.GetCreatedAt().String(), UpdatedAt: n.GetUpdatedAt().String(),
		})
	}
	// EnhancedNetwork carries the same shared fields as Network (verified against
	// model_enhanced_network.go), so every row is fully populated here too —
	// leaving dns/access_type/is_default at zero value would silently corrupt
	// half of the merged list's rows.
	enhancedRows := make([]allNetworkRow, 0, len(enhancedNetworks))
	for _, n := range enhancedNetworks {
		enhancedRows = append(enhancedRows, allNetworkRow{
			ID: n.GetId(), Name: n.GetName(), Tags: n.GetTags(), DNS: n.GetDns(),
			Subnet: n.GetSubnet(), AccessType: n.GetAccessType(),
			IsDefault: n.GetIsDefault(), TenantID: n.GetTenantId(),
			CreatedAt: n.GetCreatedAt().String(), UpdatedAt: n.GetUpdatedAt().String(),
		})
	}

	if err := d.Set("networks", flattenAllNetworks(standardRows, enhancedRows)); err != nil {
		d.Partial(true)
		return diag.FromErr(err)
	}

	// A stable ID, not a timestamp: a changing ID makes the data source appear
	// to change on every plan.
	d.SetId("checkpointsase_all_networks")
	return diags
}
