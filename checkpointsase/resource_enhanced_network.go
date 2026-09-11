package checkpointsase

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
resourceEnhancedNetwork Setup the Enhanced Network Resource CRUD operations

@return &schema.Resource
*/
func resourceEnhancedNetwork() *schema.Resource {
	return &schema.Resource{
		Description: "Manages an enhanced (SD-WAN-capable) network in Check Point SASE. " +
			"Enhanced networks support multi-region deployment and IPsec tunnels (static and " +
			"BGP-routed dynamic) — see `checkpointsase_enhanced_region`, " +
			"`checkpointsase_enhanced_static_tunnel` and " +
			"`checkpointsase_enhanced_dynamic_tunnel`. Each tunnel carries its own route, " +
			"set through that tunnel's `remote_gateway_subnets` and readable through the " +
			"`checkpointsase_enhanced_route_table` **data source**. " +
			"**`subnet` is immutable** — changing it forces resource replacement. " +
			"**Import adopts every region currently on the network into this resource's `region` list**, " +
			"including any you intend to manage separately via `checkpointsase_enhanced_region` — there is no " +
			"API-side signal distinguishing the two, since ownership is a config-only concept. Prune `region` " +
			"blocks down to the ones this resource should own before your first `plan`/`apply`; shrinking it is " +
			"a state-only convergence, not a real deletion, since updates never call a region create/delete endpoint.",
		CreateContext: resourceEnhancedNetworkCreate,
		ReadContext:   resourceEnhancedNetworkRead,
		UpdateContext: resourceEnhancedNetworkUpdate,
		DeleteContext: resourceEnhancedNetworkDelete,
		Schema: map[string]*schema.Schema{
			"last_updated": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Timestamp of the last update to this resource.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the enhanced network.",
			},
			"subnet": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "The subnet CIDR block for the enhanced network. Cannot be changed after creation. " +
					"Allowed private ranges (server-enforced): `10.0.0.0/12-22`, `172.16.0.0/12-22`, " +
					"`192.168.0.0/16-22`, `198.18.0.0/15-22`. The plan-time validator checks CIDR format only — " +
					"out-of-range prefixes are rejected at apply time by the server.",
				ValidateFunc: validation.IsCIDR,
			},
			"tags": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A list of tags to associate with the enhanced network.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"region": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "The list of regions to deploy the enhanced network in.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"harmony_sase_region_id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The Check Point SASE region ID. Retrieve available IDs from the enhanced_regions data source.",
						},
						"scale_units": {
							Type:        schema.TypeInt,
							Optional:    true,
							Default:     1,
							Description: "The number of scale units for the region. Higher values provide greater throughput and connection capacity. Defaults to 1.",
						},
						"idle": {
							Type:        schema.TypeBool,
							Optional:    true,
							Default:     true,
							Description: "Whether the region gateway is disabled for users. Defaults to true.",
						},
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The unique ID of the created region.",
						},
					},
				},
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceEnhancedNetworkImportState,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(asyncResourceTimeout),
			Update: schema.DefaultTimeout(asyncResourceTimeout),
			Delete: schema.DefaultTimeout(asyncResourceTimeout),
		},
	}
}

/*
resourceEnhancedNetworkImportState Import an enhanced network by its ID.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceEnhancedNetworkImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	diagnostics := resourceEnhancedNetworkRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import enhanced network: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}

	// Read caps how many regions it writes to state at len(existing state),
	// to avoid showing drift for regions added out-of-band via
	// checkpointsase_enhanced_region (see the comment in Read). On import
	// state starts empty, so that cap leaves `region` empty entirely.
	// Rebuild the full list here instead, restricted to the import path so
	// normal plans don't pay the extra round trips.
	//
	// This adopts EVERY region currently on the network inline, including
	// any meant to be managed by a separate checkpointsase_enhanced_region
	// resource -- there is no API-side signal that distinguishes the two,
	// ownership is a config-only concept, and StateContextFunc has no
	// access to the user's .tf to know their intent. If some of the
	// adopted regions are meant to live in their own
	// checkpointsase_enhanced_region resource instead, prune this
	// resource's `region` config down to the ones it should own before
	// the first plan/apply -- Update never calls a region create/delete
	// endpoint (see resourceEnhancedNetworkUpdate), so shrinking the
	// config is a state-only, non-destructive convergence, not a real
	// deletion.
	client := m.(*perimeter81Sdk.APIClient)
	networkId := d.Id()
	apiRegions, _, err := client.EnhancedRegionsAPI.ListEnhancedRegions(ctx, networkId).Execute()
	if err != nil {
		return nil, fmt.Errorf("could not import enhanced network: failed to list regions: %w", err)
	}
	harmonyRegions, _, err := client.EnhancedRegionsAPI.EnhancedNetworksControllerV2GetRegions(ctx).Execute()
	if err != nil {
		return nil, fmt.Errorf("could not import enhanced network: failed to list harmony regions for name lookup: %w", err)
	}
	nameToHarmonyId := make(map[string]string, len(harmonyRegions))
	for _, hr := range harmonyRegions {
		nameToHarmonyId[hr.Name] = hr.Id
	}

	regions := make([]interface{}, 0, len(apiRegions))
	for _, r := range apiRegions {
		harmonyId, ok := nameToHarmonyId[r.Name]
		if !ok {
			return nil, fmt.Errorf("could not import enhanced network: no Harmony SASE region found matching region name %q (network region id %s)", r.Name, r.Id)
		}
		entry := map[string]interface{}{
			"id":                     r.Id,
			"scale_units":            int(r.ScaleUnits),
			// Fall back to the schema default (true), not false: a config
			// that omits `idle` relies on that default, and
			// resourceEnhancedNetworkUpdate never reconciles an existing
			// region's idle state, so writing the wrong fallback here
			// would plan a permanent true -> false diff against any config
			// that never mentions idle at all.
			"idle":                   true,
			"harmony_sase_region_id": harmonyId,
		}
		if r.Attributes.RunningMode != nil {
			entry["idle"] = r.Attributes.RunningMode.Idle
		}
		regions = append(regions, entry)
	}
	if err := d.Set("region", regions); err != nil {
		return nil, fmt.Errorf("could not import enhanced network: failed to set region: %w", err)
	}

	// ResourceImporter has no diag.Diagnostics slot (only ([]*ResourceData,
	// error)), so a real warning diagnostic isn't possible here -- this is
	// the closest available substitute, visible with TF_LOG=WARN or above.
	if len(apiRegions) > 0 {
		names := make([]string, len(apiRegions))
		for i, r := range apiRegions {
			names[i] = fmt.Sprintf("%s (id %s)", r.Name, r.Id)
		}
		log.Printf("[WARN] checkpointsase_enhanced_network %s: import adopted all %d region(s) inline: %s. "+
			"If any of these should be managed by their own checkpointsase_enhanced_region resource instead, "+
			"remove them from this resource's `region` config before the first apply.",
			networkId, len(apiRegions), strings.Join(names, ", "))
	}

	return []*schema.ResourceData{d}, nil
}

/*
resourceEnhancedNetworkCreate Create an Enhanced Network.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedNetworkCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	name := d.Get("name").(string)
	subnet := d.Get("subnet").(string)
	tags := flattenStringsArrayData(d.Get("tags").([]interface{}))

	regionItems := d.Get("region").([]interface{})
	regionPayloads := make([]perimeter81Sdk.EnhancedRegionCreate, len(regionItems))
	for i, regionItem := range regionItems {
		regionMap := regionItem.(map[string]interface{})
		harmonySaseRegionId := regionMap["harmony_sase_region_id"].(string)
		scaleUnits := int32(regionMap["scale_units"].(int))
		idle := regionMap["idle"].(bool)
		regionPayloads[i] = perimeter81Sdk.EnhancedRegionCreate{
			HarmonySaseRegionId: harmonySaseRegionId,
			ScaleUnits:          &scaleUnits,
			Idle:                &idle,
		}
	}

	networkPayload := perimeter81Sdk.DeployEnhancedNetworkNetwork{
		Name:   name,
		Subnet: &subnet,
		Tags:   tags,
	}
	deployPayload := perimeter81Sdk.DeployEnhancedNetwork{
		Network: networkPayload,
		Regions: regionPayloads,
	}

	status, _, err := client.EnhancedNetworksAPI.CreateEnhancedNetwork(ctx).DeployEnhancedNetwork(deployPayload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Enhanced Network", err)
	}

	statusId := getIdFromUrl(status.GetStatusUrl())
	resource, err := pollStandardNetworkStatusForResource(ctx, client, statusId, standardNetworkPollInterval)
	if err != nil {
		if isAsyncConflict(err) {
			// A 409 means the name-match loop below is guaranteed to find the
			// very network that caused the conflict. Adopting it would point
			// Terraform state at a network this apply never created, and a
			// later destroy would delete someone else's network. Fail the
			// apply instead of adopting.
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to create Enhanced Network", err)
		}
		networks, _, listErr := client.EnhancedNetworksAPI.GetEnhancedNetworks(ctx).Execute()
		if listErr != nil {
			d.Partial(true)
			diags = appendErrorDiags(diags, "Unable to create Enhanced Network", err)
			return appendErrorDiags(diags, "Unable to create Enhanced Network", listErr)
		}
		for _, networkData := range networks {
			if networkData.Name == name {
				// The poll failed but the network was adopted into state, so the
				// apply succeeded overall: don't also surface the poll error as an
				// Error diagnostic, or Terraform would exit 1 despite a good state.
				d.SetId(networkData.Id)
				diags = appendWarningDiags(diags, "Adopted existing Enhanced Network after failed create",
					fmt.Sprintf("The create request's async poll failed, but an existing enhanced network named %q (id %s) was found and adopted into Terraform state. Confirm this is the network you intended to manage.", name, networkData.Id))
				diags = append(diags, resourceEnhancedNetworkRead(ctx, d, m)...)
				return diags
			}
		}
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Enhanced Network", err)
	}
	networkId := getIdFromUrl(resource)

	d.SetId(networkId)
	return resourceEnhancedNetworkRead(ctx, d, m)
}

/*
resourceEnhancedNetworkRead Read an Enhanced Network.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedNetworkRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Id()
	networkData, _, err := client.EnhancedNetworksAPI.GetEnhancedNetwork(ctx, networkId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to find Enhanced Network", err)
	}

	if err := d.Set("name", networkData.Name); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Network name", err)
	}
	if err := d.Set("subnet", networkData.Subnet); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Network subnet", err)
	}
	if err := d.Set("tags", networkData.Tags); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Network tags", err)
	}

	// GetEnhancedNetwork deliberately excludes regions on the public-api side
	// (EnhancedNetworkDto has `@Exclude() regions`); regions live behind a
	// separate endpoint exposed by ListEnhancedRegions. Without this call the
	// `region` block stays at zero values forever — in particular
	// `region[].id` (Computed) is never set, which breaks downstream
	// resources that reference it.
	//
	// ListEnhancedRegions does not return `harmony_sase_region_id`, so we
	// preserve the user-supplied value from existing state positionally —
	// reliable for single-region, acceptable for multi-region in practice
	// (API ordering tends to be stable).
	regions, _, err := client.EnhancedRegionsAPI.ListEnhancedRegions(ctx, networkId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to fetch enhanced network regions", err)
	}
	existingRegions, _ := d.Get("region").([]interface{})
	// Only populate as many regions as the existing state tracks. Additional
	// regions on the API side (added out-of-band via the
	// `checkpointsase_enhanced_region` resource) are managed by their own
	// resources and must NOT appear in enhanced_network state — otherwise
	// the user sees perpetual drift on enhanced_network for regions they
	// didn't declare here. Capping at min(api,state) also handles the
	// reverse case (a region was deleted externally) without panicking.
	cap := len(regions)
	if len(existingRegions) < cap {
		cap = len(existingRegions)
	}
	newRegions := make([]interface{}, 0, cap)
	for i := 0; i < cap; i++ {
		apiRegion := regions[i]
		entry := map[string]interface{}{
			"id":          apiRegion.Id,
			"scale_units": int(apiRegion.ScaleUnits),
			"idle":        false,
		}
		if apiRegion.Attributes.RunningMode != nil {
			entry["idle"] = apiRegion.Attributes.RunningMode.Idle
		}
		if existing, ok := existingRegions[i].(map[string]interface{}); ok {
			entry["harmony_sase_region_id"] = existing["harmony_sase_region_id"]
		}
		newRegions = append(newRegions, entry)
	}
	if err := d.Set("region", newRegions); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set enhanced network region", err)
	}

	return diags
}

/*
resourceEnhancedNetworkUpdate Update an Enhanced Network.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedNetworkUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	if d.HasChanges("name", "tags") {
		networkId := d.Id()
		name := d.Get("name").(string)
		tags := flattenStringsArrayData(d.Get("tags").([]interface{}))

		updateNetwork := perimeter81Sdk.EnhancedNetworkUpdateNetwork{
			Name: &name,
			Tags: tags,
		}
		updatePayload := perimeter81Sdk.EnhancedNetworkUpdate{
			Network: &updateNetwork,
		}
		_, _, err := client.EnhancedNetworksAPI.UpdateEnhancedNetwork(ctx, networkId).EnhancedNetworkUpdate(updatePayload).Execute()
		if err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to update Enhanced Network", err)
		}
		d.Set("last_updated", time.Now().Format(time.RFC850))
	}

	return resourceEnhancedNetworkRead(ctx, d, m)
}

/*
resourceEnhancedNetworkDelete Delete an Enhanced Network.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedNetworkDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Id()
	status, _, err := client.EnhancedNetworksAPI.DeleteEnhancedNetwork(ctx, networkId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete Enhanced Network", err)
	}

	statusId := getIdFromUrl(status.GetStatusUrl())
	if err := pollStandardNetworkStatus(ctx, client, statusId, standardNetworkPollInterval); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete Enhanced Network", err)
	}

	d.SetId("")
	return diags
}
