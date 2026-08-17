package checkpointsase

import (
	"context"
	"errors"
	"fmt"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
enhancedRouteTableStaticNotSupported is what a user sees, at plan time, instead
of a 422 half-way through an apply.

It is deliberately the whole explanation rather than "invalid value": the
config the user wrote is not merely mistyped, it is asking for an object the
API never lets anyone create, and the thing they actually want is one
attribute away on a different resource. A message that only rejected the value
would leave them looking for a spelling mistake.
*/
const enhancedRouteTableStaticNotSupported = `checkpointsase_enhanced_route_table does not support type = "static".

A static tunnel's route is part of the tunnel, not a separate object. Harmony
SASE creates the route at the moment the tunnel is created, and that route's
subnets ARE the tunnel's own remote_gateway_subnets — one value shown in two
places, so changing either one changes both. That leaves nothing here for
Terraform to create: the tunnel already has its route, and asking for a second
one fails the apply with "routes position 1 contains a duplicate value".

To choose which subnets a static tunnel routes, set them on the tunnel:

    resource "checkpointsase_enhanced_static_tunnel" "example" {
      # ...
      remote_gateway_subnets = ["10.50.0.0/16"]
    }

To read the resulting route back, use the matching data source, which lists
every route on the network:

    data "checkpointsase_enhanced_route_table" "example" {
      network_id = checkpointsase_enhanced_network.example.id
    }

Then remove this resource from your configuration. type = "dynamic" with
tunnel_ids is not affected and still works.`

/*
resourceEnhancedRouteTable Setup the Enhanced Route Table Resource CRUD operations

@return &schema.Resource
*/
func resourceEnhancedRouteTable() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a route-table entry for a `checkpointsase_enhanced_network`. " +
			"A route directs traffic for the specified `subnets` through a list of " +
			"dynamic tunnels. " +
			"Only `type = \"dynamic\"` with `tunnel_ids` is supported. " +
			"**`type = \"static\"` is rejected during `terraform plan`**: a static " +
			"tunnel's route is created together with the tunnel and its subnets are " +
			"the tunnel's own `remote_gateway_subnets`, so set them on " +
			"`checkpointsase_enhanced_static_tunnel` and read the resulting route " +
			"with the `checkpointsase_enhanced_route_table` data source. " +
			"**`network_id`, `type`, and `tunnel_ids` are immutable** — " +
			"changing any of them forces resource replacement.",
		CreateContext: resourceEnhancedRouteTableCreate,
		ReadContext:   resourceEnhancedRouteTableRead,
		UpdateContext: resourceEnhancedRouteTableUpdate,
		DeleteContext: resourceEnhancedRouteTableDelete,
		CustomizeDiff: resourceEnhancedRouteTableCustomizeDiff,
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
				Description: "The ID of the enhanced network this route table entry belongs to.",
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "The route type. Only `dynamic` is supported, paired with `tunnel_ids`. " +
					"`static` is still accepted by the schema but rejected at plan time with an " +
					"explanation: a static tunnel's route is its own `remote_gateway_subnets` on " +
					"`checkpointsase_enhanced_static_tunnel`, not a separate object.",
				// `static` stays in the allowed list on purpose. Removing it here
				// would reduce the plan-time failure to "expected type to be one
				// of [dynamic], got static", which tells the user nothing about
				// where the route actually lives. CustomizeDiff produces the real
				// message; this ValidateFunc still catches genuine typos.
				ValidateFunc: validation.StringInSlice([]string{"static", "dynamic"}, false),
			},
			"tunnel_id": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"tunnel_ids"},
				Description: "The static tunnel ID. **Not usable** — it pairs with `type = \"static\"`, " +
					"which is rejected at plan time. A static tunnel already has a route the moment it " +
					"is created, carrying that tunnel's `remote_gateway_subnets`; set the subnets there " +
					"instead. Kept in the schema so existing configurations and state still parse and " +
					"can be removed cleanly.",
			},
			"tunnel_ids": {
				Type:          schema.TypeList,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"tunnel_id"},
				Description: "The list of dynamic tunnel IDs. Required when type is `dynamic`. " +
					"Mutually exclusive with `tunnel_id`. Whether a dynamic tunnel is also given a " +
					"route automatically at creation, the way a static tunnel is, has not been " +
					"measured; if it is, creating this resource for such a tunnel will fail the same " +
					"way the static path does.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"subnets": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "List of subnet CIDR blocks for the route table entry.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"propagated": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the route is propagated automatically.",
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceEnhancedRouteTableImportState,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(asyncResourceTimeout),
			Update: schema.DefaultTimeout(asyncResourceTimeout),
			Delete: schema.DefaultTimeout(asyncResourceTimeout),
		},
	}
}

/*
resourceEnhancedRouteTableCustomizeDiff refuses `type = "static"` before any
API call is made.

Measured live 2026-08-17, not inferred. A static tunnel's remote_gateway_subnets
and its route-table entry's subnets are the same server value reachable through
two endpoints; writing through either one moves both:

	baseline            tunnel = 172.31.250.0/24   route = 172.31.250.0/24
	write via ROUTE     tunnel = 172.31.240.0/24   route = 172.31.240.0/24
	write via TUNNEL    tunnel = 172.31.230.0/24   route = 172.31.230.0/24

Creating a static tunnel immediately produces the route entry carrying that
tunnel's remoteGatewaySubnets — there is no window in which the tunnel has no
route. POST .../route-table/static for a tunnel that already has an entry then
fails 422 "routes position 1 contains a duplicate value" even for a different
subnet, because the duplicate key is the tunnel and not the subnet; deleting the
entry first makes the same POST succeed. And remote_gateway_subnets is Required
on checkpointsase_enhanced_static_tunnel, so every static tunnel Terraform can
build has one. Create could therefore never succeed. Adoption is not a way out
either: two Terraform resources writing one value means each plan reports drift
from the other's last apply, forever.

OPEN QUESTION, deliberately not acted on: dynamic tunnels also carry
remote_gateway_subnets in their shared settings, so the same coupling is
plausible for them. It has NOT been measured. `dynamic` is left working rather
than blocked on an inference.

Two things this does not catch, both stated rather than papered over:
  - A `type` whose value is not known until apply (computed from another
    resource) reads as "" here, so the block does not fire and the user meets
    the failure at apply instead. resourceEnhancedRouteTableCreate raises the
    same message there.
  - Destroy plans never reach CustomizeDiff in SDKv2, which is what we want:
    someone holding a static entry in state can still remove it.
*/
func resourceEnhancedRouteTableCustomizeDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	if d.Get("type").(string) != "static" {
		return nil
	}
	return errors.New(enhancedRouteTableStaticNotSupported)
}

/*
resourceEnhancedRouteTableImportState Import an enhanced route table entry by its ID.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceEnhancedRouteTableImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	diagnostics := resourceEnhancedRouteTableRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import enhanced route table: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}

/*
resourceEnhancedRouteTableCreate Create an Enhanced Route Table entry.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedRouteTableCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	routeType := d.Get("type").(string)
	subnets := flattenStringsArrayData(d.Get("subnets").([]interface{}))

	var status *perimeter81Sdk.AsyncOperationResponse
	var err error

	switch routeType {
	case "static":
		// Normally unreachable: resourceEnhancedRouteTableCustomizeDiff rejects
		// this during plan. It survives for the one case that slips past — a
		// `type` not known until apply — so that user gets the same explanation
		// instead of the raw 422. The CreateStaticRoute call it used to make is
		// gone rather than kept behind a guard, because the endpoint refuses it
		// for every tunnel the provider is able to build; see the CustomizeDiff
		// comment, and git history for the payload if the API ever changes.
		return appendErrorDiags(diags, "Unsupported route type", errors.New(enhancedRouteTableStaticNotSupported))
	case "dynamic":
		tunnelIds := flattenStringsArrayData(d.Get("tunnel_ids").([]interface{}))
		if len(tunnelIds) == 0 {
			return appendErrorDiags(diags, "tunnel_ids is required for dynamic route type", fmt.Errorf("tunnel_ids must be non-empty when type is 'dynamic'"))
		}
		payload := perimeter81Sdk.EnhancedRouteTableDynamicCreate{
			TunnelIds: tunnelIds,
			Subnets:   subnets,
		}
		status, _, err = client.EnhancedRouteTablesAPI.CreateDynamicRoute(ctx, networkId).EnhancedRouteTableDynamicCreate(payload).Execute()
	default:
		return appendErrorDiags(diags, "Invalid route type", fmt.Errorf("type must be 'static' or 'dynamic', got: %s", routeType))
	}

	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Enhanced Route Table entry", err)
	}

	statusId := getIdFromUrl(status.GetStatusUrl())
	resource, err := pollStandardNetworkStatusForResource(ctx, client, statusId, standardNetworkPollInterval)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Enhanced Route Table entry", err)
	}
	routeId := getIdFromUrl(resource)

	d.SetId(routeId)
	return resourceEnhancedRouteTableRead(ctx, d, m)
}

/*
resourceEnhancedRouteTableRead Read an Enhanced Route Table entry.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedRouteTableRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	routeId := d.Id()

	routeData, _, err := client.EnhancedRouteTablesAPI.GetRouteEntry(ctx, networkId, routeId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to find Enhanced Route Table entry", err)
	}

	if err := d.Set("subnets", routeData.Subnets); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Route Table subnets", err)
	}
	if err := d.Set("tunnel_ids", routeData.TunnelIds); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Route Table tunnel_ids", err)
	}
	if err := d.Set("propagated", routeData.Propagated); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Route Table propagated", err)
	}

	return diags
}

/*
resourceEnhancedRouteTableUpdate Update an Enhanced Route Table entry.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedRouteTableUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	if d.HasChange("subnets") {
		networkId := d.Get("network_id").(string)
		routeId := d.Id()
		subnets := flattenStringsArrayData(d.Get("subnets").([]interface{}))

		payload := perimeter81Sdk.RouteTableUpdate{
			Subnets: subnets,
		}

		status, _, err := client.EnhancedRouteTablesAPI.UpdateRouteEntry(ctx, networkId, routeId).RouteTableUpdate(payload).Execute()
		if err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to update Enhanced Route Table entry", err)
		}
		// UpdateRouteEntry returns an AsyncOperationResponse, so the change is
		// not applied when the call returns. Dropping it let the Read below
		// observe pre-update values and write them back into state, making a
		// successful update look like a no-op.
		//
		// The identical defect was confirmed live on the static tunnel
		// (2026-08-17): its PUT returned 202 and the acceptance test then read
		// the old tunnel_name. UpdateEnhancedNetwork, by contrast, returns
		// *EnhancedNetwork and is genuinely synchronous — checked, not assumed.
		//
		// NOT verified live here: this resource's acceptance test cannot run
		// yet, because the API auto-creates one route per tunnel and rejects a
		// second, so Create fails before Update is ever reached.
		if statusId := getIdFromUrl(status.GetStatusUrl()); statusId != "" {
			if err := pollStandardNetworkStatus(ctx, client, statusId, standardNetworkPollInterval); err != nil {
				d.Partial(true)
				return appendErrorDiags(diags, "Unable to update Enhanced Route Table entry", err)
			}
		}
		d.Set("last_updated", time.Now().Format(time.RFC850))
	}

	return resourceEnhancedRouteTableRead(ctx, d, m)
}

/*
resourceEnhancedRouteTableDelete Delete an Enhanced Route Table entry.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedRouteTableDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	routeId := d.Id()

	status, _, err := client.EnhancedRouteTablesAPI.DeleteRouteEntry(ctx, networkId, routeId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete Enhanced Route Table entry", err)
	}

	statusId := getIdFromUrl(status.GetStatusUrl())
	if err := pollStandardNetworkStatus(ctx, client, statusId, standardNetworkPollInterval); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete Enhanced Route Table entry", err)
	}

	d.SetId("")
	return diags
}
