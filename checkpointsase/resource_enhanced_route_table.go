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
enhancedRouteTableCannotCreateRoutes is what a user sees, at plan time, instead
of a 422 half-way through an apply.

It is deliberately the whole explanation rather than "invalid value": the
config the user wrote is not merely mistyped, it is asking for an object the
API never lets anyone create, and the thing they actually want is one
attribute away on a different resource. A message that only rejected the value
would leave them looking for a spelling mistake.

It covers both tunnel types because both behave the same way. An earlier
version of this message said dynamic "is not affected and still works"; that
was an untested assumption and it was wrong.
*/
const enhancedRouteTableCannotCreateRoutes = `checkpointsase_enhanced_route_table cannot create routes, for either
type = "static" or type = "dynamic".

A route is not a separate object — it belongs to its tunnel. Harmony SASE
creates the route at the moment the tunnel is created, and that route's subnets
ARE the tunnel's own remote_gateway_subnets: one value shown in two places, so
changing either one changes both. That leaves nothing here for Terraform to
create. Every tunnel already has its route, and asking for a second one fails
the apply with "routes position 1 contains a duplicate value".

To choose which subnets a tunnel routes, set them on the tunnel — whichever
kind of tunnel you have:

    resource "checkpointsase_enhanced_static_tunnel" "example" {
      # ...
      remote_gateway_subnets = ["10.50.0.0/16"]
    }

    resource "checkpointsase_enhanced_dynamic_tunnel" "example" {
      # ...
      remote_gateway_subnets = ["10.50.0.0/16"]
    }

To read the resulting routes back, use the data source of the same name, which
lists every route on the network:

    data "checkpointsase_enhanced_route_table" "example" {
      network_id = checkpointsase_enhanced_network.example.id
    }

Then remove this resource from your configuration.

One exception. If Terraform is already tracking a route entry -- only possible
if you imported one, since creating one has never worked -- run
"terraform state rm" on it instead of deleting the resource. Deleting it makes
Terraform remove the entry server-side, which takes away the tunnel's only
route and stops traffic flowing through it.`

/*
resourceEnhancedRouteTable Setup the Enhanced Route Table Resource CRUD operations

@return &schema.Resource
*/
func resourceEnhancedRouteTable() *schema.Resource {
	return &schema.Resource{
		Description: "**This resource cannot create routes and every configuration " +
			"using it is rejected during `terraform plan`**, for `type = \"static\"` " +
			"and `type = \"dynamic\"` alike. " +
			"A route is not a separate object: it belongs to its tunnel, Harmony SASE " +
			"creates it together with the tunnel, and its subnets are that tunnel's own " +
			"`remote_gateway_subnets` — one value shown in two places. " +
			"To choose which subnets a tunnel routes, set `remote_gateway_subnets` on " +
			"`checkpointsase_enhanced_static_tunnel` or " +
			"`checkpointsase_enhanced_dynamic_tunnel`; to read the resulting routes, " +
			"use the `checkpointsase_enhanced_route_table` **data source**, which is " +
			"unaffected. Then remove this resource from your configuration — but if " +
			"Terraform is already tracking an entry (only possible via `terraform " +
			"import`, since creating one has never worked), use `terraform state rm` " +
			"instead: deleting the resource removes the entry server-side, which takes " +
			"away the tunnel's only route. " +
			"It is kept in the provider so that existing configurations and state " +
			"still parse and can be removed cleanly.",
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
				Description: "The route type, `static` or `dynamic`. **Neither is usable** — both " +
					"are rejected at plan time with an explanation. A tunnel's route is its own " +
					"`remote_gateway_subnets`, on `checkpointsase_enhanced_static_tunnel` or " +
					"`checkpointsase_enhanced_dynamic_tunnel`, not a separate object.",
				// Both values stay in the allowed list on purpose. Emptying it
				// would reduce the plan-time failure to "expected type to be one
				// of [], got dynamic", which tells the user nothing about where
				// the route actually lives. CustomizeDiff produces the real
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
					"is created, carrying that tunnel's `remote_gateway_subnets`; set the subnets on " +
					"`checkpointsase_enhanced_static_tunnel` instead. Kept in the schema so existing " +
					"configurations and state still parse and can be removed cleanly.",
			},
			"tunnel_ids": {
				Type:          schema.TypeList,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"tunnel_id"},
				Description: "The list of dynamic tunnel IDs. **Not usable** — it pairs with " +
					"`type = \"dynamic\"`, which is rejected at plan time. Measured 2026-08-17: a " +
					"dynamic tunnel is given a route automatically at creation exactly as a static " +
					"tunnel is, carrying that tunnel's `remote_gateway_subnets`, and a second route " +
					"for it is refused with the same `422 \"routes\" position 1 contains a duplicate " +
					"value`; set the subnets on `checkpointsase_enhanced_dynamic_tunnel` instead. " +
					"Kept in the schema so existing configurations and state still parse and can be " +
					"removed cleanly.",
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
resourceEnhancedRouteTableCustomizeDiff refuses every configuration of this
resource before any API call is made. It does not branch on `type`, because
neither type can work.

Measured live 2026-08-17, not inferred, on a static tunnel and then on a dynamic
one. A tunnel's remote_gateway_subnets and its route-table entry's subnets are
the same server value reachable through two endpoints; on the static tunnel,
writing through either one moved both:

	baseline            tunnel = 172.31.250.0/24   route = 172.31.250.0/24
	write via ROUTE     tunnel = 172.31.240.0/24   route = 172.31.240.0/24
	write via TUNNEL    tunnel = 172.31.230.0/24   route = 172.31.230.0/24

On the dynamic tunnel the route -> tunnel direction was reproduced identically;
the tunnel -> route direction was not measured, and nothing here depends on it.

What was measured for both, and is what actually closes this resource: creating
a tunnel immediately produces the route entry carrying that tunnel's
remoteGatewaySubnets — there is no window in which the tunnel has no route —
and POST .../route-table/{static,dynamic} for a tunnel that already has an entry
then fails 422 "routes position 1 contains a duplicate value" even for a
different subnet, because the duplicate key is the tunnel and not the subnet.
On the static path, deleting the entry first makes the same POST succeed.

The server source says why (perimeter81-public-api @ 03007981):
createStaticRoute / createDynamicRoute read the whole route table, append the
new entry and send the entire table back, and convertRouteTableToUpdatedRouteTable
flattens that table to one element per tunnel keyed `id: tunnel.id`. A tunnel
that already has an entry therefore yields two elements with the same key, and
the uniqueness check rejects it.

remote_gateway_subnets is Required on both checkpointsase_enhanced_static_tunnel
and checkpointsase_enhanced_dynamic_tunnel, so every tunnel Terraform can build
has a route already and Create could never succeed for either. Adoption is not a
way out either: two Terraform resources writing one value means each plan
reports drift from the other's last apply, forever.

The earlier version of this function blocked only `static`, on the stated
assumption that the dynamic path still worked. That assumption was untested and
turned out to be false; the dynamic measurement above is what closed it.

Two things this does not catch, both stated rather than papered over:
  - A `type` whose value is not known until apply (computed from another
    resource) reads as "" here. The refusal is unconditional, so the block still
    fires; resourceEnhancedRouteTableCreate carries the same message for any
    path that reaches it anyway.
  - Destroy plans never reach CustomizeDiff in SDKv2, which is what we want:
    someone holding an entry in state can still remove it.
*/
func resourceEnhancedRouteTableCustomizeDiff(_ context.Context, _ *schema.ResourceDiff, _ interface{}) error {
	return errors.New(enhancedRouteTableCannotCreateRoutes)
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
resourceEnhancedRouteTableCreate refuses to create an Enhanced Route Table
entry, for either route type.

Normally unreachable: resourceEnhancedRouteTableCustomizeDiff rejects the
configuration during plan. It survives as the backstop for anything that
reaches apply anyway, so that user gets the same explanation instead of a raw
422 part-way through. The CreateStaticRoute and CreateDynamicRoute calls this
used to make are gone rather than kept behind a guard, because both endpoints
refuse every tunnel the provider is able to build; see the CustomizeDiff
comment, and git history for the payloads if the API ever changes.

  - @param ctx context.Context - unused; the function makes no API call.
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedRouteTableCreate(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	return appendErrorDiags(diags, "Unsupported resource", errors.New(enhancedRouteTableCannotCreateRoutes))
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
