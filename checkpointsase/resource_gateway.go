package checkpointsase

import (
	"context"
	"fmt"
	"strings"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
gatewayResourceTimeout is deliberately NOT asyncResourceTimeout (30 minutes).

MEASURED 2026-09-10 against a live tenant, three creates: a single gateway
completed in ~14 minutes, and two submitted simultaneously took 13.3 and 27.8
minutes. The API accepts concurrent creates -- both answered 202 instantly with
distinct status ids -- but the BACKEND BUILDS THEM ONE AT A TIME. The second
took 2.1x the first: its own build plus the first one's, queued.

So the wall clock for the Nth gateway in flight is roughly N * 14 minutes, and
30 minutes runs out at three. Two nearly missed it, finishing with two minutes
to spare. The old default was not a margin, it was a coin toss.

Two hours covers eight queued gateways. Beyond that the operator raises it:

	resource "checkpointsase_gateway" "example" {
	  timeouts { create = "4h" }
	}

Terraform's own parallelism does not help here and can hurt: ten resources
start ten timeout clocks at once while the server serves one at a time, so the
tenth waits out all nine before it starts. -parallelism=1 makes the wait no
longer and the diagnostics far easier to read.
*/
const gatewayResourceTimeout = 2 * time.Hour

/*
gatewayImportSeparator splits the composite import id `<network_id>-<gateway_id>`.

SplitN with a limit of 2, not Split: an id containing a hyphen would otherwise
yield three parts and be refused for a shape it actually has. Tenant ids
observed so far are alphanumeric, but the provider should not fail on the day
that changes.
*/
const gatewayImportSeparator = "-"

/*
resourceGateway Setup the Gateway resource CRUD operations

ONE RESOURCE PER GATEWAY. It managed a whole region's gateway POOL until
2026-09-10, as a list of `gateways` blocks each carrying a `name`. That shape
caused every problem this resource had, and none of them were fixable inside it:

  - The name was never sent to the server. CreateInstancesInNetworkPayload is
    {regionId, idle} and nothing else, and no read model anywhere carries a
    gateway name -- confirmed on the wire, not just in the spec. It existed
    purely so the provider could tell one list entry from another.
  - Import therefore could not recover it, and wrote a `$<id>$` placeholder,
    so the first plan after an import was never empty (P81-144756).
  - Update matched old against new BY NAME, so an `idle`-only change found
    nothing to add and nothing to delete, wrote the new value into state, and
    never called the API. Terraform reported success; the gateway was
    untouched.
  - A config declaring a different NUMBER of gateways than the region held sent
    Update into add-then-delete against live gateways.

With one resource per gateway the Terraform address (`checkpointsase_gateway.a`)
is the identity, which is what a name was standing in for. All four go away.

THIS IS A BREAKING CHANGE. See the migration note in the resource Description.

@return &schema.Resource
*/
func resourceGateway() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a single gateway in one region of a `checkpointsase_network`.\n\n" +
			"**Breaking change in 3.1.0.** This resource previously managed a region's whole " +
			"gateway pool as a list of `gateways` blocks, each with a `name`. It now manages " +
			"exactly one gateway and has no `name` at all — the API never accepted one and no " +
			"endpoint returns one, so the attribute could only ever describe local state. " +
			"Declare one resource per gateway and use the Terraform address as the identity. " +
			"Existing state must be re-imported: `terraform state rm` the old resource, then " +
			"`terraform import checkpointsase_gateway.<name> <network_id>-<gateway_id>` for each " +
			"gateway.\n\n" +
			"**Every attribute forces replacement.** The API exposes create, read and delete for " +
			"a gateway and no update of any kind, so there is nothing that can be changed in " +
			"place — `idle` included.\n\n" +
			"**Creates are slow and the server serialises them.** One gateway takes about 14 " +
			"minutes; two submitted at once took 13 and 28 minutes, because the backend builds " +
			"them one after another. The default create timeout is 2 hours. For more than about " +
			"eight gateways in a single apply, raise it with a `timeouts` block, and consider " +
			"`-parallelism=1` so the diagnostics stay readable.",
		CreateContext: resourceGatewayCreate,
		ReadContext:   resourceGatewayRead,
		DeleteContext: resourceGatewayDelete,
		// No UpdateContext, and no attribute is updatable. Giving this resource
		// an Update that could only rewrite state -- which is what the previous
		// version effectively did for `idle` -- reports a change the server
		// never made.
		Schema: map[string]*schema.Schema{
			"network_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The ID of the standard network this gateway belongs to.",
			},
			"region_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "The ID of the network region to place the gateway in. This is the " +
					"network-region ID returned by `checkpointsase_network.region.region_id`, not " +
					"the cloud region ID (`cpregion_id`).",
			},
			"idle": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
				ForceNew: true,
				Description: "Whether the gateway is created idle (disabled for user traffic). " +
					"Set at creation only: the API has no endpoint that changes it afterwards, so " +
					"a change here forces replacement. No read model returns it, so Terraform " +
					"keeps the value you configured and an **imported** gateway takes whatever " +
					"the configuration says without verification — the API cannot be asked.",
				// WITHOUT THIS, IMPORT DESTROYS THE GATEWAY IT JUST ADOPTED.
				//
				// Measured 2026-09-10 on a live gateway. No read model carries
				// `idle`, so after an import state holds null while the config
				// holds a value, and this attribute is ForceNew:
				//
				//   + idle = true # forces replacement
				//   Plan: 1 to add, 0 to change, 1 to destroy.
				//
				// That is P81-144756's own complaint -- an import whose first
				// plan proposes to rebuild live infrastructure -- reappearing
				// through a different attribute after `name` was removed. The
				// suppression is what makes the adoption real.
				//
				// It applies ONLY when the prior value is absent AND the
				// resource already has an id, which is the import case and
				// nothing else: `d.Id() != ""` is what keeps Create unaffected,
				// and a genuine false -> true edit has a non-empty old value so
				// it still forces replacement, correctly. Same helper and same
				// reasoning as checkpointsase_group.description, which has the
				// identical shape of a write-only field with no read model.
				DiffSuppressFunc: suppressDiffOnEmptyOldValue,
			},

			// --- computed ------------------------------------------------------
			"dns": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The DNS hostname assigned to the gateway by the server.",
			},
			"ip": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The public IP address assigned to the gateway by the server.",
			},
			"instance_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The server-side instance size backing this gateway, e.g. `s-2vcpu-2gb`.",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the gateway was created (server-assigned).",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the gateway was last updated server-side.",
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceGatewayImportState,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(gatewayResourceTimeout),
			Delete: schema.DefaultTimeout(gatewayResourceTimeout),
		},
	}
}

/*
resourceGatewayCreate Create one gateway

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceGatewayCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	regionId := d.Get("region_id").(string)

	payload := perimeter81Sdk.CreateInstancesInNetworkPayload{
		RegionId: regionId,
		Idle:     d.Get("idle").(bool),
	}

	status, _, err := client.StandardNetworksAPI.
		StandardNetworksControllerV2AddNetworkInstance(ctx, networkId).
		CreateInstancesInNetworkPayload(payload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create gateway", err)
	}

	// THE ID COMES FROM THE ASYNC RESULT, NOT FROM A GUESS.
	//
	// This replaced getGatewayInfo, which re-read the network after the create
	// and picked the most recently created instance in the region. That was
	// wrong three ways: it raced (two concurrent creates could each take the
	// other's gateway), it returned an empty dns and ip whenever the region
	// held a single gateway (the newest-wins comparison is false against
	// itself), and it indexed Instances[0] with no length check.
	//
	// Measured 2026-09-10: result.resource IS populated for this operation, as
	// an absolute URL on the v2.3 host --
	//   https://<host>/api/rest/v2.3/networks/<network>/instances/<gatewayId>
	// -- whose last segment is the gateway id. Same treatment statusUrl gets,
	// and the same getIdFromUrl the application create path already uses.
	statusId := getIdFromUrl(status.GetStatusUrl())
	resource, err := pollStandardNetworkStatusForResource(ctx, client, statusId, standardNetworkPollInterval)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create gateway", err)
	}

	gatewayId := getIdFromUrl(resource)
	if gatewayId == "" {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create gateway",
			fmt.Errorf("the create completed but its async result carried no resource URL, so the "+
				"new gateway's id is unknown. The gateway may exist -- check the region before "+
				"retrying, or this apply will create a second one"))
	}

	d.SetId(gatewayId)
	return resourceGatewayRead(ctx, d, m)
}

/*
resourceGatewayRead Read one gateway by its own id

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceGatewayRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)

	// Addressed by the gateway's own id, so a 404 unambiguously means THIS
	// gateway is gone -- unlike the collection read the previous version used,
	// where a 404 means the URL was wrong. Treating it as drift is therefore
	// safe here, and lets `plan` report a deleted gateway instead of erroring.
	instance, resp, err := client.StandardNetworksAPI.
		StandardGetInstance(ctx, networkId, d.Id()).Execute()
	if isNotFound(resp, err) {
		d.SetId("")
		return diags
	}
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read gateway", err)
	}
	if instance == nil {
		// A 2xx whose body decodes to JSON null leaves the SDK returning a nil
		// pointer with no error. Every field access below would panic -- a
		// provider crash with a stack trace rather than a diagnostic, which is
		// exactly how the previous importer failed (P81-144756).
		d.SetId("")
		return diags
	}

	// `idle` is ABSENT here on purpose: no read model carries it, so there is
	// nothing to refresh it from and Terraform keeps the configured value.
	// There is no `name` either, and that is not an omission -- the API has
	// never had one. See the type comment.
	for key, value := range map[string]interface{}{
		"region_id":     instance.Region,
		"dns":           instance.Dns,
		"ip":            instance.Ip,
		"instance_type": instance.InstanceType,
		"created_at":    instance.CreatedAt.Format(time.RFC3339),
	} {
		if err := d.Set(key, value); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set gateway "+key, err)
		}
	}
	if instance.UpdatedAt != nil {
		if err := d.Set("updated_at", instance.UpdatedAt.Format(time.RFC3339)); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set gateway updated_at", err)
		}
	}

	return diags
}

/*
resourceGatewayDelete Delete one gateway

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceGatewayDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	regionId := d.Get("region_id").(string)
	gatewayId := d.Id()

	// The endpoint is bulk-shaped -- regions, each with a list of instances --
	// even to remove one gateway. One resource means one entry in each list.
	payload := perimeter81Sdk.RemoveRegionInstance{
		Regions: []perimeter81Sdk.RemoveRegionPayload{{
			RegionId:  &regionId,
			Instances: []perimeter81Sdk.RemoveInstancePayload{{Id: &gatewayId}},
		}},
	}

	// DeleteNetworkInstance returns its AsyncOperationResult INLINE -- there is
	// no status URL to poll -- so a non-2xx result.statusCode is the only
	// signal that the delete was rejected.
	result, resp, err := client.StandardNetworksAPI.
		StandardNetworksControllerV2DeleteNetworkInstance(ctx, networkId).
		RemoveRegionInstance(payload).Execute()
	if isNotFound(resp, err) {
		// Somebody already deleted it; destroy has nothing left to do, and
		// reporting a failure would strand the resource in state forever.
		d.SetId("")
		return diags
	}
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete gateway", err)
	}
	if result != nil && !isSuccessStatus(int(result.GetStatusCode())) {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete gateway",
			&asyncFailedError{StatusCode: int(result.GetStatusCode()), Reasons: result.GetReason()})
	}

	d.SetId("")
	return diags
}

/*
resourceGatewayImportState Import one gateway by `<network_id>-<gateway_id>`.

	terraform import checkpointsase_gateway.example <network_id>-<gateway_id>

THE SECOND HALF IS THE GATEWAY ID, NOT THE REGION ID. The previous version took
a region and adopted every gateway in it; a stale comment in the old Read said
gateway while the code said region, and the two disagreeing is how an operator
ends up passing the wrong one.

`region_id` is not parsed from the import id because Read returns it -- the
instance body carries its own region. One less thing for the caller to get
right.

`idle` cannot be recovered: no read model carries it. It defaults to false on
import, so a gateway created idle shows a diff on the first plan and needs
either the attribute set to match or a `terraform state` edit. That is a real
gap and it is stated in the attribute description rather than papered over.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceGatewayImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	parts := strings.SplitN(d.Id(), gatewayImportSeparator, 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf(
			"a gateway import id is %q, and this one is %q: "+
				"terraform import checkpointsase_gateway.<name> <network_id>%s<gateway_id>",
			"<network_id>"+gatewayImportSeparator+"<gateway_id>", d.Id(), gatewayImportSeparator)
	}
	if err := d.Set("network_id", parts[0]); err != nil {
		return nil, fmt.Errorf("could not set network_id after import: %w", err)
	}
	d.SetId(parts[1])

	diagnostics := resourceGatewayRead(ctx, d, m)
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == diag.Error {
			return nil, fmt.Errorf("could not import gateway: %s\n%s",
				diagnostic.Summary, diagnostic.Detail)
		}
	}
	// Read clears the id when the gateway is absent and returns no diagnostics
	// (see its 404 branch). Without this an import of a gateway that does not
	// exist would report success and write an empty resource into state.
	if d.Id() == "" {
		return nil, fmt.Errorf(
			"no gateway %q exists in network %q", parts[1], parts[0])
	}
	return []*schema.ResourceData{d}, nil
}
