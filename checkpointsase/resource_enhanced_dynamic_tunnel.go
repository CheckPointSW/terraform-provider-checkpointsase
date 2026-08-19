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
			"The tunnel's route is part of the tunnel: Harmony SASE creates it with the " +
			"tunnel, and its subnets are this resource's own `remote_gateway_subnets`, so " +
			"set the routed subnets there. The `checkpointsase_enhanced_route_table` " +
			"**resource** is rejected during `terraform plan` and cannot attach a route " +
			"here; read the resulting route with the " +
			"`checkpointsase_enhanced_route_table` **data source**. " +
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
				Type:     schema.TypeString,
				Required: true,
				Description: "The name of the dynamic IPSec tunnel. Must be 15 characters or fewer. " +
					"The server derives each endpoint's interface name by appending `01` to this value " +
					"(`interfaceName: ${tunnelName}0${i+1}`) and reports that decorated form on read. Terraform records " +
					"the name **you** configured, not the decorated one, so a plan straight after an apply is empty and " +
					"a name you deliberately end with `01` is sent and kept exactly as written.",
				// No DiffSuppressFunc. Reconciliation happens in Read
				// (setEnhancedDynamicTunnelNameState) instead — see the comment
				// above dynamicTunnelNameForState for why suppressing the diff
				// here was actively harmful.
				ValidateFunc: validation.StringLenBetween(0, 15),
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional description for the dynamic tunnel.",
			},
			"left_asn": {
				Type:     schema.TypeInt,
				Required: true,
				Description: "The local (Check Point SASE) BGP autonomous-system number for this dynamic tunnel. Required by the API; valid ranges per IsValidASN. " +
					"**Effectively set-once:** the v3 update request body has no field for it (`leftASN` exists only on the create shape), so changing this value cannot be " +
					"applied in place. The provider raises a warning and leaves the server-side ASN unchanged; use `terraform apply -replace=...` to change it.",
				ValidateFunc: validation.IntBetween(1, 4294967295),
			},
			"tunnel": {
				Type:     schema.TypeList,
				Required: true,
				Description: "The list of individual tunnel endpoints for this dynamic tunnel group. " +
					"**Adding** an endpoint to an existing dynamic tunnel is applied in place. **Changing or removing** an existing endpoint is not: the v3 update " +
					"request identifies an endpoint by a server-assigned id that the provider has no way to obtain, so such a change fails the apply with an " +
					"explanatory error instead of being silently dropped. Use `terraform apply -replace=...` to change or remove an endpoint, which destroys and " +
					"recreates the whole tunnel group. An **imported** dynamic tunnel records no endpoints in state (the read API returns none of `remote_asn`, " +
					"`p81_gw_internal_ip` or `remote_gw_internal_ip`), so the provider refuses to change its endpoint list at all rather than risk duplicating endpoints.",
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
				Type:     schema.TypeList,
				Required: true,
				Description: "List of Check Point SASE gateway subnet CIDR blocks (shared settings). " +
					p81GatewaySubnetsEnhancedRule +
					" The 409 above was measured on the static-tunnel endpoint; the dynamic " +
					"endpoint was not separately exercised, but both write the same " +
					"`p81GatewaySubnets` field of the same enhanced network.",
				// Same split as the static tunnel: CIDR format is checkable at plan
				// time, the allowed-value half is not. See
				// p81GatewaySubnetsEnhancedRule in utils.go.
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.IsCIDR,
				},
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
							MinItems:    1,
							Description: "List of phase 1 authentication algorithms.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"encryption": {
							Type:        schema.TypeList,
							Required:    true,
							MinItems:    1,
							Description: "List of phase 1 encryption algorithms.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"key_exchange_method": {
							Type:        schema.TypeList,
							Required:    true,
							MinItems:    1,
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
							MinItems:    1,
							Description: "List of phase 2 authentication algorithms.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"encryption": {
							Type:        schema.TypeList,
							Required:    true,
							MinItems:    1,
							Description: "List of phase 2 encryption algorithms.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"key_exchange_method": {
							Type:        schema.TypeList,
							Required:    true,
							MinItems:    1,
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

// dynamicTunnelServerNameSuffix is what the upstream model appends to a dynamic
// tunnel's name when it derives each endpoint's interface name —
// createIPSecRedundant.transform.ts:113, `interfaceName: ${tunnelName}0${i+1}`.
// A single-endpoint group therefore reads back as `<tunnelName>01`.
//
// This is dynamic-tunnel-only. A live probe created a static tunnel named
// `ProbeTun1` and the tunnels list returned `"tunnelName": "ProbeTun1"`,
// unsuffixed; the static resource must not use any of this.
const dynamicTunnelServerNameSuffix = "01"

/*
dynamicTunnelNameIsDerivedFrom reports whether serverName is a name the server
would be holding for a dynamic tunnel that was sent `configured`.

Both forms count. The suffixed one is what the live server does today; the bare
one is accepted because nothing in the API contract promises the suffix, the
sibling static tunnel does not get one, and a provider that only recognised the
decorated form would break the day the server stopped decorating.

An empty `configured` matches nothing. Without that guard a caller with no
configured name would match any tunnel the server happens to call "01".
  - @param serverName string - the name as the API reports it
  - @param configured string - the name the user wrote / Terraform sent

@return bool - true when serverName is `configured` or `configured` + "01"
*/
func dynamicTunnelNameIsDerivedFrom(serverName, configured string) bool {
	if configured == "" {
		return false
	}
	return serverName == configured || serverName == configured+dynamicTunnelServerNameSuffix
}

/*
dynamicTunnelNameForState decides what tunnel_name should hold in state after a
read, given the value already in state (`prior`) and the value the API reports.

The rule is the preserve-prior-state pattern setIfPresent and resourceGatewayRead
already use, specialised for a value the server rewrites: when the server's name
is the derived form of the name Terraform sent, the read has learned nothing new
and prior stays. Only a name the server could NOT have derived from prior is real
drift, and that is written through.

Why this rather than a DiffSuppressFunc, which is what this resource had:

	The server's name went into state verbatim, and the DiffSuppressFunc hid the
	resulting difference from the configured name. Hiding a diff does not discard
	the state value — it makes the SDK carry it into the apply, so
	d.Get("tunnel_name") in Update returned the DECORATED name, Update sent it,
	and the server decorated it again. `EnhDynTun1` became `EnhDynTun101` on
	create and `EnhDynTun10101` after one update: two characters per apply
	against a 15-character server-side cap, so a few applies in, unrelated
	changes start failing with a 400 about the name.

	The suppression was also one-sided in a way that mangles legitimate names.
	`strings.TrimSuffix(old, "01") == new || old == strings.TrimSuffix(new, "01")`
	is true for the pair (`TunA`, `TunA01`) in either direction, so a user
	renaming a tunnel to a name that is the old one plus `01` — and
	`dynamicTunnel01`, the name in this resource's own documentation example, is
	exactly that shape — had the rename silently dropped. And once the name had
	compounded to `EnhDynTun10101`, neither branch matched `EnhDynTun1` any more,
	so the diff came back forever and every apply made it worse.

	Normalising in Read fixes the cause: state holds what the user asked for, so
	there is no diff to suppress, Update sends the base name, and the server's
	own idempotent derivation keeps the name at `<configured>01` no matter how
	many times it runs. Every genuine rename is a genuine diff again.

The one case this cannot normalise is import: the importer runs Read with an
empty prior, so state takes the decorated name and the first plan against a
config holding the base name shows a rename. That apply is real — it sends the
base name, the server re-derives the same decorated name it already had, and
the read after it normalises state. It converges in one apply, and the diff is
honest about the fact that Terraform is only now learning the configured name.
  - @param prior string - tunnel_name as it currently stands in state
  - @param serverName string - tunnel_name as the API reports it

@return string - the value to write to state
*/
func dynamicTunnelNameForState(prior, serverName string) string {
	// An empty serverName is the setIfPresent case: the API told us nothing, so
	// it must not blank a name the user configured.
	if serverName == "" || dynamicTunnelNameIsDerivedFrom(serverName, prior) {
		return prior
	}
	return serverName
}

/*
setEnhancedDynamicTunnelNameState writes the reconciled tunnel_name into state.

Factored out so the offline lifecycle test drives the production reconciliation
rather than a copy of it — the interaction between what Read stores and what
Update later reads back out of d is precisely what produced the compounding-name
defect, so the test has to exercise the real thing.
  - @param d *schema.ResourceData - the terraform resource data
  - @param serverName string - tunnel_name as the API reports it

@return error - any error from the underlying d.Set
*/
func setEnhancedDynamicTunnelNameState(d *schema.ResourceData, serverName string) error {
	prior, _ := d.Get("tunnel_name").(string)
	return d.Set("tunnel_name", dynamicTunnelNameForState(prior, serverName))
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
		// listing tunnels and finding by tunnel_name — matching the derived
		// name as well as the literal one, because the server stores
		// `<tunnelName>01` for a dynamic tunnel. An exact comparison could
		// never match against that server, so this fallback silently failed to
		// find a tunnel it had just created.
		resp, _, lerr := client.EnhancedTunnelsAPI.GetEnhancedRegionTunnelsPerNetwork(ctx, networkId).Execute()
		if lerr == nil && resp != nil {
			for _, t := range resp.Data {
				if dynamicTunnelNameIsDerivedFrom(t.TunnelName, tunnelName) {
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
		// tunnel_name is the one attribute whose server-side value is not the
		// value that was sent: the server appends `01` to derive the endpoint's
		// interface name. Writing that back verbatim is what made the name grow
		// by two characters on every apply — see dynamicTunnelNameForState.
		if err := setEnhancedDynamicTunnelNameState(d, tunnel.TunnelName); err != nil {
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
		// p81_gateway_subnets / remote_gateway_subnets were never written back
		// at all before this, so the two attributes the group's sharedSettings
		// is made of could not drift-detect: edit either in HCL and the plan
		// was empty. They come off the same endpoint 0 as the IPSec settings
		// and for the same reason — they are group-wide shared settings,
		// repeated identically on every endpoint the group returns.
		if err := setEnhancedTunnelSharedSubnetState(d, &tunnel); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set Enhanced Dynamic Tunnel shared subnets", err)
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
buildDynamicTunnelUpdatePayload builds everything on the DynamicTunnelUpdate
body that comes from a single schema attribute, i.e. everything except the
three endpoint collections (see planDynamicTunnelEndpointChanges for those).

It is factored out of resourceEnhancedDynamicTunnelUpdate so the golden-body
tests in payload_marshal_test.go drive the production construction rather than
a copy of it: the update body used to carry two of this resource's fourteen
mutable attributes, and nothing offline noticed, because nothing offline
marshaled it.

The wire shape below — timing fields and phase configs nested under
`advancedSettings`, subnets nested under `sharedSettings` — is taken from the
generated model, which is the only specification available for this endpoint.
It has NOT been confirmed against a live response, and the sibling read model
was recently found to be wrong in exactly this way (the spec declared a nested
`advancedSettings` the server never sends; see SDK overlay A19 and
setEnhancedTunnelIPSecState). Treat the nesting as unverified.
  - @param d *schema.ResourceData - the terraform resource data

@return perimeter81Sdk.DynamicTunnelUpdate - the payload, minus endpoint changes
*/
func buildDynamicTunnelUpdatePayload(d *schema.ResourceData) perimeter81Sdk.DynamicTunnelUpdate {
	payload := perimeter81Sdk.DynamicTunnelUpdate{
		TunnelName: d.Get("tunnel_name").(string),
	}
	if v, ok := d.GetOk("description"); ok {
		s := v.(string)
		payload.Description = &s
	}

	// EnhancedIPSecSharedSettingsUpdate carries p81GatewaySubnets,
	// remoteGatewaySubnets, an optional `features` object and an optional
	// p81ASN. Only the two subnet lists are sent:
	//
	//   - `features` is deliberately omitted. It is optional here (unlike on
	//     create, where the SDK type makes it a required value), and the only
	//     thing this provider could put in it is NetworkFeaturesCreate{},
	//     which serializes as three explicit "enabled": false leaves. The live
	//     read capture in resource_enhanced_tunnel_read_test.go shows a real
	//     tunnel with DNSServices.redirectToResolver.enabled = true, so
	//     sending the zero value on every update would switch a feature off
	//     that this resource does not manage and the user never asked to
	//     change.
	//   - p81ASN is not left_asn's home. left_asn maps to `leftASN`, which
	//     exists on EnhancedIPSecSharedSettingsCreate and has no counterpart
	//     on the update type at all. p81ASN is a separate, server-assigned
	//     value — SDK overlay A6 removed it from the create-required list on
	//     exactly that ground ("the ASN is server-assigned once the first
	//     dynamic tunnel is created and is never supplied by the caller").
	//     Writing left_asn into it would be a guess at an equivalence the spec
	//     does not state. left_asn is therefore not updatable in v3; the
	//     warning raised in resourceEnhancedDynamicTunnelUpdate says so out
	//     loud rather than letting the change disappear.
	sharedSettings := perimeter81Sdk.EnhancedIPSecSharedSettingsUpdate{
		P81GatewaySubnets:    flattenStringsArrayData(d.Get("p81_gateway_subnets").([]interface{})),
		RemoteGatewaySubnets: flattenStringsArrayData(d.Get("remote_gateway_subnets").([]interface{})),
	}
	payload.SharedSettings = &sharedSettings

	// Every field of IPSecAdvancedSettingsV23 is a required value type, and
	// every one of them maps to a Required schema attribute, so this is always
	// fully populated — the same struct, built the same way, as the create
	// path a few functions above.
	advancedSettings := perimeter81Sdk.IPSecAdvancedSettingsV23{
		KeyExchange: d.Get("key_exchange").(string),
		IkeLifeTime: d.Get("ike_life_time").(string),
		Lifetime:    d.Get("lifetime").(string),
		DpdDelay:    d.Get("dpd_delay").(string),
		DpdTimeout:  d.Get("dpd_timeout").(string),
		Phase1:      flattenIPSecPhaseConfigV23(d.Get("phase1").([]interface{})),
		Phase2:      flattenIPSecPhaseConfigV23(d.Get("phase2").([]interface{})),
	}
	payload.AdvancedSettings = &advancedSettings

	// DynamicTunnelUpdate.RoutingType is left unset on purpose. There is no
	// routing_type schema attribute on this resource, so the provider has no
	// user intent to transmit; the field is an optional pointer, so omitting
	// it asks the server to keep whatever the group already has. The create
	// path hardcodes "route" only because RoutingType is a required value type
	// on DynamicTunnelDetails and "" is not a member of the enum — that is a
	// constraint of the create model, not a statement that this resource owns
	// the group's routing mode, and repeating it here would silently overwrite
	// a group switched to "policy" outside Terraform.

	return payload
}

/*
dynamicTunnelEndpointKey renders one `tunnel` block into a canonical string, so
that two blocks can be compared for exact equality. Every attribute of the
block contributes; %q quotes the strings so a separator character inside a
value cannot fake a match against a different field split.
  - @param block map[string]interface{} - one element of the `tunnel` list

@return string - a key equal for two blocks iff they are configured identically
*/
func dynamicTunnelEndpointKey(block map[string]interface{}) string {
	return fmt.Sprintf("%q|%q|%q|%q|%q|%q|%v|%q|%q",
		block["region_id"],
		block["auth_type"],
		block["passphrase"],
		block["customer_root_ca"],
		block["remote_public_ip"],
		block["remote_id"],
		block["remote_asn"],
		block["p81_gw_internal_ip"],
		block["remote_gw_internal_ip"],
	)
}

/*
planDynamicTunnelEndpointChanges decides what the endpoint collections on
DynamicTunnelUpdate should carry, given the `tunnel` block list before and
after the change.

Of the three collections the model offers, only one can be produced correctly
today, and this function refuses to approximate the other two:

  - addTunnels is a list of whole DynamicTunnelDetails objects and needs no
    server-side identifier, so an endpoint the user has newly written can be
    sent verbatim — the same flattenDynamicTunnelDetails the create path uses.
  - updateTunnels and removeTunnels are keyed by `id`, required on both
    DynamicTunnelUpdateUpdateTunnelsInner and
    DynamicTunnelUpdateRemoveTunnelsInner. That is the server's id for one
    endpoint of the group, and the provider has no way to learn which endpoint
    a given `tunnel` block became. The block has no id attribute; Read does not
    populate the block list; and the read model (EnhancedTunnel) carries none
    of remoteASN, p81GWInternalIP or remoteGWInternalIP, so a returned endpoint
    cannot be matched back to the block that configured it on content either.
    Pairing by list position assumes the group's endpoints come back in
    configuration order, which nothing documents; pairing by region_id assumes
    a region hosts at most one endpoint of a group, which nothing enforces.
    Either guess sends one endpoint's settings — including its pre-shared key —
    to a different endpoint, or deletes the wrong one.

So: when every endpoint that was already configured is still configured
verbatim, the difference is purely additive and comes back as addTunnels. When
any previously-configured endpoint has been edited or dropped, applying the
configuration needs an id that does not exist here, and this returns an error.
Failing the apply is the point. The alternative is the defect this change
exists to remove, where Terraform reports success and the server was never
told anything.
  - @param oldBlocks []interface{} - the `tunnel` list as it is in state
  - @param newBlocks []interface{} - the `tunnel` list as it is in the new config

@return []perimeter81Sdk.DynamicTunnelDetails - endpoints to add, nil if none
@return error - set when the change needs updateTunnels or removeTunnels
*/
func planDynamicTunnelEndpointChanges(oldBlocks, newBlocks []interface{}) ([]perimeter81Sdk.DynamicTunnelDetails, error) {
	// An empty prior list is not "this group has no endpoints yet". `tunnel`
	// is Required, so a group Terraform created always has at least one block
	// in state; the only way to reach Update with none is an import, because
	// resourceEnhancedDynamicTunnelImportState reads the resource and Read
	// does not populate the block list. Treating that as an addition would
	// send every configured endpoint to a group that already has them and
	// duplicate the lot on a live tunnel — strictly worse than the defect this
	// function exists to fix. Refuse instead.
	if len(oldBlocks) == 0 && len(newBlocks) > 0 {
		return nil, fmt.Errorf(
			"this dynamic tunnel has no `tunnel` endpoints recorded in Terraform state, so the provider cannot tell which of the %d configured endpoints already exist server-side: "+
				"sending them would add duplicates to a group that already has them. This is the state an imported dynamic tunnel is in — Read cannot repopulate the block list, "+
				"because the tunnel read model returns no remoteASN/p81GWInternalIP/remoteGWInternalIP and those are Required attributes. "+
				"Manage this tunnel with a resource Terraform created, or replace it (`terraform apply -replace=...`) so that Create records the endpoints",
			len(newBlocks))
	}

	// Counted (multiset) rather than set membership, so that dropping one of
	// two identically-configured endpoints is still recognised as a removal.
	unmatched := make(map[string]int, len(newBlocks))
	for _, item := range newBlocks {
		if block, ok := item.(map[string]interface{}); ok {
			unmatched[dynamicTunnelEndpointKey(block)]++
		}
	}
	for _, item := range oldBlocks {
		block, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		key := dynamicTunnelEndpointKey(block)
		if unmatched[key] == 0 {
			return nil, fmt.Errorf(
				"the `tunnel` endpoint for region_id %q (remote_public_ip %q) has been changed or removed, and this provider cannot apply that to an existing dynamic tunnel: "+
					"the v3 update endpoint identifies an endpoint to modify or delete by a server-assigned id (`updateTunnels[].id` / `removeTunnels[].id`, required on both) "+
					"that the provider has no way to obtain — the `tunnel` block has no id attribute, Read does not refresh the block list, and the tunnel read model returns no "+
					"remoteASN/p81GWInternalIP/remoteGWInternalIP to match a returned endpoint back to the block that configured it. "+
					"Adding a new `tunnel` block to an existing dynamic tunnel is supported and does apply. To change or remove an existing endpoint, replace the resource "+
					"(`terraform apply -replace=...`), which destroys and recreates the whole tunnel group. "+
					"This is reported as an error rather than applied partially so that the change cannot be silently dropped while Terraform reports success",
				block["region_id"], block["remote_public_ip"])
		}
		unmatched[key]--
	}

	// Whatever is still unmatched is new. Walk newBlocks (not the map) so the
	// added endpoints keep configuration order and duplicates are consumed in
	// the order the user wrote them.
	added := make([]interface{}, 0, len(newBlocks))
	for _, item := range newBlocks {
		block, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		key := dynamicTunnelEndpointKey(block)
		if unmatched[key] == 0 {
			continue
		}
		unmatched[key]--
		added = append(added, item)
	}
	if len(added) == 0 {
		return nil, nil
	}
	return flattenDynamicTunnelDetails(added), nil
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

	payload := buildDynamicTunnelUpdatePayload(d)

	// Endpoint changes are worked out before anything is sent, so a change the
	// provider cannot express fails the apply outright instead of leaving the
	// group half-updated.
	oldTunnels, newTunnels := d.GetChange("tunnel")
	oldBlocks, _ := oldTunnels.([]interface{})
	newBlocks, _ := newTunnels.([]interface{})
	addTunnels, err := planDynamicTunnelEndpointChanges(oldBlocks, newBlocks)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to update Enhanced Dynamic Tunnel", err)
	}
	payload.AddTunnels = addTunnels

	// left_asn has no field on the update type — see buildDynamicTunnelUpdatePayload.
	// Warn rather than drop it silently; a warning is the whole difference
	// between "Terraform told me it could not do this" and "Terraform said OK
	// and the next plan showed the same diff again".
	if d.HasChange("left_asn") {
		previous, desired := d.GetChange("left_asn")
		diags = appendWarningDiags(diags, "left_asn cannot be changed on an existing Enhanced Dynamic Tunnel",
			fmt.Sprintf("The configuration changes left_asn from %v to %v, but the v3 dynamic-tunnel update body has no field for it: "+
				"`leftASN` exists only on the create type (EnhancedIPSecSharedSettingsCreate) and has no counterpart on "+
				"EnhancedIPSecSharedSettingsUpdate. The local BGP ASN was left unchanged server-side and this attribute will keep "+
				"showing a diff. To apply it, replace the resource (`terraform apply -replace=...`).", previous, desired))
	}

	status, _, err := client.EnhancedTunnelsAPI.UpdateDynamicTunnel(ctx, networkId, dynamicTunnelId).DynamicTunnelUpdate(payload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to update Enhanced Dynamic Tunnel", err)
	}
	// UpdateDynamicTunnel is async, exactly like Create and Delete: it returns
	// an AsyncOperationResponse, and the change is not applied when it does.
	// The previous implementation dropped that response on the floor, so the
	// Read below could observe pre-update values and write them straight back
	// into state — an update that worked would still look like it had not.
	// statusUrl is optional on the response, so poll only when there is
	// something to poll; a missing URL must not turn a successful update into
	// a 404 against the status endpoint.
	if statusId := getIdFromUrl(status.GetStatusUrl()); statusId != "" {
		if err := pollStandardNetworkStatus(ctx, client, statusId, standardNetworkPollInterval); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to update Enhanced Dynamic Tunnel", err)
		}
	}
	d.Set("last_updated", time.Now().Format(time.RFC850))

	// Append rather than return Read's diagnostics directly, so a warning
	// raised above survives to the user.
	return append(diags, resourceEnhancedDynamicTunnelRead(ctx, d, m)...)
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
