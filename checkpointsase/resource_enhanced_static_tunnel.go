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
resourceEnhancedStaticTunnel Setup the Enhanced Static Tunnel Resource CRUD operations

@return &schema.Resource
*/
func resourceEnhancedStaticTunnel() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a static IPsec tunnel attached to a region of a " +
			"`checkpointsase_enhanced_network`. A static tunnel terminates at a single " +
			"remote endpoint identified by `remote_public_ip` (PSK) or via certificate " +
			"authentication (`auth_type = \"cert\"` + `customer_root_ca`). " +
			"The tunnel's route is part of the tunnel: Harmony SASE creates it with the " +
			"tunnel, and its subnets are this resource's own `remote_gateway_subnets`, so " +
			"set the routed subnets there — but **never as `0.0.0.0/0`**, which permanently " +
			"blocks every subsequent update of the tunnel (see that attribute). " +
			"The `checkpointsase_enhanced_route_table` " +
			"**resource** is rejected during `terraform plan` and cannot attach a route " +
			"here; read the resulting route with the " +
			"`checkpointsase_enhanced_route_table` **data source**. " +
			"**`network_id` and `region_id` are immutable** — changing either forces " +
			"resource replacement.",
		CreateContext: resourceEnhancedStaticTunnelCreate,
		ReadContext:   resourceEnhancedStaticTunnelRead,
		UpdateContext: resourceEnhancedStaticTunnelUpdate,
		DeleteContext: resourceEnhancedStaticTunnelDelete,
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
				Description: "The ID of the enhanced network this static tunnel belongs to.",
			},
			"region_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The target region ID within the enhanced network.",
			},
			"tunnel_name": {
				Type:     schema.TypeString,
				Required: true,
				Description: "The name of the static IPSec tunnel. 3-15 characters, letters and digits " +
					"only. The server derives the tunnel's `interfaceName` from this value and " +
					"rejects hyphens, underscores, dots and spaces with a 422 that names only the " +
					"derived field.",
				ValidateFunc: validation.StringMatch(tunnelNamePattern, tunnelNameRuleMessage),
			},
			"remote_public_ip": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The remote gateway public IP address.",
			},
			"remote_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "The remote gateway ID. When omitted, the server " +
					"defaults this to `remote_public_ip`; the provider reads " +
					"the server-assigned value back into state. Must be " +
					"alphanumeric or a valid IP address.",
				ValidateFunc: validateRemoteID,
			},
			"auth_type": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Authentication type. Must be `psk` (pre-shared key, requires `passphrase`) or `cert` (certificate, requires `customer_root_ca`).",
				ValidateFunc: validation.StringInSlice([]string{"psk", "cert"}, false),
			},
			"passphrase": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Pre-shared key for tunnel authentication. Required when auth_type is 'psk'. The public-api regex disallows hyphens; allowed characters are letters, digits, `.` and `_` (8-64 chars).",
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
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional description for the static tunnel.",
			},
			"peak_bandwidth": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  1000,
				ForceNew: true,
				Description: "Expected peak throughput of the tunnel communication in Mbps. Allowed range is 10–8000. Defaults to 1000. " +
					"Settable only at creation: v3's update endpoint has no bandwidth field, so changing this value replaces the tunnel (destroy and re-create) rather than updating it in place.",
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
			"p81_gateway_subnets": {
				Type:     schema.TypeList,
				Required: true,
				Description: "List of Check Point SASE gateway subnet CIDR blocks. " +
					p81GatewaySubnetsEnhancedRule,
				// The 409 quoted in p81GatewaySubnetsEnhancedRule was measured on
				// this endpoint. Only the CIDR-format half is checkable at plan
				// time; see that constant's comment for why the allowed-value half
				// is left to the server.
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.IsCIDR,
				},
			},
			"remote_gateway_subnets": {
				Type:     schema.TypeList,
				Required: true,
				Description: "List of remote gateway subnet CIDR blocks. " +
					"**Do not use the default route `0.0.0.0/0` here.** A static tunnel " +
					"created with `remote_gateway_subnets = [\"0.0.0.0/0\"]` can be created " +
					"and read but can NEVER be updated: every later `PUT` returns " +
					"`404 Remote gateway subnets not found` — including a change that does " +
					"not touch either subnet list — so the tunnel is stuck at its created " +
					"configuration for the rest of its life and the only way out is to " +
					"destroy and re-create it. Measured 2026-08-17 " +
					"(`API-FINDINGS.md` §1.2) on three tunnels differing only in this " +
					"field; the same update returns `202` when the value is a real CIDR. " +
					"Note this is the OPPOSITE of `p81_gateway_subnets`, where `0.0.0.0/0` " +
					"is a legal and recommended value. The provider does not refuse " +
					"`0.0.0.0/0` at plan time, because the API accepts it at create and a " +
					"validator here would refuse a configuration the server allows.",
				// NOT validated with validation.IsCIDR, unlike p81_gateway_subnets:
				// the 0.0.0.0/0 trap above is a well-formed CIDR, so a format check
				// would not catch it, and refusing it outright would refuse a create
				// the server accepts. Documented rather than enforced.
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
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
			StateContext: resourceEnhancedStaticTunnelImportState,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(asyncResourceTimeout),
			Update: schema.DefaultTimeout(asyncResourceTimeout),
			Delete: schema.DefaultTimeout(asyncResourceTimeout),
		},
	}
}

/*
resourceEnhancedStaticTunnelImportState Import an enhanced static tunnel by its ID.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceEnhancedStaticTunnelImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	// Read needs both network_id (URL path) and tunnel_id (d.Id()) — the
	// import handler must split the composite ID `<network_id>-<tunnel_id>`
	// before delegating. Same pattern as resourceGatewayImportState /
	// resourceEnhancedRegionImportState.
	ids := strings.SplitN(d.Id(), "-", 2)
	if len(ids) != 2 || ids[0] == "" || ids[1] == "" {
		return nil, fmt.Errorf("could not import enhanced_static_tunnel: expected composite ID in the form <network_id>-<tunnel_id>, got %q", d.Id())
	}
	if err := d.Set("network_id", ids[0]); err != nil {
		return nil, fmt.Errorf("could not import enhanced_static_tunnel: failed to set network_id: %w", err)
	}
	d.SetId(ids[1])

	diagnostics := resourceEnhancedStaticTunnelRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import enhanced static tunnel: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}

/*
flattenIPSecPhaseConfigV23 converts a phase schema block into an IPSecPhaseConfigV23 SDK model.
*/
func flattenIPSecPhaseConfigV23(phaseList []interface{}) perimeter81Sdk.IPSecPhaseConfigV23 {
	if len(phaseList) == 0 {
		return perimeter81Sdk.IPSecPhaseConfigV23{}
	}
	phaseMap := phaseList[0].(map[string]interface{})
	return perimeter81Sdk.IPSecPhaseConfigV23{
		Auth:              flattenStringsArrayData(phaseMap["auth"].([]interface{})),
		Encryption:        flattenStringsArrayData(phaseMap["encryption"].([]interface{})),
		KeyExchangeMethod: flattenStringsArrayData(phaseMap["key_exchange_method"].([]interface{})),
	}
}

/*
flattenIPSecPhaseConfigV23ToMap converts an IPSecPhaseConfigV23 SDK model to a Terraform-compatible map.
*/
func flattenIPSecPhaseConfigV23ToMap(phase perimeter81Sdk.IPSecPhaseConfigV23) []interface{} {
	phaseMap := map[string]interface{}{
		"auth":                phase.Auth,
		"encryption":          phase.Encryption,
		"key_exchange_method": phase.KeyExchangeMethod,
	}
	return []interface{}{phaseMap}
}

/*
setEnhancedTunnelIPSecState writes the six IPSec parameters that the
enhanced-tunnel GET endpoints return, and that both the static and the dynamic
enhanced-tunnel resources declare as top-level attributes:
ike_life_time, lifetime, dpd_delay, dpd_timeout, phase1 and phase2.

All six live at the TOP LEVEL of the response. Until SDK overlay A19 the spec
declared them nested inside an `advancedSettings` object that the server never
sends at all, so the generated EnhancedTunnel.AdvancedSettings pointer was nil
on every response, its nil-safe getters returned "", and both Read functions
blanked the user's configured values on every refresh. The shape here is the
one a live GET /v3/networks/enhanced/{networkId}/tunnels returned on
2026-08-16; see the A19 entry in the SDK's api/overlay.yaml for the capture and
the reasoning.

Every field is written through the same never-blank guard the write-once
credentials use (setIfPresent): a value the server did not report, or reported
as empty, leaves whatever is already in state alone rather than overwriting it.
That is what makes a repeat of the A19 defect a no-op on state instead of a
silent data loss — if these fields ever stop arriving, the user's configuration
survives.
  - @param d *schema.ResourceData - the terraform resource data
  - @param tunnel *perimeter81Sdk.EnhancedTunnel - the tunnel as returned by the API

@return error - the first d.Set error, naming the attribute that failed
*/
func setEnhancedTunnelIPSecState(d *schema.ResourceData, tunnel *perimeter81Sdk.EnhancedTunnel) error {
	for _, f := range []struct {
		key     string
		value   string
		present bool
	}{
		{"ike_life_time", tunnel.GetIkeLifeTime(), tunnel.HasIkeLifeTime()},
		{"lifetime", tunnel.GetLifetime(), tunnel.HasLifetime()},
		{"dpd_delay", tunnel.GetDpdDelay(), tunnel.HasDpdDelay()},
		{"dpd_timeout", tunnel.GetDpdTimeout(), tunnel.HasDpdTimeout()},
	} {
		if err := setIfPresent(d, f.key, f.value, f.present); err != nil {
			return fmt.Errorf("could not set %s: %w", f.key, err)
		}
	}
	// phase1/phase2 are objects rather than strings, so setIfPresent (which is
	// string-typed) does not apply; the Has* guard is the same idea.
	if tunnel.HasPhase1() {
		if err := d.Set("phase1", flattenIPSecPhaseConfigV23ToMap(tunnel.GetPhase1())); err != nil {
			return fmt.Errorf("could not set phase1: %w", err)
		}
	}
	if tunnel.HasPhase2() {
		if err := d.Set("phase2", flattenIPSecPhaseConfigV23ToMap(tunnel.GetPhase2())); err != nil {
			return fmt.Errorf("could not set phase2: %w", err)
		}
	}
	return nil
}

/*
setEnhancedTunnelSharedSubnetState writes the two subnet lists that make up an
enhanced tunnel's shared settings — p81_gateway_subnets and
remote_gateway_subnets — both of which the static and the dynamic resource
declare as Required top-level attributes.

Shared between the two Reads for the same reason setEnhancedTunnelIPSecState
is: the dynamic resource never wrote these back at all, so neither attribute
could drift-detect, and re-deriving the write in a second place is how the two
Reads diverged in the first place.

Writes go through setStringListIfPresent, so a response with no subnets leaves
the configured lists alone instead of blanking them. Both attributes are
Required in both schemas, so an empty list was never a configurable value and
declining to write one costs no fidelity.
  - @param d *schema.ResourceData - the terraform resource data
  - @param tunnel *perimeter81Sdk.EnhancedTunnel - the tunnel as returned by the API

@return error - the first d.Set error, naming the attribute that failed
*/
func setEnhancedTunnelSharedSubnetState(d *schema.ResourceData, tunnel *perimeter81Sdk.EnhancedTunnel) error {
	if err := setStringListIfPresent(d, "p81_gateway_subnets", tunnel.P81GatewaySubnets); err != nil {
		return fmt.Errorf("could not set p81_gateway_subnets: %w", err)
	}
	if err := setStringListIfPresent(d, "remote_gateway_subnets", tunnel.RemoteGatewaySubnets); err != nil {
		return fmt.Errorf("could not set remote_gateway_subnets: %w", err)
	}
	return nil
}

/*
resourceEnhancedStaticTunnelCreate Create an Enhanced Static IPSec Tunnel.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedStaticTunnelCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	regionId := d.Get("region_id").(string)
	tunnelName := d.Get("tunnel_name").(string)
	keyExchange := d.Get("key_exchange").(string)
	ikeLifeTime := d.Get("ike_life_time").(string)
	lifetime := d.Get("lifetime").(string)
	dpdDelay := d.Get("dpd_delay").(string)
	dpdTimeout := d.Get("dpd_timeout").(string)
	p81GatewaySubnets := flattenStringsArrayData(d.Get("p81_gateway_subnets").([]interface{}))
	remoteGatewaySubnets := flattenStringsArrayData(d.Get("remote_gateway_subnets").([]interface{}))
	phase1 := flattenIPSecPhaseConfigV23(d.Get("phase1").([]interface{}))
	phase2 := flattenIPSecPhaseConfigV23(d.Get("phase2").([]interface{}))

	// Public-api requires `routingType` (string) and `features` (object) on
	// every static tunnel create — see baseEnhancedIPSecTunnel.dto.ts.
	// v3: RoutingType and Features are value types (not pointers) on
	// StaticTunnelCreate — unlike StaticTunnelUpdate, where both remain
	// pointers. See model_static_tunnel_create.go vs model_static_tunnel_update.go.
	routingType := perimeter81Sdk.ROUTINGTYPE_ROUTE
	payload := perimeter81Sdk.StaticTunnelCreate{
		RegionID:             regionId,
		TunnelName:           tunnelName,
		KeyExchange:          keyExchange,
		IkeLifeTime:          ikeLifeTime,
		Lifetime:             lifetime,
		DpdDelay:             dpdDelay,
		DpdTimeout:           dpdTimeout,
		P81GatewaySubnets:    p81GatewaySubnets,
		RemoteGatewaySubnets: remoteGatewaySubnets,
		Phase1:               phase1,
		Phase2:               phase2,
		RoutingType:          routingType,
		Features:             perimeter81Sdk.NetworkFeaturesCreate{},
	}
	// v3: RemotePublicIP, RemoteID and AuthType are required strings (not
	// *string) on StaticTunnelCreate, so they're always serialized — even
	// as "" when the corresponding schema attribute is Optional and left
	// unset by the user (e.g. cert-auth tunnels with no remote_public_ip).
	// That's a behavior change baked into the v3 spec's requiredness, not
	// something introduced here; flagged in the Task 12A report rather than
	// worked around, per the type-port-only scope of this pass.
	if v, ok := d.GetOk("remote_public_ip"); ok {
		s := v.(string)
		payload.RemotePublicIP = s
	}
	if v, ok := d.GetOk("remote_id"); ok {
		s := v.(string)
		payload.RemoteID = s
	}
	if v, ok := d.GetOk("auth_type"); ok {
		s := v.(string)
		payload.AuthType = s
	}
	if v, ok := d.GetOk("passphrase"); ok {
		s := v.(string)
		payload.Passphrase = &s
	}
	if v, ok := d.GetOk("customer_root_ca"); ok {
		s := v.(string)
		payload.CustomerRootCA = &s
	}
	if v, ok := d.GetOk("description"); ok {
		s := v.(string)
		payload.Description = &s
	}
	if v, ok := d.GetOk("peak_bandwidth"); ok {
		pb := int32(v.(int))
		payload.PeakBandwidthMbps = &pb
	}

	status, _, err := client.EnhancedTunnelsAPI.CreateStaticTunnel(ctx, networkId).StaticTunnelCreate(payload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Enhanced Static Tunnel", err)
	}

	statusId := getIdFromUrl(status.GetStatusUrl())
	resource, err := pollStandardNetworkStatusForResource(ctx, client, statusId, standardNetworkPollInterval)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Enhanced Static Tunnel", err)
	}
	tunnelId := getIdFromUrl(resource)
	if tunnelId == "" {
		// Async result didn't carry a resource URL (the API
		// sometimes completes without populating result.resource).
		// Fall back to listing tunnels by network and finding by
		// our tunnel_name.
		resp, _, lerr := client.EnhancedTunnelsAPI.GetEnhancedRegionTunnelsPerNetwork(ctx, networkId).Execute()
		if lerr == nil && resp != nil {
			for _, t := range resp.Data {
				if t.TunnelName == tunnelName {
					tunnelId = t.Id
					break
				}
			}
		}
		if tunnelId == "" {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to extract Enhanced Static Tunnel id post-Create",
				fmt.Errorf("async status completed but result.resource was empty and list-by-name found no match for tunnel_name=%s", tunnelName))
		}
	}

	d.SetId(tunnelId)
	return resourceEnhancedStaticTunnelRead(ctx, d, m)
}

/*
resourceEnhancedStaticTunnelRead Read an Enhanced Static IPSec Tunnel.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedStaticTunnelRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	tunnelId := d.Id()

	tunnelData, _, err := client.EnhancedTunnelsAPI.GetStaticTunnel(ctx, networkId, tunnelId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to find Enhanced Static Tunnel", err)
	}

	if err := d.Set("tunnel_name", tunnelData.TunnelName); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Static Tunnel tunnel_name", err)
	}
	if err := d.Set("region_id", tunnelData.RegionID); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Static Tunnel region_id", err)
	}
	if err := d.Set("key_exchange", tunnelData.KeyExchange); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Static Tunnel key_exchange", err)
	}
	// ike_life_time / lifetime / dpd_delay / dpd_timeout / phase1 / phase2 all
	// come back at the top level of the response — see
	// setEnhancedTunnelIPSecState and SDK overlay A19 for the captured
	// evidence and for what the spec used to claim instead.
	if err := setEnhancedTunnelIPSecState(d, tunnelData); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Static Tunnel IPSec settings", err)
	}
	// remotePublicIP and remoteID are returned at the top level too, with real
	// values (e.g. "198.51.100.77"), in the same 2026-08-16 capture.
	//
	// The comment that used to sit here said the opposite — that both fields
	// "no longer exist on EnhancedTunnel (the read shape)", that they were
	// "write-only under v3", and that drift detection on them was therefore
	// "impossible". That described a defect in the vendor's spec, not the
	// behaviour of the API, and it is the whole reason
	// `enhanced_static_tunnel.remote_id` could never populate despite its
	// schema description promising exactly that. Do not restore it without a
	// captured response that actually shows the fields missing.
	if err := setIfPresent(d, "remote_public_ip", tunnelData.GetRemotePublicIP(), tunnelData.HasRemotePublicIP()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Static Tunnel remote_public_ip", err)
	}
	if err := setIfPresent(d, "remote_id", tunnelData.GetRemoteID(), tunnelData.HasRemoteID()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Static Tunnel remote_id", err)
	}
	// passphrase is deliberately NOT written to state, even though the same
	// capture shows the server echoing it back in plaintext.
	//
	// Nothing is gained: `passphrase` is a user-supplied Optional attribute, so
	// state already holds the configured value and plan-time comparison already
	// works. The only thing reading it back would add is detection of an
	// out-of-band PSK rotation. Against that: one capture, of one static
	// tunnel, is not evidence that every code path echoes the secret verbatim
	// — a masked or truncated echo ("********") on some tenant, tunnel type or
	// future hardening change would be written straight into state and produce
	// a permanent, unresolvable diff against the user's config, and it would
	// also copy a secret through one more code path for no benefit. This
	// matches the write-only treatment resource_openvpn.go gives
	// secret_access_key. Revisit only with a capture showing a rotated PSK
	// round-tripping intact.
	if err := d.Set("auth_type", tunnelData.AuthType); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Static Tunnel auth_type", err)
	}
	if err := setEnhancedTunnelSharedSubnetState(d, tunnelData); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Enhanced Static Tunnel shared subnets", err)
	}
	// `description` now exists on the read model (SDK overlay A19 declares it;
	// the 2026-08-16 capture shows the server returning the key), but it is
	// still not written to state here. The capture came from a tunnel created
	// WITHOUT a description, so all it proves is that the key is present and
	// empty — it is not evidence that a configured description round-trips.
	// Wiring it on that basis would risk blanking a user's description on
	// every refresh, which is the exact failure this task exists to fix.
	// Leave state untouched until a capture of a tunnel with a non-empty
	// description exists (same preserve-prior-state precedent as
	// resourceGatewayRead's `name`/`idle` handling in resource_gateway.go).
	if tunnelData.PeakBandwidthMbps != nil {
		if err := d.Set("peak_bandwidth", int(*tunnelData.PeakBandwidthMbps)); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set Enhanced Static Tunnel peak_bandwidth", err)
		}
	}

	return diags
}

/*
resourceEnhancedStaticTunnelUpdate Update an Enhanced Static IPSec Tunnel.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedStaticTunnelUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	tunnelId := d.Id()

	payload := perimeter81Sdk.StaticTunnelUpdate{}

	if v, ok := d.GetOk("tunnel_name"); ok {
		s := v.(string)
		payload.TunnelName = &s
	}
	if v, ok := d.GetOk("remote_public_ip"); ok {
		s := v.(string)
		payload.RemotePublicIP = &s
	}
	if v, ok := d.GetOk("remote_id"); ok {
		s := v.(string)
		payload.RemoteID = &s
	}
	if v, ok := d.GetOk("auth_type"); ok {
		s := v.(string)
		payload.AuthType = &s
	}
	if v, ok := d.GetOk("passphrase"); ok {
		s := v.(string)
		payload.Passphrase = &s
	}
	if v, ok := d.GetOk("customer_root_ca"); ok {
		s := v.(string)
		payload.CustomerRootCA = &s
	}
	if v, ok := d.GetOk("description"); ok {
		s := v.(string)
		payload.Description = &s
	}
	if v, ok := d.GetOk("key_exchange"); ok {
		s := v.(string)
		payload.KeyExchange = &s
	}
	if v, ok := d.GetOk("ike_life_time"); ok {
		s := v.(string)
		payload.IkeLifeTime = &s
	}
	if v, ok := d.GetOk("lifetime"); ok {
		s := v.(string)
		payload.Lifetime = &s
	}
	if v, ok := d.GetOk("dpd_delay"); ok {
		s := v.(string)
		payload.DpdDelay = &s
	}
	if v, ok := d.GetOk("dpd_timeout"); ok {
		s := v.(string)
		payload.DpdTimeout = &s
	}
	if v, ok := d.GetOk("p81_gateway_subnets"); ok {
		payload.P81GatewaySubnets = flattenStringsArrayData(v.([]interface{}))
	}
	if v, ok := d.GetOk("remote_gateway_subnets"); ok {
		payload.RemoteGatewaySubnets = flattenStringsArrayData(v.([]interface{}))
	}
	if v := d.Get("phase1").([]interface{}); len(v) > 0 {
		phase1 := flattenIPSecPhaseConfigV23(v)
		payload.Phase1 = &phase1
	}
	if v := d.Get("phase2").([]interface{}); len(v) > 0 {
		phase2 := flattenIPSecPhaseConfigV23(v)
		payload.Phase2 = &phase2
	}
	// v3: StaticTunnelUpdate has no bandwidth field at all — verified against
	// the SDK: PeakBandwidthMbps exists only on StaticTunnelCreate,
	// EnhancedTunnel and EnhancedTunnelBase, not on StaticTunnelUpdate. There
	// is nowhere left to send peak_bandwidth on update in v3; the schema
	// attribute is preserved (Phase 1 does not touch schema) but changes to
	// it can no longer be propagated to the server after tunnel creation.
	// This is a real capability regression forced by the type restructure,
	// not a design choice — flagged in the Task 12A report for a later phase.

	status, _, err := client.EnhancedTunnelsAPI.UpdateStaticTunnel(ctx, networkId, tunnelId).StaticTunnelUpdate(payload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to update Enhanced Static Tunnel", err)
	}
	// UpdateStaticTunnel is async, exactly like Create and Delete: it returns
	// an AsyncOperationResponse and the change is NOT applied when it does.
	// Dropping that response meant the Read below could observe pre-update
	// values and write them straight back into state, so a successful update
	// looked like a no-op. Measured live on 2026-08-17: the PUT returned 202
	// and the acceptance test then failed with
	//   got tunnel_name "EnhStaticTun1"; want "EnhStaticTun2"
	// because it read the tunnel before the rename had been applied.
	//
	// Same fix and same shape as resourceEnhancedDynamicTunnelUpdate.
	// statusUrl is optional on the response, so poll only when there is
	// something to poll; a missing URL must not turn a successful update into
	// a 404 against the status endpoint.
	if statusId := getIdFromUrl(status.GetStatusUrl()); statusId != "" {
		if err := pollStandardNetworkStatus(ctx, client, statusId, standardNetworkPollInterval); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to update Enhanced Static Tunnel", err)
		}
	}
	d.Set("last_updated", time.Now().Format(time.RFC850))

	return resourceEnhancedStaticTunnelRead(ctx, d, m)
}

/*
resourceEnhancedStaticTunnelDelete Delete an Enhanced Static IPSec Tunnel.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedStaticTunnelDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)
	tunnelId := d.Id()

	status, _, err := client.EnhancedTunnelsAPI.DeleteStaticTunnel(ctx, networkId, tunnelId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete Enhanced Static Tunnel", err)
	}

	statusId := getIdFromUrl(status.GetStatusUrl())
	if err := pollStandardNetworkStatus(ctx, client, statusId, standardNetworkPollInterval); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete Enhanced Static Tunnel", err)
	}

	d.SetId("")
	return diags
}
