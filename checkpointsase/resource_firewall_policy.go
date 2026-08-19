package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
resourceFirewallPolicy Setup the Firewall Policy Resource CRUD operations.
Firewall policies are auto-created with each network, so this resource "adopts"
the existing policy. There is no Create or Delete operation — only Read and Update.

@return &schema.Resource
*/
func resourceFirewallPolicy() *schema.Resource {
	return &schema.Resource{
		Description: "Manages the firewall policy of a Check Point SASE standard network. " +
			"Adopt-style: the policy is created automatically with its parent network, " +
			"so this resource reads the existing policy and applies your configuration to " +
			"it; destroying it releases it from Terraform state without deleting it. " +
			"On the v3 API the update is asynchronous, so applies take longer than a " +
			"single request.",
		CreateContext: resourceFirewallPolicyCreate,
		ReadContext:   resourceFirewallPolicyRead,
		UpdateContext: resourceFirewallPolicyUpdate,
		DeleteContext: resourceFirewallPolicyDelete,
		Schema: map[string]*schema.Schema{
			"network_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The ID of the network whose firewall policy to manage.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Required:    true,
				Description: "Whether the firewall policy is enabled.",
			},
			"allowed": {
				Type:        schema.TypeBool,
				Required:    true,
				Description: "Whether the default policy action is allow (true) or drop (false).",
			},
			"trace": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether the policy is traced.",
			},
			"policy_rules": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of firewall policy rules.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Optional:    true,
							Computed:    true,
							Description: "The unique ID of the policy rule.",
						},
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The name of the policy rule.",
						},
						"enabled": {
							Type:        schema.TypeBool,
							Required:    true,
							Description: "Whether this rule is enabled.",
						},
						"allowed": {
							Type:        schema.TypeBool,
							Required:    true,
							Description: "Whether this rule allows (true) or denies (false) the traffic.",
						},
						"services": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "List of service object IDs to match in this rule.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"log_enabled": {
							Type:        schema.TypeBool,
							Optional:    true,
							Default:     false,
							Description: "Whether logging is enabled for this rule. Required by the v3 /networks/{networkId}/firewall-policy endpoint; defaults to false so configurations written against v2.3 keep working unchanged.",
						},
					},
				},
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceFirewallPolicyImportState,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(asyncResourceTimeout),
			Update: schema.DefaultTimeout(asyncResourceTimeout),
			Delete: schema.DefaultTimeout(asyncResourceTimeout),
		},
	}
}

/*
resourceFirewallPolicyImportState Import a firewall policy by its network ID.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceFirewallPolicyImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	// Use the resource ID as the network_id
	if err := d.Set("network_id", d.Id()); err != nil {
		return nil, fmt.Errorf("could not set network_id: %s", err)
	}
	diagnostics := resourceFirewallPolicyRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import firewall policy: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}

/*
resourceFirewallPolicyCreate "adopts" the existing firewall policy for the given network by reading its current
state and setting the resource ID to the network_id. Then it applies the desired configuration via update.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceFirewallPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)

	// Existence check only: there is no CREATE endpoint for firewall policies
	// — a policy is created implicitly per network. Verify the policy is
	// reachable, adopt it by setting the resource ID, then push the HCL
	// configuration via Update. Do NOT d.Set("enabled"/"allowed") here:
	// terraform-plugin-sdk's d.Get prefers a recent d.Set over the diff/config,
	// so any pre-Update Set would clobber the HCL values and Update would push
	// the server's existing values back instead of the user's configuration.
	if _, _, err := client.FirewallPolicyAPI.GetGranularFirewallPolicy(ctx, networkId).Execute(); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read Firewall Policy for adoption", err)
	}

	d.SetId(networkId)
	return resourceFirewallPolicyUpdate(ctx, d, m)
}

/*
resourceFirewallPolicyRead Read a Firewall Policy by network ID.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceFirewallPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)

	policyData, _, err := client.FirewallPolicyAPI.GetGranularFirewallPolicy(ctx, networkId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to find Firewall Policy", err)
	}

	if err := d.Set("enabled", policyData.Enabled); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Firewall Policy enabled", err)
	}
	if err := d.Set("allowed", policyData.Allowed); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Firewall Policy allowed", err)
	}

	policyRules := flattenFirewallPolicyRules(policyData.PolicyRules)
	if err := d.Set("policy_rules", policyRules); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Firewall Policy rules", err)
	}

	// v3's GranularFirewallPolicy declares policyLoggingEnabled required, so
	// it is always present on the response — no nil guard needed. The SDK
	// maps our `trace` attribute onto that field.
	if err := d.Set("trace", policyData.PolicyLoggingEnabled); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Firewall Policy trace", err)
	}

	return diags
}

/*
flattenFirewallPolicyRules converts a list of GranularFirewallPolicyRule SDK models to a Terraform-compatible list.
*/
func flattenFirewallPolicyRules(rules []perimeter81Sdk.GranularFirewallPolicyRule) []interface{} {
	if rules == nil {
		return make([]interface{}, 0)
	}
	result := make([]interface{}, len(rules))
	for i, rule := range rules {
		ruleMap := map[string]interface{}{
			"name":        rule.Name,
			"enabled":     rule.Enabled,
			"allowed":     rule.Allowed,
			"services":    rule.Services,
			"log_enabled": rule.LogEnabled,
		}
		if rule.Id != nil {
			ruleMap["id"] = *rule.Id
		} else {
			ruleMap["id"] = ""
		}
		result[i] = ruleMap
	}
	return result
}

/*
firewallPolicyUnrestricted returns the SourcesAndDestinations value that serialises to exactly
`{}` — the wire shape the v3 firewall-policy endpoint requires for "this rule is not restricted
by source (or destination)".

Why this specific value, rather than the obvious ones:

  - The zero value SourcesAndDestinations{} cannot be used. It is a oneOf wrapper whose
    MarshalJSON returns (nil, nil) when no variant is set (see model_sources_and_destinations.go),
    and encoding/json turns a (nil, nil) return into "unexpected end of JSON input". That fails
    inside Execute()'s setBody, so the request never reaches the wire — for every policy_rules
    entry, not just this one.
  - The Addresses variant cannot produce `{}` either. Its only field is
    `Addresses []string` with `json:"addresses"` and no omitempty, so an empty one marshals to
    `{"addresses":[]}` and a nil one to `{"addresses":null}`. Measured live 2026-08-19,
    `{"addresses":[]}` is a 400: `policyRules.0.sources.addresses must contain at least 1
    elements`. The server's validator (sourcesAndDestinations.model.ts) marks each of users /
    groups / addresses `@IsOptional` *and* `@ArrayMinSize(1)`, so the minimum applies only when
    the key is present: omit the key, or send at least one element. Never send it empty.
  - UsersAndGroups has omitempty on both of its fields, so an empty one marshals to `{}` — which
    is what the server accepts (202, measured live 2026-08-19).

Which oneOf variant carries the empty object is invisible on the wire: `{}` names no variant.
The choice of UsersAndGroups here is purely a marshalling detail, not a claim that the rule is
scoped by users or groups. TestPayloadMarshalGranularFirewallPolicy pins the resulting JSON.
*/
func firewallPolicyUnrestricted() perimeter81Sdk.SourcesAndDestinations {
	return perimeter81Sdk.UsersAndGroupsAsSourcesAndDestinations(&perimeter81Sdk.UsersAndGroups{})
}

/*
buildGranularFirewallPolicyRule converts a single policy_rules schema block (as produced by
d.Get("policy_rules").([]interface{})) into a GranularFirewallPolicyRule SDK model. Factored out
of resourceFirewallPolicyUpdate so it can be exercised directly by payload_marshal_test.go — this
is the exact code path that produces Sources/Destinations, so a regression here (e.g. reverting to
the zero-value SourcesAndDestinations{}, or to an empty Addresses list) is caught by marshaling
its output, not just by inspecting schema shape.
*/
func buildGranularFirewallPolicyRule(ruleMap map[string]interface{}) perimeter81Sdk.GranularFirewallPolicyRule {
	rule := perimeter81Sdk.GranularFirewallPolicyRule{
		Name:         ruleMap["name"].(string),
		Enabled:      ruleMap["enabled"].(bool),
		Allowed:      ruleMap["allowed"].(bool),
		LogEnabled:   ruleMap["log_enabled"].(bool),
		Sources:      firewallPolicyUnrestricted(),
		Destinations: firewallPolicyUnrestricted(),
	}
	if v, ok := ruleMap["id"].(string); ok && v != "" {
		rule.Id = &v
	}
	// The len > 0 guard is load-bearing, not defensive. `services` carries the same
	// @IsOptional + @ArrayMinSize(1) pair as sources/destinations (networkPolicyRule.model.ts),
	// and Services has omitempty but is a non-nil empty slice here whenever the user omits the
	// attribute — d.Get returns []interface{}{}, and the SDK's IsNil() reports a non-nil empty
	// slice as present. Assigning it unconditionally therefore sends `"services": []` and earns
	// a 400 for every rule that is not scoped by service.
	if v, ok := ruleMap["services"].([]interface{}); ok && len(v) > 0 {
		rule.Services = flattenStringsArrayData(v)
	}
	return rule
}

/*
resourceFirewallPolicyUpdate Update the Firewall Policy configuration.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceFirewallPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)

	// Read current policy to get the policy ID
	policyData, _, err := client.FirewallPolicyAPI.GetGranularFirewallPolicy(ctx, networkId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read Firewall Policy for update", err)
	}

	enabled := d.Get("enabled").(bool)
	allowed := d.Get("allowed").(bool)

	// Build policy rules from schema
	policyRulesRaw := d.Get("policy_rules").([]interface{})
	policyRules := make([]perimeter81Sdk.GranularFirewallPolicyRule, len(policyRulesRaw))
	for i, ruleRaw := range policyRulesRaw {
		policyRules[i] = buildGranularFirewallPolicyRule(ruleRaw.(map[string]interface{}))
	}

	updatePayload := perimeter81Sdk.GranularFirewallPolicy{
		Id:          policyData.Id,
		Enabled:     enabled,
		Allowed:     allowed,
		PolicyRules: policyRules,
	}

	// v3's GranularFirewallPolicy declares policyLoggingEnabled required, so
	// it is always sent. The SDK maps our `trace` attribute onto that field.
	updatePayload.SetPolicyLoggingEnabled(d.Get("trace").(bool))

	asyncResp, httpResp, err := client.FirewallPolicyAPI.UpdateGranularFirewallPolicy(ctx, networkId).
		GranularFirewallPolicy(updatePayload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to update Firewall Policy", err)
	}
	_ = httpResp

	statusId := getIdFromUrl(asyncResp.GetStatusUrl())
	pollErr := pollAsync(ctx, func(ctx context.Context) (asyncResult, *http.Response, error) {
		status, resp, err := client.NetworksAPI.NetworksControllerV2Status(ctx, statusId).Execute()
		if err != nil {
			return asyncResult{}, resp, err
		}
		out := asyncResult{Completed: status.GetCompleted()}
		if r := status.Result; r != nil {
			out.StatusCode = int(r.GetStatusCode())
			out.Reasons = r.GetReason()
		}
		return out, resp, nil
	}, 10*time.Second, 2)
	if pollErr != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Firewall Policy update did not complete", pollErr)
	}

	return resourceFirewallPolicyRead(ctx, d, m)
}

/*
resourceFirewallPolicyDelete is a no-op since firewall policies cannot be deleted —
they are created automatically with each network. The resource is simply removed from state.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceFirewallPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Firewall policies cannot be deleted — they are auto-created with the network.
	// Remove from state only.
	d.SetId("")
	return nil
}
