package checkpointsase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
firewallPolicyAddressesXOR is the server's own message for the one combination a sources or
destinations block may not contain (updateFirewallRulesGranular.interceptor.ts). It is quoted
verbatim, not paraphrased, so that a user who searches for the string they were shown by
`terraform plan` finds the same string in the API's documentation and support answers — and so
that the plan-time refusal is recognisably the same rule as the 400 it replaces.
*/
const firewallPolicyAddressesXOR = "Addresses can not be in the same object with groups or users"

/*
resourceFirewallPolicy Setup the Firewall Policy Resource CRUD operations.
Firewall policies are auto-created with each network, so this resource "adopts"
the existing policy. There is no Create endpoint; Delete cannot remove the policy
either, and instead clears the rules Terraform created — see
resourceFirewallPolicyDelete for why that is necessary and what it leaves behind.

@return &schema.Resource
*/
func resourceFirewallPolicy() *schema.Resource {
	return &schema.Resource{
		Description: "Manages the firewall policy of a Check Point SASE standard network. " +
			"Adopt-style: the policy is created automatically with its parent network, " +
			"so this resource reads the existing policy and applies your configuration to it. " +
			"**`terraform destroy` clears the policy's rules and then releases the policy from " +
			"state without deleting it.** Clearing the rules is required, not cosmetic: a rule " +
			"holds references to `checkpointsase_object_addresses` and " +
			"`checkpointsase_object_services` objects, and those objects cannot be deleted while " +
			"a rule still names them, so leaving the rules behind makes every dependent object in " +
			"the same destroy fail with `409 CONFLICT: This object cannot be edited or deleted " +
			"because it is currently in use.` Destroy does **not** restore `enabled`, `allowed` " +
			"or `trace` to the values the policy had before Terraform adopted it — the API never " +
			"reported them, so they cannot be restored; they keep whatever was last applied. " +
			"On the v3 API the update is asynchronous, so applies take longer than a " +
			"single request.",
		CreateContext: resourceFirewallPolicyCreate,
		ReadContext:   resourceFirewallPolicyRead,
		UpdateContext: resourceFirewallPolicyUpdate,
		DeleteContext: resourceFirewallPolicyDelete,
		CustomizeDiff: resourceFirewallPolicyCustomizeDiff,
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
				Type:     schema.TypeList,
				Optional: true,
				Description: "List of firewall policy rules. **The order of these blocks is the " +
					"order the firewall evaluates them in**: the API assigns each rule a priority " +
					"from its position in this list, so moving a block changes which rule wins. " +
					"The list is applied wholesale — a rule that is not in your configuration is " +
					"removed from the policy.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Optional:    true,
							Computed:    true,
							Description: "The unique ID of the policy rule. Assigned by the server when the rule is created; supply it only to keep an existing rule's identity. Two rules with the same ID are refused with a 409.",
						},
						"name": {
							Type:         schema.TypeString,
							Required:     true,
							Description:  "The name of the policy rule. Must be 5–50 characters — the API rejects anything shorter or longer.",
							ValidateFunc: validation.StringLenBetween(5, 50),
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
						"sources": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Description: "Restricts where the traffic this rule matches comes from. " +
								"Omit the block to leave the rule unrestricted by source (the API's " +
								"empty `{}`), which is the only way to express \"any source\". " +
								"Set either `addresses`, or `users` and/or `groups` — not `addresses` " +
								"together with either of the other two: the API refuses that with " +
								"`" + firewallPolicyAddressesXOR + "`, and so does `terraform plan`.",
							Elem: firewallPolicyRuleEndpointResource(),
						},
						"destinations": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Description: "Restricts where the traffic this rule matches is going. " +
								"Omit the block to leave the rule unrestricted by destination (the " +
								"API's empty `{}`), which is the only way to express \"any " +
								"destination\". Set either `addresses`, or `users` and/or `groups` — " +
								"not `addresses` together with either of the other two: the API " +
								"refuses that with `" + firewallPolicyAddressesXOR + "`, and so does " +
								"`terraform plan`.",
							Elem: firewallPolicyRuleEndpointResource(),
						},
						"services": {
							Type:     schema.TypeList,
							Optional: true,
							MinItems: 1,
							Description: "IDs of `checkpointsase_object_services` shared objects this rule matches — " +
								"**not** port numbers or protocol names. Pass " +
								"`checkpointsase_object_services.example.id`; a literal like `443` or `tcp/443` " +
								"is rejected by the API. Omit the attribute for a rule that matches every " +
								"service; an explicitly empty list is refused, because the API requires at " +
								"least one element whenever the field is present.",
							Elem: &schema.Schema{Type: schema.TypeString},
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
firewallPolicyRuleEndpointResource is the element schema shared by a rule's `sources` and
`destinations` blocks. Both sides are the same type server-side
(SourcesAndDestinationsResponse), so they get the same three attributes here.

MinItems/MaxItems are the whole of the schema-level validation that is available. The mutual
exclusion between `addresses` and `users`/`groups` cannot be expressed this way: SDKv2's
ExactlyOneOf and ConflictsWith take absolute attribute paths, and every path that could reach
inside `policy_rules` — indexed (`policy_rules.0.sources.0.users`), unindexed, or starred — is
rejected by schema.InternalValidate with "configuration block reference ... can only be used with
TypeList and MaxItems: 1 configuration blocks", because `policy_rules` is a list of many. A
relative sibling name is rejected as an unknown attribute. Measured, not assumed — see
TestFirewallPolicySchemaCannotExpressTheXOR, which fails if a future SDK upgrade makes any of
those forms work and this comment becomes wrong. The exclusion is enforced in
resourceFirewallPolicyCustomizeDiff instead.

MinItems: 1 *is* enforced inside nested blocks (TestFirewallPolicyEmptyListsAreRejectedAtPlanTime
proves it), which matters for more than tidiness: without it, `addresses = []` would be silently
dropped and the rule would widen from "these addresses" to "any address" with no warning.
*/
func firewallPolicyRuleEndpointResource() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"addresses": {
				Type:     schema.TypeList,
				Optional: true,
				MinItems: 1,
				Description: "IDs of `checkpointsase_object_addresses` shared objects — **not** CIDRs, " +
					"IP addresses or hostnames. Pass `checkpointsase_object_addresses.example.id`; a " +
					"literal like `10.0.0.0/8` is rejected by the API. Cannot be combined with `users` " +
					"or `groups` in the same block. Omit the attribute rather than setting it to `[]` — " +
					"the API requires at least one element whenever the field is present.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"users": {
				Type:     schema.TypeList,
				Optional: true,
				MinItems: 1,
				MaxItems: 10,
				Description: "IDs of users. May be combined with `groups`, but not with `addresses`. " +
					"At most 10 — the API enforces that limit. Omit the attribute rather than setting " +
					"it to `[]`.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"groups": {
				Type:     schema.TypeList,
				Optional: true,
				MinItems: 1,
				Description: "IDs of groups. May be combined with `users`, but not with `addresses`. " +
					"Omit the attribute rather than setting it to `[]`.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

/*
firewallPolicyRuleEndpointLists pulls the three lists out of one `sources` or `destinations`
block, returning nil — never an empty slice — for anything absent or empty.

nil rather than empty matters on the write path: UsersAndGroups relies on omitempty to keep an
unused key out of the body, and omitempty drops a nil slice but keeps an empty one. An empty one
would reach the wire as `"users": []` and earn a 400.

raw[0] can be nil for a block written as `sources {}`, so the map assertion is checked rather
than assumed.
*/
func firewallPolicyRuleEndpointLists(raw []interface{}) (addresses, users, groups []string) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	block, ok := raw[0].(map[string]interface{})
	if !ok {
		return nil, nil, nil
	}
	list := func(key string) []string {
		v, ok := block[key].([]interface{})
		if !ok || len(v) == 0 {
			return nil
		}
		return flattenStringsArrayData(v)
	}
	return list("addresses"), list("users"), list("groups")
}

/*
expandFirewallPolicyRuleEndpoint turns one `sources` or `destinations` block into the
SourcesAndDestinations oneOf the API expects.

An absent block, an empty block, and a block whose lists are all empty all mean the same thing —
unrestricted — and all produce `{}`. See firewallPolicyUnrestricted for why that value is what it
is.
*/
func expandFirewallPolicyRuleEndpoint(raw []interface{}) perimeter81Sdk.SourcesAndDestinations {
	addresses, users, groups := firewallPolicyRuleEndpointLists(raw)
	if len(addresses) > 0 {
		return perimeter81Sdk.AddressesAsSourcesAndDestinations(
			&perimeter81Sdk.Addresses{Addresses: addresses})
	}
	if len(users) > 0 || len(groups) > 0 {
		return perimeter81Sdk.UsersAndGroupsAsSourcesAndDestinations(
			&perimeter81Sdk.UsersAndGroups{Users: users, Groups: groups})
	}
	return firewallPolicyUnrestricted()
}

/*
flattenFirewallPolicyRuleEndpoint is the read-side inverse: it turns the SourcesAndDestinations
the API returned back into the zero-or-one element list the schema holds.

Returning an empty list for the unrestricted case is what keeps plans clean. A configuration with
no `sources` block has `sources.# = 0` in state, so emitting a one-element block full of empty
lists here would show as a diff on every plan, forever — the failure mode that made the enhanced
tunnel read shape a release blocker.
*/
func flattenFirewallPolicyRuleEndpoint(sd perimeter81Sdk.SourcesAndDestinations) []interface{} {
	block := map[string]interface{}{}
	if sd.Addresses != nil && len(sd.Addresses.Addresses) > 0 {
		block["addresses"] = sd.Addresses.Addresses
	}
	if sd.UsersAndGroups != nil {
		if len(sd.UsersAndGroups.Users) > 0 {
			block["users"] = sd.UsersAndGroups.Users
		}
		if len(sd.UsersAndGroups.Groups) > 0 {
			block["groups"] = sd.UsersAndGroups.Groups
		}
	}
	if len(block) == 0 {
		return []interface{}{}
	}
	return []interface{}{block}
}

/*
validateFirewallPolicyRules enforces the one rule the schema cannot: within a single `sources` or
`destinations` block, `addresses` excludes `users` and `groups`.

It is called from two places on purpose. resourceFirewallPolicyCustomizeDiff runs it at plan
time, which is where a user should learn about it. resourceFirewallPolicyUpdate runs it again at
apply time, because a list that was entirely unknown while planning (`addresses = var.something`)
reads as absent in a diff and would otherwise slip through to a 400 mid-apply.

The message quotes the server's wording and names the rule index and side, because the server's
own error does not say which rule it means.
*/
func validateFirewallPolicyRules(rules []interface{}) error {
	for i, ruleRaw := range rules {
		ruleMap, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		for _, field := range []string{"sources", "destinations"} {
			raw, ok := ruleMap[field].([]interface{})
			if !ok {
				continue
			}
			addresses, users, groups := firewallPolicyRuleEndpointLists(raw)
			if len(addresses) == 0 || (len(users) == 0 && len(groups) == 0) {
				continue
			}
			return fmt.Errorf("policy_rules.%d.%s: %s. Set either addresses, or users and/or groups, in one %s block — for a rule that needs both, split it into two rules",
				i, field, firewallPolicyAddressesXOR, field)
		}
	}
	return nil
}

/*
resourceFirewallPolicyCustomizeDiff refuses at plan time the source/destination combination the
API refuses at apply time. Destroy plans never reach CustomizeDiff in SDKv2, so an invalid rule
already in state can still be removed.
*/
func resourceFirewallPolicyCustomizeDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	rules, ok := d.Get("policy_rules").([]interface{})
	if !ok {
		return nil
	}
	return validateFirewallPolicyRules(rules)
}

/*
firewallPolicyEndpointWire is the read-side counterpart of one `sources` or `destinations`
object, and exists because the generated SourcesAndDestinations cannot decode two of the three
shapes the server actually returns.

SourcesAndDestinations is a oneOf, and its generated UnmarshalJSON asks each variant in turn
whether the object is "its" shape by unmarshalling and re-marshalling it:

  - `{}` matches nothing. Addresses refuses it (its `addresses` field is required), and an empty
    UsersAndGroups re-marshals to `{}`, which the generated code reads as "empty struct, no
    match". Result: `data failed to match schemas in oneOf(SourcesAndDestinations)`.
  - `{"addresses":[...]}` matches twice. Addresses matches legitimately; UsersAndGroups also
    "matches", because it has no required fields and captures `addresses` into
    AdditionalProperties, so it re-marshals to something non-empty. Result:
    `data matches more than one schema in oneOf(SourcesAndDestinations)`.
  - `{"users":[...]}`, `{"groups":[...]}` and the two together are the only shapes that decode.

That error surfaces from GetGranularFirewallPolicy as a decode failure on a 200, which fails
Read for every policy containing a rule that is either unrestricted or scoped by address — in
other words, for almost every policy this resource can now create. The defect is in the generated
SDK (a spec-level fix would be to stop modelling this object as a oneOf: server-side it is one
class with three optional arrays, sourcesAndDestinations.model.ts), so it cannot be fixed from
here. getGranularFirewallPolicy falls back to this type instead, which is a faithful decode of
the documented response and needs no oneOf discrimination at all.
*/
type firewallPolicyEndpointWire struct {
	Users     []string `json:"users,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}

/*
toSDK converts a decoded endpoint object into the SDK's oneOf, so that everything downstream of
the read — flattenFirewallPolicyRuleEndpoint, and the acceptance tests' assertions — works
against one type regardless of which decoder produced it.

The server enforces the addresses/users+groups exclusion on write, so no response can legally
contain both; addresses is checked first and wins if one ever does.
*/
func (w firewallPolicyEndpointWire) toSDK() perimeter81Sdk.SourcesAndDestinations {
	if len(w.Addresses) > 0 {
		return perimeter81Sdk.AddressesAsSourcesAndDestinations(
			&perimeter81Sdk.Addresses{Addresses: w.Addresses})
	}
	if len(w.Users) > 0 || len(w.Groups) > 0 {
		return perimeter81Sdk.UsersAndGroupsAsSourcesAndDestinations(
			&perimeter81Sdk.UsersAndGroups{Users: w.Users, Groups: w.Groups})
	}
	return firewallPolicyUnrestricted()
}

// firewallPolicyRuleWire is one element of the response's policyRules array.
type firewallPolicyRuleWire struct {
	Id           *string                    `json:"id,omitempty"`
	Name         string                     `json:"name"`
	Enabled      bool                       `json:"enabled"`
	Allowed      bool                       `json:"allowed"`
	Sources      firewallPolicyEndpointWire `json:"sources"`
	Destinations firewallPolicyEndpointWire `json:"destinations"`
	Services     []string                   `json:"services,omitempty"`
	LogEnabled   bool                       `json:"logEnabled"`
}

// firewallPolicyWire is the whole GET /v3/networks/{networkId}/firewall-policy response body.
type firewallPolicyWire struct {
	Id                   string                   `json:"id"`
	Enabled              bool                     `json:"enabled"`
	Allowed              bool                     `json:"allowed"`
	PolicyLoggingEnabled bool                     `json:"policyLoggingEnabled"`
	PolicyRules          []firewallPolicyRuleWire `json:"policyRules"`
}

/*
decodeGranularFirewallPolicy decodes a firewall-policy response body into the SDK model without
going through the oneOf decoder that cannot represent it.

An empty `id` is treated as a failed decode rather than as a policy with no ID: the field is
required in the response, so its absence means this body is not a firewall policy — an error
envelope returned with a 200, say — and silently adopting a zero-valued policy would be worse
than reporting the original decode error.
*/
func decodeGranularFirewallPolicy(body []byte) (*perimeter81Sdk.GranularFirewallPolicy, error) {
	var wire firewallPolicyWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, err
	}
	if wire.Id == "" {
		return nil, fmt.Errorf("response carries no policy id, so it is not a firewall policy body")
	}

	policy := &perimeter81Sdk.GranularFirewallPolicy{
		Id:                   wire.Id,
		Enabled:              wire.Enabled,
		Allowed:              wire.Allowed,
		PolicyLoggingEnabled: wire.PolicyLoggingEnabled,
		PolicyRules:          make([]perimeter81Sdk.GranularFirewallPolicyRule, len(wire.PolicyRules)),
	}
	for i, rule := range wire.PolicyRules {
		policy.PolicyRules[i] = perimeter81Sdk.GranularFirewallPolicyRule{
			Id:           rule.Id,
			Name:         rule.Name,
			Enabled:      rule.Enabled,
			Allowed:      rule.Allowed,
			Sources:      rule.Sources.toSDK(),
			Destinations: rule.Destinations.toSDK(),
			Services:     rule.Services,
			LogEnabled:   rule.LogEnabled,
		}
	}
	return policy, nil
}

/*
getGranularFirewallPolicy is the single read entry point for this resource: the SDK call, plus a
fallback for the one failure mode the SDK's generated oneOf decoder cannot avoid (see
firewallPolicyEndpointWire).

The fallback is deliberately narrow. It engages only when the request itself succeeded — a
non-nil response with a status below 300 — and only when the SDK handed back the body it failed
to decode. Anything else, including a genuinely malformed body, returns the original error
unchanged, so a real API failure is never reported as a decode quirk. When the SDK is fixed the
primary path simply starts succeeding and this code stops running, with no behaviour change.
*/
func getGranularFirewallPolicy(ctx context.Context, client *perimeter81Sdk.APIClient, networkId string) (*perimeter81Sdk.GranularFirewallPolicy, *http.Response, error) {
	policy, httpResp, err := client.FirewallPolicyAPI.GetGranularFirewallPolicy(ctx, networkId).Execute()
	if err == nil {
		return policy, httpResp, nil
	}
	if httpResp == nil || httpResp.StatusCode >= http.StatusMultipleChoices {
		return policy, httpResp, err
	}
	apiErr, ok := err.(*perimeter81Sdk.GenericOpenAPIError)
	if !ok || len(apiErr.Body()) == 0 {
		return policy, httpResp, err
	}
	decoded, decodeErr := decodeGranularFirewallPolicy(apiErr.Body())
	if decodeErr != nil {
		return policy, httpResp, err
	}
	return decoded, httpResp, nil
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
	if _, _, err := getGranularFirewallPolicy(ctx, client, networkId); err != nil {
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

	policyData, _, err := getGranularFirewallPolicy(ctx, client, networkId)
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
			// sources/destinations were dropped here until 2026-08-19. The read model
			// carries them — Sources and Destinations are required fields on the same
			// struct used for writes — so leaving them out meant every plan reported a
			// diff on a rule that had not changed, even once Create worked.
			"sources":      flattenFirewallPolicyRuleEndpoint(rule.Sources),
			"destinations": flattenFirewallPolicyRuleEndpoint(rule.Destinations),
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
	// The two lookups are guarded because payload tests and older callers build a rule map
	// without these keys; both fields already hold the unrestricted `{}` value in that case.
	if v, ok := ruleMap["sources"].([]interface{}); ok {
		rule.Sources = expandFirewallPolicyRuleEndpoint(v)
	}
	if v, ok := ruleMap["destinations"].([]interface{}); ok {
		rule.Destinations = expandFirewallPolicyRuleEndpoint(v)
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
	policyData, _, err := getGranularFirewallPolicy(ctx, client, networkId)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read Firewall Policy for update", err)
	}

	enabled := d.Get("enabled").(bool)
	allowed := d.Get("allowed").(bool)

	// Build policy rules from schema
	policyRulesRaw := d.Get("policy_rules").([]interface{})
	// Backstop for values that were unknown at plan time and so invisible to CustomizeDiff.
	if err := validateFirewallPolicyRules(policyRulesRaw); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Invalid Firewall Policy rule", err)
	}
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

	// The two summaries are kept apart deliberately: "the API refused the request" and "the API
	// accepted the request and the operation then failed or never finished" send a reader to
	// different places, and this resource's diagnostics are the only trace of either.
	if accepted, err := putGranularFirewallPolicy(ctx, client, networkId, updatePayload); err != nil {
		d.Partial(true)
		if accepted {
			return appendErrorDiags(diags, "Firewall Policy update did not complete", err)
		}
		return appendErrorDiags(diags, "Unable to update Firewall Policy", err)
	}

	return resourceFirewallPolicyRead(ctx, d, m)
}

/*
putGranularFirewallPolicy sends one PUT /v3/networks/{networkId}/firewall-policy and waits for the
async operation it starts to finish.

Factored out of resourceFirewallPolicyUpdate so Delete can reuse it. The waiting is the reason it
exists as a function rather than being duplicated: UpdateGranularFirewallPolicy returns an
AsyncOperationResponse, so the policy has *not* changed when the call returns. Three shipped bugs
on this branch came from treating an AsyncOperationResponse as a completed write — the caller reads
back pre-write values and stores them as if the write had never happened. Delete has the same
exposure with a worse symptom: it would return before the rules were actually gone, and the object
deletes Terraform runs immediately afterwards would still hit 409 "currently in use".

@return bool - whether the API accepted the request (true once the PUT itself succeeded, so a
non-nil error alongside true means the accepted operation failed or never completed)
@return error - the first failure, if any
*/
func putGranularFirewallPolicy(ctx context.Context, client *perimeter81Sdk.APIClient, networkId string, payload perimeter81Sdk.GranularFirewallPolicy) (bool, error) {
	asyncResp, _, err := client.FirewallPolicyAPI.UpdateGranularFirewallPolicy(ctx, networkId).
		GranularFirewallPolicy(payload).Execute()
	if err != nil {
		return false, err
	}

	// statusUrl is optional on AsyncOperationResponse. A missing one must not turn a successful
	// write into a 404 against the status endpoint, so poll only when there is something to poll.
	statusId := getIdFromUrl(asyncResp.GetStatusUrl())
	if statusId == "" {
		return false, nil
	}
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
		return true, pollErr
	}
	return true, nil
}

/*
buildGranularFirewallPolicyClear turns a policy just read from the API into the PUT body that
removes all of its rules and changes nothing else.

Factored out of resourceFirewallPolicyDelete so payload_marshal_test.go can pin the resulting JSON.
Two things about this body are invisible to any test that does not marshal it:

  - policyRules must be a non-nil empty slice. GranularFirewallPolicy.ToMap writes the key
    unconditionally, so a nil slice reaches the wire as `"policyRules": null`, which is not an array
    and fails the endpoint's @IsArray. `[]` is what clears the rules.
  - the three scalars are copies of what the read returned, so the write is a no-op on everything
    except the rules. A regression to hardcoded defaults would still marshal cleanly and would still
    clear the rules — it would just silently rewrite the policy's switches on every destroy.
*/
func buildGranularFirewallPolicyClear(policy *perimeter81Sdk.GranularFirewallPolicy) perimeter81Sdk.GranularFirewallPolicy {
	return perimeter81Sdk.GranularFirewallPolicy{
		Id:                   policy.Id,
		Enabled:              policy.Enabled,
		Allowed:              policy.Allowed,
		PolicyLoggingEnabled: policy.PolicyLoggingEnabled,
		PolicyRules:          []perimeter81Sdk.GranularFirewallPolicyRule{},
	}
}

/*
resourceFirewallPolicyDelete clears the policy's rules, then removes the resource from state.

The policy object itself genuinely cannot be deleted — it is created implicitly with the network
and there is no DELETE endpoint. But the *rules* are what Terraform created, and they are what
makes destroy fail: a rule holds references to `checkpointsase_object_addresses` and
`checkpointsase_object_services` objects, and while a rule references an object the object cannot
be removed. Removing this resource from state without clearing the rules leaves them behind, and
every dependent object destroyed afterwards in the same run answers

	409 CONFLICT: This object cannot be edited or deleted because it is currently in use.

Measured 2026-08-19: TestAccFirewallPolicy_basic applied every step, then its post-test destroy
failed with three such 409s. Note this only became reachable with commit 1cfe921, which added the
sources/destinations schema — before it, no rule could name an object, so nothing was ever pinned.

`policyRules: []` is the sanctioned way to clear them, not an approximation:
networkPolicyGranularUpdate.model.ts declares policyRules with @IsNestedArray and no minimum, so an
empty array validates; and the update path is a full replace (the interceptor rebuilds the rule set
from the request body alone and POSTs it to firewall/apply-policy, reading nothing back), so rules
absent from the array are dropped rather than merged. A probe on 2026-08-19 confirmed a
freshly-created network's policy is exactly
{"enabled":false,"allowed":true,"policyLoggingEnabled":false,"policyRules":[]}, so clearing rules
returns the policy to the shape a network is born with.

The three scalars are echoed back from the read, not reset and not taken from state. The PUT
requires all of enabled / allowed / policyLoggingEnabled (each @IsBoolean with no @IsOptional), so
something must be sent; the question is only what. This resource *adopts* a policy it did not
create and never records the values it had before adoption, so it cannot restore them. Of the three
candidates:

  - Echo the server's current values (chosen). The write is then a no-op on everything except the
    rules, which is the narrowest change that fixes the 409s. It also cannot clobber a value that
    someone changed outside Terraform between the last apply and the destroy.
  - Reset to the observed new-network defaults (false / true / false). This looks like "restore",
    but it is a guess that the defaults of a *fresh* network were this policy's prior values — false
    for any network whose policy was configured before Terraform adopted it, and silently
    destructive on destroy, which is the last place a user is watching.
  - Send the values in Terraform state. Strictly worse than echoing: state is what Terraform last
    wrote, so it reproduces the adopted-and-modified values while adding a staleness window.

The consequence to be honest about: after destroy the policy keeps whatever enabled / allowed /
policyLoggingEnabled Terraform last applied. Destroy releases the objects and removes the rules; it
does not undo the policy-level switches. That is a limitation of adopting an undeletable object, and
it is documented on the resource rather than papered over.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceFirewallPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get("network_id").(string)

	policyData, httpResp, err := getGranularFirewallPolicy(ctx, client, networkId)
	if err != nil {
		// A policy exists only as part of its network, so a 404 here means the network is already
		// gone and the rules with it. Nothing to release; treat it as done rather than stranding
		// the resource in state forever.
		if isNotFound(httpResp, err) {
			d.SetId("")
			return diags
		}
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read Firewall Policy for delete", err)
	}

	// No rules means nothing pins a dependent object, so there is nothing to clear and no reason to
	// spend a write and an async poll on every destroy.
	if len(policyData.PolicyRules) == 0 {
		d.SetId("")
		return diags
	}

	clearPayload := buildGranularFirewallPolicyClear(policyData)

	// The failure must surface. Swallowing it would put the resource's own destroy back to "success"
	// while leaving the rules in place, and the 409s would then land on the object resources
	// destroyed after this one — which is exactly the confusing failure this change exists to fix.
	if accepted, err := putGranularFirewallPolicy(ctx, client, networkId, clearPayload); err != nil {
		d.Partial(true)
		if accepted {
			return appendErrorDiags(diags, "Firewall Policy rule clearing did not complete", err)
		}
		return appendErrorDiags(diags, "Unable to clear Firewall Policy rules for delete", err)
	}

	d.SetId("")
	return diags
}
