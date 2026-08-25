package checkpointsase

import (
	"context"
	"errors"
	"net/http"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
private_dns.go holds what the two enhanced private-DNS resources
(checkpointsase_enhanced_network_private_dns and
checkpointsase_enhanced_region_private_dns) share: the async PUT, the expander
that builds its body, and the flattener that reads the result back.

They share it because the request and response models are literally the same
types -- CustomDnsUpdate in, CustomDns out -- and only the SDK call and the id
differ between the two. Two copies of the async wait would be two places for the
"a 202 is not a completed write" bug to come back.
*/

/*
THE ATTRIBUTE NAMES ARE CONSTANTS, AND privateDNSSchema DECLARES THEM.

Both are here for one reason: expandCustomDnsUpdate reads the resource's
attributes by name, and a name it reads that the schema does not declare returns
a zero value with no error, no diff and nothing in the logs. This codebase has
shipped that exact class of defect repeatedly -- a flattener that never assigned
routingType and sent `""` against a required enum, a flattener that dropped an
unknown bucket, a diagnostic whose guidance never reached the wire. Every one
looked right in review.

Declaring the schema and reading it through the same constants makes the mismatch
unrepresentable rather than merely unlikely: there is one spelling of each name in
the package, so a rename is one edit and a typo is a compile error. The residual
risk -- a NEW attribute added to the schema that no expander reads -- is what
TestPrivateDNSSchemaDeclaresExactlyTheAttributesTheExpanderReads catches.

Tasks 2 and 3 must call privateDNSSchema and add only their own address
attributes (network_id, plus region_id for the region resource). Restating any of
this in a resource file re-opens the hole.
*/
const (
	privateDNSAttrEnabled        = "enabled"
	privateDNSAttrAttributes     = "attributes"
	privateDNSAttrServers        = "servers"
	privateDNSAttrAddress        = "address"
	privateDNSAttrIsTLS          = "is_tls"
	privateDNSAttrSearchDomains  = "search_domains"
	privateDNSAttrDNSPolicy      = "dns_policy"
	privateDNSAttrPublic         = "public"
	privateDNSAttrPrivate        = "private"
	privateDNSAttrDomains        = "domains"
	privateDNSAttrMode           = "mode"
	privateDNSAttrPublicFallback = "public_fallback"
)

/*
privateDNSPrivateModes are the two values dnsPolicy.private.mode admits
(swagger.yaml:4616).

Validated case-SENSITIVELY -- validation.StringInSlice(..., false) -- because this
API does not fold case on enums and a case-insensitive check would let
"matchpattern" through plan and fail 15 minutes into an apply. That is the Phase 3
`access` / `"Read"` lesson; nothing here has been measured against a wrong-case
value, so the strict reading is the safe one.
*/
var privateDNSPrivateModes = []string{"matchPattern", "resolveAllViaPrivate"}

/*
privateDNSSchema returns the attributes both enhanced private-DNS resources
share: `enabled` and the `attributes` block under it.

It is the whole resource schema bar the object's address. Callers add `network_id`
(and `region_id`), because that is the only thing that differs between them --
the request and response models are literally the same types.

EVERY LIMIT HERE IS SOURCED, NOT CHOSEN:

  - servers / search_domains maxItems 4 (swagger.yaml:4489, :4496), and the live
    400 in API-FINDINGS.md 1.31 quotes "attributes.servers must contain not more
    than 4 elements", so the spec and the server agree.
  - dns_policy.public.domains and .private.domains maxItems 100
    (swagger.yaml:4601, :4626) -- NOT 4. The plan's Task 2 Step 1 implies 4 for
    every list here; the spec does not.
  - `domains` is Required inside `public` and `private`, and `mode` and
    `public_fallback` are Required inside `private` (swagger.yaml:4595, :4609).
    The blocks themselves are optional; what is required is required only once you
    write one.
  - MinItems is 0 everywhere. No array here carries a minItems, and for anything
    an operator can clear, [] is the only way to clear it.

TWO RULES ARE NOT EXPRESSIBLE IN A SCHEMA and remain the resources' to add, in a
shared CustomizeDiff, so they are recorded here rather than lost:

  - servers must be non-empty WHEN enabled is true ("must contain at least one
    entry when enabled is true", swagger.yaml:4492) and may be empty when it is
    false -- API-FINDINGS.md 1.31 measured {"enabled": false, ...servers: []} as a
    202. A conditional minimum is not MinItems, and setting MinItems: 1 here would
    make the legal "off" body unwritable.
  - servers, search_domains and both domains lists are uniqueItems
    (swagger.yaml:4488, :4495, :4600, :4625). helper/schema has no uniqueItems for
    a TypeList, and the order these arrive in is meaningful (API-FINDINGS.md 1.31:
    the write round-trips byte-exactly, non-alphabetical order preserved), so a
    TypeSet would be wrong. Uniqueness therefore has to be a diff-time check.

Descriptions are mandatory: TestSchemaEveryAttributeHasADescription walks every
registered resource and fails on a blank one, so writing them here is what stops
Tasks 2 and 3 inheriting a failure they did not cause.

Tasks 2 and 3 will each still need their own listAttributeEmptyPolicy entries --
that map is keyed by resource name, so a shared schema cannot supply them. All
four list attributes below are mayBeEmpty.

@return map[string]*schema.Schema - `enabled` and `attributes`
*/
func privateDNSSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		privateDNSAttrEnabled: {
			Type:        schema.TypeBool,
			Required:    true,
			Description: "Whether private DNS is enabled for this network or region.",
		},
		privateDNSAttrAttributes: {
			Type:     schema.TypeList,
			Optional: true,
			MaxItems: 1,
			Description: "Private DNS configuration. May be omitted when `enabled` is false; the " +
				"provider still sends the empty servers and search domain arrays the API requires " +
				"on every write.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					privateDNSAttrServers: {
						Type:     schema.TypeList,
						Optional: true,
						MaxItems: 4,
						Description: "Private DNS servers, in priority order. Must contain at " +
							"least one entry when `enabled` is true. Addresses must be unique.",
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								privateDNSAttrAddress: {
									Type:        schema.TypeString,
									Required:    true,
									Description: "IP address of the DNS server.",
								},
								privateDNSAttrIsTLS: {
									Type:     schema.TypeBool,
									Optional: true,
									// Required in the spec, Optional here: the
									// only value an omitted bool can mean is
									// false, which is what the server stores and
									// what it returns (measured: isTLS comes back
									// even when false), so requiring every
									// operator to write `is_tls = false` would buy
									// nothing.
									Description: "Whether DNS-over-TLS is used for this server. Defaults to false.",
								},
							},
						},
					},
					privateDNSAttrSearchDomains: {
						Type:     schema.TypeList,
						Optional: true,
						MaxItems: 4,
						Description: "DNS search domains, in the order they should be tried. " +
							"Sent as an empty array when unset; entries must be unique.",
						Elem: &schema.Schema{Type: schema.TypeString},
					},
					privateDNSAttrDNSPolicy: {
						Type:     schema.TypeList,
						Optional: true,
						MaxItems: 1,
						Description: "Per-domain DNS policy. Omitting this block clears any policy " +
							"already configured, because the write is a full replacement.",
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								privateDNSAttrPublic: {
									Type:        schema.TypeList,
									Optional:    true,
									MaxItems:    1,
									Description: "Domains resolved via public DNS.",
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											privateDNSAttrDomains: {
												Type:        schema.TypeList,
												Required:    true,
												MaxItems:    100,
												Description: "Domains to resolve via public DNS. Entries must be unique.",
												Elem:        &schema.Schema{Type: schema.TypeString},
											},
										},
									},
								},
								privateDNSAttrPrivate: {
									Type:        schema.TypeList,
									Optional:    true,
									MaxItems:    1,
									Description: "Domains resolved via the private DNS servers.",
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											privateDNSAttrMode: {
												Type:         schema.TypeString,
												Required:     true,
												ValidateFunc: validation.StringInSlice(privateDNSPrivateModes, false),
												Description: "DNS resolution mode for private domains. One of " +
													"`matchPattern` or `resolveAllViaPrivate`. Case-sensitive.",
											},
											privateDNSAttrPublicFallback: {
												Type:        schema.TypeBool,
												Required:    true,
												Description: "Whether to fall back to public DNS when private DNS fails.",
											},
											privateDNSAttrDomains: {
												Type:        schema.TypeList,
												Required:    true,
												MaxItems:    100,
												Description: "Private domains. Entries must be unique.",
												Elem:        &schema.Schema{Type: schema.TypeString},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

/*
privateDNSPollInterval is the cadence putPrivateDNSAndWait polls the status
endpoint at. It matches putGranularFirewallPolicy's hardcoded 10s deliberately:
this task is a new call site for an existing pattern, not a retiming of it.

MEASURED AND NOT ACTED ON: every async 202 on this API carries
`samplingTime: 120` (API-FINDINGS.md 1.28) -- the server stating a sampling
cadence an order of magnitude larger than what every poller in this provider
uses. Honouring it is a change to make once, across all of them, with each path's
own value read rather than assumed from the network-create measurement. Doing it
here alone would leave this one endpoint twelve times slower to converge than its
neighbours, for no reason a reader of this file could see.

It is a var rather than a const solely so private_dns_test.go can collapse it and
drive a three-poll operation in microseconds instead of twenty seconds. Nothing
in the provider assigns it.
*/
var privateDNSPollInterval = 10 * time.Second

// privateDNSTransientBudget allows two 5xx/EOF blips per operation, matching the
// transient budgets in async.go.
const privateDNSTransientBudget = 2

/*
errPrivateDNSNoStatusUrl is returned when the API accepts the PUT with a 202 that
carries no statusUrl, so there is nothing to poll.

THIS IS A DELIBERATE CHOICE AND IT DIFFERS FROM putGranularFirewallPolicy, which
returns (false, nil) in the same situation -- i.e. silently does not wait, and
reports the apply as successful. This helper exists for exactly one reason: a 202
means the write has NOT happened yet. A 202 with nothing to poll is therefore a
write this provider cannot confirm, and reporting an unconfirmable write as a
successful apply is the failure the whole helper is against.

The cost is a false failure if the server ever legitimately returns a 202 with no
statusUrl for a write that did land. Nine probes on 2026-08-26 never saw one:
every async 202 measured carried a statusUrl (API-FINDINGS.md 1.28). If that
changes, revisit this as the decision it is, rather than "fixing" it back to match
the firewall-policy path.
*/
var errPrivateDNSNoStatusUrl = errors.New(
	"the API accepted the private DNS update with a 202 that carried no statusUrl, " +
		"so the operation could not be followed to completion and this provider cannot " +
		"confirm the write landed")

/*
putPrivateDNSAndWait sends one PUT .../privateDNS and waits for the async
operation it starts.

THE WAIT IS NOT OPTIONAL AND IS NOT WHAT THE MILESTONE SPEC ASSUMED. The spec
calls these Pattern B singletons, which elsewhere in this provider
(checkpointsase_support_options) means a synchronous PUT. Both enhanced private
DNS PUTs declare ONLY a 202 -- there is no 200 in either response map
(swagger.yaml:633, :699) -- so the write has NOT happened when the call returns.
Reading back immediately stores pre-write values as if the apply succeeded, which
is the failure putGranularFirewallPolicy's comment records shipping three times.

THE statusUrl IS NOT FOLLOWED, AND THAT IS THE POINT. Measured 2026-08-26
(API-FINDINGS.md 1.28): the statusUrl in a 202 body is absolute, names a host the
request did not go to, and carries an /api/rest/v2.3/ path rather than /v3/. Only
its last path segment is used, resolved against the configured client, exactly as
getIdFromUrl does at the other twelve call sites. Following the field literally
would leave the operator's configured BASE_URL -- which exists so a non-US tenant
talks to its own region -- and poll whatever tenant lives at the other host. It
would do so invisibly, because that deployment answers with a well-formed
{"completed":...} too.

The status endpoint is /v3/networks/status/{statusId}. THIS IS ASSUMED, NOT
MEASURED (probe P6): the firewall-policy path on the same /v3/networks/{networkId}/
prefix resolves there, and 202_Accepted is one shared response component, but no
capture of a private-DNS statusUrl being polled exists. If a probe shows a
different path, this is the one line to change.

`send` is the caller's already-built SDK call, so the two enhanced resources share
the waiting without sharing a request builder -- one takes networkId, the other
networkId and regionId, and neither shape belongs in here.

CALLERS MUST RENDER A NON-NIL err THROUGH appendErrorDiagsWithGuidance, NOT
appendErrorDiags. Errors out of here are GenericOpenAPIErrors or wrap one, and
appendErrorDiags promotes the server's response body into Detail and discards
whatever the caller wrapped it with -- so guidance attached at the call site would
never reach the wire.

  - @param ctx context.Context - propagated into the poll, so a Terraform timeout
    produces a deadline error rather than a hang or a false success
  - @param client *perimeter81Sdk.APIClient - the configured client, which is what
    the status id is resolved against
  - @param send func - the caller's already-built PUT

@return bool - whether the API accepted the request. True once the PUT itself
succeeded, so a non-nil error alongside true means the accepted operation failed,
never completed, or could not be followed. The two cases pick different caller
summaries: "the API refused the request" sends a reader somewhere else entirely
from "the API accepted the request and the operation then failed".
@return error - the first failure, if any
*/
func putPrivateDNSAndWait(
	ctx context.Context,
	client *perimeter81Sdk.APIClient,
	send func(context.Context) (*perimeter81Sdk.AsyncOperationResponse, *http.Response, error),
) (bool, error) {
	asyncResp, _, err := send(ctx)
	if err != nil {
		return false, err
	}

	statusId := getIdFromUrl(asyncResp.GetStatusUrl())
	if statusId == "" {
		return true, errPrivateDNSNoStatusUrl
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
	}, privateDNSPollInterval, privateDNSTransientBudget)
	if pollErr != nil {
		return true, withStatusID(statusId, pollErr)
	}
	return true, nil
}

/*
expandCustomDnsUpdate builds the full-replacement PUT body from resource data.

THE PUT IS A FULL REPLACEMENT, NEVER A DIFF. The operation description is
explicit: "This is a full replacement: always send the complete desired
configuration. Any field omitted from `attributes` (such as `searchDomains`) is
cleared, not preserved -- to keep current values, resend the full object returned
by the corresponding GET endpoint." So this reads every attribute the resource
declares on every call, including the ones Terraform reports as unchanged.

`attributes` IS ALWAYS SENT, EVEN WHEN DISABLING. Measured 2026-08-26
(API-FINDINGS.md 1.31): `{"enabled": false}` on its own is a 422, and it is
exactly what GET .../privateDNS returns for an unconfigured network -- so the read
body cannot be echoed back as a write, which is what the quoted description above
tells you to do. The legal "off" body is
`{"enabled": false, "attributes": {"servers": [], "searchDomains": []}}`.

EVERY ARRAY IS EMPTY, NEVER NIL. Servers and SearchDomains are declared without
omitempty (model_custom_dns_update_attributes.go:23), as are
DnsPolicyPublic.Domains and DnsPolicyPrivate.Domains, so a nil slice reaches the
wire as `"servers": null` -- not an array, and the endpoint's @IsArray answers 400
`attributes.servers must be an array`. Both variants compile and both marshal
without error, which is why payload_marshal_test.go pins the body and not the
struct.

The attribute keys read here are the contract between this file and the two
resources that call it: `enabled`, and inside a single `attributes` block,
`servers` (of `address` / `is_tls`), `search_domains`, and `dns_policy`
(`public.domains`, and `private.mode` / `private.public_fallback` /
`private.domains`). A resource that spells one of them differently sends a zero
value for it silently -- this cannot tell a renamed key from an unset one.
testPrivateDNSResourceSchema in private_dns_test.go mirrors them.

  - @param d *schema.ResourceData - the resource data

@return perimeter81Sdk.CustomDnsUpdate - the complete PUT body
*/
func expandCustomDnsUpdate(d *schema.ResourceData) perimeter81Sdk.CustomDnsUpdate {
	payload := perimeter81Sdk.CustomDnsUpdate{
		Enabled: d.Get(privateDNSAttrEnabled).(bool),
		Attributes: perimeter81Sdk.CustomDnsUpdateAttributes{
			// Non-nil so the "off" body, and any config that fills one list and
			// not the other, marshal as `[]`. Overwritten below when the
			// attributes block carries values.
			Servers:       []perimeter81Sdk.CustomDnsServer{},
			SearchDomains: []string{},
		},
	}

	block, ok := singleBlock(d.Get(privateDNSAttrAttributes))
	if !ok {
		return payload
	}

	payload.Attributes.Servers = expandCustomDnsServers(block[privateDNSAttrServers])
	searchDomains, _ := block[privateDNSAttrSearchDomains].([]interface{})
	payload.Attributes.SearchDomains = flattenStringsArrayData(searchDomains)
	payload.Attributes.DnsPolicy = expandDnsPolicy(block[privateDNSAttrDNSPolicy])

	return payload
}

/*
singleBlock unwraps a MaxItems: 1 block into the map it holds.

Absent and present-but-empty are different answers here, and the difference is
not obvious from the values. helper/schema represents a block the operator WROTE
with nothing set inside it as a one-element list whose element is nil -- not as a
map of zero values, and not as an empty list. Measured on this file's own schema:

	dns_policy { public {} private { mode = "matchPattern" } }
	-> "public": []interface{}{interface{}(nil)}
	   "private": []interface{}{map[string]interface{}{"mode":"matchPattern", ...}}

So `public {}` and no `public` block at all differ only by that nil element, and a
bare items[0].(map[string]interface{}) both panics on it and, guarded with the
usual `, ok` and a `return false`, silently drops a block the operator wrote. This
reports it as PRESENT with nothing in it, which is what it is; every caller reads
through map lookups, and a lookup on a nil map is legal and yields the same zero
value an unset attribute would.

Only an absent block and one written as an empty list report false.

  - @param raw interface{} - the value d.Get returned for the block

@return map[string]interface{} - the block's attributes, empty if it set none
@return bool - whether the operator wrote the block at all
*/
func singleBlock(raw interface{}) (map[string]interface{}, bool) {
	items, ok := raw.([]interface{})
	if !ok || len(items) == 0 {
		return nil, false
	}
	block, ok := items[0].(map[string]interface{})
	if !ok {
		return map[string]interface{}{}, true
	}
	return block, true
}

/*
expandCustomDnsServers builds the `servers` array.

It is always non-nil, so it marshals as `[]` rather than `null` -- see
expandCustomDnsUpdate for why that difference is a 400.

  - @param raw interface{} - the value d.Get returned for `servers`

@return []perimeter81Sdk.CustomDnsServer - the servers, empty rather than nil
*/
func expandCustomDnsServers(raw interface{}) []perimeter81Sdk.CustomDnsServer {
	items, _ := raw.([]interface{})

	servers := make([]perimeter81Sdk.CustomDnsServer, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		address, _ := entry[privateDNSAttrAddress].(string)
		isTLS, _ := entry[privateDNSAttrIsTLS].(bool)
		servers = append(servers, perimeter81Sdk.CustomDnsServer{
			Address: address,
			IsTLS:   isTLS,
		})
	}
	return servers
}

/*
expandDnsPolicy builds the optional `dnsPolicy` sub-object.

It returns nil -- keeping the key off the wire entirely, since DnsPolicy is a
pointer with omitempty -- when the config carries no dns_policy block, and also
when a block is present but names neither `public` nor `private`. An empty
`dnsPolicy: {}` is a shape no probe has sent and the schema does not ask for, so
the narrower reading is the safe one: an empty block is the same configuration as
no block.

This interacts with the full-replacement contract above: a config that drops its
dns_policy block CLEARS the policy rather than leaving it alone. That is what the
operation description says omission means, and what an operator deleting a block
from HCL expects.

  - @param raw interface{} - the value d.Get returned for `dns_policy`

@return *perimeter81Sdk.DnsPolicy - the policy, or nil to omit the key
*/
func expandDnsPolicy(raw interface{}) *perimeter81Sdk.DnsPolicy {
	block, ok := singleBlock(raw)
	if !ok {
		return nil
	}

	policy := perimeter81Sdk.DnsPolicy{}
	if publicBlock, ok := singleBlock(block[privateDNSAttrPublic]); ok {
		domains, _ := publicBlock[privateDNSAttrDomains].([]interface{})
		policy.Public = &perimeter81Sdk.DnsPolicyPublic{
			Domains: flattenStringsArrayData(domains),
		}
	}
	if privateBlock, ok := singleBlock(block[privateDNSAttrPrivate]); ok {
		mode, _ := privateBlock[privateDNSAttrMode].(string)
		publicFallback, _ := privateBlock[privateDNSAttrPublicFallback].(bool)
		domains, _ := privateBlock[privateDNSAttrDomains].([]interface{})
		policy.Private = &perimeter81Sdk.DnsPolicyPrivate{
			Mode:           mode,
			PublicFallback: publicFallback,
			Domains:        flattenStringsArrayData(domains),
		}
	}

	if policy.Public == nil && policy.Private == nil {
		return nil
	}
	return &policy
}

/*
flattenCustomDnsAttributes maps the enhanced read model into the `attributes`
block.

A NIL a IS THE NORMAL CASE, NOT AN EDGE CASE. Measured 2026-08-26
(API-FINDINGS.md 1.31): GET .../privateDNS on a network that has never been
configured returns exactly `{"enabled": false}`, with no `attributes` key, which
CustomDns decodes to a nil *CustomDnsAttributes. That is every Read before the
first apply lands, so a flattener that dereferences it panics the provider on the
ordinary path rather than on a rare one.

ORDER IS PRESERVED, NOT SORTED. The same measurement found this endpoint unusually
well-behaved: two servers with different isTLS values and two search domains sent
in deliberately non-alphabetical order came back in the order sent, with nothing
reordered, deduplicated or normalised. Unlike API-FINDINGS.md 1.15 there is no
canonicalisation here for a flattener to reproduce, so echoing what arrived is
both correct and diff-free.

THIS IS THE ENHANCED READ MODEL ONLY. Standard networks return
CustomDnsAttributesResponse, whose dnsPolicy.private collapses to forwardDNSUpdate
alone (plan D3), so the two standard data sources cannot share this function.

  - @param a *perimeter81Sdk.CustomDnsAttributes - the attributes as read, or nil

@return []interface{} - the `attributes` block, empty when the API sent none
*/
func flattenCustomDnsAttributes(a *perimeter81Sdk.CustomDnsAttributes) []interface{} {
	if a == nil {
		return []interface{}{}
	}

	servers := make([]interface{}, 0, len(a.Servers))
	for _, server := range a.Servers {
		servers = append(servers, map[string]interface{}{
			privateDNSAttrAddress: server.GetAddress(),
			privateDNSAttrIsTLS:   server.GetIsTLS(),
		})
	}

	searchDomains := make([]string, 0, len(a.SearchDomains))
	searchDomains = append(searchDomains, a.GetSearchDomains()...)

	return []interface{}{map[string]interface{}{
		privateDNSAttrServers:       servers,
		privateDNSAttrSearchDomains: searchDomains,
		privateDNSAttrDNSPolicy:     flattenDnsPolicy(a.DnsPolicy),
	}}
}

/*
flattenDnsPolicy maps the optional `dnsPolicy` sub-object into its block.

An absent policy flattens to an empty list, which is what an unset Optional block
holds in state, so a network with no DNS policy produces no diff. The two
sub-blocks are emitted only when the server sent them, for the same reason.

  - @param p *perimeter81Sdk.DnsPolicy - the policy as read, or nil

@return []interface{} - the `dns_policy` block, empty when there is none
*/
func flattenDnsPolicy(p *perimeter81Sdk.DnsPolicy) []interface{} {
	if p == nil {
		return []interface{}{}
	}

	block := map[string]interface{}{}
	if public := p.Public; public != nil {
		block[privateDNSAttrPublic] = []interface{}{map[string]interface{}{
			privateDNSAttrDomains: public.GetDomains(),
		}}
	}
	if private := p.Private; private != nil {
		block[privateDNSAttrPrivate] = []interface{}{map[string]interface{}{
			privateDNSAttrMode:           private.GetMode(),
			privateDNSAttrPublicFallback: private.GetPublicFallback(),
			privateDNSAttrDomains:        private.GetDomains(),
		}}
	}

	if len(block) == 0 {
		return []interface{}{}
	}
	return []interface{}{block}
}
