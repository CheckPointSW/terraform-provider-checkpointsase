package checkpointsase

import (
	"context"
	"net/http"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
data_source_standard_private_dns.go holds the two READ-ONLY private-DNS data
sources for the STANDARD network family:

  - checkpointsase_standard_network_private_dns
    GET /v3/networks/standard/{networkId}/privateDNS
  - checkpointsase_standard_region_private_dns
    GET /v3/networks/standard/{networkId}/regions/{regionId}/privateDNS

Both siblings live in one file on the Phase 4 precedent, because everything bar
the SDK call and the id is shared between them.

THE ASYMMETRY WITH private_dns.go IS THE WHOLE POINT OF THIS FILE, so read it
before changing anything here. private_dns.go serves two RESOURCES on the
ENHANCED endpoints; this file serves two DATA SOURCES on the STANDARD ones.
swagger.yaml:1726 and :1752 declare `get` and nothing else for the standard
paths, and api_standard_private_dns.go contains exactly two operations, both
http.MethodGet. There is no write path here at all -- so no expander, no async
poll, no statusUrl, no Delete semantics, and no attribute is Optional+Computed.
EVERY attribute this file exposes is Computed.

WHAT IS SHARED AND WHAT IS NOT. The attribute NAMES are shared -- every one of
them is a privateDNSAttr* constant from private_dns.go (plus privateDNSAttrRegionID
from resource_enhanced_region_private_dns.go), because a key spelled differently
in a flattener than in a schema surfaces a zero value with no error, no diff and
nothing in the logs. So is flattenCustomDnsServers. What is NOT shared is
flattenCustomDnsAttributes, and not by choice: the standard family returns
CustomDnsAttributesResponse where the enhanced family returns CustomDnsAttributes,
and Go will not let one function take both. See flattenCustomDnsAttributesResponse
for what the difference actually costs.
*/

/*
privateDNSAttrForwardDNSUpdate is the one attribute the standard read model has
that the enhanced one does not.

DECLARED HERE AND NOT IN private_dns.go, on the privateDNSAttrRegionID precedent
and for the same reason: the constants in private_dns.go are shared because more
than one file spells them. Only this file has a forward_dns_update attribute, so
there is already exactly one spelling of it in the package. If an enhanced object
ever grows one, move it.

@see privateDNSAttrRegionID in resource_enhanced_region_private_dns.go
*/
const privateDNSAttrForwardDNSUpdate = "forward_dns_update"

/*
The two base id strings. Each data source's id is its base plus a digest of its
ARGUMENTS -- never the base alone. See standardNetworkPrivateDNSID.
*/
const (
	standardNetworkPrivateDNSIDBase = "checkpointsase_standard_network_private_dns"
	standardRegionPrivateDNSIDBase  = "checkpointsase_standard_region_private_dns"
)

/*
standardPrivateDNSNotFoundGuidance is appended to the diagnostic when the read is
a 404.

A 404 HERE IS AN ERROR THE OPERATOR MUST SEE, NOT DRIFT, and that is the opposite
of what the two enhanced private-DNS RESOURCES do with the same status. The two
are not inconsistent. A resource Read that 404s has an id it can clear, and
clearing it is how Terraform reports "the thing you were tracking has gone" and
plans a recreation. A data source has no id to clear and nothing to recreate: it
would set an empty result, every downstream reference would silently read the zero
value, and the apply would proceed on data that was never fetched. The two shipped
network-scoped standard data sources -- dataSourceRouteTableRead and
dataSourceNetworkHealthRead -- already surface every read error unconditionally,
and this matches them.

WHAT THE 404 CANNOT TELL YOU, and the wording is careful about it. Probe P10
measured a bogus networkId against THIS endpoint on 2026-08-26:

	GET /v3/networks/standard/{bogus}/privateDNS
	-> 404 {"message":"network doesnt exists","messageCode":"NOT_FOUND","status":404}

That body names the network. A bogus REGION id has never been sent to the region
endpoint -- no probe has ever hit the standard region path in any state -- so
whether a wrong region_id is distinguishable from a wrong network_id is UNKNOWN,
and this text does not pretend otherwise.
*/
const standardPrivateDNSNotFoundGuidance = "The API answered 404: the network, or the region " +
	"within it, does not exist. A data source cannot report this as drift the way a resource " +
	"can — there is nothing for it to recreate — so it fails the plan instead of reading an " +
	"empty result that every reference to it would then silently consume. Check `network_id` " +
	"(and `region_id`) against `checkpointsase_standard_networks`."

/*
standardPrivateDNSSchema returns the body attributes both standard private-DNS
data sources expose: `enabled` and the `attributes` block under it.

It is the whole schema bar the object's address; callers add `network_id` (and
`region_id`).

EVERYTHING IS Computed AND NOTHING IS Optional. That is not a stylistic choice --
there is no write path on this family, so there is no value for an operator to
supply and no diff for the provider to reconcile. In particular the
Optional+Computed that API-FINDINGS.md 1.31 forces on the ENHANCED resources'
`attributes` has no analogue here: that exists to stop a resource diffing for ever
against a server that returns `attributes` once anything has been written, and a
data source never plans a change at all.

THE TWO DISABLED READ SHAPES STILL APPLY (API-FINDINGS.md 1.31, corrected
2026-08-26). A never-configured object reads back as exactly `{"enabled": false}`
with NO `attributes` key; an object something has written to reads back with
`attributes` present and its arrays empty. A reader that assumed the first shape
was the only disabled shape would be wrong about every object anyone has ever
configured. Here that costs nothing beyond `attributes.#` being 0 in the first
case and 1 in the second, which is what flattenCustomDnsAttributesResponse
produces and what the data source's own description says.

NO MaxItems, NO MinItems, ANYWHERE. Both are constraints on what a CONFIGURATION
may contain, and nothing here is configurable; helper/schema's InternalValidate
refuses them on a Computed-only attribute, and TestProvider runs it.

Descriptions are mandatory: TestSchemaEveryAttributeHasADescription walks every
registered data source and fails on a blank one.

@return map[string]*schema.Schema - `enabled` and `attributes`
*/
func standardPrivateDNSSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		privateDNSAttrEnabled: {
			Type:        schema.TypeBool,
			Computed:    true,
			Description: "Whether private DNS is enabled for this network or region.",
		},
		privateDNSAttrAttributes: {
			Type:     schema.TypeList,
			Computed: true,
			Description: "Private DNS configuration, as the API returned it. This list holds " +
				"either one element or none: the API omits `attributes` entirely for an object " +
				"nothing has ever configured, and returns it — with empty arrays when private " +
				"DNS is off — for one that has been written to. Both shapes are normal.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					privateDNSAttrServers: {
						Type:     schema.TypeList,
						Computed: true,
						Description: "Private DNS servers, in the priority order the API " +
							"returned them.",
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								privateDNSAttrAddress: {
									Type:        schema.TypeString,
									Computed:    true,
									Description: "IP address of the DNS server.",
								},
								privateDNSAttrIsTLS: {
									Type:        schema.TypeBool,
									Computed:    true,
									Description: "Whether DNS-over-TLS is used for this server.",
								},
							},
						},
					},
					privateDNSAttrSearchDomains: {
						Type:     schema.TypeList,
						Computed: true,
						Description: "DNS search domains, in the order the API returned them. " +
							"A list rather than a set: the order is meaningful and the API " +
							"preserves it.",
						Elem: &schema.Schema{Type: schema.TypeString},
					},
					privateDNSAttrDNSPolicy: {
						Type:        schema.TypeList,
						Computed:    true,
						Description: "Per-domain DNS policy. Empty when the object has none.",
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								privateDNSAttrPublic: {
									Type:        schema.TypeList,
									Computed:    true,
									Description: "Domains resolved via public DNS.",
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											privateDNSAttrDomains: {
												Type:        schema.TypeList,
												Computed:    true,
												Description: "Domains resolved via public DNS.",
												Elem:        &schema.Schema{Type: schema.TypeString},
											},
										},
									},
								},
								privateDNSAttrPrivate: {
									Type:        schema.TypeList,
									Computed:    true,
									Description: "Domains resolved via the private DNS servers.",
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											privateDNSAttrMode: {
												Type:     schema.TypeString,
												Computed: true,
												Description: "DNS resolution mode for private domains: " +
													"`matchPattern` or `resolveAllViaPrivate`.",
											},
											privateDNSAttrPublicFallback: {
												Type:     schema.TypeBool,
												Computed: true,
												Description: "Whether resolution falls back to public DNS " +
													"when private DNS fails.",
											},
											privateDNSAttrDomains: {
												Type:        schema.TypeList,
												Computed:    true,
												Description: "Private domains.",
												Elem:        &schema.Schema{Type: schema.TypeString},
											},
											privateDNSAttrForwardDNSUpdate: {
												Type:     schema.TypeBool,
												Computed: true,
												Description: "Whether DNS updates (RFC 2136) are forwarded " +
													"to the private DNS servers. Read-only, and returned " +
													"only by the standard network family — the enhanced " +
													"private-DNS resources have no equivalent.",
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
dataSourceStandardNetworkPrivateDNS reads one standard network's private-DNS
configuration.

@return &schema.Resource
*/
func dataSourceStandardNetworkPrivateDNS() *schema.Resource {
	s := standardPrivateDNSSchema()
	s[privateDNSAttrNetworkID] = &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		Description: "ID of the standard network whose private DNS to read. The network must " +
			"exist — this endpoint answers `404` for an id it does not know, and the data " +
			"source fails rather than returning an empty result.",
	}
	return &schema.Resource{
		Description: "Read the private DNS configuration of a single standard " +
			"`checkpointsase_network`. This is READ-ONLY because the API is: the standard " +
			"family exposes `GET` and nothing else on this path, unlike the enhanced family, " +
			"which has the `checkpointsase_enhanced_network_private_dns` resource.",
		ReadContext: dataSourceStandardNetworkPrivateDNSRead,
		Schema:      s,
	}
}

/*
dataSourceStandardRegionPrivateDNS reads one region's private-DNS configuration
within a standard network.

@return &schema.Resource
*/
func dataSourceStandardRegionPrivateDNS() *schema.Resource {
	s := standardPrivateDNSSchema()
	s[privateDNSAttrNetworkID] = &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		Description: "ID of the standard network the region belongs to. The network must " +
			"exist — this endpoint answers `404` for an id it does not know, and the data " +
			"source fails rather than returning an empty result.",
	}
	s[privateDNSAttrRegionID] = &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		Description: "ID of the region within that standard network. This is the region's own " +
			"server-assigned id — `region[*].region_id` on `checkpointsase_network` — NOT the " +
			"`cpregion_id` catalogue entry the region was created from; the two are different " +
			"values and the catalogue id is not a valid path segment here.",
	}
	return &schema.Resource{
		Description: "Read the private DNS configuration of a single region inside a standard " +
			"`checkpointsase_network`. This is READ-ONLY because the API is: the standard " +
			"family exposes `GET` and nothing else on this path, unlike the enhanced family, " +
			"which has the `checkpointsase_enhanced_region_private_dns` resource.",
		ReadContext: dataSourceStandardRegionPrivateDNSRead,
		Schema:      s,
	}
}

/*
standardNetworkPrivateDNSID and standardRegionPrivateDNSID build each data
source's id from its ARGUMENTS.

NEVER A CONSTANT. A data source that takes arguments and hardcodes its id gives
two instances holding different results one Terraform identity, and this project
has shipped that defect once already; testAccCheckDataSourceIDsDiffer in
data_source_acc_check_helpers_test.go exists because of it. Unlike Phase 4's
no-argument policy data sources, both of these take arguments, so both must
derive.

The parts go through dataSourceArgumentDigest, which LENGTH-PREFIXES each one:
"10:network_id" cannot be read as any other sequence of parts, whatever the parts
contain. That matters here rather than being decoration -- the v3 document types
both networkId and regionId as bare `type: string` with no pattern
(openapi.yaml:1136), so no character is provably absent from either, and a
naive join would let one pair of ids produce another pair's id.
See TestDataSourceArgumentDigestIsUnambiguous.

  - @param networkId string - the network's id
  - @param regionId string - the region's id, for the region variant

@return string - the data source's id
*/
func standardNetworkPrivateDNSID(networkId string) string {
	return standardNetworkPrivateDNSIDBase + "-" + dataSourceArgumentDigest(
		privateDNSAttrNetworkID+"="+networkId,
	)
}

func standardRegionPrivateDNSID(networkId, regionId string) string {
	return standardRegionPrivateDNSIDBase + "-" + dataSourceArgumentDigest(
		privateDNSAttrNetworkID+"="+networkId,
		privateDNSAttrRegionID+"="+regionId,
	)
}

/*
getStandardNetworkPrivateDNS and getStandardRegionPrivateDNS issue the one GET
each data source makes.

Factored out so the tests drive exactly the call the data source drives, and so
the SDK's service name appears once per path rather than once per caller.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param client *perimeter81Sdk.APIClient - the configured client
  - @param networkId string - the standard network's id
  - @param regionId string - the region's id, for the region variant

@return *perimeter81Sdk.CustomDnsResponse - the configuration as read
@return *http.Response - kept so the caller can classify a 404
@return error
*/
func getStandardNetworkPrivateDNS(ctx context.Context, client *perimeter81Sdk.APIClient,
	networkId string) (*perimeter81Sdk.CustomDnsResponse, *http.Response, error) {

	return client.StandardPrivateDNSAPI.GetStandardNetworkPrivateDNS(ctx, networkId).Execute()
}

func getStandardRegionPrivateDNS(ctx context.Context, client *perimeter81Sdk.APIClient,
	networkId, regionId string) (*perimeter81Sdk.CustomDnsResponse, *http.Response, error) {

	return client.StandardPrivateDNSAPI.
		GetStandardRegionPrivateDNS(ctx, networkId, regionId).Execute()
}

/*
dataSourceStandardNetworkPrivateDNSRead reads one standard network's private DNS.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func dataSourceStandardNetworkPrivateDNSRead(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(privateDNSAttrNetworkID).(string)

	customDns, resp, err := getStandardNetworkPrivateDNS(ctx, client, networkId)
	if err != nil {
		return standardPrivateDNSReadError(diags, d,
			"Unable to read standard network private DNS", resp, err)
	}

	if diags := setStandardPrivateDNSState(diags, d, customDns,
		"standard network private DNS"); diags.HasError() {
		return diags
	}

	d.SetId(standardNetworkPrivateDNSID(networkId))
	return diags
}

/*
dataSourceStandardRegionPrivateDNSRead reads one region's private DNS inside a
standard network.

NOTHING HAS EVER PROBED THIS ENDPOINT, in any state. Every captured private-DNS
body in this project came from the network paths -- the standard network path for
the unconfigured shape (API-FINDINGS.md 1.31) and the ENHANCED network path for
every populated one (1.31, 1.34). So the shape this function flattens is what the
spec declares (swagger.yaml:1752 -> CustomDnsResponse), not what anything has been
observed to return. If a live read here disagrees, that divergence is the finding.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func dataSourceStandardRegionPrivateDNSRead(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(privateDNSAttrNetworkID).(string)
	regionId := d.Get(privateDNSAttrRegionID).(string)

	customDns, resp, err := getStandardRegionPrivateDNS(ctx, client, networkId, regionId)
	if err != nil {
		return standardPrivateDNSReadError(diags, d,
			"Unable to read standard region private DNS", resp, err)
	}

	if diags := setStandardPrivateDNSState(diags, d, customDns,
		"standard region private DNS"); diags.HasError() {
		return diags
	}

	d.SetId(standardRegionPrivateDNSID(networkId, regionId))
	return diags
}

/*
standardPrivateDNSReadError turns a failed read into the diagnostic the operator
sees, and is the single place either data source decides what a 404 means.

It ALWAYS returns an error. See standardPrivateDNSNotFoundGuidance for why a 404
is not drift here, and note that neither branch calls d.SetId: an id is set only
after a successful read, so a failed read leaves the data source with nothing in
state rather than with a stale identity attached to values it never fetched.

d.Partial(true) matches every other read in this provider.

  - @param diags diag.Diagnostics - the diagnostics so far
  - @param d *schema.ResourceData - the terraform resource data
  - @param summary string - the diagnostic summary
  - @param resp *http.Response - the response, for classifying the status
  - @param err error - the error the SDK returned

@return diag.Diagnostics - with one error appended
*/
func standardPrivateDNSReadError(diags diag.Diagnostics, d *schema.ResourceData, summary string,
	resp *http.Response, err error) diag.Diagnostics {

	d.Partial(true)
	if isNotFound(resp, err) {
		return appendErrorDiagsWithGuidance(diags, summary,
			standardPrivateDNSNotFoundGuidance, err)
	}
	return appendErrorDiags(diags, summary, err)
}

/*
setStandardPrivateDNSState writes a decoded CustomDnsResponse into state. Both
data sources use it; neither adds a field of its own.

A NIL customDns DOES NOT ERROR, AND WITHOUT THIS GUARD IT PANICS. The generated
decode runs json.Unmarshal into a **CustomDnsResponse, so a literal `null` body
leaves the pointer nil and the strict `enabled` requiredProperties check in
CustomDnsResponse.UnmarshalJSON never runs. The generated getters are nil-safe,
but customDns.Attributes below is a DIRECT FIELD ACCESS and would dereference it.
Unmeasured on this endpoint -- no probe has seen a null body -- but a panic is the
one failure mode Terraform cannot report as a diagnostic, and the unconfigured
shape is the right reading of an empty answer anyway (API-FINDINGS.md 1.31: a
never-configured object reads as {"enabled": false}). Same guard, same reasoning,
as resourceEnhancedNetworkPrivateDNSRead.

  - @param diags diag.Diagnostics - the diagnostics so far
  - @param d *schema.ResourceData - the terraform resource data
  - @param customDns *perimeter81Sdk.CustomDnsResponse - the decoded body, or nil
  - @param label string - names the object in any diagnostic

@return diag.Diagnostics
*/
func setStandardPrivateDNSState(diags diag.Diagnostics, d *schema.ResourceData,
	customDns *perimeter81Sdk.CustomDnsResponse, label string) diag.Diagnostics {

	if customDns == nil {
		customDns = &perimeter81Sdk.CustomDnsResponse{}
	}

	if err := d.Set(privateDNSAttrEnabled, customDns.GetEnabled()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set "+label+" enabled", err)
	}
	if err := d.Set(privateDNSAttrAttributes,
		flattenCustomDnsAttributesResponse(customDns.Attributes)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set "+label+" attributes", err)
	}
	return diags
}

/*
flattenCustomDnsAttributesResponse maps the STANDARD read model into the
`attributes` block.

IT IS A NEAR-COPY OF flattenCustomDnsAttributes AND IT HAS TO BE. The standard
family returns CustomDnsAttributesResponse and the enhanced family returns
CustomDnsAttributes; the two structs are field-for-field identical except that
`dnsPolicy` is *DnsPolicyResponse here and *DnsPolicy there, and Go will not let
one function take both. What CAN be shared is shared: flattenCustomDnsServers is
called rather than restated, and every key is a privateDNSAttr* constant. Do not
"unify" these by converting one model into the other -- the dnsPolicy halves are
different types with different fields, so the conversion would silently drop
exactly the fields plan decision D3 is about.

A NIL a IS THE NORMAL CASE, NOT AN EDGE CASE, and it is measured: probe P3
(2026-08-26, API-FINDINGS.md 1.31) read a standard network as exactly
`{"enabled": false}` with no `attributes` key, which decodes to a nil pointer. A
flattener that dereferenced it would panic on the ordinary path.

  - @param a *perimeter81Sdk.CustomDnsAttributesResponse - the attributes as read, or nil

@return []interface{} - the `attributes` block, empty when the API sent none
*/
func flattenCustomDnsAttributesResponse(a *perimeter81Sdk.CustomDnsAttributesResponse) []interface{} {
	if a == nil {
		return []interface{}{}
	}

	searchDomains := make([]string, 0, len(a.SearchDomains))
	searchDomains = append(searchDomains, a.GetSearchDomains()...)

	return []interface{}{map[string]interface{}{
		privateDNSAttrServers:       flattenCustomDnsServers(a.Servers),
		privateDNSAttrSearchDomains: searchDomains,
		privateDNSAttrDNSPolicy:     flattenDnsPolicyResponse(a.DnsPolicy),
	}}
}

/*
flattenDnsPolicyResponse maps the standard family's `dnsPolicy` into its block.

  - @param p *perimeter81Sdk.DnsPolicyResponse - the policy as read, or nil

@return []interface{} - the `dns_policy` block, empty when there is none
*/
func flattenDnsPolicyResponse(p *perimeter81Sdk.DnsPolicyResponse) []interface{} {
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
		block[privateDNSAttrPrivate] = []interface{}{
			flattenDnsPolicyResponsePrivate(private),
		}
	}

	if len(block) == 0 {
		return []interface{}{}
	}
	return []interface{}{block}
}

/*
flattenDnsPolicyResponsePrivate is the answer to plan decision D3, and it is the
one function in this file that reads AdditionalProperties on purpose.

THE GENERATED STRUCT IS MISSING THREE OF THE FOUR FIELDS. swagger.yaml:4632
declares DnsPolicyResponse as `allOf[DnsPolicy, {private: {forwardDNSUpdate}}]`.
Under allOf that is a MERGE: the standard family's `private` carries `mode`,
`publicFallback` and `domains` from DnsPolicy -- all three of them REQUIRED there
(swagger.yaml:4609) -- plus the read-only `forwardDNSUpdate` the override adds.
openapi-generator resolved the allOf by REPLACING the sub-object instead, so
DnsPolicyResponseAllOfPrivate has exactly one field, ForwardDNSUpdate
(model_dns_policy_response_all_of_private.go:23).

The three missing fields are not lost. Every schema in this family carries
`additionalProperties: true`, and the generated UnmarshalJSON deletes only
"forwardDNSUpdate" before storing the rest, so anything else on the wire lands in
AdditionalProperties. This function reads them from there.

WHY READ THEM RATHER THAN OMIT THEM. This is the API-FINDINGS.md 2.1 class
exactly: EnhancedTunnel, overlay A19, where "a generated client therefore reads
nil for every one of those eight fields" and "in our case that silently blanked
user configuration". A data source that exposed only forward_dns_update would
report three empty fields for values the API declares it returns, with no error
anywhere.

THE PROBE DID NOT DECIDE THIS, AND THE BRIEF SAID IT WOULD. Task 4's step 1 says
to decide from P3's captured body. P3's captured body is `{"enabled": false}` --
seventeen bytes, no `attributes` key, and therefore no `dnsPolicy` key either. It
is silent on the question. The decision is made on the spec plus the asymmetry of
the two errors: reading a key the server never sends yields the same zero value
omitting it would, whereas omitting a key the server does send is the 2.1 failure
and is invisible.

SO THIS FUNCTION'S THREE AdditionalProperties FIELDS ARE SPEC-DERIVED, NOT
CAPTURE-DERIVED. No standard endpoint has ever been observed returning a
populated private-DNS body, at network or region level. The nearest measurement is
API-FINDINGS.md 1.34, which round-tripped a full dnsPolicy on the ENHANCED network
path, where the typed model has all three fields and none of this applies.

An absent key and a key whose value is false are indistinguishable here, because
the schema is Computed and Terraform has no null. That is stated rather than
worked around: it costs a reader nothing on a read-only attribute, and inventing a
tri-state would be inventing information.

@see LEFTOVERS.md L35 -- the candidate overlay entry that would remove the need
for this function.

  - @param private *perimeter81Sdk.DnsPolicyResponseAllOfPrivate - the private half, non-nil

@return map[string]interface{} - the `private` block's attributes
*/
func flattenDnsPolicyResponsePrivate(
	private *perimeter81Sdk.DnsPolicyResponseAllOfPrivate) map[string]interface{} {

	return map[string]interface{}{
		// Typed on the generated struct.
		privateDNSAttrForwardDNSUpdate: private.GetForwardDNSUpdate(),
		// Absent from the generated struct; read out of the additionalProperties
		// bag by their WIRE names, which are camelCase and are not the Terraform
		// attribute names beside them.
		privateDNSAttrMode: additionalPropertyString(
			private.AdditionalProperties, "mode"),
		privateDNSAttrPublicFallback: additionalPropertyBool(
			private.AdditionalProperties, "publicFallback"),
		privateDNSAttrDomains: additionalPropertyStrings(
			private.AdditionalProperties, "domains"),
	}
}

/*
The three additionalProperty* readers below take a value out of a generated
model's AdditionalProperties bag and coerce it to the Go type the schema wants.

They are deliberately TOTAL: a missing key, a null, or a value of the wrong JSON
type all yield the zero value rather than an error. That is right for a read-only
attribute -- there is no user input to reject, the alternative is failing an
entire plan because one field of one record was surprising, and the surprise is
visible in state either way.

encoding/json decodes into interface{} as string, bool, float64 and []interface{},
which is what these assert against; nothing here will see a json.Number.

  - @param bag map[string]interface{} - the model's AdditionalProperties, possibly nil
  - @param key string - the WIRE name of the field, not the Terraform attribute name

@return the value, or its zero
*/
func additionalPropertyString(bag map[string]interface{}, key string) string {
	value, _ := bag[key].(string)
	return value
}

func additionalPropertyBool(bag map[string]interface{}, key string) bool {
	value, _ := bag[key].(bool)
	return value
}

// additionalPropertyStrings returns an empty slice rather than nil for an absent
// or malformed list, and SKIPS non-string elements rather than substituting "":
// a positional gap in a domain list would be worse than a shorter list.
func additionalPropertyStrings(bag map[string]interface{}, key string) []string {
	items, _ := bag[key].([]interface{})
	values := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			values = append(values, s)
		}
	}
	return values
}
