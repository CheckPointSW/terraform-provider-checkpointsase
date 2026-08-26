package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
privateDNSAttrRegionID is the second half of this resource's address.

IT IS DECLARED HERE AND NOT IN private_dns.go, WHICH IS A DELIBERATE ASYMMETRY
WITH privateDNSAttrNetworkID. The constants in private_dns.go are there because
expandCustomDnsUpdate reads the BODY attributes by name, so a name it reads that
the schema does not declare returns a zero value silently; and network_id is
alongside them because BOTH resources declare it, so two string literals in two
files would be exactly the drift that block exists to remove. Neither applies to
region_id: no shared code reads it, and only this file declares it, so there is
already only one spelling of it in the package.

@see privateDNSAttrNetworkID in private_dns.go
*/
const privateDNSAttrRegionID = "region_id"

/*
privateDNSRegionIDSeparator joins the two path parameters into one Terraform id.

":" rather than "-", and that is a correction to the test plan rather than a
preference. Row EPD-I01 writes the id as `<network_id>-<region_id>`, and a "-"
separator is ambiguous the moment either half contains one -- which network ids
demonstrably do (`net-0123...`). SplitN on the FIRST "-" of "net-abc-reg-def"
yields ("net", "abc-reg-def"), so the resource would issue a request against a
network id that never existed and report the 404 as drift.

":" is the checkpointsase_group_membership precedent (Pattern D), and the
argument there is stronger than the one available here: group and user ids are
EnglishNumericId in the API document, `^[a-zA-Z0-9_\-]*$`, so a colon PROVABLY
cannot occur inside one. The v3 document types both networkId and regionId as
bare `type: string` with no pattern (openapi.yaml:1136), so no such proof exists
for this resource, and none is claimed. What is claimed is weaker and sufficient:
the split takes the FIRST colon, so only network_id has to be colon-free for the
parse to be unambiguous, and every network id this provider has ever seen is
`net-` followed by a UUID.

If a network id containing a colon ever turns up, this is the one constant to
change -- and parseEnhancedRegionPrivateDNSID's error message is what the
operator will see first.
*/
const privateDNSRegionIDSeparator = ":"

/*
resourceEnhancedRegionPrivateDNS manages the private DNS configuration of ONE
REGION of one enhanced network:
GET and PUT /v3/networks/enhanced/{networkId}/regions/{regionId}/privateDNS.

It is the sibling of checkpointsase_enhanced_network_private_dns and everything
that file's header says applies here: it is a SETTING on an object that already
exists rather than an object, so "create" is adopt-and-write, "update" is the
identical call, "destroy" makes no request (D9), and the write is ASYNCHRONOUS --
the PUT declares only a 202 (swagger.yaml:699), so the write has not happened when
the call returns. The body, the schema, the expander, the flattener, the diff
rules and the async wait are all in private_dns.go, shared verbatim; this file is
this resource's ADDRESS and its CRUD wiring and nothing else.

THE REGION ENDPOINT HAS NEVER BEEN MEASURED, AND NOTHING HERE MAY PRETEND
OTHERWISE. Every capture behind API-FINDINGS.md 1.31 -- the two disabled read
shapes, the 422 for a body with no `attributes`, the 400 for a null array, the
byte-exact round trip -- was taken against the NETWORK path. No probe has ever
touched `/regions/{regionId}/privateDNS`. What justifies reusing all of it is the
SPEC: the two paths share the request model (CustomDnsUpdate), the response model
(CustomDns), the response map (202 only) and the operation description, word for
word. That is a good reason to expect the same behaviour and it is not evidence
of it. Every fixture in resource_enhanced_region_private_dns_test.go is therefore
labelled spec-derived, and TestAccEnhancedRegionPrivateDNS_basic is the first
thing that will find out.

A REGION IS SCOPED INSIDE A NETWORK, and the API says nothing about how the two
configurations interact -- whether a region's private DNS overrides the network's,
merges with it, or is independent of it. This resource does not model any
relationship between them, because none has been measured. Pointing this resource
and checkpointsase_enhanced_network_private_dns at the same network is therefore
supported; what each one writes is the API's business.

@return &schema.Resource
*/
func resourceEnhancedRegionPrivateDNS() *schema.Resource {
	return &schema.Resource{
		Description: "Manages the private DNS configuration of ONE REGION of a Check Point SASE " +
			"**enhanced network** — " +
			"`GET`/`PUT /v3/networks/enhanced/{networkId}/regions/{regionId}/privateDNS`. " +
			"This is a setting on a region that already exists, not an object of its own: " +
			"the API has no create and no delete for it, so `terraform apply` adopts the " +
			"region's current private DNS configuration and replaces it with yours. " +
			"**Every write is a full replacement.** Anything omitted from `attributes` is " +
			"cleared rather than preserved, including `search_domains` and the whole " +
			"`dns_policy` block — to keep a value, write it. " +
			"The write is asynchronous: the API answers `202 Accepted` and the provider polls " +
			"the operation to completion before reporting the apply as done. " +
			"Setting `enabled = false` is the supported way to turn private DNS off. On the " +
			"FIRST write to a region that has never been configured, omitting the " +
			"`attributes` block is enough: the provider synthesises the empty `servers` and " +
			"`search_domains` arrays the API requires. After anything has been written, " +
			"omitting the block carries the last-applied values forward instead — write " +
			"`attributes {}` to send empty arrays deliberately. " +
			"**`attributes` is computed as well as optional**, because the API returns the " +
			"object on every read once anything has been written — a region that has never " +
			"been configured reads back as `{\"enabled\": false}` with no `attributes` key, " +
			"and one that has been explicitly disabled reads back with `attributes` present " +
			"and empty. Removing the block from your configuration therefore leaves whatever " +
			"the region already holds rather than clearing it; there is nothing it could " +
			"clear to, since a write with no `attributes` object is rejected. To empty a " +
			"list write it empty, and to drop the DNS policy remove the `dns_policy` block — " +
			"the blocks nested inside `attributes` are optional only, so omitting one of those " +
			"does still clear it. " +
			"**Everything above about what this API requires, returns and rejects was " +
			"measured on the enhanced-NETWORK private-DNS endpoint**, not on this one: the " +
			"two read shapes, the `422` for a write with no `attributes`, and the " +
			"order-preserving round trip all come from probes against " +
			"`/v3/networks/enhanced/{networkId}/privateDNS` (`API-FINDINGS.md` §1.31, §1.34). " +
			"That endpoint takes the identical request and response models and the same " +
			"specification applies to both, so this is the documented contract rather than a " +
			"guess — but the region route itself has not been probed, and the acceptance test " +
			"is the first thing that will know if it differs. " +
			privateDNSNoOpDeleteNote + " " +
			"Import with the network id and the region id joined by a colon: " +
			"`terraform import checkpointsase_enhanced_region_private_dns.this " +
			"<network_id>:<region_id>`. A colon is the separator because a hyphen appears " +
			"inside network ids themselves. " +
			"This resource and `checkpointsase_enhanced_network_private_dns` address " +
			"different endpoints; how the API combines a region's private DNS with its " +
			"network's is not documented and is not modelled here.",
		CreateContext: resourceEnhancedRegionPrivateDNSCreate,
		ReadContext:   resourceEnhancedRegionPrivateDNSRead,
		UpdateContext: resourceEnhancedRegionPrivateDNSUpdate,
		DeleteContext: resourceEnhancedRegionPrivateDNSDelete,
		CustomizeDiff: resourceEnhancedRegionPrivateDNSCustomizeDiff,
		Schema:        enhancedRegionPrivateDNSSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: resourceEnhancedRegionPrivateDNSImportState,
		},
		// The write is asynchronous and this resource POLLS it to completion, so
		// without this it inherits SDKv2's 20-minute system default and the
		// operator has no `timeouts {}` block to raise it with. Thirteen other
		// resources in this package already declare asyncResourceTimeout for the
		// same reason.
		//
		// THERE IS DELIBERATELY NO Delete TIMEOUT. Delete makes no API call at all
		// (D9, privateDNSNoOpDeleteNote) -- it clears the id and returns -- so
		// declaring a budget for it would advertise a wait that cannot happen.
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(asyncResourceTimeout),
			Update: schema.DefaultTimeout(asyncResourceTimeout),
		},
	}
}

/*
enhancedRegionPrivateDNSSchema is privateDNSSchema plus this resource's two-part
address.

privateDNSSchema is CALLED, not restated, and that is the whole point of it
existing: expandCustomDnsUpdate reads the body attributes by name, and a name it
reads that the schema does not declare returns a zero value with no error, no
diff and nothing in the logs. One declaration means a typo is a compile error
rather than a silently dropped field. See the comment above the constants in
private_dns.go.

BOTH address attributes are Required and ForceNew, for the reason the network
resource's network_id is: they are the object's ADDRESS. This resource does not
own a network or a region, it owns one setting on the region those two ids name
together, so pointing it at a different region is a different object rather than
a change to this one. There is nothing to migrate and nothing to destroy on the
way -- Delete makes no request (D9) -- so the replace is free.

@return map[string]*schema.Schema
*/
func enhancedRegionPrivateDNSSchema() map[string]*schema.Schema {
	s := privateDNSSchema()
	s[privateDNSAttrNetworkID] = &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		ForceNew: true,
		Description: "ID of the enhanced network the region belongs to. Changing it replaces " +
			"the resource: together with `region_id` it is the address of the setting, not a " +
			"property of it. The network must already exist — this endpoint answers `404` " +
			"for an id it does not know.",
	}
	s[privateDNSAttrRegionID] = &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		ForceNew: true,
		Description: "ID of the region within that enhanced network whose private DNS this " +
			"configures. Changing it replaces the resource. This is the region's own id — the " +
			"`id` of a `region` block on `checkpointsase_enhanced_network`, NOT the " +
			"`harmony_sase_region_id` catalogue entry that block was created from; the two are " +
			"different values and the catalogue id is not a valid path segment here.",
	}
	return s
}

/*
getEnhancedRegionPrivateDNS issues the one GET this resource makes.

Factored out only so that Create's adoption check and Read make demonstrably the
same call: a Create that checked a different path from the one Read polls would
adopt something Read then reports as missing.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param client *perimeter81Sdk.APIClient - the configured client
  - @param networkId string - the enhanced network's id
  - @param regionId string - the region's id within that network

@return *perimeter81Sdk.CustomDns - the configuration as read
@return *http.Response - kept so the caller can classify a 404
@return error
*/
func getEnhancedRegionPrivateDNS(ctx context.Context, client *perimeter81Sdk.APIClient,
	networkId string, regionId string) (*perimeter81Sdk.CustomDns, *http.Response, error) {

	return client.EnhancedPrivateDNSAPI.
		GetEnhancedRegionPrivateDNS(ctx, networkId, regionId).Execute()
}

/*
resourceEnhancedRegionPrivateDNSCreate adopts the region's existing private DNS
configuration and then writes the configured one.

There is no create endpoint: the configuration exists as soon as the region does.
So this GETs it as a reachability and existence check, sets the id, and delegates
to Update -- the same shape as resourceEnhancedNetworkPrivateDNSCreate and, before
it, resourceFirewallPolicyCreate.

THE 404 HERE IS AN ERROR, NOT DRIFT, WHICH IS THE OPPOSITE OF READ. The two are
not inconsistent: in Read a 404 means an object Terraform was tracking has gone,
which is drift. Here nothing is being tracked yet -- the operator has just named a
network or a region that does not exist -- and silently succeeding would produce
an apply against an address that was never valid.

DO NOT d.Set ANY BODY ATTRIBUTE HERE. terraform-plugin-sdk's d.Get prefers a
recent d.Set over the diff, so setting the region's CURRENT values before Update
runs would clobber the operator's HCL and push the server's existing values
straight back -- the resource would report success having applied nothing.

The id is set BEFORE the write, deliberately. If the write is accepted and then
fails to complete, Terraform still holds an id and the next plan shows the drift;
an unset id would leave a region whose DNS may have changed with nothing tracking
it.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedRegionPrivateDNSCreate(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(privateDNSAttrNetworkID).(string)
	regionId := d.Get(privateDNSAttrRegionID).(string)

	if _, _, err := getEnhancedRegionPrivateDNS(ctx, client, networkId, regionId); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to read enhanced region private DNS for adoption", err)
	}

	d.SetId(enhancedRegionPrivateDNSID(networkId, regionId))
	return resourceEnhancedRegionPrivateDNSUpdate(ctx, d, m)
}

/*
resourceEnhancedRegionPrivateDNSRead reads the region's private DNS configuration
into state.

A 404 CLEARS THE ID AND RETURNS NO ERROR, AND THAT IS CORRECT HERE EVEN THOUGH IT
WAS WRONG THREE TIMES IN PHASE 3. Do not "fix" this back.

The Phase 3/4 hazard was a COLLECTION endpoint: a 404 there meant the URL was
wrong, and treating it as drift silently emptied Terraform's state on a
misconfiguration, so the next apply proposed recreating objects that had never
gone anywhere. This is a SINGLE OBJECT addressed by two user-supplied ids, and
probe P10 measured what a wrong network id gets on 2026-08-26:

	GET /v3/networks/enhanced/{bogus}/privateDNS
	-> 404 {"message":"Network doesn't exist.","messageCode":"NOT_FOUND","status":404}

The message names the cause and the cause is the object, not the route. A network
or region deleted outside Terraform is exactly the drift a Read is supposed to
report, and both ids are required user-supplied arguments, so the vanished-parent
case is directly reachable through HCL and has to plan as a recreation rather than
as an apply-time failure (test-plan row EPD-D01).

THAT P10 CAPTURE IS FROM THE NETWORK PATH, NOT THIS ONE. No probe has ever hit
/regions/{regionId}/privateDNS at all. The 404 is in the region operation's
declared response map (openapi.yaml:1121) exactly as it is in the network's, and
a bogus REGION id -- as opposed to a bogus network id -- has never been sent to
anything. If it turns out to answer something other than a 404, this branch is
where that shows up and this is the comment to correct.

`attributes` MAY BE ABSENT, AND THAT IS THE ORDINARY CASE. API-FINDINGS.md 1.31
measured an unconfigured network reading back as exactly `{"enabled": false}`,
with no `attributes` key at all, which decodes to a nil *CustomDnsAttributes.
flattenCustomDnsAttributes handles the nil; nothing here may dereference it.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedRegionPrivateDNSRead(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(privateDNSAttrNetworkID).(string)
	regionId := d.Get(privateDNSAttrRegionID).(string)

	customDns, resp, err := getEnhancedRegionPrivateDNS(ctx, client, networkId, regionId)
	if err != nil {
		if isNotFound(resp, err) {
			// The network or the region is gone -- see the doc comment. Drift, not
			// failure: clear the id and say nothing, so the next plan proposes
			// recreating the configuration on a parent the operator will have to
			// recreate too.
			d.SetId("")
			return diags
		}
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read enhanced region private DNS", err)
	}

	// Both are no-ops on every path today: each was just read OUT of the attribute
	// it is written back to. They are kept because they make Read the single place
	// that populates this resource's state -- the importer sets network_id and
	// region_id only so that the GET above has a path to build, and if that ever
	// changed to deriving the address from d.Id() these are the lines that would
	// carry it into state. Removing them would move that responsibility somewhere
	// less obvious for no gain.
	if err := d.Set(privateDNSAttrNetworkID, networkId); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set enhanced region private DNS network_id", err)
	}
	if err := d.Set(privateDNSAttrRegionID, regionId); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set enhanced region private DNS region_id", err)
	}
	// A 200 WITH A `null` BODY DOES NOT ERROR, and without this it PANICS. decode
	// runs json.Unmarshal into *CustomDns; a literal `null` unmarshals cleanly and
	// leaves the pointer nil, so classifyAPIError never sees a failure. The
	// generated getters are nil-safe (GetEnabled checks o == nil), but
	// customDns.Attributes below is a DIRECT FIELD ACCESS and dereferences it.
	//
	// Unmeasured on this endpoint -- no probe has seen a null body -- but a panic
	// is the one failure mode Terraform cannot report as a diagnostic, and the
	// unconfigured shape is the correct reading of an empty answer anyway
	// (API-FINDINGS.md 1.31: a never-configured object reads as {"enabled":false}).
	if customDns == nil {
		customDns = &perimeter81Sdk.CustomDns{}
	}

	if err := d.Set(privateDNSAttrEnabled, customDns.GetEnabled()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set enhanced region private DNS enabled", err)
	}
	if err := d.Set(privateDNSAttrAttributes,
		flattenCustomDnsAttributes(customDns.Attributes)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set enhanced region private DNS attributes", err)
	}

	return diags
}

/*
resourceEnhancedRegionPrivateDNSUpdate sends the one PUT this resource makes and
waits for the async operation it starts.

CREATE AND UPDATE ARE THE SAME CALL, which is why Create delegates here rather
than duplicating it. There is no POST on this path; a "create" is a PUT against a
configuration that already exists.

THE BODY IS A FULL REPLACEMENT, and expandCustomDnsUpdate builds all of it from
the resource's attributes on every apply -- including the ones Terraform reports
as unchanged. The operation description is explicit that an omitted field is
cleared rather than preserved.

The response body is discarded in favour of delegating to Read, deliberately: the
two shapes differ (`CustomDnsUpdate` in, `CustomDns` out, and the read of an
unconfigured region carries no `attributes` at all), and using the write's own
echo would mean no apply ever exercises the code path the NEXT plan compares
against -- which is precisely how a read-shape mismatch survives an acceptance
run.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedRegionPrivateDNSUpdate(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(privateDNSAttrNetworkID).(string)
	regionId := d.Get(privateDNSAttrRegionID).(string)
	payload := expandCustomDnsUpdate(d)

	accepted, err := putPrivateDNSAndWait(ctx, client,
		func(ctx context.Context) (*perimeter81Sdk.AsyncOperationResponse, *http.Response, error) {
			return client.EnhancedPrivateDNSAPI.
				UpdateEnhancedRegionPrivateDNS(ctx, networkId, regionId).
				CustomDnsUpdate(payload).
				Execute()
		})
	if err != nil {
		d.Partial(true)

		// appendErrorDiagsWithGuidance, not appendErrorDiags: the latter promotes
		// the server's body into Detail and discards the caller's wrapper, so
		// guidance attached any other way never reaches the operator. See its doc
		// comment (utils.go:1252).
		if accepted {
			return appendErrorDiagsWithGuidance(diags,
				"The enhanced region private DNS update was accepted but did not complete",
				privateDNSWriteAcceptedButNotCompleted, err)
		}
		return appendErrorDiagsWithGuidance(diags,
			"Unable to update enhanced region private DNS",
			privateDNSWriteRefused, err)
	}

	return resourceEnhancedRegionPrivateDNSRead(ctx, d, m)
}

/*
resourceEnhancedRegionPrivateDNSDelete removes the resource from Terraform state
and makes NO API call. That is decision D9, not an unfinished function -- read
privateDNSNoOpDeleteNote before changing it.

The warning is part of the behaviour rather than decoration. A destroy that
silently changes nothing and a destroy that silently rewrites a production
region's DNS resolution print the same thing in the console; the diagnostic is
the only thing that tells the operator which one happened, and "a no-op that
explains itself" is what D9 asks for.

  - @param ctx context.Context - unused; there is no request to make.
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - unused; there is no request to make.

@return diag.Diagnostics
*/
func resourceEnhancedRegionPrivateDNSDelete(_ context.Context, d *schema.ResourceData,
	_ interface{}) diag.Diagnostics {

	var diags diag.Diagnostics

	networkId := d.Get(privateDNSAttrNetworkID).(string)
	regionId := d.Get(privateDNSAttrRegionID).(string)
	diags = appendWarningDiags(diags,
		"Private DNS left unchanged on the region",
		fmt.Sprintf("Terraform has stopped tracking the private DNS configuration of region %q "+
			"in network %q and made no API call. The region keeps whatever private DNS "+
			"configuration was last applied — destroying this resource does not turn private "+
			"DNS off, because changing how a live region resolves names as a side effect of "+
			"removing a Terraform resource is not something a destroy should do. To turn it "+
			"off, apply `enabled = false` first and then destroy.", regionId, networkId))

	d.SetId("")
	return diags
}

/*
resourceEnhancedRegionPrivateDNSCustomizeDiff enforces the two rules
privateDNSSchema records as inexpressible in a schema: the conditional `servers`
minimum, and uniqueness across the four lists the API declares uniqueItems.

Both live in validatePrivateDNSDiff so this resource and the network one enforce
exactly the same rules. Neither is expressible as MinItems or as a TypeSet -- see
that function for why each would be wrong rather than merely inconvenient.

Destroy plans never reach CustomizeDiff in SDKv2, which is what we want: a destroy
has no configuration to check, and this resource's destroy does nothing anyway.

  - @param ctx context.Context - unused
  - @param d *schema.ResourceDiff - the diff
  - @param m interface{} - unused

@return error
*/
func resourceEnhancedRegionPrivateDNSCustomizeDiff(_ context.Context, d *schema.ResourceDiff,
	_ interface{}) error {

	return validatePrivateDNSDiff(d)
}

/*
enhancedRegionPrivateDNSID joins the two path parameters into this resource's id.

It exists so that Create and the importer cannot disagree about the format: the
importer PARSES what Create WRITES, and an id built by string concatenation in one
place and split by a constant in the other is a defect nothing would catch until
somebody tried to import.

  - @param networkId string - the enhanced network's id
  - @param regionId string - the region's id within it

@return string - "<network_id>:<region_id>"
*/
func enhancedRegionPrivateDNSID(networkId, regionId string) string {
	return networkId + privateDNSRegionIDSeparator + regionId
}

/*
parseEnhancedRegionPrivateDNSID splits a "<network_id>:<region_id>" resource id.

SplitN with n=2 rather than Split, so a region id containing a colon still parses:
only the FIRST colon separates, and only network_id therefore has to be
colon-free. See privateDNSRegionIDSeparator for why that is the claim being made
rather than the stronger one group_membership can make.

BOTH HALVES ARE CHECKED NON-EMPTY, and that check is not cosmetic. url.PathEscape
turns an empty segment into an empty segment, so an id of ":reg-1" would send
GET /v3/networks/enhanced//regions/reg-1/privateDNS -- a DIFFERENT ROUTE rather
than a 404 on this one, whose failure says nothing the operator can act on. The
same applies to "net-1:", which would collapse the path a segment further along.

No character-class check, unlike parseGroupMembershipID. That function can reject
whitespace and punctuation because the API document types its two ids as
EnglishNumericId, `^[a-zA-Z0-9_\-]*$`; this one's are typed as bare `type: string`
with no pattern at all (openapi.yaml:1136), so any charset this rejected would be
this file's invention and would refuse ids the server might legitimately issue.
The cost is that a pasted " net-1:reg-1" reaches the API as %20net-1 and comes
back as a 404; that is a worse message than group membership's and it is the
honest one available here.

  - @param id string - the composite resource id

@return (string, string, error) - networkId, regionId, and why the id was rejected
*/
func parseEnhancedRegionPrivateDNSID(id string) (string, string, error) {
	parts := strings.SplitN(id, privateDNSRegionIDSeparator, 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("an enhanced region private DNS import id is the network id "+
			"and the region id joined by %q, and %q is not: terraform import "+
			"checkpointsase_enhanced_region_private_dns.<name> <network_id>%s<region_id>",
			privateDNSRegionIDSeparator, id, privateDNSRegionIDSeparator)
	}
	return parts[0], parts[1], nil
}

/*
resourceEnhancedRegionPrivateDNSImportState imports one region's private DNS
configuration by the composite id.

	terraform import checkpointsase_enhanced_region_private_dns.this <network_id>:<region_id>

Both halves are set as ATTRIBUTES before Read runs, because Read builds its URL
from the attributes rather than from d.Id(). Without them Read would GET
/v3/networks/enhanced//regions//privateDNS, which is a different route altogether
rather than a 404 on this one.

The id is REWRITTEN through enhancedRegionPrivateDNSID rather than left as the
operator typed it. It is the same string on every legal input, which is exactly
why it is cheap insurance: it makes the imported resource's id come from the same
function Create's does, so the two cannot drift apart in a future edit and leave
an imported resource whose id is formatted differently from an applied one.

The empty-id check afterwards is not redundant with the error check above it.
Read reports a vanished parent by clearing the id and returning NO diagnostics
(see its comment on why a 404 is drift here), so an import of a network or region
that does not exist would otherwise report success and write an empty resource
into state.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceEnhancedRegionPrivateDNSImportState(ctx context.Context, d *schema.ResourceData,
	m interface{}) ([]*schema.ResourceData, error) {

	networkId, regionId, err := parseEnhancedRegionPrivateDNSID(d.Id())
	if err != nil {
		return nil, err
	}
	if err := d.Set(privateDNSAttrNetworkID, networkId); err != nil {
		return nil, fmt.Errorf("could not set network_id from the import id %q: %w", d.Id(), err)
	}
	if err := d.Set(privateDNSAttrRegionID, regionId); err != nil {
		return nil, fmt.Errorf("could not set region_id from the import id %q: %w", d.Id(), err)
	}
	d.SetId(enhancedRegionPrivateDNSID(networkId, regionId))

	diagnostics := resourceEnhancedRegionPrivateDNSRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import enhanced region private DNS: %s, \n %s",
					diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	if d.Id() == "" {
		return nil, fmt.Errorf("no such enhanced network region: network %q, region %q. The API "+
			"answered 404 for it, so there is no private DNS configuration to import. Note that "+
			"`region_id` is the region's OWN id, not the harmony_sase_region_id it was created "+
			"from", networkId, regionId)
	}

	return []*schema.ResourceData{d}, nil
}
