package checkpointsase

import (
	"context"
	"fmt"
	"net/http"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
privateDNSNoOpDeleteNote is what `terraform destroy` does to an enhanced
private-DNS resource.

DECISION D9 (2026-08-25) chose to leave the configuration in place on destroy.
SUPERSEDED 2026-09-17 (P81-145399): D9's no-op left a live tenant resolving
through servers, search domains and a `dns_policy` that no Terraform
configuration, and no API call, could any longer be traced to. QA measured the
consequence directly -- destroy an `enhanced_network_private_dns`, then GET the
same `privateDNS` endpoint on the next line, and the configuration written by the
apply is still there, byte-for-byte, `enabled: true` included. A destroy that
exits 0 having changed nothing on the tenant is not a smaller harm than the one D9
was written against; it is the same shape of surprise from the other direction,
and it is silent in the same way.

So Delete now sends the PUT this resource's Update would send for
`enabled = false` with empty `attributes` -- the measured legal "off" body
(API-FINDINGS.md 1.31; see defaultCustomDnsUpdate in private_dns.go) -- and waits
for it exactly as Update does. There is nothing D9's firewall-policy/support-options
distinction rested on that survives this: this resource is a SETTING with no
create and no delete of its own, so "destroy" was never going to mean "delete an
object" either way, and turning the setting off is now the write, not the
side effect. Import, then destroy without ever running `terraform apply`, produces
the identical write a `terraform apply` of `enabled = false` would -- which is
also new: under D9 an unconfigured import followed immediately by destroy made no
request at all.
*/
const privateDNSNoOpDeleteNote = "`terraform destroy` on this resource turns private DNS " +
	"off: it sends the same write `enabled = false` with empty `attributes` would, and waits " +
	"for it to complete before returning, exactly as `terraform apply` does. Destroying this " +
	"resource is therefore NOT free of side effects — it changes how the network resolves " +
	"names, on purpose, so that a destroyed Terraform resource and the tenant's live " +
	"configuration cannot go on disagreeing silently. If you want the configuration left in " +
	"place, do not destroy this resource; remove it from state instead " +
	"(`terraform state rm`)."

/*
privateDNSWriteAcceptedButNotCompleted and privateDNSWriteRefused are the two
guidance paragraphs the async write path attaches to a failure.

They are separate because the two situations send an operator to different
places, and putPrivateDNSAndWait's `accepted` return is the only thing that tells
them apart. "The API refused the request" means nothing changed and the message
body says why. "The API accepted the request and the operation then failed" means
the network may or may not now hold the new configuration, and the honest advice
is to look rather than to assume either way.

Both are rendered through appendErrorDiagsWithGuidance, never appendErrorDiags:
errors out of putPrivateDNSAndWait are GenericOpenAPIErrors or wrap one, and
appendErrorDiags promotes the server's body into Detail and DISCARDS whatever the
caller wrapped it with -- so guidance attached any other way never reaches the
wire. That was measured on the SWG policies and is why the helper exists
(utils.go:1283).

Neither mentions `terraform untaint`, and that omission needs re-checking now that
Delete writes (P81-145399 retired D9). A tainted resource is destroyed before it is
recreated, and this resource's destroy now turns private DNS off before the
replacement Create/Update turns it back on -- two writes and one async wait where
there used to be zero, but not a loss: the same values are re-applied, in order,
before Terraform reports success. Nothing here has measured that sequence racing
against itself, so treat it as expected rather than as proven fast.

BOTH ARE RENDERED BY THE REGION RESOURCE TOO, WHICH IS WHY NEITHER SAYS "network"
ANY MORE AND WHY THE REFUSAL NO LONGER SAYS "this endpoint". They were written for
checkpointsase_enhanced_network_private_dns and read correctly there; the moment
checkpointsase_enhanced_region_private_dns started rendering them, "the network's
private DNS configuration is unchanged" told an operator about the wrong object,
and "the two rejections measured on this endpoint" asserted measurements that do
not exist -- API-FINDINGS.md 1.31's 422 and 400 were both taken against the
NETWORK path. The wording below is the size of the claim there is evidence for.

STALE NEGATIVE CORRECTED: this used to add "and no probe has ever touched the
region one". Probe p14 has -- probes/p14-enh-region.json is a GET of
/regions/{regionId}/privateDNS, and it is the capture that revealed the third
disabled read shape (API-FINDINGS.md 1.37). What no probe has done is WRITE to the
region path, so the two REJECTIONS quoted in the constant are still
network-path-only, which is the claim the family-neutral wording protects.

THE REFUSAL PARAGRAPH SAID `null` AND IT WAS WRONG TWICE, corrected 2026-08-26.
It used to describe "an array that arrived as `null` rather than `[]`" and to warn
that "the field it names first is not necessarily the field you got wrong".
Neither is what was measured. probes/p7-off-noservers.request.json is
`{"enabled":false,"attributes":{"searchDomains":[]}}` -- `servers` OMITTED, not
null; no request capture in the whole phase contains a JSON `null` at all, and
there is no way to write one in HCL, so an operator was being sent to look for a
shape they could not have produced. And all three errors in the response name
`servers`, which IS the omitted field, so telling them to distrust the field name
pointed away from the fastest route to the fix. This is the same generalisation
API-FINDINGS.md 1.37 retired for split tunnelling; commit 8b554df fixed it in
splitTunnelingWriteRefused in five places and left this twin standing. The wording
now mirrors that one deliberately -- if you change one, change both.
*/
const privateDNSWriteAcceptedButNotCompleted = "The API ACCEPTED this write and then the " +
	"operation did not complete successfully, so the target may or may not now hold the " +
	"configuration above — Terraform cannot tell from here. Run `terraform plan` to see what " +
	"it actually holds before changing anything; re-applying is safe once you have " +
	"looked, because the write is a full replacement and cannot be applied twice to different " +
	"effect. Destroying this resource DOES now send its own write -- `enabled = false` with " +
	"empty `attributes` -- so a destroy after a partial write still lands on a known state; " +
	"it does not need the partial write to have completed first."

const privateDNSWriteRefused = "The API REFUSED this write, so the private DNS " +
	"configuration is unchanged. The message above is the server's own. Three rejections have " +
	"been measured on the enhanced-network private DNS endpoint, which takes the identical " +
	"request body: a `422` for a body with no `attributes` object; a `400` naming an array the " +
	"request left OUT (the complaints cluster on the array that is actually missing, so the " +
	"field they name is the field to add — it may raise several complaints about one array, so " +
	"count the distinct array names rather than the messages); and a `400` reading " +
	"`{\"message\":\"Invalid IP address\"}` for a `servers` address that sits inside the " +
	"network's own subnet, which is about your ADDRESSING and not your typing."

/*
resourceEnhancedNetworkPrivateDNS manages the private DNS configuration of one
enhanced network: GET and PUT /v3/networks/enhanced/{networkId}/privateDNS.

IT IS A SETTING ON AN EXISTING OBJECT, NOT AN OBJECT. There is no POST and no
DELETE on this path -- the configuration exists as soon as the network does, with
`enabled: false` and nothing else. So "create" means adopt-and-write, "update" is
the identical call, and "destroy" means write the same "off" body Update would for
`enabled = false` (see privateDNSNoOpDeleteNote and P81-145399 -- this used to
mean stop tracking and issue no request, decision D9, which left a destroyed
resource's configuration live on the tenant). Only one Terraform resource in one
configuration should own a given network's private DNS; a second would fight the
first on every apply, on every destroy now too.

THE WRITE IS ASYNCHRONOUS. The PUT declares no success response but 202 -- there is
no 200 in its response map (swagger.yaml:633) -- so the write has NOT happened when
the call returns; putPrivateDNSAndWait polls the
operation to completion before this resource reads anything back. Reading
immediately would store pre-write values as if the apply had succeeded, which is
the failure putGranularFirewallPolicy's comment records shipping three times.

Everything about the body -- the schema, the full-replacement expander, the
flattener and the async wait -- lives in private_dns.go, because the region
resource makes the identical call against a different path. This file is the
network's address, its CRUD wiring, and nothing else.

@return &schema.Resource
*/
func resourceEnhancedNetworkPrivateDNS() *schema.Resource {
	return &schema.Resource{
		Description: "Manages the private DNS configuration of a Check Point SASE **enhanced " +
			"network** — `GET`/`PUT /v3/networks/enhanced/{networkId}/privateDNS`. " +
			"This is a setting on a network that already exists, not an object of its own: " +
			"the API has no create and no delete for it, so `terraform apply` adopts the " +
			"network's current private DNS configuration and replaces it with yours. " +
			"**Every write is a full replacement.** Anything omitted from `attributes` is " +
			"cleared rather than preserved, including `search_domains` and the whole " +
			"`dns_policy` block — to keep a value, write it. " +
			"The write is asynchronous: the API answers `202 Accepted` and the provider polls " +
			"the operation to completion before reporting the apply as done. " +
			"Setting `enabled = false` is the supported way to turn private DNS off. On the " +
			"FIRST write to a network that has never been configured, omitting the " +
			"`attributes` block is enough: the provider synthesises the empty `servers` and " +
			"`search_domains` arrays the API requires. After anything has been written, " +
			"omitting the block carries the last-applied values forward instead — write " +
			"`attributes {}` to send empty arrays deliberately. " +
			"**`attributes` is computed as well as optional**, because the API returns the " +
			"object on every read once anything has been written — a network that has never " +
			"been configured reads back as `{\"enabled\": false}` with no `attributes` key, " +
			"and one that has been explicitly disabled reads back with `attributes` present " +
			"and empty. Removing the block from your configuration therefore leaves whatever " +
			"the network already holds rather than clearing it; there is nothing it could " +
			"clear to, since the API rejects a write with no `attributes` object. To empty a " +
			"list write it empty, and to drop the DNS policy remove the `dns_policy` block — " +
			"the blocks nested inside `attributes` are optional only, so omitting one of those " +
			"does still clear it. " +
			privateDNSNoOpDeleteNote + " " +
			"Import with the network id: `terraform import " +
			"checkpointsase_enhanced_network_private_dns.this <network_id>`. " +
			"The standard-network equivalent of this endpoint is read-only, which is an " +
			"API asymmetry rather than a modelling choice.",
		CreateContext: resourceEnhancedNetworkPrivateDNSCreate,
		ReadContext:   resourceEnhancedNetworkPrivateDNSRead,
		UpdateContext: resourceEnhancedNetworkPrivateDNSUpdate,
		DeleteContext: resourceEnhancedNetworkPrivateDNSDelete,
		CustomizeDiff: resourceEnhancedNetworkPrivateDNSCustomizeDiff,
		Schema:        enhancedNetworkPrivateDNSSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: resourceEnhancedNetworkPrivateDNSImportState,
		},
		// The write is asynchronous and this resource POLLS it to completion, so
		// without this it inherits SDKv2's 20-minute system default and the
		// operator has no `timeouts {}` block to raise it with. Thirteen other
		// resources in this package already declare asyncResourceTimeout for the
		// same reason.
		//
		// Delete now PUTs and polls too (P81-145399, privateDNSNoOpDeleteNote), so
		// it needs the same budget Create and Update have, not the absence this
		// block used to document.
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(asyncResourceTimeout),
			Update: schema.DefaultTimeout(asyncResourceTimeout),
			Delete: schema.DefaultTimeout(asyncResourceTimeout),
		},
	}
}

/*
enhancedNetworkPrivateDNSSchema is privateDNSSchema plus this resource's address.

privateDNSSchema is CALLED, not restated, and that is the whole point of it
existing: expandCustomDnsUpdate reads the body attributes by name, and a name it
reads that the schema does not declare returns a zero value with no error, no
diff and nothing in the logs. One declaration means a typo is a compile error
rather than a silently dropped field. See the comment above the constants in
private_dns.go.

`network_id` is Required and ForceNew because it is the object's ADDRESS: this
resource does not own a network's identity, it owns one setting on the network
that id names, so pointing it at a different network is a different object rather
than a change to this one. A replace now costs one real write: Delete turns
private DNS off on the OLD network before Create adopts and writes the new one
(P81-145399 retired D9's no-op) -- there is nothing to migrate, but it is no longer
free.

@return map[string]*schema.Schema
*/
func enhancedNetworkPrivateDNSSchema() map[string]*schema.Schema {
	s := privateDNSSchema()
	s[privateDNSAttrNetworkID] = &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		ForceNew: true,
		Description: "ID of the enhanced network whose private DNS this configures. Changing it " +
			"replaces the resource: it is the address of the setting, not a property of it. " +
			"The network must already exist — this endpoint answers `404` " +
			"(`{\"message\":\"Network doesn't exist.\"}`) for an id it does not know.",
	}
	return s
}

/*
getEnhancedNetworkPrivateDNS issues the one GET this resource makes.

Factored out only so that Create's adoption check and Read make demonstrably the
same call: a Create that checked a different path from the one Read polls would
adopt something Read then reports as missing.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param client *perimeter81Sdk.APIClient - the configured client
  - @param networkId string - the enhanced network's id

@return *perimeter81Sdk.CustomDns - the configuration as read
@return *http.Response - kept so the caller can classify a 404
@return error
*/
func getEnhancedNetworkPrivateDNS(ctx context.Context, client *perimeter81Sdk.APIClient,
	networkId string) (*perimeter81Sdk.CustomDns, *http.Response, error) {

	return client.EnhancedPrivateDNSAPI.GetEnhancedNetworkPrivateDNS(ctx, networkId).Execute()
}

/*
resourceEnhancedNetworkPrivateDNSCreate adopts the network's existing private DNS
configuration and then writes the configured one.

There is no create endpoint: the configuration exists as soon as the network does.
So this GETs it as a reachability and existence check, sets the id, and delegates
to Update -- the same shape as resourceFirewallPolicyCreate, which adopts a
per-network policy object for the same reason.

THE 404 HERE IS AN ERROR, NOT DRIFT, WHICH IS THE OPPOSITE OF READ. The two are
not inconsistent: in Read a 404 means an object Terraform was tracking has gone,
which is drift. Here nothing is being tracked yet -- the operator has just named
a network that does not exist -- and silently succeeding would produce an apply
against a network id that was never valid.

DO NOT d.Set ANY BODY ATTRIBUTE HERE. terraform-plugin-sdk's d.Get prefers a
recent d.Set over the diff, so setting the network's CURRENT values before Update
runs would clobber the operator's HCL and push the server's existing values
straight back -- the resource would report success having applied nothing.

The id is set BEFORE the write, deliberately. If the write is accepted and then
fails to complete, Terraform still holds an id and the next plan shows the drift;
an unset id would leave a network whose DNS may have changed with nothing
tracking it.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedNetworkPrivateDNSCreate(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(privateDNSAttrNetworkID).(string)

	if _, _, err := getEnhancedNetworkPrivateDNS(ctx, client, networkId); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to read enhanced network private DNS for adoption", err)
	}

	d.SetId(networkId)
	return resourceEnhancedNetworkPrivateDNSUpdate(ctx, d, m)
}

/*
resourceEnhancedNetworkPrivateDNSRead reads the network's private DNS
configuration into state.

A 404 CLEARS THE ID AND RETURNS NO ERROR, AND THAT IS CORRECT HERE EVEN THOUGH IT
WAS WRONG THREE TIMES IN PHASE 3. Do not "fix" this back.

The Phase 3/4 hazard was a COLLECTION endpoint: a 404 there meant the URL was
wrong, and treating it as drift silently emptied Terraform's state on a
misconfiguration, so the next apply proposed recreating objects that had never
gone anywhere. This endpoint is a SINGLE OBJECT addressed by a
user-supplied id, and P10 measured what a wrong id gets on 2026-08-26:

	GET /v3/networks/enhanced/{bogus}/privateDNS
	-> 404 {"message":"Network doesn't exist.","messageCode":"NOT_FOUND","status":404}

The message names the cause and the cause is the object, not the route. A network
deleted outside Terraform is exactly the drift a Read is supposed to report, and
`network_id` is a required user-supplied argument, so the vanished-parent case is
directly reachable through HCL and has to plan as a recreation rather than as an
apply-time failure (test-plan row EPD-D01).

`attributes` MAY BE ABSENT, AND THAT IS THE ORDINARY CASE. API-FINDINGS.md 1.31
measured an unconfigured network reading back as exactly `{"enabled": false}`,
with no `attributes` key at all, which decodes to a nil *CustomDnsAttributes.
flattenCustomDnsAttributes handles the nil; nothing here may dereference it.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedNetworkPrivateDNSRead(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(privateDNSAttrNetworkID).(string)

	customDns, resp, err := getEnhancedNetworkPrivateDNS(ctx, client, networkId)
	if err != nil {
		if isNotFound(resp, err) {
			// The network itself is gone -- see the doc comment. Drift, not
			// failure: clear the id and say nothing, so the next plan proposes
			// recreating the configuration on a network the operator will have
			// to recreate too.
			d.SetId("")
			return diags
		}
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read enhanced network private DNS", err)
	}

	// A no-op on every path today: networkId was just read OUT of this attribute,
	// so writing it back changes nothing. It is kept because it makes Read the
	// single place that populates this resource's state -- the importer sets
	// network_id only so that the GET above has a path to build, and if that ever
	// changed to deriving the address from d.Id() this is the line that would carry
	// it into state. Removing it would move that responsibility somewhere less
	// obvious for no gain.
	if err := d.Set(privateDNSAttrNetworkID, networkId); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set enhanced network private DNS network_id", err)
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
		return appendErrorDiags(diags, "Unable to set enhanced network private DNS enabled", err)
	}
	if err := d.Set(privateDNSAttrAttributes,
		flattenCustomDnsAttributes(customDns.Attributes)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set enhanced network private DNS attributes", err)
	}

	return diags
}

/*
resourceEnhancedNetworkPrivateDNSUpdate sends the one PUT this resource makes and
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
unconfigured network carries no `attributes` at all), and using the write's own
echo would mean no apply ever exercises the code path the NEXT plan compares
against -- which is precisely how a read-shape mismatch survives an acceptance
run.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedNetworkPrivateDNSUpdate(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(privateDNSAttrNetworkID).(string)
	payload := expandCustomDnsUpdate(d)

	accepted, err := putPrivateDNSAndWait(ctx, client,
		func(ctx context.Context) (*perimeter81Sdk.AsyncOperationResponse, *http.Response, error) {
			return client.EnhancedPrivateDNSAPI.
				UpdateEnhancedNetworkPrivateDNS(ctx, networkId).
				CustomDnsUpdate(payload).
				Execute()
		})
	if err != nil {
		d.Partial(true)

		// appendErrorDiagsWithGuidance, not appendErrorDiags: the latter promotes
		// the server's body into Detail and discards the caller's wrapper, so
		// guidance attached any other way never reaches the operator. See its doc
		// comment (utils.go:1283).
		if accepted {
			return appendErrorDiagsWithGuidance(diags,
				"The enhanced network private DNS update was accepted but did not complete",
				privateDNSWriteAcceptedButNotCompleted, err)
		}
		return appendErrorDiagsWithGuidance(diags,
			"Unable to update enhanced network private DNS",
			privateDNSWriteRefused, err)
	}

	return resourceEnhancedNetworkPrivateDNSRead(ctx, d, m)
}

/*
resourceEnhancedNetworkPrivateDNSDelete turns private DNS off on the network and
then removes the resource from Terraform state.

THIS USED TO MAKE NO API CALL AT ALL (decision D9), and that no-op is what
P81-145399 retired: a `terraform destroy` that clears state without a request
left every configured server, search domain and DNS policy live on the tenant,
silently, forever, with no plan line ever able to show it again. `putPrivateDNSAndWait`
with `defaultCustomDnsUpdate()` is exactly the write `terraform apply` of
`enabled = false` with an empty `attributes` block would send -- see
privateDNSNoOpDeleteNote and defaultCustomDnsUpdate's own comment for why that
body, and no other, is the one that both clears the configuration and is legal to
send.

THE ID IS ONLY CLEARED ON SUCCESS. If the write is refused or never completes,
this resource stays tracked and the error is the operator's signal to look and
retry -- clearing the id here regardless would tell Terraform the destroy
succeeded while the tenant might still hold the old configuration, which is the
same silent-drift failure this rewrite exists to close.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceEnhancedNetworkPrivateDNSDelete(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(privateDNSAttrNetworkID).(string)
	payload := defaultCustomDnsUpdate()

	accepted, err := putPrivateDNSAndWait(ctx, client,
		func(ctx context.Context) (*perimeter81Sdk.AsyncOperationResponse, *http.Response, error) {
			return client.EnhancedPrivateDNSAPI.
				UpdateEnhancedNetworkPrivateDNS(ctx, networkId).
				CustomDnsUpdate(payload).
				Execute()
		})
	if err != nil {
		d.Partial(true)

		// appendErrorDiagsWithGuidance, not appendErrorDiags: see the same note on
		// resourceEnhancedNetworkPrivateDNSUpdate.
		if accepted {
			return appendErrorDiagsWithGuidance(diags,
				"The enhanced network private DNS destroy write was accepted but did not complete",
				privateDNSWriteAcceptedButNotCompleted, err)
		}
		return appendErrorDiagsWithGuidance(diags,
			"Unable to turn off enhanced network private DNS on destroy",
			privateDNSWriteRefused, err)
	}

	d.SetId("")
	return diags
}

/*
resourceEnhancedNetworkPrivateDNSCustomizeDiff enforces the two rules
privateDNSSchema records as inexpressible in a schema: the conditional `servers`
minimum, and uniqueness across the four lists the API declares uniqueItems.

Both live in validatePrivateDNSDiff so the region resource enforces exactly the
same rules from its own CustomizeDiff. Neither is expressible as MinItems or as a
TypeSet -- see that function for why each would be wrong rather than merely
inconvenient.

Destroy plans never reach CustomizeDiff in SDKv2, which is what we want: a destroy
has no configuration to check, and Delete's own payload is the fixed
defaultCustomDnsUpdate() body rather than anything read from the diff, so there is
nothing here for CustomizeDiff to validate even now that destroy writes
(P81-145399).

  - @param ctx context.Context - unused
  - @param d *schema.ResourceDiff - the diff
  - @param m interface{} - unused

@return error
*/
func resourceEnhancedNetworkPrivateDNSCustomizeDiff(_ context.Context, d *schema.ResourceDiff,
	_ interface{}) error {

	return validatePrivateDNSDiff(d)
}

/*
resourceEnhancedNetworkPrivateDNSImportState imports one enhanced network's
private DNS configuration by the network id.

	terraform import checkpointsase_enhanced_network_private_dns.this <network_id>

The id IS the network id -- there is nothing to parse and no digest to compute,
because the configuration is addressed entirely by the network it belongs to. So
`network_id` is set from it before Read runs; without that, Read would GET
/v3/networks/enhanced//privateDNS, which is a different route altogether rather
than a 404 on this one.

The empty-id check afterwards is not redundant with the error check above it.
Read reports a vanished network by clearing the id and returning NO diagnostics
(see its comment on why a 404 is drift here), so an import of a network that does
not exist would otherwise report success and write an empty resource into state.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceEnhancedNetworkPrivateDNSImportState(ctx context.Context, d *schema.ResourceData,
	m interface{}) ([]*schema.ResourceData, error) {

	networkId := d.Id()
	if networkId == "" {
		return nil, fmt.Errorf("an enhanced network private DNS import id is the network id, " +
			"and this one is empty: terraform import " +
			"checkpointsase_enhanced_network_private_dns.<name> <network_id>")
	}
	// THIS LINE IS WHAT MAKES IMPORT WORK, and it is the opposite of the
	// identically-shaped line in Read. Do not "tidy" it away.
	//
	// Read addresses the object by the network_id ATTRIBUTE, not by d.Id(). On
	// import the attribute is empty -- networkId here came out of d.Id() -- so
	// without this the GET below is /v3/networks/enhanced//privateDNS: an empty
	// path segment, which is a DIFFERENT ROUTE rather than a 404 on this one.
	// Pinned by TestEnhancedNetworkPrivateDNSImportSetsNetworkIdBeforeReading,
	// which asserts the whole request list so the empty segment is visible
	// rather than inferred.
	if err := d.Set(privateDNSAttrNetworkID, networkId); err != nil {
		return nil, fmt.Errorf("could not set network_id from the import id %q: %w", networkId, err)
	}

	diagnostics := resourceEnhancedNetworkPrivateDNSRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import enhanced network private DNS: %s, \n %s",
					diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	if d.Id() == "" {
		return nil, fmt.Errorf("no such enhanced network: %q. The API answered 404 "+
			"(\"Network doesn't exist.\") for it, so there is no private DNS configuration to "+
			"import", networkId)
	}

	return []*schema.ResourceData{d}, nil
}
