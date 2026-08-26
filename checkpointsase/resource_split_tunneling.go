package checkpointsase

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
resource_split_tunneling.go is checkpointsase_split_tunneling in full: the
schema, the expander, the flattener, the polled write and the CRUD wiring.

IT IS ONE FILE BECAUSE THERE IS ONE RESOURCE. The two enhanced private-DNS
resources share private_dns.go because they make the identical call against two
different paths; nothing shares this endpoint. Extracting a "shared" helper here
would create an abstraction with a single caller, which is the thing that made
the private-DNS split worth doing in the first place -- it is not a house style
to be copied blindly.

WHAT IS COPIED FROM THAT SIBLING, deliberately: the shape of the async write
(send, take the last segment of statusUrl, poll to completion), the no-op Delete
(D9), the 404-is-drift Read, and the rule that every async failure is rendered
through appendErrorDiagsWithGuidance rather than appendErrorDiags. Those are
house patterns and they are established there.

WHAT DIFFERS, and it is deliberate rather than an oversight: Create sets the id
AFTER the write completes, not before. See resourceSplitTunnelingCreate.
*/

/*
THE ATTRIBUTE NAMES ARE CONSTANTS for the same reason private_dns.go gives:
expandSplitTunneling reads the resource's attributes by name, and a name it reads
that the schema does not declare returns a zero value with NO error, no diff and
nothing in the logs. One spelling per package makes a typo a compile error.

network_id IS DECLARED AGAIN HERE rather than reusing privateDNSAttrNetworkID,
and that is a choice. That constant belongs to the shared private-DNS schema and
is documented as such; borrowing it would couple two unrelated resources through
a name, so that a rename in one silently retargets the other. The anti-drift
argument is about one schema having one spelling of its own keys, not about the
package having one string literal.
*/
const (
	splitTunnelingAttrNetworkID          = "network_id"
	splitTunnelingAttrDefaultMode        = "default_tunneling_mode"
	splitTunnelingAttrExceptData         = "except_data"
	splitTunnelingAttrCidr               = "cidr"
	splitTunnelingAttrAddressObjectIds   = "address_object_ids"
	splitTunnelingAttrUpdatableObjectIds = "updatable_object_ids"
	splitTunnelingAttrExceptions         = "exceptions"
	splitTunnelingAttrExceptionType      = "type"
	splitTunnelingAttrExceptionDest      = "destination"
)

/*
splitTunnelingModes are the two values defaultTunnelingMode admits
(swagger.yaml:7114-7117).

Validated case-SENSITIVELY -- validation.StringInSlice(..., false) -- because
this API does not fold case on enums and a case-insensitive check would let
"Out_Of_Tunnel" through plan and fail well into an apply. That is the Phase 3
`access` / `"Read"` lesson; nothing has been measured against a wrong-case value
here, so the strict reading is the safe one.
*/
var splitTunnelingModes = []string{"via_tunnel", "out_of_tunnel"}

/*
splitTunnelingNoOpDeleteNote is what `terraform destroy` does to this resource,
and -- the part that matters -- what it does NOT do.

DECISION D9, taken by the operator on 2026-08-25 and settled for all three of
Phase 5's write resources: destroy clears Terraform state and issues NO request.

It is even less arguable here than it is for private DNS. There is no "off" for a
tunnelling mode: every network has one, always, and the only write a Delete could
make is a different mode -- which would change which of a live network's traffic
goes through the tunnel, as a side effect of somebody removing a Terraform
resource, with no plan line saying so. Split tunnelling decides what is inspected
and what bypasses inspection, so a silent flip is a security change.

Nothing is released by leaving it, either. Firewall policy's Delete writes
`policyRules: []` because its rules PIN other Terraform objects; this pins
nothing, so no dependent destroy fails because the configuration is still there.
*/
const splitTunnelingNoOpDeleteNote = "`terraform destroy` on this resource makes NO API call. " +
	"It releases Terraform's claim on the setting and leaves the network's split tunnelling " +
	"exactly as it is — whatever mode and destinations were last applied stay in force. There is " +
	"no \"off\" for a tunnelling mode: every network has one, so a destroy that wrote something " +
	"would be changing which traffic bypasses the tunnel as a side effect of removing a Terraform " +
	"resource. If you want a different mode, apply it first, then destroy."

/*
splitTunnelingWriteAcceptedButNotCompleted and splitTunnelingWriteRefused are the
two guidance paragraphs the async write attaches to a failure.

They are separate because the two situations send an operator to different
places, and putSplitTunnelingAndWait's `accepted` return is the only thing that
tells them apart. "The API refused the request" means nothing changed and the
message body says why. "The API accepted the request and the operation then
failed" means the network may or may not now hold the new configuration, and the
honest advice is to look rather than to assume either way.

Both are rendered through appendErrorDiagsWithGuidance, NEVER appendErrorDiags:
errors out of putSplitTunnelingAndWait are GenericOpenAPIErrors or wrap one, and
appendErrorDiags promotes the server's body into Detail and DISCARDS whatever the
caller wrapped it with -- so guidance attached any other way never reaches the
wire (utils.go:1283).

THE REFUSAL PARAGRAPH NAMES THE 409 ON PURPOSE. The SDK decodes it into a
dedicated model (UpdateSplitTunnelingConfigurationAsync409Response,
api_networks.go:549) but formatErrorMessage cannot read that model -- it
fmt.Sprintf("%v")s the struct and then tries to json.Unmarshal the result, which
fails for anything that is not a map[string]string -- so err.Error() for a 409 on
this path is the bare string "409 Conflict". The message only reaches an operator
because appendErrorDiags prefers GenericOpenAPIError.Body(), which is the raw
server JSON. Pinned by TestSplitTunnelingUpdateSurfacesThe409Message.
*/
const splitTunnelingWriteAcceptedButNotCompleted = "The API ACCEPTED this write and then the " +
	"operation did not complete successfully, so the network may or may not now hold the " +
	"configuration above — Terraform cannot tell from here. Run `terraform plan` to see what it " +
	"actually holds before changing anything; re-applying is safe once you have looked, because " +
	"`default_tunneling_mode`, `cidr`, `address_object_ids` and `updatable_object_ids` are a full " +
	"replacement and cannot be applied twice to different effect. Destroying this resource would " +
	"NOT undo a partial write: its Delete makes no API call at all."

const splitTunnelingWriteRefused = "The API REFUSED this write, so the network's split tunnelling " +
	"is unchanged. The message above is the server's own. Three refusals have been measured on " +
	"this endpoint: a `404` (`{\"message\":\"network doesnt exist\"}`) for a `network_id` the API " +
	"does not know; a `400` naming `exceptData.cidr`, `exceptData.addressObjectIds` and " +
	"`exceptData.updatableObjectIds` together when any one of the three arrays is missing — it " +
	"reports every array complaint at once, so the field it names first is not necessarily the " +
	"one you got wrong; and a `400` reading \"Exceptions are not supported in via_tunnel mode.\" " +
	"A `409` on this path means the API could not reconcile the updatable objects in the " +
	"configuration."

/*
splitTunnelingPollInterval is the cadence putSplitTunnelingAndWait polls the
status endpoint at. It matches putPrivateDNSAndWait's and
putGranularFirewallPolicy's hardcoded 10s deliberately: this is a new call site
for an existing pattern, not a retiming of it.

MEASURED AND NOT ACTED ON: every async 202 on this API carries
`samplingTime: 120` -- including the ones captured from THIS endpoint on
2026-08-26 (API-FINDINGS.md 1.28, 1.29) -- so the server is stating a sampling
cadence an order of magnitude larger than what every poller in this provider
uses. Honouring it is one change across all of them, with each path's own value
read rather than assumed. Doing it here alone would leave this endpoint twelve
times slower to converge than its neighbours for no reason a reader of this file
could see. Tracked as LEFTOVERS.md L13.

It is a var rather than a const solely so the tests can collapse it and drive a
multi-poll operation in microseconds instead of half a minute. Nothing in the
provider assigns it.
*/
var splitTunnelingPollInterval = 10 * time.Second

// splitTunnelingTransientBudget allows two 5xx/EOF blips per operation, matching
// the transient budgets in async.go.
const splitTunnelingTransientBudget = 2

/*
errSplitTunnelingNoStatusUrl is returned when the API accepts the PUT with a 202
that carries no statusUrl, so there is nothing to poll.

Same decision as putPrivateDNSAndWait, and it differs from
putGranularFirewallPolicy, which returns (false, nil) in the same situation --
i.e. silently does not wait and reports the apply as successful. A 202 means the
write has NOT happened yet, so a 202 with nothing to poll is a write this
provider cannot confirm, and reporting an unconfirmable write as a successful
apply is the failure the whole helper exists to prevent.

The cost is a false failure if the server ever legitimately returns a 202 with no
statusUrl for a write that did land. Every async 202 measured on this endpoint on
2026-08-26 carried one (API-FINDINGS.md 1.28, 1.29 -- six writes across the two
probe networks). If that changes, revisit this as the decision it is.
*/
var errSplitTunnelingNoStatusUrl = errors.New(
	"the API accepted the split tunnelling update with a 202 that carried no statusUrl, " +
		"so the operation could not be followed to completion and this provider cannot " +
		"confirm the write landed")

/*
resourceSplitTunneling manages the split tunnelling configuration of one network:
GET /v3/networks/{networkId}/split-tunneling and
PUT /v3/networks/{networkId}/split-tunneling/async.

IT TAKES EITHER FAMILY. The path has no enhanced/standard segment, and probe P1
confirmed it on 2026-08-26: the GET returned 200 with BYTE-IDENTICAL bodies on an
enhanced and on a standard network, and writes were accepted on both. This is the
only Phase 5 resource that is not family-specific.

IT IS A SETTING ON AN EXISTING OBJECT, NOT AN OBJECT. There is no POST and no
DELETE on this path -- every network has a tunnelling mode as soon as it exists.
So "create" means adopt-and-write, "update" is the identical call, and "destroy"
means stop tracking (D9, see splitTunnelingNoOpDeleteNote). Only one Terraform
resource in one configuration should own a given network's split tunnelling; a
second would fight the first on every apply.

THE WRITE IS ASYNCHRONOUS. The PUT declares only a 202 (swagger.yaml:1289), so
the write has NOT happened when the call returns; putSplitTunnelingAndWait polls
the operation to completion before this resource reads anything back.

@return &schema.Resource
*/
func resourceSplitTunneling() *schema.Resource {
	return &schema.Resource{
		Description: "Manages the split tunnelling configuration of a Check Point SASE network — " +
			"`GET /v3/networks/{networkId}/split-tunneling` and " +
			"`PUT /v3/networks/{networkId}/split-tunneling/async`. " +
			"**`network_id` takes EITHER a standard or an enhanced network id.** This path has no " +
			"family segment, and both were verified on 2026-08-26 to return byte-identical bodies " +
			"and to accept writes. " +
			"This is a setting on a network that already exists, not an object of its own: the " +
			"API has no create and no delete for it, so `terraform apply` adopts the network's " +
			"current split tunnelling and replaces it with yours. " +
			"`default_tunneling_mode`, `except_data.cidr`, `except_data.address_object_ids` and " +
			"`except_data.updatable_object_ids` are a **full replacement** — what you write is " +
			"what the network gets, and dropping an entry removes it. " +
			"The write is asynchronous: the API answers `202 Accepted` and the provider polls the " +
			"operation to completion before reporting the apply as done. " +
			"**`except_data.exceptions` is READ-ONLY, and the cost of that is that you cannot " +
			"create an exception with this resource either.** An exception is traffic that " +
			"bypasses the tunnel. The v3 endpoint MERGES the field rather than replacing it, so " +
			"nothing sent through it can ever remove a saved exception — an empty array, an " +
			"omitted key and shrinking the covering `cidr` were all measured on 2026-08-26 to " +
			"leave the exception in place, and switching to `via_tunnel` only HIDES it, since " +
			"exceptions are not supported in that mode and the read stops returning them. Switch " +
			"back and the exception returns from server-side storage. A resource that could write " +
			"the field could therefore resurrect bypass rules its operator never wrote and " +
			"Terraform never displayed, so it surfaces exceptions for inspection and never sends " +
			"them. Adding or removing one is a console operation until the API gains a replace " +
			"path. " +
			splitTunnelingNoOpDeleteNote + " " +
			"Import with the network id: `terraform import checkpointsase_split_tunneling.this " +
			"<network_id>`.",
		CreateContext: resourceSplitTunnelingCreate,
		ReadContext:   resourceSplitTunnelingRead,
		UpdateContext: resourceSplitTunnelingUpdate,
		DeleteContext: resourceSplitTunnelingDelete,
		/*
			THERE IS DELIBERATELY NO CustomizeDiff, and this is a decision with a
			measurement behind it rather than an omission.

			The rule a validator would enforce is "exceptions are not supported in
			via_tunnel mode". The v3 document asserts it; this repo's own
			V3-TERRAFORM-TEST-PLAN.md:1055 withdrew the claim after reading the
			backend and concluding no cross-field validator exists. THE WIRE
			DISAGREES WITH THAT READING. Measured 2026-08-26 (API-FINDINGS.md 1.30):

			  PUT {"defaultTunnelingMode":"via_tunnel",
			       "exceptData":{"cidr":[],"addressObjectIds":[],
			                     "updatableObjectIds":[],
			                     "exceptions":[{"type":"cidr",
			                                    "destination":"10.99.0.1/32"}]}}
			    -> 400 {"message":"Exceptions are not supported in via_tunnel mode.",
			            "messageCode":"BAD_REQUEST","status":400}

			  the identical body WITHOUT exceptions -> 202

			So the server refuses clearly and names the reason, which is Phase 2's
			OS-N03 branch: a plan-time refusal there is optional, and Phase 4's
			lesson is to let a specific, actionable server error answer rather than
			duplicating it at plan time.

			And the combination is unreachable from here anyway. `exceptions` is
			Computed-only (see the schema), so expandSplitTunneling never sends the
			key, and no configuration a user can write produces the rejected body.
			A validator would guard a state the schema already prevents.
		*/
		Schema: splitTunnelingSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: resourceSplitTunnelingImportState,
		},
		// The write is asynchronous and this resource POLLS it to completion, so
		// without this it inherits SDKv2's 20-minute system default and the
		// operator has no `timeouts {}` block to raise it with. Fifteen other
		// resources in this package already declare asyncResourceTimeout for the
		// same reason. Pinned by TestSplitTunnelingDeclaresAnAsyncTimeout, and
		// exercised by TestSplitTunnelingCreateTimesOutWithoutWritingAnId.
		//
		// THERE IS DELIBERATELY NO Delete TIMEOUT. Delete makes no API call at all
		// (D9, splitTunnelingNoOpDeleteNote) -- it clears the id and returns -- so
		// declaring a budget for it would advertise a wait that cannot happen.
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(asyncResourceTimeout),
			Update: schema.DefaultTimeout(asyncResourceTimeout),
		},
	}
}

/*
splitTunnelingSchema declares the resource.

EVERY LIMIT AND EVERY ABSENCE OF ONE IS SOURCED:

  - defaultTunnelingMode and exceptData are both in SplitTunnelingBase's required
    list (swagger.yaml:7120-7122), so both are Required here.

  - cidr, addressObjectIds and updatableObjectIds carry NO minItems, NO maxItems
    and NO uniqueItems (swagger.yaml:7127-7147). Each carries `default: []`. So
    no MaxItems is declared, MinItems stays 0, and TypeList is right -- there is
    no uniqueness rule to make a set worth its cost.

  - ORDER IS PRESERVED, AND THAT IS NOW MEASURED RATHER THAN ASSUMED. These
    shipped as TypeList while nothing had been measured about ordering, on the
    reasoning that a set discards an ordering nobody has shown the server
    discards. API-FINDINGS.md 1.31 has since settled it: three cidr entries sent
    deliberately non-ascending -- "10.80.0.0/16", "10.10.0.0/16", "10.50.0.0/16"
    -- came back in exactly that order, and a sorting server would have moved
    10.80 to the end.

    BE PRECISE ABOUT HOW FAR ONE PROBE REACHES. It measured `cidr`, on ONE
    network, of the ENHANCED family. addressObjectIds and updatableObjectIds were
    sent EMPTY in that probe, so their ordering is still unmeasured, and so is the
    whole question on the STANDARD family. TypeList is right for all three either
    way -- it is the conservative choice under both outcomes -- but only the first
    of them has evidence behind it, and a comment that generalised this to "the
    three arrays" would be claiming two measurements that do not exist.

  - MEASURED 2026-08-26 (API-FINDINGS.md 1.31): all three arrays are REQUIRED ON
    THE WIRE even when empty, `default: []` notwithstanding. Omitting any one
    returns a 400 whose data.errors names all three. They are Optional in HCL and
    always sent as [] by expandSplitTunneling; see there for why that is not a
    contradiction.

  - cidr's items carry an IPv4 CIDR pattern (swagger.yaml:7131). validation.IsCIDR
    is WIDER than that pattern -- it accepts IPv6 too -- which is the safe
    direction: the provider never refuses something the server accepts, and a
    typo still fails at plan instead of fifteen minutes into an apply. The
    element patterns on addressObjectIds and updatableObjectIds are NOT enforced,
    and that is deliberate: swagger.yaml:7138 says addressObjectIds is
    ^[a-zA-Z0-9]{11}$, while the live 400 captured on 2026-08-26 complains that
    each value "must be shorter than or equal to 10 characters" and "longer than
    or equal to 10 characters". Spec and server disagree about the length by one,
    so any check here would be refusing ids on evidence that contradicts itself.

Descriptions are mandatory: TestSchemaEveryAttributeHasADescription walks every
registered resource and fails on a blank one.

@return map[string]*schema.Schema
*/
func splitTunnelingSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		splitTunnelingAttrNetworkID: {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
			Description: "ID of the network whose split tunnelling this configures. **Either a " +
				"standard or an enhanced network id** — this endpoint has no family segment, and " +
				"both were measured returning identical bodies and accepting writes. Changing it " +
				"replaces the resource: it is the address of the setting, not a property of it. " +
				"The network must already exist — this endpoint answers `404` " +
				"(`{\"message\":\"network doesnt exist\"}`) for an id it does not know.",
		},
		splitTunnelingAttrDefaultMode: {
			Type:         schema.TypeString,
			Required:     true,
			ValidateFunc: validation.StringInSlice(splitTunnelingModes, false),
			Description: "How traffic is treated by default. `via_tunnel` sends all internet " +
				"traffic through the cloud gateway EXCEPT the destinations in `except_data`; " +
				"`out_of_tunnel` sends none of it through EXCEPT those destinations. So " +
				"`except_data` is the exception list in both modes, and flipping the mode inverts " +
				"what it means. Case-sensitive: the API does not fold case on this enum.",
		},
		splitTunnelingAttrExceptData: {
			Type:     schema.TypeList,
			Required: true,
			MaxItems: 1,
			Description: "The destinations that are the exception to `default_tunneling_mode`. " +
				"Required, and required on the wire even when every list in it is empty: the API " +
				"refuses a write with no `exceptData` object, and refuses one whose `cidr`, " +
				"`address_object_ids` or `updatable_object_ids` is missing. Write `except_data {}` " +
				"to send three empty arrays.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					splitTunnelingAttrCidr: {
						Type:     schema.TypeList,
						Optional: true,
						Description: "CIDR blocks that are the exception to the default mode. " +
							"Sent as an empty array when unset — the API requires the key even " +
							"when it has no members. The plan-time check is CIDR FORMAT only; " +
							"whether a given range is acceptable to the network is the server's " +
							"decision.",
						Elem: &schema.Schema{
							Type:         schema.TypeString,
							ValidateFunc: validation.IsCIDR,
						},
					},
					splitTunnelingAttrAddressObjectIds: {
						Type:     schema.TypeList,
						Optional: true,
						Description: "IDs of shared address objects that are the exception to the " +
							"default mode, as created by `checkpointsase_object_addresses`. Sent " +
							"as an empty array when unset — the API requires the key even when it " +
							"has no members.",
						Elem: &schema.Schema{Type: schema.TypeString},
					},
					splitTunnelingAttrUpdatableObjectIds: {
						Type:     schema.TypeList,
						Optional: true,
						Description: "IDs (UUIDs) of updatable objects that are the exception to " +
							"the default mode, as listed by the " +
							"`checkpointsase_updatable_objects` data source. Sent as an empty " +
							"array when unset — the API requires the key even when it has no " +
							"members. A `409` on apply means the API could not reconcile these.",
						Elem: &schema.Schema{Type: schema.TypeString},
					},
					splitTunnelingAttrExceptions: {
						/*
							exceptions is Computed-only, and that is a deliberate
							decision measured on 2026-08-26 -- not an oversight and
							not a TODO. See API-FINDINGS.md 1.29 and LEFTOVERS.md
							L33. Do NOT make it Optional.

							The v3 endpoint MERGES this field instead of replacing
							it. Sending [] and omitting the key are the same thing:
							both produce an empty payload list, and the merge then
							restores every saved exception that is still valid.
							Measured, each write polled to completion: [] left the
							exception, omitting it left the exception, and shrinking
							cidr so no included range covered it ALSO left the
							exception -- which the schema explicitly promises will
							clean it up (swagger.yaml:7156).

							The trap that makes this security-relevant rather than
							cosmetic: via_tunnel does not support exceptions, so the
							READ stops returning them -- but they are still stored.
							Switch back to out_of_tunnel WITHOUT sending exceptions
							and they come back. An exception is traffic bypassing
							the tunnel, so a resource that could write this field
							could resurrect bypass rules its operator never wrote
							and Terraform never displayed.

							Computed-only cannot produce either failure. The cost,
							which is in the resource description and not only here:
							an exception cannot be CREATED through this resource
							either. That stays a console operation until L33 is
							resolved.

							The console does have a working clear, via a shape the
							v3 document does not contain at all (exclusionMode +
							includeDestinations/excludeDestinations). Do NOT reach
							for it: it is absent from swagger.yaml and
							v3.upstream.yaml, and coupling to an undocumented
							interface is a scope change, not a task step.
						*/
						Type:     schema.TypeList,
						Computed: true,
						Description: "Saved subnet exceptions that bypass the tunnel, as the API " +
							"reports them. **Read-only, and that means you cannot create one here " +
							"either.** The v3 write merges this field rather than replacing it, so " +
							"nothing this provider could send would ever remove a saved exception, " +
							"and a `via_tunnel` network hides its exceptions rather than deleting " +
							"them — so a resource that stored what it read could reintroduce " +
							"bypass rules on the next switch back to `out_of_tunnel`. Add and " +
							"remove exceptions in the console.",
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								splitTunnelingAttrExceptionType: {
									Type:        schema.TypeString,
									Computed:    true,
									Description: "Type of destination. The API documents one value, `cidr`.",
								},
								splitTunnelingAttrExceptionDest: {
									Type:     schema.TypeString,
									Computed: true,
									Description: "The exempt destination in CIDR notation, e.g. " +
										"`10.1.2.0/24` for a subnet or `10.1.2.3/32` for a single address.",
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
expandSplitTunneling builds the PUT body from resource data.

EVERY ARRAY IS EMPTY, NEVER NIL, AND THAT IS THE WHOLE POINT OF THIS FUNCTION.
Measured 2026-08-26 (API-FINDINGS.md 1.31): omitting any of `cidr`,
`addressObjectIds` or `updatableObjectIds` returns a 400 whose data.errors names
all three -- "exceptData.cidr must be an array", and the same for the other two --
despite each carrying `default: []` in the schema. The generated model declares
all four fields `omitempty`, but SplitTunnelingData.ToMap gates on IsNil rather
than on the struct tag (model_split_tunneling_data.go, utils.go:334), so a
non-nil empty slice reaches the wire as `[]` and a nil one is omitted entirely.
Both variants compile and both marshal without error, which is why the test pins
the BODY and not the struct.

That is why the three arrays are Optional in HCL and required on the wire without
contradiction: a configuration that names none of them still sends all three.

EXCEPTIONS ARE NEVER SENT. Exceptions stays nil, so IsNil drops the key. That is
decision D5 and the schema comment on the attribute is the argument for it; the
one-line version is that the v3 write merges rather than replaces, so anything
this provider sent could add an exception and could never remove one. Leaving the
key off is also what makes the via_tunnel 400 (API-FINDINGS.md 1.30)
unreachable from here.

  - @param d *schema.ResourceData - the resource data

@return perimeter81Sdk.SplitTunnelingBase - the complete PUT body
*/
func expandSplitTunneling(d *schema.ResourceData) perimeter81Sdk.SplitTunnelingBase {
	payload := perimeter81Sdk.SplitTunnelingBase{
		DefaultTunnelingMode: d.Get(splitTunnelingAttrDefaultMode).(string),
		ExceptData: perimeter81Sdk.SplitTunnelingData{
			// Non-nil so a configuration that names none of them still sends
			// three `[]`s. Overwritten below when the block carries values.
			Cidr:               []string{},
			AddressObjectIds:   []string{},
			UpdatableObjectIds: []string{},
		},
	}

	// singleBlock lives in private_dns.go, and is shared rather than restated
	// because the thing it gets right is not obvious: helper/schema represents a
	// block the operator WROTE with nothing in it as a one-element list whose
	// element is NIL, not as a map of zero values, so the idiomatic
	// `items[0].(map[string]interface{})` guard reports `except_data {}` as
	// ABSENT.
	//
	// IT IS NOT LOAD-BEARING HERE, AND SAYING OTHERWISE WOULD BE OVERCLAIMING.
	// Measured by mutation: replacing it with that naive guard leaves the body
	// byte-identical, because the early return below already carries the three
	// empty arrays and a lookup on a nil map yields the same zero value an unset
	// attribute would. It is used because one spelling of this unwrapping in the
	// package is worth having, and because the moment any field in this block
	// gets a default that differs from its zero value, the distinction becomes
	// load-bearing with no warning.
	block, ok := singleBlock(d.Get(splitTunnelingAttrExceptData))
	if !ok {
		return payload
	}

	cidr, _ := block[splitTunnelingAttrCidr].([]interface{})
	payload.ExceptData.Cidr = flattenStringsArrayData(cidr)
	addressObjectIds, _ := block[splitTunnelingAttrAddressObjectIds].([]interface{})
	payload.ExceptData.AddressObjectIds = flattenStringsArrayData(addressObjectIds)
	updatableObjectIds, _ := block[splitTunnelingAttrUpdatableObjectIds].([]interface{})
	payload.ExceptData.UpdatableObjectIds = flattenStringsArrayData(updatableObjectIds)

	return payload
}

/*
flattenSplitTunnelingData maps the read model into the `except_data` block.

The three id lists are always non-nil, so a network with none stores [] rather
than null and a configuration that names none produces no diff.

`exceptions` IS ABSENT FROM THE RESPONSE IN via_tunnel MODE, and that is normal
rather than an edge case: exceptions are not supported in that mode, so the key
does not come back at all (API-FINDINGS.md 1.29, row d). It decodes to a nil
slice and flattens to an empty list. Note what that empty list does NOT mean --
the exceptions may still be stored server-side and will reappear on a switch back
to out_of_tunnel. Nothing here can tell the two apart, which is a large part of
why the attribute is Computed-only.

  - @param data perimeter81Sdk.SplitTunnelingData - the exceptData as read

@return []interface{} - the single `except_data` block
*/
func flattenSplitTunnelingData(data perimeter81Sdk.SplitTunnelingData) []interface{} {
	cidr := make([]string, 0, len(data.Cidr))
	cidr = append(cidr, data.GetCidr()...)
	addressObjectIds := make([]string, 0, len(data.AddressObjectIds))
	addressObjectIds = append(addressObjectIds, data.GetAddressObjectIds()...)
	updatableObjectIds := make([]string, 0, len(data.UpdatableObjectIds))
	updatableObjectIds = append(updatableObjectIds, data.GetUpdatableObjectIds()...)

	return []interface{}{map[string]interface{}{
		splitTunnelingAttrCidr:               cidr,
		splitTunnelingAttrAddressObjectIds:   addressObjectIds,
		splitTunnelingAttrUpdatableObjectIds: updatableObjectIds,
		splitTunnelingAttrExceptions:         flattenSplitTunnelingExceptions(data.Exceptions),
	}}
}

/*
flattenSplitTunnelingExceptions maps the saved exceptions into their block list.

Always non-nil, so a network with none stores [] rather than null.

  - @param exceptions []perimeter81Sdk.SplitTunnelingException - as read

@return []interface{} - one map per exception, empty when there are none
*/
func flattenSplitTunnelingExceptions(
	exceptions []perimeter81Sdk.SplitTunnelingException) []interface{} {

	flattened := make([]interface{}, 0, len(exceptions))
	for _, exception := range exceptions {
		flattened = append(flattened, map[string]interface{}{
			splitTunnelingAttrExceptionType: exception.GetType(),
			splitTunnelingAttrExceptionDest: exception.GetDestination(),
		})
	}
	return flattened
}

/*
putSplitTunnelingAndWait sends one PUT .../split-tunneling/async and waits for
the async operation it starts.

THE WAIT IS NOT OPTIONAL. The PUT declares only a 202 (swagger.yaml:1289) -- there
is no 200 in the response map -- so the write has NOT happened when the call
returns. Reading back immediately stores pre-write values as if the apply
succeeded, which is the failure putGranularFirewallPolicy's comment records
shipping three times on this branch.

THE statusUrl IS NOT FOLLOWED, AND THAT IS THE POINT. Measured 2026-08-26
(API-FINDINGS.md 1.28), including on this endpoint: the statusUrl in a 202 body is
absolute, names a host the request did not go to, and carries an /api/rest/v2.3/
path rather than /v3/. Only its last path segment is used, resolved against the
configured client, exactly as getIdFromUrl does at the other twelve call sites.
Following the field literally would leave the operator's configured BASE_URL --
which exists so a non-US tenant talks to its own region -- and poll whatever
tenant lives at the other host. It would do so INVISIBLY, because that deployment
answers with a well-formed {"completed":...} too: a green apply for a write it
never saw. Pinned by
TestPutSplitTunnelingAndWaitResolvesStatusUrlAgainstTheConfiguredClient.

The status endpoint is /v3/networks/status/{statusId} (api_networks.go:325). The
202s captured from this endpoint on 2026-08-26 all carry
.../api/rest/v2.3/networks/status/{id}, whose last segment resolves there.

  - @param ctx context.Context - propagated into the poll, so a Terraform timeout
    produces a deadline error rather than a hang or a false success
  - @param client *perimeter81Sdk.APIClient - the configured client, which is what
    the status id is resolved against
  - @param networkId string - the network whose configuration is being written
  - @param payload perimeter81Sdk.SplitTunnelingBase - the complete body

@return bool - whether the API accepted the request. True once the PUT itself
succeeded, so a non-nil error alongside true means the accepted operation failed,
never completed, or could not be followed. The two cases pick different caller
summaries: "the API refused the request" sends a reader somewhere else entirely
from "the API accepted the request and the operation then failed".
@return error - the first failure, if any
*/
func putSplitTunnelingAndWait(
	ctx context.Context,
	client *perimeter81Sdk.APIClient,
	networkId string,
	payload perimeter81Sdk.SplitTunnelingBase,
) (bool, error) {

	asyncResp, _, err := client.NetworksAPI.
		UpdateSplitTunnelingConfigurationAsync(ctx, networkId).
		Body(payload).
		Execute()
	if err != nil {
		return false, err
	}

	statusId := getIdFromUrl(asyncResp.GetStatusUrl())
	if statusId == "" {
		return true, errSplitTunnelingNoStatusUrl
	}

	pollErr := pollAsync(ctx, func(ctx context.Context) (asyncResult, *http.Response, error) {
		status, resp, err := client.NetworksAPI.NetworksControllerV2Status(ctx, statusId).Execute()
		if err != nil {
			return asyncResult{}, resp, err
		}
		// THE result BLOCK IS WHAT MAKES SPT-N02 REAL. pollAsync requires a 2xx
		// result.statusCode, not merely completed == true -- but it can only do
		// that with a StatusCode to look at, and StatusCode stays 0 when this
		// block is skipped. isSuccessStatus (async.go:147) treats 0 as success,
		// because some successful completions elsewhere omit statusCode. So
		// dropping these three lines turns every failed completion into a green
		// apply, silently. Pinned by
		// TestSplitTunnelingCreateFailsOnANon2xxCompletion.
		//
		// A `completed: true` WITH NO `result` IS THEREFORE REPORTED AS SUCCESS,
		// and that is an UNMEASURED assumption on this endpoint. No probe has
		// forced a failing write here and recorded whether `result` is present.
		// Until one has, do not read a green apply as proof the server finished
		// the work. Same caveat as putPrivateDNSAndWait, inherited from the shared
		// helper rather than introduced here.
		out := asyncResult{Completed: status.GetCompleted()}
		if r := status.Result; r != nil {
			out.StatusCode = int(r.GetStatusCode())
			out.Reasons = r.GetReason()
		}
		return out, resp, nil
	}, splitTunnelingPollInterval, splitTunnelingTransientBudget)
	if pollErr != nil {
		return true, withStatusID(statusId, pollErr)
	}
	return true, nil
}

/*
getSplitTunneling issues the one GET this resource makes.

Factored out only so that Create's adoption check and Read make demonstrably the
same call: a Create that checked a different path from the one Read polls would
adopt something Read then reports as missing.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param client *perimeter81Sdk.APIClient - the configured client
  - @param networkId string - the network's id, of either family

@return *perimeter81Sdk.SplitTunnelingBase - the configuration as read
@return *http.Response - kept so the caller can classify a 404
@return error
*/
func getSplitTunneling(ctx context.Context, client *perimeter81Sdk.APIClient,
	networkId string) (*perimeter81Sdk.SplitTunnelingBase, *http.Response, error) {

	return client.NetworksAPI.GetSplitTunnelingConfiguration(ctx, networkId).Execute()
}

/*
resourceSplitTunnelingCreate adopts the network's existing split tunnelling and
then writes the configured one.

There is no create endpoint: every network has a tunnelling mode as soon as it
exists. So this GETs it as a reachability and existence check, writes, and only
then sets the id.

THE 404 HERE IS AN ERROR, NOT DRIFT, WHICH IS THE OPPOSITE OF READ. The two are
not inconsistent: in Read a 404 means an object Terraform was tracking has gone,
which is drift. Here nothing is being tracked yet -- the operator has just named a
network that does not exist -- and silently succeeding would produce an apply
against a network id that was never valid.

DO NOT d.Set ANY BODY ATTRIBUTE HERE. terraform-plugin-sdk's d.Get prefers a
recent d.Set over the diff, so setting the network's CURRENT values before the
write would clobber the operator's HCL and push the server's existing values
straight back -- the resource would report success having applied nothing.

THE ID IS SET AFTER THE WRITE, AND THIS IS THE ONE PLACE THIS RESOURCE
DELIBERATELY DIVERGES FROM checkpointsase_enhanced_network_private_dns, WHICH
SETS IT BEFORE. Do not "align" them without reading this.

Test-plan rows SPT-N02 and SPT-N03 both require that a write which is accepted
and then fails, or which times out mid-poll, writes NO id to state. The private-DNS
resource made the opposite trade for a reason that does not hold here: it wanted
Terraform to keep tracking a network whose DNS may have changed. The difference is
that this resource is fully recoverable without state. Its id IS network_id, a
required argument the operator has already written down, and every write is a full
replacement of the three destination lists and the mode -- so the next `terraform
apply` retries the identical write and converges, and `terraform import` can adopt
the network at any time. Nothing is orphaned by declining to record the id, and the
failed apply's own diagnostic says what to look at.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceSplitTunnelingCreate(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(splitTunnelingAttrNetworkID).(string)

	if _, _, err := getSplitTunneling(ctx, client, networkId); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read split tunnelling for adoption", err)
	}

	if writeDiags := writeSplitTunneling(ctx, d, client, networkId); writeDiags.HasError() {
		return append(diags, writeDiags...)
	}

	d.SetId(networkId)
	return resourceSplitTunnelingRead(ctx, d, m)
}

/*
resourceSplitTunnelingRead reads the network's split tunnelling into state.

A 404 CLEARS THE ID AND RETURNS NO ERROR, AND THAT IS CORRECT HERE EVEN THOUGH IT
WAS WRONG THREE TIMES IN PHASE 3. Do not "fix" this back.

The Phase 3/4 hazard was a COLLECTION endpoint: a 404 there meant the URL was
wrong, and treating it as drift silently emptied Terraform's state on a
misconfiguration, so the next apply proposed recreating objects that had never
gone anywhere. This endpoint is a SINGLE OBJECT addressed by a user-supplied id,
and probe P10 measured what a wrong id gets on 2026-08-26:

	GET /v3/networks/{bogus}/split-tunneling
	-> 404 {"message":"network doesnt exist","messageCode":"NOT_FOUND","status":404}

The message names the cause and the cause is the object, not the route. A network
deleted outside Terraform is exactly the drift a Read is supposed to report, and
`network_id` is a required user-supplied argument, so the vanished-parent case is
directly reachable through HCL and has to plan as a recreation rather than as an
apply-time failure (test-plan row SPT-D01).

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceSplitTunnelingRead(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(splitTunnelingAttrNetworkID).(string)

	splitTunneling, resp, err := getSplitTunneling(ctx, client, networkId)
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
		return appendErrorDiags(diags, "Unable to read split tunnelling", err)
	}

	// A no-op on every path today: networkId was just read OUT of this attribute,
	// so writing it back changes nothing. It is kept because it makes Read the
	// single place that populates this resource's state -- the importer sets
	// network_id only so that the GET above has a path to build.
	if err := d.Set(splitTunnelingAttrNetworkID, networkId); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set split tunnelling network_id", err)
	}
	// A 200 WITH A `null` BODY DOES NOT ERROR, and without this it PANICS. decode
	// runs json.Unmarshal into *SplitTunnelingBase; a literal `null` unmarshals
	// cleanly and leaves the pointer nil, so classifyAPIError never sees a
	// failure. The generated getters are nil-safe, but splitTunneling.ExceptData
	// below is a DIRECT FIELD ACCESS -- ExceptData is a value, not a pointer, so
	// there is no nil-safe getter for it -- and it dereferences the receiver.
	//
	// Unmeasured on this endpoint, but a panic is the one failure mode Terraform
	// cannot report as a diagnostic.
	if splitTunneling == nil {
		splitTunneling = &perimeter81Sdk.SplitTunnelingBase{}
	}

	if err := d.Set(splitTunnelingAttrDefaultMode,
		splitTunneling.GetDefaultTunnelingMode()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set split tunnelling default_tunneling_mode", err)
	}
	if err := d.Set(splitTunnelingAttrExceptData,
		flattenSplitTunnelingData(splitTunneling.ExceptData)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set split tunnelling except_data", err)
	}

	return diags
}

/*
resourceSplitTunnelingUpdate sends the one PUT this resource makes and waits for
the async operation it starts.

CREATE AND UPDATE MAKE THE SAME CALL, through writeSplitTunneling. They are not
the same FUNCTION because Create has an adoption check in front of it and sets
the id behind it; see resourceSplitTunnelingCreate for why the id is set after
the write rather than before.

The response body is discarded in favour of delegating to Read, deliberately: the
write's own echo is a 202 beacon and carries no configuration at all, and even if
it did, using it would mean no apply ever exercises the code path the NEXT plan
compares against.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceSplitTunnelingUpdate(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	networkId := d.Get(splitTunnelingAttrNetworkID).(string)

	if writeDiags := writeSplitTunneling(ctx, d, client, networkId); writeDiags.HasError() {
		return append(diags, writeDiags...)
	}

	return resourceSplitTunnelingRead(ctx, d, m)
}

/*
writeSplitTunneling expands the configuration, sends it, waits, and turns a
failure into the right diagnostic.

It exists so that Create and Update cannot drift apart in what they send or in
how they report a failure -- the two differ only in what happens around the write,
not in the write itself.

appendErrorDiagsWithGuidance, not appendErrorDiags: the latter promotes the
server's body into Detail and discards the caller's wrapper, so guidance attached
any other way never reaches the operator (utils.go:1283).

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param client *perimeter81Sdk.APIClient - the configured client
  - @param networkId string - the network being written to

@return diag.Diagnostics - empty on success
*/
func writeSplitTunneling(ctx context.Context, d *schema.ResourceData,
	client *perimeter81Sdk.APIClient, networkId string) diag.Diagnostics {

	var diags diag.Diagnostics

	accepted, err := putSplitTunnelingAndWait(ctx, client, networkId, expandSplitTunneling(d))
	if err == nil {
		return diags
	}

	d.Partial(true)
	if accepted {
		return appendErrorDiagsWithGuidance(diags,
			"The split tunnelling update was accepted but did not complete",
			splitTunnelingWriteAcceptedButNotCompleted, err)
	}
	return appendErrorDiagsWithGuidance(diags,
		"Unable to update split tunnelling",
		splitTunnelingWriteRefused, err)
}

/*
resourceSplitTunnelingDelete removes the resource from Terraform state and makes
NO API call. That is decision D9, not an unfinished function -- read
splitTunnelingNoOpDeleteNote before changing it.

The warning is part of the behaviour rather than decoration. A destroy that
silently changes nothing and a destroy that silently changes which traffic
bypasses the tunnel print the same thing in the console; the diagnostic is the
only thing that tells the operator which one happened.

  - @param ctx context.Context - unused; there is no request to make.
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - unused; there is no request to make.

@return diag.Diagnostics
*/
func resourceSplitTunnelingDelete(_ context.Context, d *schema.ResourceData,
	_ interface{}) diag.Diagnostics {

	var diags diag.Diagnostics

	networkId := d.Get(splitTunnelingAttrNetworkID).(string)
	diags = appendWarningDiags(diags,
		"Split tunnelling left unchanged on the network",
		fmt.Sprintf("Terraform has stopped tracking the split tunnelling configuration of network "+
			"%q and made no API call. The network keeps whatever mode and destinations were last "+
			"applied — destroying this resource does not turn split tunnelling off, because there "+
			"is no \"off\" for a tunnelling mode and changing which of a live network's traffic "+
			"bypasses the tunnel as a side effect of removing a Terraform resource is not "+
			"something a destroy should do. To change it, apply the mode you want first and then "+
			"destroy.", networkId))

	d.SetId("")
	return diags
}

/*
resourceSplitTunnelingImportState imports one network's split tunnelling by the
network id.

	terraform import checkpointsase_split_tunneling.this <network_id>

The id IS the network id -- there is nothing to parse, no separator to choose and
no digest to compute, because the configuration is addressed entirely by the
network it belongs to. So `network_id` is set from it before Read runs; without
that, Read would GET /v3/networks//split-tunneling, which is a different route
altogether rather than a 404 on this one.

The empty-id check afterwards is not redundant with the error check above it.
Read reports a vanished network by clearing the id and returning NO diagnostics
(see its comment on why a 404 is drift here), so an import of a network that does
not exist would otherwise report success and write an empty resource into state.

WHAT AN IMPORT OF A via_tunnel NETWORK DOES NOT TELL YOU, and it belongs here
rather than only in the schema: `except_data.exceptions` will be empty, and that
does not mean the network has none. Exceptions are not supported in via_tunnel
mode, so the read does not return them even though they are still stored
(API-FINDINGS.md 1.29).

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceSplitTunnelingImportState(ctx context.Context, d *schema.ResourceData,
	m interface{}) ([]*schema.ResourceData, error) {

	networkId := d.Id()
	if networkId == "" {
		return nil, fmt.Errorf("a split tunnelling import id is the network id, and this one is " +
			"empty: terraform import checkpointsase_split_tunneling.<name> <network_id>")
	}
	// THIS LINE IS WHAT MAKES IMPORT WORK, and it is the opposite of the
	// identically-shaped line in Read. Do not "tidy" it away.
	//
	// Read addresses the object by the network_id ATTRIBUTE, not by d.Id(). On
	// import the attribute is empty -- networkId here came out of d.Id() -- so
	// without this the GET below is /v3/networks//split-tunneling: an empty path
	// segment, which is a DIFFERENT ROUTE rather than a 404 on this one. Pinned
	// by TestSplitTunnelingImportSetsNetworkIdBeforeReading, which asserts the
	// whole request list so the empty segment is visible rather than inferred.
	if err := d.Set(splitTunnelingAttrNetworkID, networkId); err != nil {
		return nil, fmt.Errorf("could not set network_id from the import id %q: %w", networkId, err)
	}

	diagnostics := resourceSplitTunnelingRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import split tunnelling: %s, \n %s",
					diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	if d.Id() == "" {
		return nil, fmt.Errorf("no such network: %q. The API answered 404 (\"network doesnt "+
			"exist\") for it, so there is no split tunnelling configuration to import", networkId)
	}

	return []*schema.ResourceData{d}, nil
}
