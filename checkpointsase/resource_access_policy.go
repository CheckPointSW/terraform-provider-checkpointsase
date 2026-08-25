package checkpointsase

import (
	"context"
	"fmt"
	"strings"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
accessPolicyResourceID is this resource's Terraform id, and it is a constant.

/v3/ia/access/policy addresses the tenant's ONE web-access policy by path; there
is no id to fetch and nothing to disambiguate. Something still has to go in
d.SetId(), because an empty id means "this resource does not exist" to Terraform.

Not a timestamp, for the reason recorded on supportOptionsResourceID and in L16c:
an id that changes on every read breaks every depends_on, output and
interpolation that points at it. A constant is the only value that is the same
after a refresh as before it.
*/
const accessPolicyResourceID = "access-policy"

/*
accessPolicyConditionTypeDatetime is the only value the API's condition `type`
admits.

Two independent sources agree and neither is our own inference: the `Condition`
schema in the OpenAPI document declares `enum: [datetime]`, and
p81-mongo-validation-schemas' schemas-shared/molecules.types.json declares
`$defs.conditionTypes` as `enum: ["datetime"]`, which is what the stored document
is validated against.

That is why `conditions` in this schema is a flat list of time windows rather
than a list of typed buckets: with exactly one legal type, the type level carries
no information and would only give a user a string to get wrong. The mapping is
recorded on the attribute itself.
*/
const accessPolicyConditionTypeDatetime = "datetime"

/*
accessPolicyBucket maps one Terraform attribute to the API's `type` string for
the same thing.

The API models a rule's sources and destinations as a LIST of `{type, value}`
objects, one per kind of thing being matched. This resource exposes them as named
attributes inside a single block instead, which is the shape
checkpointsase_firewall_policy already uses and which buys three things the wire
shape does not:

  - The set of legal types is enforced at plan time by the schema itself, with no
    string to mistype.
  - Bucket ORDER stops existing. A list of typed buckets is order-sensitive to
    Terraform but not to the server, so a user who wrote `groups` before `users`
    would diff against a server that always answers users-first, forever.
  - The server's canonicalisation (API-FINDINGS 1.15) lands on "attribute not
    set", which is already how Terraform spells "nothing here".

The cost, stated because it is real: a bucket type the server adds later is
DROPPED by the flattener rather than carried through. Under a whole-policy
resource it would be removed on the next apply regardless -- the configuration is
the policy -- but the value would disappear from state first, without a warning.
Adding the type here is what fixes that.
*/
type accessPolicyBucket struct {
	// attr is the Terraform attribute name, in snake_case.
	attr string
	// apiType is the `type` string the API uses for the same bucket.
	apiType string
}

/*
accessPolicySourceBuckets is every legal source type, IN THE ORDER THE SERVER
RETURNS THEM (API-FINDINGS 1.15: an empty `sources` reads back as users, groups,
addresses). The order is not required for correctness -- the flattener keys on
`type`, not on position -- but sending the array in the server's own order keeps
a captured request body comparable with a captured response body, which is what
the round-trip fixture below depends on.

Sourced from the `AccessPolicySource.type` enum in the OpenAPI document, which
agrees with `RuleWeb.sources` in p81-mongo-validation-schemas (anyOf of
usersObject, groupsObject, addressObject).
*/
var accessPolicySourceBuckets = []accessPolicyBucket{
	{attr: "users", apiType: "users"},
	{attr: "groups", apiType: "groups"},
	{attr: "addresses", apiType: "addresses"},
}

/*
accessPolicyDestinationBuckets is the same for destinations, again in the order
API-FINDINGS 1.15 recorded: customUrls, categories,
applicationControlApplications, updatableObjects.

Note that the source and destination vocabularies do NOT overlap, and that the
HTTPS-inspection policy's are different again (phase4-verification, W1). Nothing
here may be shared with that resource.
*/
var accessPolicyDestinationBuckets = []accessPolicyBucket{
	{attr: "custom_urls", apiType: "customUrls"},
	{attr: "categories", apiType: "categories"},
	{attr: "application_control_applications", apiType: "applicationControlApplications"},
	{attr: "updatable_objects", apiType: "updatableObjects"},
}

// accessPolicyAppliedOnValues is the `appliedOn` enum. The OpenAPI document and
// `$defs.ruleAppliedOn` in p81-mongo-validation-schemas agree exactly, and
// phase4-verification exercised all three against the live tenant.
var accessPolicyAppliedOnValues = []string{"sites", "agents", "both"}

/*
accessPolicyActionValues is the `action` enum, and it is the one place in this
file where the two authorities DISAGREE.

The OpenAPI document declares `enum: [allow, block, warning]` on
AccessPolicyRule.action. `$defs.SWGAction` in p81-mongo-validation-schemas
declares four: allow, block, warning, redirect.

The narrower list is taken deliberately. `SWGAction` is shared across several SWG
object types, `redirect` has no target field anywhere in RuleWeb -- whose
$jsonSchema sets additionalProperties:false, so there is nowhere for one to go --
and nothing in phase4-verification exercised it. The /v3 write model is what
answers this request, and it declares three.

If a tenant turns out to accept `redirect`, widening this list is the whole fix,
and the 422 the server returns until then names the field. This is the opposite
call from the `inspect`/`appliedOn` matrix in Task 3, and for the opposite reason:
there, the restriction was known to be tenant-dependent, so encoding it would have
refused legal configuration. Here the restriction is in the API contract itself.
*/
var accessPolicyActionValues = []string{"allow", "block", "warning"}

// accessPolicyStatusValues is the `status` enum: `active` or `inactive`. The
// OpenAPI document and `$defs.SWGStatus` agree, and perimeter81-swg-api's own
// component fixtures use `active`. It is NOT `enabled`/`disabled`.
var accessPolicyStatusValues = []string{"active", "inactive"}

// accessPolicyWeekdayValues is the `weekdays` enum, three-letter and
// capitalised, from `$defs.weekDays` and from the `Condition` schema in the
// OpenAPI document. Matched case-sensitively on purpose: `mon` would pass a
// case-insensitive plan and then be rejected by the server.
var accessPolicyWeekdayValues = []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

/*
accessPolicyDestroyWarning is the sentence a `terraform destroy` on this resource
has to have been preceded by, quoted from the API's own documentation of
DELETE /v3/ia/access/policy.

It is a constant so that the resource description and the delete function's
diagnostic cannot drift apart, and so that an operator who searches for the
string they were shown finds it here.
*/
const accessPolicyDestroyWarning = "Destroying this resource deletes EVERY web access rule in " +
	"the tenant, including any rule created in the console, and the API documents the " +
	"consequence as \"all internet traffic will be allowed after deletion\"."

/*
resourceAccessPolicy manages the tenant's ENTIRE ordered list of web access
rules as one resource.

That shape follows from the endpoint. /v3/ia/access/policy exposes GET, POST over
the whole `webRules` array, and DELETE, and nothing per-rule -- so a rule's
precedence comes from its position in the array, and the array is composed by
whoever builds the POST body. Under a resource-per-rule that composer would be
Terraform's scheduler, which creates independent resources in arbitrary order and
in parallel; the same configuration applied twice could then produce two
different policies, with no error and no diff. Here the composer is the
configuration, so the order written is the order stored.

@return &schema.Resource
*/
func resourceAccessPolicy() *schema.Resource {
	return &schema.Resource{
		Description: "Manages the **entire** web access policy of a Check Point SASE tenant — the " +
			"whole ordered `webRules` list, as one resource. " +
			"The API has no per-rule endpoint: `GET`, `POST` over the complete array and " +
			"`DELETE` are all it offers, and a rule's priority comes from its position in that " +
			"array. So this resource owns the whole list, the order of your `rule` blocks is the " +
			"order the policy is stored in, and every apply is a single `POST` that replaces the " +
			"array. There is no partial update. " +
			"**Any rule that is not in your configuration is removed on the next apply.** That " +
			"includes rules somebody added in the Harmony SASE console: this resource cannot " +
			"merge with them, and adopting a tenant whose policy is also edited by hand will " +
			"delete those edits. Only one Terraform resource, in one configuration, can manage " +
			"this policy. " +
			"**`terraform destroy` empties the policy completely.** " + accessPolicyDestroyWarning + " " +
			"There is no partial destroy and no rule is kept: the API cannot express an empty " +
			"`POST` (it answers `400 VALIDATION_WEB_RULES_REQUIRED`), so removing the last rule " +
			"is the `DELETE` and the `DELETE` is all of it. " +
			"Import with any id; the resource is a tenant-wide singleton whose id is always " +
			"`" + accessPolicyResourceID + "`.",
		CreateContext: resourceAccessPolicyWrite,
		ReadContext:   resourceAccessPolicyRead,
		UpdateContext: resourceAccessPolicyWrite,
		DeleteContext: resourceAccessPolicyDelete,
		CustomizeDiff: resourceAccessPolicyCustomizeDiff,
		Schema: map[string]*schema.Schema{
			"rule": {
				/*
					A TypeList, and NEVER a TypeSet.

					Order is the entire reason this resource exists. A TypeSet
					stores its elements by hash, so the order written would be
					discarded -- silently. Nothing would fail to compile, no
					test that only checked contents would fail, and the tenant's
					policy would come out in an order nobody chose. For a policy
					engine that is not a cosmetic difference; it is which rule
					wins. TestAccessPolicyRuleListIsOrderedNotASet pins it.
				*/
				Type:     schema.TypeList,
				Required: true,
				MinItems: 1,
				Description: "The complete, ordered list of web access rules for this tenant. " +
					"**The order of these blocks is the order the rules are stored in**: the " +
					"server preserves the array it is sent and derives each rule's `priority` " +
					"from its position. Note that which end of the list is evaluated first is " +
					"**not** documented by the API and has not been measured — see the " +
					"`priority` attribute. " +
					"At least one rule is required. The API rejects an empty array with " +
					"`400 VALIDATION_WEB_RULES_REQUIRED`, so `rule = []` fails at plan time " +
					"rather than after a round trip; to have no rules at all, remove the " +
					"resource and let `terraform destroy` issue the API's `DELETE`. " +
					"**Rules missing from this list are deleted on apply.**",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "The server-assigned id of this rule. Computed only: the API " +
								"mints it and there is nothing useful a configuration could set it " +
								"to. It is stable across a rewrite that leaves the rule in place.",
						},
						"priority": {
							Type:     schema.TypeInt,
							Computed: true,
							Description: "The server-assigned priority of this rule. Computed only — " +
								"**a `priority` sent by a client is discarded outright**, not " +
								"adjusted. Measured: priority descends with array position, " +
								"`len(rule) - 1 - index`, so the first block gets the highest " +
								"number and the last block gets `0`. " +
								"**Whether priority `0` is evaluated first or last is not " +
								"established.** The API documents the field only as \"updated " +
								"automatically\", and it cannot be inferred from the numbering. " +
								"Do not rely on either reading until it is measured.",
						},
						"name": {
							Type:     schema.TypeString,
							Required: true,
							Description: "The name of the rule. 1–100 characters and may not contain " +
								"`<` or `>`.",
							ValidateFunc: validation.All(
								validation.StringLenBetween(1, 100),
								validateAccessPolicyRuleName,
							),
						},
						"applied_on": {
							Type:     schema.TypeString,
							Required: true,
							Description: "Where the rule applies: `agents`, `sites`, or `both`. All " +
								"three were exercised against a live tenant.",
							ValidateFunc: validation.StringInSlice(accessPolicyAppliedOnValues, false),
						},
						"action": {
							Type:     schema.TypeString,
							Required: true,
							Description: "What the rule does with traffic it matches: `allow`, `block` " +
								"or `warning`.",
							ValidateFunc: validation.StringInSlice(accessPolicyActionValues, false),
						},
						"status": {
							Type:     schema.TypeString,
							Required: true,
							Description: "Whether the rule is in force: `active` or `inactive`. An " +
								"`inactive` rule stays in the policy and keeps its position, but is " +
								"not evaluated.",
							ValidateFunc: validation.StringInSlice(accessPolicyStatusValues, false),
						},
						"sources": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Description: "Restricts who the rule matches. **Omitting the block is the " +
								"only way to express \"any source\".** A block that is present but " +
								"empty is refused at plan time: the server answers an unrestricted " +
								"rule with empty buckets, which read back as no block at all, so a " +
								"configuration holding an empty block could never converge. " +
								"Each attribute takes object **ids**, not names.",
							Elem: accessPolicySourcesResource(),
						},
						"destinations": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Description: "Restricts what the rule matches traffic to. **Omitting the " +
								"block is the only way to express \"any destination\".** A block that " +
								"is present but empty is refused at plan time, for the reason given " +
								"on `sources`. Each attribute takes object **ids**, not names or URLs.",
							Elem: accessPolicyDestinationsResource(),
						},
						"conditions": {
							/*
								A TypeSet. Time windows have no order: nothing in the API
								assigns one, nothing in RuleWeb.json records one, and the
								server was never measured preserving one. A TypeList would
								be asserting a property nobody has checked, and the cost of
								being wrong is a permanent diff on every rule with more
								than one window.

								`rule` is deliberately the ONLY ordered list in this
								resource, which is the whole of Option B's contract: order
								is the security posture for RULES and means nothing
								anywhere else.
							*/
							Type:     schema.TypeSet,
							Optional: true,
							Description: "Time windows during which the rule is in force. Omit it for " +
								"a rule with no time constraint, which is the default. Order is not " +
								"significant. " +
								"This maps to the API's `conditions` array, whose only legal entry " +
								"type is `datetime`; because there is exactly one type, the type " +
								"level is not exposed and each block here is one entry of that " +
								"bucket's `value`.",
							Elem: accessPolicyConditionResource(),
						},
					},
				},
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceAccessPolicyImportState,
		},
	}
}

/*
validateAccessPolicyRuleName rejects the two characters the API's own pattern
rejects.

The OpenAPI document declares `pattern: ^[^<>]+$` on AccessPolicyRule.name, and
p81-mongo-validation-schemas resolves `$defs.ruleName` to `string-1-100`. Only
the character exclusion is enforced here as a pattern; the length is a separate
validator so that a name that is both too long and contains `<` reports both
problems rather than one.

The message quotes the rule rather than the regex, because a user shown
`must match ^[^<>]+$` has to decode it before they can act.
*/
func validateAccessPolicyRuleName(v interface{}, k string) (warns []string, errs []error) {
	name, ok := v.(string)
	if !ok {
		return nil, []error{fmt.Errorf("%s: expected a string", k)}
	}
	for _, c := range name {
		if c == '<' || c == '>' {
			return nil, []error{fmt.Errorf(
				"%s: a rule name may not contain < or >, and %q does; the API rejects it with "+
					"a schema validation error", k, name)}
		}
	}
	return nil, nil
}

/*
resourceAccessPolicyCustomizeDiff refuses a `sources` or `destinations` block
that is present but empty, at plan time, and it exists because the alternative is
a plan that never converges.

THE MECHANISM, because it is not obvious and the wrong fix is tempting. The
server answers an unrestricted rule with one EMPTY bucket per legal type
(API-FINDINGS 1.15), and flattenAccessPolicySources correctly drops those, so
such a rule always reads back as ZERO blocks. A configuration that spells "any
source" as `sources {}` or `sources { users = [] }` holds ONE. Those two never
meet: every plan proposes `rule.N.sources.#: "0" -> "1"`, the apply succeeds, the
re-read writes 0 back, and the next plan proposes it again. Measured, on this
resource's own probe fixture, through the real Diff path.

WHY THIS AND NOT NORMALISATION. The obvious-looking fix is to have the expander
treat an empty block as absent. It does not work, and it is worth writing down
why so that nobody spends an afternoon on it: the diff is computed at PLAN time
from configuration against state, and the expander runs at APPLY time, long
after. Normalising there fixes what is POSTed and leaves the perpetual diff
untouched.

That is measured, not argued. expandAccessPolicySources has ALWAYS omitted an
empty bucket -- it is the write-side half of the same normalisation, and
TestAccessPolicyExpandOmitsEmptyBuckets pins it -- and the diff was still
`rule.0.sources.#: "0" -> "1"` on every plan. Delete this function and
TestAccessPolicyEmptyEndpointBlockIsRefusedAtPlanTime prints exactly that, with
the expander's normalisation fully in place. So the expander-side fix has been
in the code the whole time and never helped.

Making the empty spelling genuinely work would instead need a DiffSuppressFunc on
the block's `.#` count key, which in SDKv2 cannot suppress a nested block's count
without leaving the child keys unsuppressed. So the honest choice is between a
silent permanent diff and a loud plan-time error, and this is the error. It names
the block and says to remove it.

The same wording is now on both attribute descriptions, and it matches
checkpointsase_firewall_policy, which has said "the only way to express any
source" since it shipped.

UNKNOWN VALUES ARE SKIPPED, not rejected. `sources { users = [x.y.id] }` where
the id is not yet known reads as an EMPTY SET during plan, which is
indistinguishable here from a genuinely empty block -- so a guard without that
check refuses a correct configuration whenever a rule references a resource
created in the same apply, which is the normal case. It was written without it
first and TestAccessPolicyPopulatedEndpointBlockStillPlans caught it.

  - @param d *schema.ResourceDiff - the planned diff

@return error - a plan-time refusal naming the block, or nil
*/
func resourceAccessPolicyCustomizeDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	rules, ok := d.Get("rule").([]interface{})
	if !ok {
		return nil
	}

	for index := range rules {
		for _, endpoint := range []struct {
			attr    string
			buckets []accessPolicyBucket
			any     string
		}{
			{"sources", accessPolicySourceBuckets, "any source"},
			{"destinations", accessPolicyDestinationBuckets, "any destination"},
		} {
			path := fmt.Sprintf("rule.%d.%s", index, endpoint.attr)
			blocks, ok := d.Get(path).([]interface{})
			if !ok || len(blocks) == 0 {
				continue // omitted, which is the spelling this guard is steering towards
			}

			empty := true
			for _, bucket := range endpoint.buckets {
				key := fmt.Sprintf("%s.0.%s", path, bucket.attr)
				/*
					THE COUNT KEY, not the collection key. Measured: for
					`users = [some_resource.x.id]` at plan time,
					NewValueKnown("…users") answers true while
					NewValueKnown("…users.#") answers false -- the unknown is
					recorded against the element count, and asking about the
					collection itself gets a confident "known" for a set that
					reads as empty. Checking the wrong key here is not a subtle
					degradation: it refuses every rule that references a resource
					created in the same apply, which is the normal case.
				*/
				if !d.NewValueKnown(key+".#") || !d.NewValueKnown(key) {
					// Not yet computable, so assume it will be non-empty. A
					// genuinely empty one still cannot converge and will be
					// caught on the next plan, once the value is known; a false
					// refusal here would break correct configuration now.
					empty = false
					break
				}
				if len(accessPolicyCollection(d.Get(key))) > 0 {
					empty = false
					break
				}
			}

			if empty {
				return fmt.Errorf(
					"%s is present but empty. Remove the block entirely: omitting it is the "+
						"only way to express %q. An empty block cannot be applied -- the server "+
						"returns an unrestricted rule as empty buckets, which read back as no "+
						"block at all, so %s would propose the same change on every plan and "+
						"never converge",
					path, endpoint.any, path)
			}
		}
	}

	return nil
}

// accessPolicySourcesResource is the element schema of a rule's `sources` block:
// one attribute per legal source type. See accessPolicyBucket for why the API's
// `{type, value}` list is not exposed directly.
func accessPolicySourcesResource() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"users": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Ids of `checkpointsase_user` objects this rule matches. A set: order " +
					"is not significant. Omit it to leave the rule unrestricted by user.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"groups": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Ids of `checkpointsase_group` objects this rule matches. A set: order " +
					"is not significant. Omit it to leave the rule unrestricted by group.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"addresses": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Ids of `checkpointsase_object_addresses` objects this rule matches — " +
					"**not** CIDRs or IP literals. A set: order is not significant. Omit it to " +
					"leave the rule unrestricted by address.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

// accessPolicyDestinationsResource is the element schema of a rule's
// `destinations` block. The destination vocabulary is disjoint from the source
// one, which is why the two element schemas are separate functions rather than
// one shared helper.
func accessPolicyDestinationsResource() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"custom_urls": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Ids of custom-URL shared objects this rule matches. A set: order is " +
					"not significant. Omit it to leave the rule unrestricted by custom URL list.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"categories": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Ids of web categories this rule matches, as returned by the " +
					"`checkpointsase_web_categories` data source. A set: order is not " +
					"significant. Omit it to leave the rule unrestricted by category.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"application_control_applications": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Ids of application-control applications this rule matches, as " +
					"returned by the `checkpointsase_application_control_applications` data " +
					"source. A set: order is not significant. Omit it to leave the rule " +
					"unrestricted by application.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"updatable_objects": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Ids of updatable objects this rule matches, as returned by the " +
					"`checkpointsase_updatable_objects` data source. A set: order is not " +
					"significant. Omit it to leave the rule unrestricted by updatable object.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

// accessPolicyConditionResource is one time window: the days it covers and the
// clock times it starts and ends at. It is one element of the API's
// `conditions[type=datetime].value`.
func accessPolicyConditionResource() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"weekdays": {
				/*
					A TypeSet, and this is the one of the four that would have bitten.
					RuleWeb.json declares weekdays `uniqueItems: true`, which IS set
					semantics -- and unlike a multi-window rule, EVERY rule with a time
					constraint has a weekdays array, so a server that returns them in
					its own order rather than the configuration's would diff forever on
					the common case rather than the rare one.
				*/
				Type:     schema.TypeSet,
				Required: true,
				Description: "The days this window covers, as the API's three-letter capitalised " +
					"abbreviations: `Mon`, `Tue`, `Wed`, `Thu`, `Fri`, `Sat`, `Sun`. Matched " +
					"case-sensitively. A set: order is not significant, and the API's own " +
					"stored-document schema declares it `uniqueItems`.",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice(accessPolicyWeekdayValues, false),
				},
			},
			"start_hour": {
				Type:         schema.TypeInt,
				Required:     true,
				Description:  "The hour the window opens, 0–23, in the tenant's timezone.",
				ValidateFunc: validation.IntBetween(0, 23),
			},
			"start_minute": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      0,
				Description:  "The minute the window opens, 0–59. Defaults to `0`.",
				ValidateFunc: validation.IntBetween(0, 59),
			},
			"end_hour": {
				Type:         schema.TypeInt,
				Required:     true,
				Description:  "The hour the window closes, 0–23, in the tenant's timezone.",
				ValidateFunc: validation.IntBetween(0, 23),
			},
			"end_minute": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      0,
				Description:  "The minute the window closes, 0–59. Defaults to `0`.",
				ValidateFunc: validation.IntBetween(0, 59),
			},
		},
	}
}

/*
resourceAccessPolicyWrite is BOTH CreateContext and UpdateContext, and that is
the point rather than a shortcut.

The endpoint has no partial update. POST /v3/ia/access/policy takes the complete
`webRules` array and replaces the tenant's policy with it, so "create the policy"
and "change the policy" are byte-for-byte the same request: build the whole list
from configuration, send it once. Two functions would be two copies of one call,
and the only thing that could ever differ between them is a bug.

What follows the write is not optional. The server canonicalises what it stores
-- empty sources, destinations and conditions come back expanded into one bucket
per legal type, and priority is reassigned positionally (API-FINDINGS 1.15/1.16)
-- so state built from the REQUEST would disagree with the next Read on every
rule, forever. rereadAfterWrite fetches the only authoritative account of what
the policy became, and retries a transient failure because by that point the
tenant is already enforcing the new list.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceAccessPolicyWrite(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)
	ops := accessPolicyOps(client)

	rules := expandAccessPolicyRules(d.Get("rule").([]interface{}))

	// writeAccessPolicyRules refuses an empty list before any request leaves, and
	// MinItems on `rule` refuses one at plan time. Both are kept: the schema stops
	// the configuration a user writes, and the writer stops anything that reaches
	// it another way -- and the failure the writer is guarding against is that
	// somebody "fixes" an empty POST by routing it to the DELETE that clears the
	// tenant's whole policy.
	if err := ops.write(ctx, rules); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to write the tenant's web access policy", err)
	}

	// The id is set only after the write has landed. Setting it earlier would put
	// a resource in state that owns a policy the tenant does not have.
	d.SetId(accessPolicyResourceID)

	stored, err := rereadAfterWrite(ctx, ops)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "The web access policy was written but could not be read back", err)
	}

	if err := d.Set("rule", flattenAccessPolicyRules(stored)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set the tenant's web access policy rules", err)
	}

	return diags
}

/*
resourceAccessPolicyRead reads the whole policy back into state.

A FAILED READ IS NEVER AN EMPTY LIST. On this endpoint absence arrives as an
empty array, not as a 404; a 404 means the URL is wrong, which is the documented
symptom of an unset BASE_URL sending every call to the US production host.
Swallowing that as "the policy is empty" is the defect that shipped three times in
Phase 3, and here it is worse than it was there: Terraform would plan to re-POST
a policy that already exists, over a tenant the provider never managed to read.
The read closure in accessPolicyOps returns the error, and this function reports
it.

An empty list that the server really did return IS a legitimate state -- somebody
emptied the policy in the console, or called DELETE -- and it is written to state
as an empty list rather than by clearing the id. The distinction matters: an
empty list plans as an in-place update that re-POSTs the configured rules, while
a cleared id plans as a create. Both converge on the same single POST, but only
the first leaves the resource addressable in the meantime, and neither ever
issues a DELETE.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceAccessPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	rules, _, err := accessPolicyOps(client).read(ctx)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read the tenant's web access policy", err)
	}

	if err := d.Set("rule", flattenAccessPolicyRules(rules)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set the tenant's web access policy rules", err)
	}

	// A bucket type this provider has no attribute for is dropped by the
	// flattener and would otherwise vanish without trace -- and because the
	// configuration has no block for it either, the resulting plan is EMPTY and
	// the next apply quietly widens the policy. See unknownAccessPolicyBucketTypes.
	if dropped := unknownAccessPolicyBucketTypes(rules); len(dropped) > 0 {
		diags = appendWarningDiags(diags,
			"The web access policy uses rule types this provider does not know",
			fmt.Sprintf("These restrictions were dropped when the policy was read into state, "+
				"and the next apply will REMOVE them from the tenant because Terraform cannot "+
				"see them: %s. Upgrade the provider, or stop managing this policy with "+
				"Terraform until it supports these types.", strings.Join(dropped, ", ")))
	}

	return diags
}

/*
resourceAccessPolicyDelete calls DELETE /v3/ia/access/policy, with no guard in
front of it, and that is correct here.

This resource owns the entire policy. Destroying it therefore means the policy is
gone -- there is no remainder to preserve and nothing to be careful of, so the
"only DELETE when the remainder is empty" gate that a per-rule resource would
need has no condition to test. It is also the only route: POST cannot express an
empty array (400 VALIDATION_WEB_RULES_REQUIRED, API-FINDINGS 1.18).

What it does is not small, and the resource description says so in the API's own
words: every rule in the tenant goes, including rules Terraform never created,
and all internet traffic is allowed afterwards.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceAccessPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	if err := accessPolicyOps(client).deleteAll(ctx); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to delete the tenant's web access policy", err)
	}

	d.SetId("")
	return diags
}

/*
resourceAccessPolicyImportState adopts the tenant's existing policy.

The import id is ignored, for the reason recorded on
resourceSupportOptionsImportState: there is one policy per tenant and the API
addresses it by path, so no id a user could supply selects something different,
including a mistyped one. Import therefore stores the same constant id a created
resource holds, and an imported resource is byte-identical in state to a created
one.

Worth saying out loud, because import is where this resource is most likely to
surprise: importing does not merge. Whatever the tenant's policy is at import
time is written into state, and the FIRST apply after that replaces it with the
configuration. Run `terraform plan` and read it before applying.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceAccessPolicyImportState(ctx context.Context, d *schema.ResourceData,
	m interface{}) ([]*schema.ResourceData, error) {
	d.SetId(accessPolicyResourceID)

	diagnostics := resourceAccessPolicyRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import the tenant's web access policy: %s, \n %s",
					diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}

/*
expandAccessPolicyRules turns the configuration's ordered `rule` blocks into the
array that is POSTed.

IT MUST NEVER SORT, DEDUPE OR REORDER. The array's order is the policy's order
(API-FINDINGS 1.16), so index i here is the rule the user wrote i-th.

  - @param raw []interface{} - d.Get("rule"), which is ordered because `rule` is a TypeList

@return []perimeter81Sdk.AccessPolicyRule - the complete list, in configuration order
*/
func expandAccessPolicyRules(raw []interface{}) []perimeter81Sdk.AccessPolicyRule {
	rules := make([]perimeter81Sdk.AccessPolicyRule, 0, len(raw))

	for index, item := range raw {
		block, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		rule := perimeter81Sdk.AccessPolicyRule{
			Name:         block["name"].(string),
			AppliedOn:    block["applied_on"].(string),
			Action:       block["action"].(string),
			Status:       block["status"].(string),
			Sources:      expandAccessPolicySources(block["sources"]),
			Destinations: expandAccessPolicyDestinations(block["destinations"]),
			Conditions:   expandAccessPolicyConditions(block["conditions"]),
			/*
				The priority sent is DISCARDED by the server, which reassigns it
				from array position (API-FINDINGS 1.16). It is still computed
				here rather than left at zero, for one reason: the field is a
				non-pointer int32 on the generated model, so ToMap writes it
				unconditionally and something is going out either way. Sending
				the value the server is about to assign keeps a captured request
				body comparable with the response, instead of a column of zeroes
				that reads like a client that thinks it is setting priorities.
			*/
			Priority: int32(len(raw) - 1 - index),
		}

		/*
			The id is sent when state has one and omitted when it does not.

			It is how the server recognises a rule it already holds
			(API-FINDINGS 1.17 records that the write model accepts `id`), and
			sending it is what keeps rule ids stable across a rewrite that left
			the rule in place -- measured in phase4-verification.

			`id` is Computed-only, so this value always comes from state, one per
			index, and can never collide. It does follow POSITION rather than
			content: reorder two blocks and each inherits the other's id. That is
			harmless -- the write replaces the whole array, so the CONTENT at
			every position is exactly what the configuration says -- but it is
			why an external consumer should key on a rule's name, not its id.
		*/
		if id, ok := block["id"].(string); ok && id != "" {
			rule.Id = perimeter81Sdk.PtrString(id)
		}

		// Belt and braces. Every slice above is non-nil by construction, so the
		// nil-slice normalisation cannot fire and AdditionalProperties is empty
		// on a rule we built -- but routing every rule through the same
		// sanitiser is what stops a later field addition from bypassing it.
		rules = append(rules, sanitiseAccessPolicyRule(rule))
	}

	return rules
}

/*
expandAccessPolicySources turns a rule's `sources` block into the API's array of
typed buckets.

A bucket whose list is empty is OMITTED rather than sent with an empty value.
Both forms mean "unrestricted" to the server -- schemas-shared/molecules.types.json
gives usersObject, groupsObject and addressObject a `value` of `minItems: 0`, and
perimeter81-swg-api's own fixtures spell "any source" as buckets with empty
values -- so this is a choice about what we send, not about what is legal, and
omitting keeps the request minimal and matches what the flattener produces.

A block with every attribute empty therefore produces an empty array, which
API-FINDINGS 1.15 measured as accepted.

  - @param raw interface{} - block["sources"], a MaxItems-1 list

@return []perimeter81Sdk.AccessPolicySource - never nil; a nil slice serialises as JSON null, which this endpoint answers with a 500 (API-FINDINGS 1.19)
*/
func expandAccessPolicySources(raw interface{}) []perimeter81Sdk.AccessPolicySource {
	sources := []perimeter81Sdk.AccessPolicySource{}
	block := accessPolicySingleBlock(raw)
	if block == nil {
		return sources
	}

	for _, bucket := range accessPolicySourceBuckets {
		values := flattenStringsArrayData(accessPolicyCollection(block[bucket.attr]))
		if len(values) == 0 {
			continue
		}
		sources = append(sources, perimeter81Sdk.AccessPolicySource{
			Type:  bucket.apiType,
			Value: values,
		})
	}

	return sources
}

// expandAccessPolicyDestinations is expandAccessPolicySources for the
// destination vocabulary. The two are not merged because the vocabularies are
// disjoint and the generated models are different types.
func expandAccessPolicyDestinations(raw interface{}) []perimeter81Sdk.AccessPolicyDestination {
	destinations := []perimeter81Sdk.AccessPolicyDestination{}
	block := accessPolicySingleBlock(raw)
	if block == nil {
		return destinations
	}

	for _, bucket := range accessPolicyDestinationBuckets {
		values := flattenStringsArrayData(accessPolicyCollection(block[bucket.attr]))
		if len(values) == 0 {
			continue
		}
		destinations = append(destinations, perimeter81Sdk.AccessPolicyDestination{
			Type:  bucket.apiType,
			Value: values,
		})
	}

	return destinations
}

/*
expandAccessPolicyConditions turns the rule's time windows into the API's single
`datetime` bucket.

No windows means an EMPTY array, not a bucket with an empty value -- the same
choice, and for the same reason, as expandAccessPolicySources. API-FINDINGS 1.15
measured `conditions: []` accepted, and it is the form the server itself
canonicalises FROM, so it is the known-good shape to send.

  - @param raw interface{} - block["conditions"], a list of time windows

@return []perimeter81Sdk.Condition - never nil
*/
func expandAccessPolicyConditions(raw interface{}) []perimeter81Sdk.Condition {
	conditions := []perimeter81Sdk.Condition{}

	windows := accessPolicyCollection(raw)
	if len(windows) == 0 {
		return conditions
	}

	values := make([]perimeter81Sdk.ConditionValueInner, 0, len(windows))
	for _, item := range windows {
		block, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		values = append(values, perimeter81Sdk.ConditionValueInner{
			Weekdays: flattenStringsArrayData(accessPolicyCollection(block["weekdays"])),
			StartTime: perimeter81Sdk.ConditionTime{
				Hour:   int32(block["start_hour"].(int)),
				Minute: int32(block["start_minute"].(int)),
			},
			EndTime: perimeter81Sdk.ConditionTime{
				Hour:   int32(block["end_hour"].(int)),
				Minute: int32(block["end_minute"].(int)),
			},
		})
	}

	if len(values) == 0 {
		return conditions
	}

	return append(conditions, perimeter81Sdk.Condition{
		Type:  accessPolicyConditionTypeDatetime,
		Value: values,
	})
}

// accessPolicySingleBlock unwraps a MaxItems-1 nested block, returning nil when
// it is absent or explicitly null. `sources {}` with no attributes set decodes to
// a non-nil map with empty values, which the callers then produce an empty
// bucket array from -- the same result as omitting the block, which is what the
// server means by it.
func accessPolicySingleBlock(raw interface{}) map[string]interface{} {
	list := accessPolicyCollection(raw)
	if len(list) == 0 || list[0] == nil {
		return nil
	}
	block, ok := list[0].(map[string]interface{})
	if !ok {
		return nil
	}
	return block
}

/*
accessPolicyCollection narrows an interface{} that should hold a collection --
of strings, or of nested blocks -- returning nil for an absent or wrongly-typed value rather than
panicking. The nested attributes are all Optional, so absent is ordinary.

It accepts BOTH forms because the two are not interchangeable and the compiler
will not tell you which one you have: every id collection in this resource, and
`conditions`, are TypeSets, which d.Get hands back as a *schema.Set, while
`sources` and `destinations` are TypeLists and arrive as []interface{}. Handling
only the second is how a set attribute silently reads as empty -- which here
would mean "unrestricted", i.e. a rule that matches everything.
*/
func accessPolicyCollection(raw interface{}) []interface{} {
	switch value := raw.(type) {
	case *schema.Set:
		if value == nil {
			return nil
		}
		return value.List()
	case []interface{}:
		return value
	default:
		return nil
	}
}

/*
flattenAccessPolicyRules turns the server's `webRules` array into `rule` blocks,
in the server's order.

This is the function that decides whether the resource works. THE SERVER DOES NOT
RETURN WHAT IT WAS SENT: an empty `sources` reads back as three typed buckets with
empty values, an empty `destinations` as four, and an empty `conditions` as one
(API-FINDINGS 1.15). Writing those into state as set attributes would put
`sources { users = [] groups = [] addresses = [] }` in state against a
configuration that has no `sources` block at all, and every plan from then on
would propose a change to a resource nobody touched -- with an apply that never
converges, because the next read produces the same thing again.

So an empty bucket is dropped, and a block whose every bucket was empty is not
emitted at all. TestAccessPolicyReadProducesNoPermanentDiff drives exactly the
body the live probe recorded through this function and then plans against it.

  - @param rules []perimeter81Sdk.AccessPolicyRule - the list as returned by a GET

@return []interface{} - `rule` blocks, in the same order
*/
func flattenAccessPolicyRules(rules []perimeter81Sdk.AccessPolicyRule) []interface{} {
	flattened := make([]interface{}, 0, len(rules))

	for _, rule := range rules {
		flattened = append(flattened, map[string]interface{}{
			"id":           rule.GetId(),
			"name":         rule.GetName(),
			"applied_on":   rule.GetAppliedOn(),
			"action":       rule.GetAction(),
			"status":       rule.GetStatus(),
			"priority":     int(rule.GetPriority()),
			"sources":      flattenAccessPolicySources(rule.GetSources()),
			"destinations": flattenAccessPolicyDestinations(rule.GetDestinations()),
			"conditions":   flattenAccessPolicyConditions(rule.GetConditions()),
		})
	}

	return flattened
}

/*
unknownAccessPolicyBucketTypes reports every source or destination `type` the
server returned that this provider has no attribute for, as
"rule-name: sources.someNewType" strings.

It exists because the flatteners have to drop such a bucket -- there is nowhere
to put it -- and dropping it SILENTLY is worse than it first looks. Trace it: the
server holds a rule restricted by an unknown type; Read flattens it away, so
state says the block is absent; the configuration also has no block, so THE PLAN
IS EMPTY and the operator is shown nothing; and the next apply for any unrelated
reason POSTs the whole array without the restriction. That is a policy widening
with no plan output, which is the one thing a declarative tool exists to prevent.

A warning does not stop it, but it makes it visible on the refresh that precedes
every plan. TestAccessPolicyBucketTablesCoverTheAPIEnums is the other half and
the better half: it fails at build time when the spec grows a type, so the
warning is the backstop for a server that is ahead of the spec rather than the
primary defence.

  - @param rules []perimeter81Sdk.AccessPolicyRule - the list as returned by a GET

@return []string - one entry per dropped bucket; nil when nothing was dropped
*/
func unknownAccessPolicyBucketTypes(rules []perimeter81Sdk.AccessPolicyRule) []string {
	known := func(buckets []accessPolicyBucket, apiType string) bool {
		for _, bucket := range buckets {
			if bucket.apiType == apiType {
				return true
			}
		}
		return false
	}

	var dropped []string
	for _, rule := range rules {
		for _, source := range rule.GetSources() {
			if !known(accessPolicySourceBuckets, source.GetType()) {
				dropped = append(dropped,
					fmt.Sprintf("%s: sources.%s", rule.GetName(), source.GetType()))
			}
		}
		for _, destination := range rule.GetDestinations() {
			if !known(accessPolicyDestinationBuckets, destination.GetType()) {
				dropped = append(dropped,
					fmt.Sprintf("%s: destinations.%s", rule.GetName(), destination.GetType()))
			}
		}
	}
	return dropped
}

/*
flattenAccessPolicySources collapses the server's typed buckets into one
`sources` block, dropping every bucket with an empty value.

If nothing survives, it returns an EMPTY list rather than a block of empty
attributes: that is what makes "the server expanded my absent sources into three
empty buckets" read back as "there is no sources block", which is what the
configuration says and what the server means.

A bucket whose `type` is not one this provider knows is skipped. That is a real
loss and it is recorded on accessPolicyBucket; under a whole-policy resource the
value would be removed on the next apply regardless, because the configuration is
the policy.
*/
func flattenAccessPolicySources(sources []perimeter81Sdk.AccessPolicySource) []interface{} {
	block := map[string]interface{}{}

	for _, source := range sources {
		values := source.GetValue()
		if len(values) == 0 {
			continue
		}
		for _, bucket := range accessPolicySourceBuckets {
			if source.GetType() == bucket.apiType {
				block[bucket.attr] = values
			}
		}
	}

	if len(block) == 0 {
		return []interface{}{}
	}
	return []interface{}{block}
}

// flattenAccessPolicyDestinations is flattenAccessPolicySources for the
// destination vocabulary, with the same empty-bucket rule and for the same
// reason.
func flattenAccessPolicyDestinations(destinations []perimeter81Sdk.AccessPolicyDestination) []interface{} {
	block := map[string]interface{}{}

	for _, destination := range destinations {
		values := destination.GetValue()
		if len(values) == 0 {
			continue
		}
		for _, bucket := range accessPolicyDestinationBuckets {
			if destination.GetType() == bucket.apiType {
				block[bucket.attr] = values
			}
		}
	}

	if len(block) == 0 {
		return []interface{}{}
	}
	return []interface{}{block}
}

/*
flattenAccessPolicyConditions turns the server's `datetime` bucket back into the
flat list of time windows the schema exposes.

The bucket the server adds to a rule with no time constraint carries an empty
`value` (API-FINDINGS 1.15), so it contributes nothing and the result is an empty
list -- which is what a rule with no `conditions` block holds. That is the third
half of the same defect flattenAccessPolicySources guards against, and the one
that is easiest to miss, because the empty bucket is present on EVERY rule rather
than only on unrestricted ones.
*/
func flattenAccessPolicyConditions(conditions []perimeter81Sdk.Condition) []interface{} {
	flattened := []interface{}{}

	for _, condition := range conditions {
		if condition.GetType() != accessPolicyConditionTypeDatetime {
			continue
		}
		for _, window := range condition.GetValue() {
			start := window.GetStartTime()
			end := window.GetEndTime()
			flattened = append(flattened, map[string]interface{}{
				"weekdays":     window.GetWeekdays(),
				"start_hour":   int(start.Hour),
				"start_minute": int(start.Minute),
				"end_hour":     int(end.Hour),
				"end_minute":   int(end.Minute),
			})
		}
	}

	return flattened
}
