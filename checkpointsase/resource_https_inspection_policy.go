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
httpsInspectionPolicyResourceID is this resource's Terraform id, and it is a
constant, for the same reason accessPolicyResourceID is.

/v3/ia/https-inspection/policy addresses the tenant's ONE HTTPS-inspection policy
by path; there is no id to fetch and nothing to disambiguate. An id that changed
on every read would break every depends_on, output and interpolation pointing at
it (L16c).
*/
const httpsInspectionPolicyResourceID = "https-inspection-policy"

/*
httpsInspectionBucket maps one Terraform attribute to the API's `type` string.

It is DELIBERATELY a separate type from accessPolicyBucket rather than a shared
one. The two policies' vocabularies are different -- this one has `applications`
as a source and `domains` as a destination, and it uses `addresses` on BOTH sides
where the access policy uses it on neither -- so a shared type would let a table
from one resource be passed to a flattener from the other and produce wrong
`type` strings on the wire with nothing failing to compile. Two types make that a
compile error.

The trade the named-attribute shape makes is the same one accessPolicyBucket
records: a bucket type the server adds later is DROPPED by the flattener. See
unknownHttpsInspectionBucketTypes for the runtime warning and
TestHttpsInspectionBucketTablesCoverTheAPIEnums for the build-time one.
*/
type httpsInspectionBucket struct {
	// attr is the Terraform attribute name, in snake_case.
	attr string
	// apiType is the `type` string the API uses for the same bucket.
	apiType string
}

/*
httpsInspectionSourceBuckets is every legal source type.

Sourced from the `HttpsInspectionSource.type` enum in the OpenAPI document, in
the document's own order, which agrees with `$defs.ruleBypassSources` in
p81-mongo-validation-schemas (anyOf of addressObject, usersObject, groupsObject,
applicationsObject).

This vocabulary is NOT the access policy's: `applications` exists here and
nowhere in AccessPolicySource. TestHttpsInspectionBucketTablesCoverTheAPIEnums
holds this table to the document rather than to the sibling resource.
*/
var httpsInspectionSourceBuckets = []httpsInspectionBucket{
	{attr: "users", apiType: "users"},
	{attr: "groups", apiType: "groups"},
	{attr: "applications", apiType: "applications"},
	{attr: "addresses", apiType: "addresses"},
}

/*
httpsInspectionDestinationBuckets is the same for destinations, from the
`HttpsInspectionDestination.type` enum, again agreeing with
`$defs.ruleBypassDestinations`.

Five types against the access policy's four, and only two names overlap. Note
`addresses` appears in BOTH tables here, which it never does for the access
policy -- so an attribute name alone does not tell you which side it belongs to.
*/
var httpsInspectionDestinationBuckets = []httpsInspectionBucket{
	{attr: "categories", apiType: "categories"},
	{attr: "domains", apiType: "domains"},
	{attr: "addresses", apiType: "addresses"},
	{attr: "updatable_objects", apiType: "updatableObjects"},
	{attr: "application_control_applications", apiType: "applicationControlApplications"},
}

// httpsInspectionAppliedOnValues is the `appliedOn` enum. The OpenAPI document
// and `$defs.ruleAppliedOn` in p81-mongo-validation-schemas agree exactly, and
// phase4-verification exercised all three against the live tenant.
var httpsInspectionAppliedOnValues = []string{"sites", "agents", "both"}

/*
httpsInspectionActionValues is the `action` enum, and the WIDER of the two
available lists is taken here -- the opposite call from
accessPolicyActionValues, on purpose.

The OpenAPI document declares `enum: [bypass, inspect, inspectNoDecrypt]`.
`$defs.bypassAction` in p81-mongo-validation-schemas declares only two:
`[bypass, inspect]`.

The document's three are taken because the narrower source cannot be the
authority here:

  - RuleBypass.json sets `validationAction: "warn"`, so the stored-document
    schema LOGS a mismatch rather than rejecting the write. It cannot be what
    refuses a value.
  - phase4-verification MEASURED `inspectNoDecrypt` reaching the application's
    own validator and coming back 422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED --
    a specific, named refusal, which is a server that KNOWS the value, not one
    that has never heard of it.
  - That 422 is tenant-dependent: the schema records that `inspectNoDecrypt`
    "requires the Inspection Policy feature". Narrowing the enum here would
    refuse, at plan time and on every tenant, a value that a feature-enabled
    tenant accepts.

Where accessPolicyActionValues narrowed because the restriction was in the API
CONTRACT, this one widens because the restriction is in the TENANT.
*/
var httpsInspectionActionValues = []string{"bypass", "inspect", "inspectNoDecrypt"}

/*
httpsInspectionActionInspectNoDecrypt is the one action/appliedOn combination
this provider refuses at plan time. See
resourceHttpsInspectionPolicyCustomizeDiff for why it is the only one.
*/
const httpsInspectionActionInspectNoDecrypt = "inspectNoDecrypt"

// httpsInspectionStatusValues is the `status` enum: `active` or `inactive`. The
// OpenAPI document and `$defs.SWGStatus` agree. It is NOT `enabled`/`disabled`.
var httpsInspectionStatusValues = []string{"active", "inactive"}

/*
httpsInspectionDestroyWarning is what a `terraform destroy` on this resource
does, said plainly.

Unlike DELETE /v3/ia/access/policy, the API's documentation of
DELETE /v3/ia/https-inspection/policy states only the mechanical effect --
"Delete all HTTPS Inspection policy rules" -- and says nothing about what happens
to the traffic afterwards. That silence is reproduced rather than filled in: what
the tenant does with traffic that was being bypassed is decided by its
HTTPS-inspection settings, including the cleanup-rule default action this
provider does not manage, and it has not been measured.
*/
const httpsInspectionDestroyWarning = "Destroying this resource removes EVERY HTTPS-inspection " +
	"bypass rule in the tenant, including any rule created in the console. The API documents " +
	"the call as \"Delete all HTTPS Inspection policy rules\". Traffic that those rules were " +
	"excluding from inspection stops being excluded; what is then done with it is decided by " +
	"the tenant's own HTTPS-inspection settings, which this resource does not manage."

/*
resourceHttpsInspectionPolicy manages the tenant's ENTIRE ordered list of
HTTPS-inspection bypass rules as one resource.

The shape follows from the endpoint, exactly as it does for
checkpointsase_access_policy: /v3/ia/https-inspection/policy exposes GET, POST
over the whole `bypassRules` array, and DELETE, and nothing per-rule. A rule's
precedence comes from its position in the array, and the array is composed by
whoever builds the POST body -- so under a resource-per-rule that composer would
be Terraform's scheduler, and the same configuration applied twice could produce
two different policies with no error and no diff. Here the composer is the
configuration.

@return &schema.Resource
*/
func resourceHttpsInspectionPolicy() *schema.Resource {
	return &schema.Resource{
		Description: "Manages the **entire** HTTPS-inspection policy of a Check Point SASE tenant — " +
			"the whole ordered `bypassRules` list, as one resource. " +
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
			"**`terraform destroy` empties the policy completely.** " + httpsInspectionDestroyWarning + " " +
			"There is no partial destroy and no rule is kept: the API cannot express an empty " +
			"`POST` (it answers `400 VALIDATION_BYPASS_RULES_REQUIRED`), so removing the last " +
			"rule is the `DELETE` and the `DELETE` is all of it. " +
			"The tenant-wide cleanup-rule default action (`cleanupBypassRuleDefaultAction`) is " +
			"**not** managed here and is left untouched by every write. " +
			"Import with any id; the resource is a tenant-wide singleton whose id is always " +
			"`" + httpsInspectionPolicyResourceID + "`.",
		CreateContext: resourceHttpsInspectionPolicyWrite,
		ReadContext:   resourceHttpsInspectionPolicyRead,
		UpdateContext: resourceHttpsInspectionPolicyWrite,
		DeleteContext: resourceHttpsInspectionPolicyDelete,
		CustomizeDiff: resourceHttpsInspectionPolicyCustomizeDiff,
		Schema: map[string]*schema.Schema{
			"rule": {
				/*
					A TypeList, and NEVER a TypeSet.

					Order is the entire reason this resource exists. A TypeSet
					stores its elements by hash, so the order written would be
					discarded -- silently. Nothing would fail to compile, no
					test that only checked contents would fail, and the
					tenant's policy would come out in an order nobody chose.
					For a policy engine that is not cosmetic; it is which rule
					wins. TestHttpsInspectionRuleListIsOrderedNotASet pins it.

					It is also the ONLY list in this resource whose order can
					mean anything. Every id collection below is a TypeSet.
				*/
				Type:     schema.TypeList,
				Required: true,
				MinItems: 1,
				Description: "The complete, ordered list of HTTPS-inspection bypass rules for this " +
					"tenant. " +
					"**The order of these blocks is the order the rules are stored in**: the " +
					"server preserves the array it is sent and derives each rule's `priority` " +
					"from its position. Note that which end of the list is evaluated first is " +
					"**not** documented by the API and has not been measured — see the " +
					"`priority` attribute. " +
					"At least one rule is required. The API rejects an empty array with " +
					"`400 VALIDATION_BYPASS_RULES_REQUIRED`, so `rule = []` fails at plan time " +
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
								validateHttpsInspectionRuleName,
							),
						},
						"applied_on": {
							Type:     schema.TypeString,
							Required: true,
							Description: "Where the rule applies: `agents`, `sites`, or `both`. All " +
								"three were exercised against a live tenant. " +
								"This is half of a cross-field rule the server enforces: see " +
								"`action`.",
							ValidateFunc: validation.StringInSlice(httpsInspectionAppliedOnValues, false),
						},
						"action": {
							Type:     schema.TypeString,
							Required: true,
							Description: "What the rule does with traffic it matches: `bypass` (skip " +
								"HTTPS inspection), `inspect`, or `inspectNoDecrypt`. " +
								"**`action` and `applied_on` are validated together by the server, " +
								"and most of that rule depends on whether your tenant has the " +
								"Inspection Policy feature — which this provider cannot see.** " +
								"Only the part that is true on every tenant is checked at plan " +
								"time: `inspectNoDecrypt` is rejected with `sites` or `both` " +
								"regardless of the feature. `inspect` outside `sites` is " +
								"deliberately **not** refused here: it is valid on `agents` and " +
								"`both` once the feature is enabled, and the server answers " +
								"`422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED` when it is not. " +
								"The API declares `action` optional and defaults it to `bypass`; " +
								"it is required here so that both halves of that cross-field rule " +
								"are always visible in the configuration. Write `bypass` to get " +
								"the API's default.",
							ValidateFunc: validation.StringInSlice(httpsInspectionActionValues, false),
						},
						"status": {
							Type:     schema.TypeString,
							Required: true,
							Description: "Whether the rule is in force: `active` or `inactive`. An " +
								"`inactive` rule stays in the policy and keeps its position, but is " +
								"not evaluated.",
							ValidateFunc: validation.StringInSlice(httpsInspectionStatusValues, false),
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
							Elem: httpsInspectionSourcesResource(),
						},
						"destinations": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Description: "Restricts what the rule matches traffic to. **Omitting the " +
								"block is the only way to express \"any destination\".** A block " +
								"that is present but empty is refused at plan time, for the reason " +
								"given on `sources`. Each attribute takes object **ids**, not names " +
								"or URLs.",
							Elem: httpsInspectionDestinationsResource(),
						},
					},
				},
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceHttpsInspectionPolicyImportState,
		},
	}
}

/*
validateHttpsInspectionRuleName rejects the two characters the API's own pattern
rejects.

The OpenAPI document declares `pattern: ^[^<>]+$` and `maxLength: 100` on
HttpsInspectionRule.name, and p81-mongo-validation-schemas resolves
RuleBypass.name through `$defs.ruleName` to `string-1-100`. Only the character
exclusion is enforced here as a pattern; the length is a separate validator so
that a name that is both too long and contains `<` reports both problems rather
than one.

The message quotes the rule rather than the regex, because a user shown
`must match ^[^<>]+$` has to decode it before they can act.
*/
func validateHttpsInspectionRuleName(v interface{}, k string) (warns []string, errs []error) {
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
resourceHttpsInspectionPolicyCustomizeDiff carries the two plan-time refusals
this resource makes. Both are in one function because CustomizeDiff takes one.

FIRST: an empty `sources` or `destinations` block, refused for exactly the
reason resourceAccessPolicyCustomizeDiff refuses it. The server answers an
unrestricted rule with one EMPTY bucket per legal type (API-FINDINGS 1.15), the
flatteners correctly drop those, so such a rule always reads back as ZERO blocks
while a configuration spelling "any source" as `sources {}` holds ONE. The two
never meet: every plan proposes `rule.N.sources.#: "0" -> "1"`, the apply
succeeds, the re-read writes 0 back, and the next plan proposes it again.
Normalising in the expander does not help -- the diff is computed at PLAN time
and the expander runs at APPLY time -- which was measured on the sibling
resource, not argued.

SECOND: `action = "inspectNoDecrypt"` with `applied_on` of `sites` or `both`.

That is the ONLY part of the action/appliedOn matrix that is safe to enforce
here, and the restriction that looks more obvious is the one that must NOT be.
Measured on a tenant with the Inspection Policy feature DISABLED
(phase4-verification):

	bypass           + sites/agents/both  -> 200
	inspect          + sites              -> 200
	inspect          + agents             -> 422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED
	inspect          + both               -> 422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED
	inspectNoDecrypt + sites/agents/both  -> 422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED

Read off that table alone, "inspect is sites-only" looks like a rule. It is not:
the API schema says `inspect` is ALSO valid on `agents` and `both` once the
feature is enabled, so a validator encoding it would refuse, on every tenant
forever, configuration that a feature-enabled tenant accepts -- and this provider
cannot see the feature flag. The server's 422 is specific and names the field,
which is exactly when letting the server answer is right. The milestone spec says
to enforce it; the milestone spec is wrong, and phase4-verification says so.

`inspectNoDecrypt` + `sites`/`both` is different in kind: the schema says it is
"rejected on 'sites' and 'both' REGARDLESS of the feature", so no tenant can
accept it and refusing it costs nobody anything.

UNKNOWN VALUES ARE SKIPPED THROUGHOUT, not rejected. For the endpoint blocks the
check is on the `.#` COUNT key, because a set holding an unknown id reads as
EMPTY during plan while NewValueKnown on the collection itself answers true --
so a guard on the wrong key refuses every rule that references a resource created
in the same apply, which is the normal case. For the action pair, either string
can be an unresolved interpolation, and refusing on the empty-string reading of
one would be the same bug in a different shape.

  - @param d *schema.ResourceDiff - the planned diff

@return error - a plan-time refusal naming the rule, or nil
*/
func resourceHttpsInspectionPolicyCustomizeDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	rules, ok := d.Get("rule").([]interface{})
	if !ok {
		return nil
	}

	for index := range rules {
		for _, endpoint := range []struct {
			attr    string
			buckets []httpsInspectionBucket
			any     string
		}{
			{"sources", httpsInspectionSourceBuckets, "any source"},
			{"destinations", httpsInspectionDestinationBuckets, "any destination"},
		} {
			path := fmt.Sprintf("rule.%d.%s", index, endpoint.attr)
			blocks, ok := d.Get(path).([]interface{})
			if !ok || len(blocks) == 0 {
				continue // omitted, which is the spelling this guard is steering towards
			}

			empty := true
			for _, bucket := range endpoint.buckets {
				key := fmt.Sprintf("%s.0.%s", path, bucket.attr)
				// THE COUNT KEY, not the collection key. Measured on the
				// sibling resource: for `users = [some_resource.x.id]` at plan
				// time, NewValueKnown("...users") answers true while
				// NewValueKnown("...users.#") answers false. Checking only the
				// second is not a subtle degradation -- it refuses every rule
				// that references a resource created in the same apply.
				if !d.NewValueKnown(key+".#") || !d.NewValueKnown(key) {
					// Not yet computable, so assume it will be non-empty. A
					// genuinely empty one still cannot converge and is caught on
					// the next plan once the value is known; a false refusal
					// here would break correct configuration now.
					empty = false
					break
				}
				if len(policyCollection(d.Get(key))) > 0 {
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

		actionKey := fmt.Sprintf("rule.%d.action", index)
		appliedOnKey := fmt.Sprintf("rule.%d.applied_on", index)
		if !d.NewValueKnown(actionKey) || !d.NewValueKnown(appliedOnKey) {
			continue // decided at apply time; the server's 422 is the backstop
		}
		action, _ := d.Get(actionKey).(string)
		appliedOn, _ := d.Get(appliedOnKey).(string)
		if action == httpsInspectionActionInspectNoDecrypt &&
			(appliedOn == "sites" || appliedOn == "both") {
			return fmt.Errorf(
				"rule.%d has action %q with applied_on %q, which no tenant accepts. The API "+
					"schema states that %q requires the Inspection Policy feature and is valid "+
					"ONLY on applied_on \"agents\" -- it is \"rejected on 'sites' and 'both' "+
					"regardless of the feature\", so this would answer "+
					"422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED. Use applied_on \"agents\", or "+
					"action \"bypass\" or \"inspect\"",
				index, action, appliedOn, httpsInspectionActionInspectNoDecrypt)
		}
	}

	return nil
}

// httpsInspectionSourcesResource is the element schema of a rule's `sources`
// block: one attribute per legal source type. See httpsInspectionBucket for why
// the API's `{type, value}` list is not exposed directly, and why this is not
// the access policy's source vocabulary.
func httpsInspectionSourcesResource() *schema.Resource {
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
			"applications": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Client applications this rule matches — a source type the web access " +
					"policy does not have. The API declares these as ids; the SWG service's own " +
					"stored bypass rules hold executable names such as `notepad.exe`, and which " +
					"of the two a tenant expects has **not** been verified against a live " +
					"policy, so pass exactly what the Harmony SASE console shows. A set: order " +
					"is not significant. Omit it to leave the rule unrestricted by application.",
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

// httpsInspectionDestinationsResource is the element schema of a rule's
// `destinations` block. Note that `addresses` appears here as well as in
// httpsInspectionSourcesResource: on this policy the two vocabularies overlap,
// which they never do on the access policy.
func httpsInspectionDestinationsResource() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"categories": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Ids of web categories this rule matches, as returned by the " +
					"`checkpointsase_web_categories` data source. A set: order is not " +
					"significant. Omit it to leave the rule unrestricted by category.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"domains": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Domains this rule matches — a destination type the web access policy " +
					"does not have. A set: order is not significant. Omit it to leave the rule " +
					"unrestricted by domain.",
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
			"updatable_objects": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Ids of updatable objects this rule matches, as returned by the " +
					"`checkpointsase_updatable_objects` data source. A set: order is not " +
					"significant. Omit it to leave the rule unrestricted by updatable object.",
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
		},
	}
}

/*
resourceHttpsInspectionPolicyWrite is BOTH CreateContext and UpdateContext, and
that is the point rather than a shortcut.

The endpoint has no partial update. POST /v3/ia/https-inspection/policy takes the
complete `bypassRules` array and replaces the tenant's policy with it, so "create
the policy" and "change the policy" are byte-for-byte the same request: build the
whole list from configuration, send it once. Two functions would be two copies of
one call, and the only thing that could ever differ between them is a bug.

What follows the write is not optional. The server canonicalises what it stores
-- empty sources and destinations come back expanded into one bucket per legal
type, and priority is reassigned positionally (API-FINDINGS 1.15/1.16) -- so
state built from the REQUEST would disagree with the next Read on every rule,
forever. rereadAfterWrite fetches the only authoritative account of what the
policy became, and retries a transient failure because by that point the tenant
is already enforcing the new list.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceHttpsInspectionPolicyWrite(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)
	ops := httpsInspectionPolicyOps(client)

	rules := expandHttpsInspectionRules(d.Get("rule").([]interface{}))

	// writeHttpsInspectionRules refuses an empty list before any request leaves,
	// and MinItems on `rule` refuses one at plan time. Both are kept: the schema
	// stops the configuration a user writes, and the writer stops anything that
	// reaches it another way -- and the failure the writer guards against is that
	// somebody "fixes" an empty POST by routing it to the DELETE that clears the
	// tenant's whole policy.
	if err := ops.write(ctx, rules); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to write the tenant's HTTPS inspection policy", err)
	}

	// The id is set only after the write has landed. Setting it earlier would put
	// a resource in state that owns a policy the tenant does not have.
	d.SetId(httpsInspectionPolicyResourceID)

	stored, err := rereadAfterWrite(ctx, ops)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"The HTTPS inspection policy was written but could not be read back", err)
	}

	if err := d.Set("rule", flattenHttpsInspectionRules(stored)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to set the tenant's HTTPS inspection policy rules", err)
	}

	return diags
}

/*
resourceHttpsInspectionPolicyRead reads the whole policy back into state.

A FAILED READ IS NEVER AN EMPTY LIST. On this endpoint absence arrives as an
empty array, not as a 404; a 404 means the URL is wrong, which is the documented
symptom of an unset BASE_URL sending every call to the US production host.
Swallowing that as "the policy is empty" is the defect that shipped three times
in Phase 3, and here it is worse than it was there: Terraform would plan to
re-POST a policy that already exists, over a tenant the provider never managed to
read. The read closure in httpsInspectionPolicyOps returns the error, and this
function reports it.

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
func resourceHttpsInspectionPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	rules, _, err := httpsInspectionPolicyOps(client).read(ctx)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read the tenant's HTTPS inspection policy", err)
	}

	if err := d.Set("rule", flattenHttpsInspectionRules(rules)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to set the tenant's HTTPS inspection policy rules", err)
	}

	// A bucket type this provider has no attribute for is dropped by the
	// flattener and would otherwise vanish without trace -- and because the
	// configuration has no block for it either, the resulting plan is EMPTY and
	// the next apply quietly widens the policy. See
	// unknownHttpsInspectionBucketTypes.
	if dropped := unknownHttpsInspectionBucketTypes(rules); len(dropped) > 0 {
		diags = appendWarningDiags(diags,
			"The HTTPS inspection policy uses rule types this provider does not know",
			fmt.Sprintf("These restrictions were dropped when the policy was read into state, "+
				"and the next apply will REMOVE them from the tenant because Terraform cannot "+
				"see them: %s. Upgrade the provider, or stop managing this policy with "+
				"Terraform until it supports these types.", strings.Join(dropped, ", ")))
	}

	return diags
}

/*
resourceHttpsInspectionPolicyDelete calls DELETE /v3/ia/https-inspection/policy,
with no guard in front of it, and that is correct here.

This resource owns the entire policy. Destroying it therefore means the policy is
gone -- there is no remainder to preserve and nothing to be careful of, so the
"only DELETE when the remainder is empty" gate that a per-rule resource would
need has no condition to test. It is also the only route: POST cannot express an
empty array (400 VALIDATION_BYPASS_RULES_REQUIRED, API-FINDINGS 1.18).

What it does is not small, and the resource description says so plainly: every
bypass rule in the tenant goes, including rules Terraform never created.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceHttpsInspectionPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	if err := httpsInspectionPolicyOps(client).deleteAll(ctx); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to delete the tenant's HTTPS inspection policy", err)
	}

	d.SetId("")
	return diags
}

/*
resourceHttpsInspectionPolicyImportState adopts the tenant's existing policy.

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
func resourceHttpsInspectionPolicyImportState(ctx context.Context, d *schema.ResourceData,
	m interface{}) ([]*schema.ResourceData, error) {
	d.SetId(httpsInspectionPolicyResourceID)

	diagnostics := resourceHttpsInspectionPolicyRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf(
					"could not import the tenant's HTTPS inspection policy: %s, \n %s",
					diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}

/*
expandHttpsInspectionRules turns the configuration's ordered `rule` blocks into
the array that is POSTed.

IT MUST NEVER SORT, DEDUPE OR REORDER. The array's order is the policy's order
(API-FINDINGS 1.16), so index i here is the rule the user wrote i-th.

Note what it does NOT build: `log`, and the tenant-wide
`cleanupBypassRuleDefaultAction`. `log` is auto-assigned by the server and is
refused outright alongside `applied_on` of `sites` or `both`
(perimeter81-swg-api's validateBypassLog), so an Optional+Computed attribute
would risk exactly the perpetual diff this resource is built to avoid.
`cleanupBypassRuleDefaultAction` is feature-gated off on the only tenant
available -- both values answer 422 -- so implementing it would ship untestable
code; writeHttpsInspectionRules leaves it unset, which is what keeps a tenant's
existing value untouched.

  - @param raw []interface{} - d.Get("rule"), which is ordered because `rule` is a TypeList

@return []perimeter81Sdk.HttpsInspectionRule - the complete list, in configuration order
*/
func expandHttpsInspectionRules(raw []interface{}) []perimeter81Sdk.HttpsInspectionRule {
	rules := make([]perimeter81Sdk.HttpsInspectionRule, 0, len(raw))

	for index, item := range raw {
		block, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		rule := perimeter81Sdk.HttpsInspectionRule{
			Name:         block["name"].(string),
			AppliedOn:    block["applied_on"].(string),
			Status:       block["status"].(string),
			Sources:      expandHttpsInspectionSources(block["sources"]),
			Destinations: expandHttpsInspectionDestinations(block["destinations"]),
			// The priority sent is DISCARDED by the server, which reassigns it
			// from array position (API-FINDINGS 1.16). It is still computed here
			// rather than left at zero, for one reason: the field is a
			// non-pointer int32 on the generated model, so ToMap writes it
			// unconditionally and something is going out either way. Sending the
			// value the server is about to assign keeps a captured request body
			// comparable with the response, instead of a column of zeroes that
			// reads like a client that thinks it is setting priorities.
			Priority: int32(len(raw) - 1 - index),
		}

		// action is a POINTER on this model -- the API declares it optional and
		// defaults it to "bypass" -- but the schema makes it Required, so there
		// is always a value to send and it is always the user's.
		rule.Action = perimeter81Sdk.PtrString(block["action"].(string))

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

		// Belt and braces. Both slices above are non-nil by construction, so the
		// nil-slice normalisation cannot fire and AdditionalProperties is empty
		// on a rule we built -- but routing every rule through the same sanitiser
		// is what stops a later field addition from bypassing it.
		rules = append(rules, sanitiseHttpsInspectionRule(rule))
	}

	return rules
}

/*
expandHttpsInspectionSources turns a rule's `sources` block into the API's array
of typed buckets.

A bucket whose list is empty is OMITTED rather than sent with an empty value.
Both forms mean "unrestricted" to the server -- schemas-shared/molecules.types.json
gives usersObject, groupsObject, applicationsObject and addressObject a `value`
of `minItems: 0`, and perimeter81-swg-api's own component fixtures spell "any
source" as buckets with empty values (bypassRulesWithAnySource) -- so this is a
choice about what we send, not about what is legal, and omitting keeps the
request minimal and matches what the flattener produces.

  - @param raw interface{} - block["sources"], a MaxItems-1 list

@return []perimeter81Sdk.HttpsInspectionSource - never nil; a nil slice serialises as JSON null, which this endpoint family answers with a 500 (API-FINDINGS 1.19)
*/
func expandHttpsInspectionSources(raw interface{}) []perimeter81Sdk.HttpsInspectionSource {
	sources := []perimeter81Sdk.HttpsInspectionSource{}
	block := policySingleBlock(raw)
	if block == nil {
		return sources
	}

	for _, bucket := range httpsInspectionSourceBuckets {
		values := flattenStringsArrayData(policyCollection(block[bucket.attr]))
		if len(values) == 0 {
			continue
		}
		sources = append(sources, perimeter81Sdk.HttpsInspectionSource{
			Type:  bucket.apiType,
			Value: values,
		})
	}

	return sources
}

// expandHttpsInspectionDestinations is expandHttpsInspectionSources for the
// destination vocabulary. The two are not merged because the vocabularies differ
// and the generated models are different types.
func expandHttpsInspectionDestinations(raw interface{}) []perimeter81Sdk.HttpsInspectionDestination {
	destinations := []perimeter81Sdk.HttpsInspectionDestination{}
	block := policySingleBlock(raw)
	if block == nil {
		return destinations
	}

	for _, bucket := range httpsInspectionDestinationBuckets {
		values := flattenStringsArrayData(policyCollection(block[bucket.attr]))
		if len(values) == 0 {
			continue
		}
		destinations = append(destinations, perimeter81Sdk.HttpsInspectionDestination{
			Type:  bucket.apiType,
			Value: values,
		})
	}

	return destinations
}

/*
flattenHttpsInspectionRules turns the server's `bypassRules` array into `rule`
blocks, in the server's order.

This is the function that decides whether the resource works. THE SERVER DOES NOT
RETURN WHAT IT WAS SENT: an empty `sources` reads back as one typed bucket per
legal type with an empty value, and an empty `destinations` likewise
(API-FINDINGS 1.15, and phase4-verification W1 records that this list
canonicalises the same way). Writing those into state as set attributes would put
`sources { users = [] groups = [] ... }` in state against a configuration that
has no `sources` block at all, and every plan from then on would propose a change
to a resource nobody touched -- with an apply that never converges, because the
next read produces the same thing again.

So an empty bucket is dropped, and a block whose every bucket was empty is not
emitted at all. TestHttpsInspectionReadProducesNoPermanentDiff drives a whole
policy body through this function and then plans against it.

  - @param rules []perimeter81Sdk.HttpsInspectionRule - the list as returned by a GET

@return []interface{} - `rule` blocks, in the same order
*/
func flattenHttpsInspectionRules(rules []perimeter81Sdk.HttpsInspectionRule) []interface{} {
	flattened := make([]interface{}, 0, len(rules))

	for _, rule := range rules {
		flattened = append(flattened, map[string]interface{}{
			"id":           rule.GetId(),
			"name":         rule.GetName(),
			"applied_on":   rule.GetAppliedOn(),
			"action":       rule.GetAction(),
			"status":       rule.GetStatus(),
			"priority":     int(rule.GetPriority()),
			"sources":      flattenHttpsInspectionSources(rule.GetSources()),
			"destinations": flattenHttpsInspectionDestinations(rule.GetDestinations()),
		})
	}

	return flattened
}

/*
unknownHttpsInspectionBucketTypes reports every source or destination `type` the
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
every plan. TestHttpsInspectionBucketTablesCoverTheAPIEnums is the other half and
the better half: it fails at build time when the spec grows a type, so the
warning is the backstop for a server that is ahead of the spec rather than the
primary defence. That backstop matters more here than on the access policy: two
of the actions on this endpoint are feature-gated, so this vocabulary is the one
likelier to grow.

  - @param rules []perimeter81Sdk.HttpsInspectionRule - the list as returned by a GET

@return []string - one entry per dropped bucket; nil when nothing was dropped
*/
func unknownHttpsInspectionBucketTypes(rules []perimeter81Sdk.HttpsInspectionRule) []string {
	known := func(buckets []httpsInspectionBucket, apiType string) bool {
		for _, bucket := range buckets {
			if bucket.apiType == apiType {
				return true
			}
		}
		return false
	}

	// AN EMPTY BUCKET OF AN UNKNOWN TYPE IS NOT A DROPPED VALUE, so it must not
	// warn. The server returns one bucket per legal type with an empty `value`
	// for any unrestricted rule (API-FINDINGS 1.15), so the day the API grows a
	// type, EVERY unrestricted rule on the tenant would otherwise report that the
	// next apply is about to remove entries that do not exist. A warning that
	// fires on healthy configuration teaches operators to ignore warnings, which
	// costs more than the one it was written to raise. Written in from the start
	// here; on the access policy it had to be added in a fix round.
	hasValues := func(v []string) bool { return len(v) > 0 }

	var dropped []string
	for _, rule := range rules {
		for _, source := range rule.GetSources() {
			if hasValues(source.GetValue()) && !known(httpsInspectionSourceBuckets, source.GetType()) {
				dropped = append(dropped,
					fmt.Sprintf("%s: sources.%s", rule.GetName(), source.GetType()))
			}
		}
		for _, destination := range rule.GetDestinations() {
			if hasValues(destination.GetValue()) &&
				!known(httpsInspectionDestinationBuckets, destination.GetType()) {
				dropped = append(dropped,
					fmt.Sprintf("%s: destinations.%s", rule.GetName(), destination.GetType()))
			}
		}
	}
	return dropped
}

/*
flattenHttpsInspectionSources collapses the server's typed buckets into one
`sources` block, dropping every bucket with an empty value.

If nothing survives, it returns an EMPTY list rather than a block of empty
attributes: that is what makes "the server expanded my absent sources into typed
empty buckets" read back as "there is no sources block", which is what the
configuration says and what the server means.

A bucket whose `type` is not one this provider knows is skipped. That is a real
loss and it is recorded on httpsInspectionBucket; under a whole-policy resource
the value would be removed on the next apply regardless, because the
configuration is the policy.

The loop over the table BREAKS on the first match rather than continuing: two
buckets of the same type would otherwise silently last-win instead of being
noticed, and on this policy `addresses` is a legal type on both sides, so the
table lookup is doing more work than the access policy's.
*/
func flattenHttpsInspectionSources(sources []perimeter81Sdk.HttpsInspectionSource) []interface{} {
	block := map[string]interface{}{}

	for _, source := range sources {
		values := source.GetValue()
		if len(values) == 0 {
			continue
		}
		for _, bucket := range httpsInspectionSourceBuckets {
			if source.GetType() == bucket.apiType {
				block[bucket.attr] = values
				break
			}
		}
	}

	if len(block) == 0 {
		return []interface{}{}
	}
	return []interface{}{block}
}

// flattenHttpsInspectionDestinations is flattenHttpsInspectionSources for the
// destination vocabulary, with the same empty-bucket rule and for the same
// reason.
func flattenHttpsInspectionDestinations(
	destinations []perimeter81Sdk.HttpsInspectionDestination) []interface{} {
	block := map[string]interface{}{}

	for _, destination := range destinations {
		values := destination.GetValue()
		if len(values) == 0 {
			continue
		}
		for _, bucket := range httpsInspectionDestinationBuckets {
			if destination.GetType() == bucket.apiType {
				block[bucket.attr] = values
				break
			}
		}
	}

	if len(block) == 0 {
		return []interface{}{}
	}
	return []interface{}{block}
}
