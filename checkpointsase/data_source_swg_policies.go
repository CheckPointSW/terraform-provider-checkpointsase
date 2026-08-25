package checkpointsase

import (
	"context"
	"fmt"
	"strings"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
The two read-only views of the Internet Access policies.

Each shares its NAME with the resource of the same name, which Terraform permits
-- resources and data sources live in separate namespaces -- and which is the
convention for "read what is there without owning it". A configuration can hold
`data "checkpointsase_access_policy" "current" {}` and
`resource "checkpointsase_access_policy" "managed" {}` at once, though a
configuration that does both is usually a mistake: the resource owns the whole
list, so the data source next to it reads what the resource wrote.

What these are FOR is the case where the resource is wrong: a tenant whose policy
is maintained in the Harmony SASE console, and a Terraform configuration that
needs to see it -- to name a rule in an output, to count rules, to assert
something about them -- without adopting it. The resource would delete every
console-made rule on the next apply. These read and do not write.

Both take no arguments. Both surface `controlled_by` read-only. And both treat a
failed read as an error rather than as an empty policy, which is the point they
share with the resources and is spelled out on
dataSourceAccessPolicyRead.
*/

/*
accessPolicyDataSourceID and httpsInspectionPolicyDataSourceID are the two data
sources' Terraform ids, and they are constants.

Neither data source takes an argument, so every instance of one reads exactly the
same thing and is interchangeable with every other -- there is nothing for an id
to distinguish. That is the same reasoning data_source_web_categories.go records,
and it is deliberately NOT the argument-derived id the identity data sources use:
`checkpointsase_users` hashes its filters because two instances with different
filters are genuinely different reads. Here there are no filters.

Not a timestamp, for the reason recorded in L16c: fifteen of sixteen data sources
written before web_categories used time.Now(), which changes on every read and so
defeats any downstream reference to the data source's own id.

The values differ from the RESOURCE ids (`access-policy`,
`https-inspection-policy`) on purpose. A data source and a resource of the same
name are different objects in state, and giving them the same id string would
make the two indistinguishable in a state file that a human is reading.
*/
const (
	accessPolicyDataSourceID          = "checkpointsase_access_policy"
	httpsInspectionPolicyDataSourceID = "checkpointsase_https_inspection_policy"
)

/*
swgPolicyControlledByDescription is the `controlled_by` attribute's
documentation, shared by both data sources because the field is the same field.

It says what is known and stops. `controlledBy` reads `quantum` or `hsase`; the
enum is all the API document gives, the live tenant answered `hsase`
(phase4-verification, W3), and what the value MEANS for a client has not been
investigated. So it is surfaced and nothing acts on it -- not the resources, not
these data sources, no validator, no branch. A guess about it would be a guess
about whether this provider should be writing to a tenant at all.
*/
const swgPolicyControlledByDescription = "Which product owns this policy: `quantum` or `hsase`. " +
	"Read-only, and **surfaced without being interpreted** — the API documents nothing beyond " +
	"the two values, and what they imply for a client has not been investigated. Nothing in " +
	"this provider reads or branches on it. A tenant answering `quantum` may well be one whose " +
	"policy should not be written by the matching resource, but that is a hypothesis, not a " +
	"measurement, so do not build a `count` or a `for_each` on it without confirming what it " +
	"means for your tenant."

// swgPolicyPriorityDescription documents the server-assigned priority on both
// data sources. It is the resource's wording minus the write-side half, and it
// keeps the same refusal to claim an evaluation order: API-FINDINGS 1.16
// measured the NUMBERING and explicitly did not measure which end is consulted
// first.
const swgPolicyPriorityDescription = "The server-assigned priority of this rule. Measured: " +
	"priority descends with array position, `len(rule) - 1 - index`, so the first rule in the " +
	"list has the highest number and the last has `0`. " +
	"**Whether priority `0` is evaluated first or last is not established.** The API documents " +
	"the field only as \"updated automatically\", and it cannot be inferred from the numbering. " +
	"Do not rely on either reading until it is measured."

// swgPolicyRuleListDescription is the shared part of the `rule` list's
// documentation: it is ordered, and the order is the stored order.
const swgPolicyRuleListDescription = "The tenant's rules, **in the order the server stores " +
	"them**, which is the order that determines precedence. The list is empty when the tenant " +
	"has no rules — which is a real state, reachable from the console or from a " +
	"`terraform destroy` of the matching resource, and is reported as an empty list rather " +
	"than as an error."

/*
dataSourceAccessPolicy reads the tenant's web access policy without owning it.

@return &schema.Resource
*/
func dataSourceAccessPolicy() *schema.Resource {
	return &schema.Resource{
		Description: "Reads the tenant's **entire** web access policy — the whole ordered " +
			"`webRules` list from `GET /v3/ia/access/policy` — without managing it. " +
			"Use this to inspect a policy that something else owns: a tenant maintained in " +
			"the Harmony SASE console, or one managed by a different Terraform configuration. " +
			"It takes no arguments; there is one policy per tenant and the API addresses it " +
			"by path. " +
			"This does **not** adopt the policy and never writes. The " +
			"`checkpointsase_access_policy` RESOURCE of the same name is the writing half, and " +
			"it owns the whole list — using both against the same tenant means the data " +
			"source reads back what the resource wrote, and the resource still deletes every " +
			"rule the configuration does not contain.",
		ReadContext: dataSourceAccessPolicyRead,
		Schema: map[string]*schema.Schema{
			"controlled_by": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: swgPolicyControlledByDescription,
			},
			"rule": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: swgPolicyRuleListDescription,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The server-assigned id of this rule.",
						},
						"priority": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: swgPolicyPriorityDescription,
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The name of the rule.",
						},
						"applied_on": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Where the rule applies: `agents`, `sites`, or `both`.",
						},
						"action": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "What the rule does with traffic it matches: `allow`, " +
								"`block` or `warning`.",
						},
						"status": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "Whether the rule is in force: `active` or `inactive`. An " +
								"`inactive` rule keeps its position in the policy but is not " +
								"evaluated.",
						},
						"sources": {
							Type:     schema.TypeList,
							Computed: true,
							Description: "What the rule matches traffic FROM, as object ids. " +
								"**Absent when the rule is unrestricted by source.** The server " +
								"returns an unrestricted rule as one empty bucket per legal type " +
								"(API-FINDINGS 1.15); those carry no information and are dropped, " +
								"so \"any source\" reads as no block rather than as a block of " +
								"empty lists. Never longer than one element.",
							Elem: &schema.Resource{
								Schema: computedIDSetAttributes(accessPolicyBucketAttrs(accessPolicySourceBuckets),
									"matched as a source"),
							},
						},
						"destinations": {
							Type:     schema.TypeList,
							Computed: true,
							Description: "What the rule matches traffic TO, as object ids. " +
								"**Absent when the rule is unrestricted by destination**, for the " +
								"reason given on `sources`. Never longer than one element.",
							Elem: &schema.Resource{
								Schema: computedIDSetAttributes(accessPolicyBucketAttrs(accessPolicyDestinationBuckets),
									"matched as a destination"),
							},
						},
						"conditions": {
							Type:     schema.TypeSet,
							Computed: true,
							Description: "The time windows during which the rule is in force. Empty " +
								"when the rule has no time constraint. Order is not significant — " +
								"nothing in the API assigns one — which is why this is a set here " +
								"and on the resource. " +
								"This is the API's `conditions` array, whose only legal entry type " +
								"is `datetime`; with exactly one type the type level carries no " +
								"information and is not exposed, so each block is one entry of " +
								"that bucket's value.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"weekdays": {
										Type:     schema.TypeSet,
										Computed: true,
										Description: "The days the window covers, as `Mon`–`Sun`. A " +
											"set: order is not significant.",
										Elem: &schema.Schema{Type: schema.TypeString},
									},
									"start_hour": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "The hour the window opens, 0–23.",
									},
									"start_minute": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "The minute the window opens, 0–59.",
									},
									"end_hour": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "The hour the window closes, 0–23.",
									},
									"end_minute": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "The minute the window closes, 0–59.",
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
dataSourceHttpsInspectionPolicy reads the tenant's HTTPS-inspection policy
without owning it.

@return &schema.Resource
*/
func dataSourceHttpsInspectionPolicy() *schema.Resource {
	return &schema.Resource{
		Description: "Reads the tenant's **entire** HTTPS-inspection policy — the whole ordered " +
			"`bypassRules` list from `GET /v3/ia/https-inspection/policy` — without managing " +
			"it. " +
			"Use this to inspect a policy that something else owns: a tenant maintained in " +
			"the Harmony SASE console, or one managed by a different Terraform configuration. " +
			"It takes no arguments; there is one policy per tenant and the API addresses it " +
			"by path. " +
			"This does **not** adopt the policy and never writes. The " +
			"`checkpointsase_https_inspection_policy` RESOURCE of the same name is the writing " +
			"half, and it owns the whole list — using both against the same tenant means the " +
			"data source reads back what the resource wrote, and the resource still deletes " +
			"every rule the configuration does not contain. " +
			"The tenant-wide cleanup-rule default action (`cleanupBypassRuleDefaultAction`) " +
			"is not exposed here: it is feature-gated off on the only tenant it could be " +
			"measured against.",
		ReadContext: dataSourceHttpsInspectionPolicyRead,
		Schema: map[string]*schema.Schema{
			"controlled_by": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: swgPolicyControlledByDescription,
			},
			"rule": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: swgPolicyRuleListDescription,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The server-assigned id of this rule.",
						},
						"priority": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: swgPolicyPriorityDescription,
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The name of the rule.",
						},
						"applied_on": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Where the rule applies: `agents`, `sites`, or `both`.",
						},
						"action": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "What the rule does with traffic it matches: `bypass` " +
								"(skip HTTPS inspection), `inspect`, or `inspectNoDecrypt`. " +
								"Always present: the API declares it optional on the write model " +
								"with a default of `bypass`, and a rule stored without one reads " +
								"back as `bypass` (API-FINDINGS 1.21).",
						},
						"status": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "Whether the rule is in force: `active` or `inactive`. An " +
								"`inactive` rule keeps its position in the policy but is not " +
								"evaluated.",
						},
						"sources": {
							Type:     schema.TypeList,
							Computed: true,
							Description: "What the rule matches traffic FROM, as object ids. " +
								"**Absent when the rule is unrestricted by source.** The server " +
								"returns an unrestricted rule as one empty bucket per legal type " +
								"(API-FINDINGS 1.15); those carry no information and are dropped, " +
								"so \"any source\" reads as no block rather than as a block of " +
								"empty lists. Never longer than one element. " +
								"This vocabulary is **not** the web access policy's: " +
								"`applications` exists here and nowhere in that one, and " +
								"`addresses` is legal on both sides of a rule here and on neither " +
								"there.",
							Elem: &schema.Resource{
								Schema: computedIDSetAttributes(httpsInspectionBucketAttrs(httpsInspectionSourceBuckets),
									"matched as a source"),
							},
						},
						"destinations": {
							Type:     schema.TypeList,
							Computed: true,
							Description: "What the rule matches traffic TO, as object ids. " +
								"**Absent when the rule is unrestricted by destination**, for the " +
								"reason given on `sources`. Never longer than one element.",
							Elem: &schema.Resource{
								Schema: computedIDSetAttributes(httpsInspectionBucketAttrs(httpsInspectionDestinationBuckets),
									"matched as a destination"),
							},
						},
					},
				},
			},
		},
	}
}

/*
accessPolicyBucketAttrs and httpsInspectionBucketAttrs read the Terraform
attribute names out of one of the bucket tables.

They exist because the two bucket types are DELIBERATELY separate types (see
accessPolicyBucket): a shared type would let a table from one resource be passed
to a flattener from the other and produce wrong `type` strings on the wire with
nothing failing to compile. The price of that guarantee is that the one field
they have in common cannot be read generically without a type switch, and two
four-line functions are cheaper and clearer than one generic with a type switch
inside it.

@return []string - the attribute names, in table order
*/
func accessPolicyBucketAttrs(buckets []accessPolicyBucket) []string {
	attrs := make([]string, 0, len(buckets))
	for _, bucket := range buckets {
		attrs = append(attrs, bucket.attr)
	}
	return attrs
}

// httpsInspectionBucketAttrs is accessPolicyBucketAttrs for the other table.
func httpsInspectionBucketAttrs(buckets []httpsInspectionBucket) []string {
	attrs := make([]string, 0, len(buckets))
	for _, bucket := range buckets {
		attrs = append(attrs, bucket.attr)
	}
	return attrs
}

/*
computedIDSetAttributes builds one Computed set-of-strings attribute per name,
so that a data source's `sources` or `destinations` block is GENERATED from the
same bucket table the flattener keys on.

That is the whole point of it. The flatteners are reused unchanged -- these data
sources call flattenAccessPolicyRules and flattenHttpsInspectionRules, not copies
-- and those write into the map under bucket.attr. Hand-listing the attribute
names here would give two places that have to agree, and the failure when they
did not would be silent: d.Set DROPS a key the schema does not declare, so a
whole class of restriction would simply be missing from the data source's output
with nothing to notice it. Generating from the table means the schema cannot
disagree with the flattener, because both read the same slice.

  - @param attrs []string - accessPolicyBucketAttrs(...) or httpsInspectionBucketAttrs(...)
  - @param role string - "matched as a source" or "matched as a destination", for the description

@return map[string]*schema.Schema
*/
func computedIDSetAttributes(attrs []string, role string) map[string]*schema.Schema {
	attributes := make(map[string]*schema.Schema, len(attrs))
	for _, attr := range attrs {
		attributes[attr] = &schema.Schema{
			Type:     schema.TypeSet,
			Computed: true,
			Description: fmt.Sprintf("Ids of the `%s` objects this rule matches, %s. A set: "+
				"order is not significant, and the API does not promise one. Absent when the "+
				"rule places no restriction of this kind.", attr, role),
			Elem: &schema.Schema{Type: schema.TypeString},
		}
	}
	return attributes
}

/*
dataSourceAccessPolicyRead reads the whole web access policy into state.

A FAILED READ IS NEVER AN EMPTY LIST, and on a data source that rule has teeth
the resource's version does not. The resource at least ends up with a plan
somebody can look at; a data source is consumed directly, so
`length(data.checkpointsase_access_policy.current.rule)` or a `for_each` over it
would collapse to ZERO on a failed read -- and every resource downstream of that
`for_each` would be planned for destruction, from a transport error. Conflating
absence with failure is the defect that shipped three times in Phase 3 and this
is its worst form.

The two cases are genuinely different on this endpoint and both are handled:

  - An empty policy is a REAL state. It arrives as a 200 with an empty array,
    reachable by emptying the policy in the console or by destroying the matching
    resource. It is written to state as an empty list.

  - A failure arrives as an error from the SDK, including a 404 -- which on this
    endpoint means the URL is wrong, the documented symptom of an unset BASE_URL
    sending every call to the US production host. It is reported.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().

  - @param d *schema.ResourceData - the terraform resource data

  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func dataSourceAccessPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	rules, controlledBy, _, err := accessPolicyOps(client).read(ctx)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read the tenant's web access policy", err)
	}

	if err := d.Set("rule", flattenAccessPolicyRules(rules)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set the tenant's web access policy rules", err)
	}
	if err := d.Set("controlled_by", controlledBy); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set the tenant's web access policy controlled_by", err)
	}

	diags = append(diags, swgDroppedBucketWarning(unknownAccessPolicyBucketTypes(rules),
		"web access policy")...)

	// A constant id, for the reason on accessPolicyDataSourceID: this data source
	// takes no arguments, so every instance reads the same thing.
	d.SetId(accessPolicyDataSourceID)
	return diags
}

// dataSourceHttpsInspectionPolicyRead is dataSourceAccessPolicyRead for the
// other policy. Read the comment on that one: the read-error-is-never-an-empty-
// list argument is the same and is the reason both of these exist in this shape.
func dataSourceHttpsInspectionPolicyRead(ctx context.Context, d *schema.ResourceData,
	m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	rules, controlledBy, _, err := httpsInspectionPolicyOps(client).read(ctx)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read the tenant's HTTPS inspection policy", err)
	}

	if err := d.Set("rule", flattenHttpsInspectionRules(rules)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set the tenant's HTTPS inspection policy rules", err)
	}
	if err := d.Set("controlled_by", controlledBy); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to set the tenant's HTTPS inspection policy controlled_by", err)
	}

	diags = append(diags, swgDroppedBucketWarning(unknownHttpsInspectionBucketTypes(rules),
		"HTTPS inspection policy")...)

	d.SetId(httpsInspectionPolicyDataSourceID)
	return diags
}

/*
swgDroppedBucketWarning reports the source or destination types the flattener had
to drop because this provider has no attribute for them.

The detectors are the resources' -- unknownAccessPolicyBucketTypes and
unknownHttpsInspectionBucketTypes -- because "which types does this provider
know" is one question with one answer. Only the wording differs, and it has to:
the resources warn that the NEXT APPLY will remove the restriction, which is true
of a resource that owns the policy and false of a data source that only reads.
What is true here is narrower and still worth saying, because a value silently
missing from a data source is a value a downstream `for_each` never sees.

  - @param dropped []string - the detector's output; nil when nothing was dropped
  - @param policyName string - for the message

@return diag.Diagnostics - empty when nothing was dropped
*/
func swgDroppedBucketWarning(dropped []string, policyName string) diag.Diagnostics {
	var diags diag.Diagnostics
	if len(dropped) == 0 {
		return diags
	}
	return appendWarningDiags(diags,
		fmt.Sprintf("The %s uses rule types this provider does not know", policyName),
		fmt.Sprintf("These restrictions are MISSING from what this data source returned, "+
			"because there is no attribute to put them in: %s. Nothing downstream of this data "+
			"source can see them, so any decision made from it is being made on a partial view "+
			"of the policy. Upgrade the provider. Reading is not destructive — unlike the "+
			"matching resource, this data source never writes — so the tenant is unaffected.",
			strings.Join(dropped, ", ")))
}
