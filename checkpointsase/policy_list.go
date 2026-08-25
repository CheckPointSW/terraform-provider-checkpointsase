package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
The whole-list machinery for the two Internet Access rule lists.

The API exposes a tenant-wide array of rules and no per-rule endpoint: GET,
POST-the-whole-array and DELETE-the-whole-policy are all there is. Each of the
two resources built on this file therefore owns its ENTIRE list and performs one
write per apply -- the configuration's ordered list IS the array that is POSTed.

That shape is a decision, not an accident. priority is positional and reassigned
by the server on every write (API-FINDINGS 1.16), so rule precedence is decided
by whoever composes the POST body. Under a resource-per-rule model that composer
would be Terraform's scheduler, which creates independent resources in arbitrary
order and in parallel -- so the same configuration applied twice could produce
two different policies with no error and no diff. For a policy engine, order IS
the security posture, so the composer has to be the configuration.

Two measured facts shape everything below:

  - The read model carries fields the write model refuses, so a GET body cannot
    be echoed back (API-FINDINGS 1.17). See stripServerFields.
  - POST rejects an empty array (API-FINDINGS 1.18), so clearing a policy is
    DELETE's job and only DELETE's. The writers refuse an empty list before any
    request leaves rather than quietly routing it to the destructive call; a
    resource that wants the policy gone calls deleteAll itself, from Delete.
*/

const (
	/*
		policyReReadInterval and policyReReadTransientBudget govern the re-read
		that follows a successful write.

		They exist because that re-read is the ONLY place a retry earns its
		keep. A failed FIRST read has changed nothing, so failing is clean. A
		failed re-read is different in kind: the POST already succeeded, the
		tenant's policy is the new one, and the canonical form of it -- which is
		what state has to hold -- is the one thing Terraform does not have.

		Only transient failures are retried -- 5xx, EOF, connection reset --
		classified by the existing classifyAPIError. A 422 is retried zero times,
		because repeating it changes nothing.
	*/
	policyReReadInterval        = 100 * time.Millisecond
	policyReReadTransientBudget = 3
)

/*
accessPolicyRefusedFields are the keys /v3/ia/access/policy returns on a read
and rejects on a write. Measured: POSTing an unmodified GET body answers
422 VALIDATION_INCORRECT_SCHEMA, `"fromDefault" is not allowed`
(API-FINDINGS 1.17).

id and log are deliberately ABSENT from this list. Both are accepted by the
write model, and the id is how the server recognises a rule it already has: strip
it from a rule that came back with one and the next write mints a NEW rule beside
the old one instead of updating it, doubling the policy on every apply.
*/
var accessPolicyRefusedFields = []string{"className", "fromDefault", "objectId"}

/*
httpsInspectionRefusedFields is the same list for /v3/ia/https-inspection/policy,
which additionally returns _created_at (phase4-verification, W1).

The two lists are supersets of one policy's needs, so a single union would also
work -- stripping a key that is absent is a no-op. They are kept separate and
named anyway, because the difference between the two read models is real and a
reader who sees one list would reasonably conclude the two endpoints agree.
*/
var httpsInspectionRefusedFields = []string{"_created_at", "className", "fromDefault", "objectId"}

/*
stripServerFields removes the keys the write model refuses.

It returns a COPY and never mutates the caller's map. The caller is holding the
list it is about to POST, and that list is also what it will compare against or
fall back to if the write is abandoned. Editing in place would alter it even on
the branches that never write, and the damage would only surface on a later
apply.

  - @param rule map[string]interface{} - the rule's undeclared fields, i.e. the
    generated model's AdditionalProperties
  - @param refused []string - accessPolicyRefusedFields or httpsInspectionRefusedFields

The copy is SHALLOW: the values are shared with the caller's map. That is
correct as used here, because only top-level keys are deleted and no nested
value is ever written -- but a caller that wanted to edit a nested value would
need its own deep copy.

@return map[string]interface{} - a copy without the refused keys; nil for a nil input
*/
func stripServerFields(rule map[string]interface{}, refused []string) map[string]interface{} {
	if rule == nil {
		return nil
	}
	kept := make(map[string]interface{}, len(rule))
	for k, v := range rule {
		kept[k] = v
	}
	for _, k := range refused {
		delete(kept, k)
	}
	return kept
}

/*
sanitiseAccessPolicyRule returns a copy of the rule that the write model will
accept.

The refused fields are not declared on AccessPolicyRule, so the generated
UnmarshalJSON collects them into AdditionalProperties and the generated ToMap
writes every one of them back out. Stripping AdditionalProperties is therefore
the whole of the strip, and it is also why id and log survive it automatically:
they are declared struct fields and were never in the map.

The nil-slice normalisation below is a second, separate job on the same copy;
see the comment on it.
*/
func sanitiseAccessPolicyRule(rule perimeter81Sdk.AccessPolicyRule) perimeter81Sdk.AccessPolicyRule {
	rule.AdditionalProperties = stripServerFields(rule.AdditionalProperties, accessPolicyRefusedFields)
	// A nil slice serialises as JSON null, and ToMap emits these three fields
	// unconditionally, so a rule assembled in Go with any of them unset goes out
	// as "conditions":null. MEASURED (API-FINDINGS 1.15): `conditions: []` is
	// accepted -- the server expands it into typed buckets and answers 200. That
	// is the authority for normalising to `[]`.
	//
	// What null itself does is EXTRAPOLATION, not measurement: 1.19 measured
	// `conditions` sent as the STRING "disabled" and got 500 "RuleWeb#upsert
	// internal server error occurred", indistinguishable from the endpoint being
	// down -- which is exactly how it was first misread. null is a type error of
	// the same shape, so the same 500 is likely but was not observed. Either way
	// the fix is to send the form that is known-good.
	if rule.Conditions == nil {
		rule.Conditions = []perimeter81Sdk.Condition{}
	}
	if rule.Destinations == nil {
		rule.Destinations = []perimeter81Sdk.AccessPolicyDestination{}
	}
	if rule.Sources == nil {
		rule.Sources = []perimeter81Sdk.AccessPolicySource{}
	}
	return rule
}

// sanitiseHttpsInspectionRule is sanitiseAccessPolicyRule for the other list,
// with the other refusal list. See httpsInspectionRefusedFields for why the two
// are not merged.
func sanitiseHttpsInspectionRule(rule perimeter81Sdk.HttpsInspectionRule) perimeter81Sdk.HttpsInspectionRule {
	rule.AdditionalProperties = stripServerFields(rule.AdditionalProperties, httpsInspectionRefusedFields)
	// See sanitiseAccessPolicyRule: a nil slice goes out as null and this list
	// declares both arrays required. It has no conditions field.
	if rule.Destinations == nil {
		rule.Destinations = []perimeter81Sdk.HttpsInspectionDestination{}
	}
	if rule.Sources == nil {
		rule.Sources = []perimeter81Sdk.HttpsInspectionSource{}
	}
	return rule
}

/*
policyListOps binds the generic machinery below to one of the two endpoints.
Everything that differs between the access policy and the HTTPS-inspection
policy -- path, array name, rule type, refusal list -- is captured here, so what
is written generically is written once.

read returns the *http.Response alongside the error so that a transient failure
can be told from a permanent one -- classifyAPIError needs the status code, and
without it a 500 is indistinguishable from a 400. Only the re-read after a write
acts on that; see rereadAfterWrite.

read also returns `controlledBy`, which no RESOURCE uses. It is here rather than
in a second closure because there is one GET behind both, and two closures over
the same request is how the data source and the resource end up disagreeing
about what a read of this endpoint is. The resources discard it with `_`, which
is the honest spelling of "this resource does not manage that field": the value
says which product owns the policy (quantum or hsase) and its meaning is
UNINVESTIGATED (phase4-verification, W3), so nothing in this provider may act on
it. The two data sources surface it read-only.

Errors from all three may be wrapped with %w. appendErrorDiags recovers the
server's message body with errors.As, so wrapping no longer costs the operator
`"fromDefault" is not allowed` in favour of a bare `422 Unprocessable Entity`.
(It used to: the direct type assertion was fixed in this same change.)
*/
type policyListOps[R any] struct {
	// policyName names the list in errors this file raises itself.
	policyName string
	// sanitise strips the fields the write model refuses. It is per-rule
	// rather than per-list because the resource composes the list itself, from
	// configuration, and passes each rule through this on the way out.
	sanitise func(R) R
	// read GETs the whole policy document: the rule list, and the controlledBy
	// marker beside it in the same envelope. The response is returned so that
	// callers who retry can classify the failure; it is nil when the request
	// never landed.
	read func(context.Context) ([]R, string, *http.Response, error)
	// write POSTs the whole list, in the order given. It refuses an empty one;
	// see writeAccessPolicyRules.
	write func(context.Context, []R) error
	// deleteAll clears the ENTIRE tenant policy -- the API documents it as "all
	// internet traffic will be allowed after deletion". It is the resource's
	// Delete and nothing else: POST cannot express an empty array
	// (API-FINDINGS 1.18), so this is the only call that empties a policy, and
	// it must never be reached as a fallback from a failed or empty write.
	deleteAll func(context.Context) error
}

// accessPolicyOps binds the machinery to /v3/ia/access/policy.
func accessPolicyOps(client *perimeter81Sdk.APIClient) policyListOps[perimeter81Sdk.AccessPolicyRule] {
	return policyListOps[perimeter81Sdk.AccessPolicyRule]{
		policyName: "access policy",
		sanitise:   sanitiseAccessPolicyRule,
		read: func(ctx context.Context) ([]perimeter81Sdk.AccessPolicyRule, string, *http.Response, error) {
			body, httpResp, err := client.InternetAccessPoliciesAPI.GetAccessPolicy(ctx).Execute()
			if err != nil {
				return nil, "", httpResp, err
			}
			if body == nil {
				return nil, "", httpResp, nil
			}
			data := body.GetData()
			return data.GetWebRules(), data.GetControlledBy(), httpResp, nil
		},
		write: func(ctx context.Context, rules []perimeter81Sdk.AccessPolicyRule) error {
			return writeAccessPolicyRules(ctx, client, rules)
		},
		deleteAll: func(ctx context.Context) error {
			_, err := client.InternetAccessPoliciesAPI.DeleteAccessPolicy(ctx).Execute()
			return err
		},
	}
}

// httpsInspectionPolicyOps binds the machinery to /v3/ia/https-inspection/policy.
func httpsInspectionPolicyOps(client *perimeter81Sdk.APIClient) policyListOps[perimeter81Sdk.HttpsInspectionRule] {
	return policyListOps[perimeter81Sdk.HttpsInspectionRule]{
		policyName: "HTTPS inspection policy",
		sanitise:   sanitiseHttpsInspectionRule,
		read: func(ctx context.Context) ([]perimeter81Sdk.HttpsInspectionRule, string, *http.Response, error) {
			body, httpResp, err := client.InternetAccessPoliciesAPI.GetHttpsInspectionPolicy(ctx).Execute()
			if err != nil {
				return nil, "", httpResp, err
			}
			if body == nil {
				return nil, "", httpResp, nil
			}
			data := body.GetData()
			return data.GetBypassRules(), data.GetControlledBy(), httpResp, nil
		},
		write: func(ctx context.Context, rules []perimeter81Sdk.HttpsInspectionRule) error {
			return writeHttpsInspectionRules(ctx, client, rules)
		},
		deleteAll: func(ctx context.Context) error {
			_, err := client.InternetAccessPoliciesAPI.DeleteHttpsInspectionPolicy(ctx).Execute()
			return err
		},
	}
}

/*
writeAccessPolicyRules POSTs the whole webRules array, in the order given.

The array order is the policy's order and the server keeps it, reassigning
priority positionally (API-FINDINGS 1.16). This function must therefore never
sort, dedupe or otherwise reorder what it is handed.

IT REFUSES AN EMPTY LIST, BEFORE ANY REQUEST LEAVES. The server rejects one with
400 VALIDATION_WEB_RULES_REQUIRED (API-FINDINGS 1.18), so an empty POST could
never succeed -- and the tempting "fix" for that is to route it to DELETE, which
would put the call that clears a tenant's entire policy on the ordinary write
path. Emptying a policy is the resource's Delete calling deleteAll, and nothing
else.

  - @param client *perimeter81Sdk.APIClient - the API client
  - @param rules []perimeter81Sdk.AccessPolicyRule - the complete list to store

@return error - the SDK's error unwrapped, or a refusal for an empty list
*/
func writeAccessPolicyRules(ctx context.Context, client *perimeter81Sdk.APIClient,
	rules []perimeter81Sdk.AccessPolicyRule) error {
	if len(rules) == 0 {
		return fmt.Errorf("refusing to POST an empty access policy: the server answers " +
			"400 VALIDATION_WEB_RULES_REQUIRED, and clearing the policy is DELETE's job")
	}
	body := perimeter81Sdk.NewUpdateAccessPolicyRulesRequest(rules)
	_, _, err := client.InternetAccessPoliciesAPI.UpdateAccessPolicy(ctx).
		UpdateAccessPolicyRulesRequest(*body).Execute()
	return err
}

// writeHttpsInspectionRules is writeAccessPolicyRules for the bypassRules array,
// whose empty-list refusal is 400 VALIDATION_BYPASS_RULES_REQUIRED. It leaves
// cleanupBypassRuleDefaultAction unset: the field is feature-gated off on the
// only tenant available (both values answer 422), so implementing it would ship
// untestable code. The Phase 4 plan schedules the LEFTOVERS.md entry in Task 6;
// it is not written yet, so do not read this as a citation of one.
func writeHttpsInspectionRules(ctx context.Context, client *perimeter81Sdk.APIClient,
	rules []perimeter81Sdk.HttpsInspectionRule) error {
	if len(rules) == 0 {
		return fmt.Errorf("refusing to POST an empty HTTPS inspection policy: the server " +
			"answers 400 VALIDATION_BYPASS_RULES_REQUIRED, and clearing the policy is " +
			"DELETE's job")
	}
	body := perimeter81Sdk.NewUpsertHttpsInspectionPolicy(rules)
	_, _, err := client.InternetAccessPoliciesAPI.UpdateHttpsInspectionPolicy(ctx).
		UpsertHttpsInspectionPolicy(*body).Execute()
	return err
}

/*
rereadAfterWrite re-reads the list after a write that has already succeeded, and
is the only retrying read in this file.

KEPT ON REVISED GROUNDS. It was built for the per-rule model, where a failed
re-read lost a server-minted RULE ID and the next apply appended a second copy.
That reason is gone: the resource id is the policy, so nothing is orphaned, and
the write is a whole-list replace, which is idempotent. The retry is kept anyway,
because a second reason was always underneath the first one and is untouched by
the change of shape:

The re-read is the only authoritative post-state. The server canonicalises what
it is sent -- empty sources, destinations and conditions come back expanded into
one entry per legal type, and priority is reassigned positionally
(API-FINDINGS 1.15/1.16) -- so state populated from the REQUEST would diff
forever against the next Read. Only the response says what the tenant now has.

And the asymmetry that justified retrying only here still holds, with a worse
tail. If the FIRST read fails, nothing has happened and failing is clean. If this
one fails, the POST landed and the apply that produced it reports failure, so the
resource is left either absent from state while the policy is live, or tainted --
and recreating a tainted whole-policy resource BEGINS with the DELETE that clears
the tenant's policy. §1.19 measured that this endpoint answers 500s, so spending
three retries to stay out of that is cheap.
*/
func rereadAfterWrite[R any](ctx context.Context, ops policyListOps[R]) ([]R, error) {
	backoff := policyReReadInterval
	remaining := policyReReadTransientBudget

	for {
		rules, _, resp, err := ops.read(ctx)
		if err == nil {
			return rules, nil
		}
		if classifyAPIError(resp, err) == errKindTransient && remaining > 0 {
			remaining--
			if waitErr := sleepCtx(ctx, backoff); waitErr != nil {
				return nil, fmt.Errorf("%s: the wait before re-reading was cut short. %s Cause: %w",
					policyWrittenNotReadBack(ops.policyName), reapplyToResync, waitErr)
			}
			backoff *= 2
			continue
		}
		return nil, fmt.Errorf("%s: the list could not be read back. %s Cause: %w",
			policyWrittenNotReadBack(ops.policyName), reapplyToResync, err)
	}
}

/*
policyWrittenNotReadBack opens every error on the far side of a successful write.
The operator has to be told that the tenant's policy WAS changed before being
told what went wrong, because state is now the one thing that does not describe
the tenant.

It deliberately does NOT say "re-applying will duplicate it". That was the
per-rule model's hazard, where a lost rule id meant the next apply appended a
second copy. A whole-list write replaces the array, so re-applying is safe and is
in fact the fix. What is not safe is deciding the apply failed and removing the
resource from the configuration, because the rules are live on the server and
nothing would then be tracking them.
*/
func policyWrittenNotReadBack(policyName string) string {
	return fmt.Sprintf("the %s WAS written and the tenant is now enforcing it, but "+
		"Terraform could not read it back, so state does not hold the server's "+
		"canonicalised form of it", policyName)
}

// reapplyToResync is the second half of the same sentence: what to do.
const reapplyToResync = "Re-applying is safe and is the fix: the write replaces the whole " +
	"list, so it cannot duplicate anything. Do NOT remove the resource from the " +
	"configuration instead -- the rules are live on the server and nothing would be " +
	"tracking them."

/*
policySingleBlock unwraps a MaxItems-1 nested block, returning nil when it is
absent or explicitly null. `sources {}` with no attributes set decodes to a
non-nil map with empty values, which the callers then produce an empty bucket
array from -- the same result as omitting the block, which is what the server
means by it. (The configuration is refused at plan time anyway; see each
resource's CustomizeDiff.)

It lives here rather than in either resource because both whole-policy resources
have the same MaxItems-1 `sources`/`destinations` blocks. It was named
accessPolicySingleBlock while only one of them existed.
*/
func policySingleBlock(raw interface{}) map[string]interface{} {
	list := policyCollection(raw)
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
policyCollection narrows an interface{} that should hold a collection -- of
strings, or of nested blocks -- returning nil for an absent or wrongly-typed
value rather than panicking. The nested attributes are all Optional, so absent is
ordinary.

It accepts BOTH forms because the two are not interchangeable and the compiler
will not tell you which one you have: every id collection in these two resources
is a TypeSet, which d.Get hands back as a *schema.Set, while the `sources` and
`destinations` wrapper blocks are TypeLists and arrive as []interface{}. Handling
only the second is how a set attribute silently reads as empty -- which in a
policy rule would mean "unrestricted", i.e. a rule that matches everything.
*/
func policyCollection(raw interface{}) []interface{} {
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
