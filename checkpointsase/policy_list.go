package checkpointsase

import (
	"context"
	"fmt"
	"sync"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
)

/*
Pattern A: the whole-list read-modify-write machinery for the two Internet
Access rule lists.

The API exposes a tenant-wide array of rules and no per-rule endpoint. Adding
one rule means reading the whole list, appending, and re-POSTing it; removing
one means re-POSTing the remainder. Every operation here therefore writes rules
this provider does not own, and a bug does not fail loudly -- it silently
deletes somebody else's rules. That is why the machinery lives in one file with
one set of tests rather than being written twice inside two resources.

Three measured facts shape everything below:

  - The read model carries fields the write model refuses, so a GET body cannot
    be echoed back (API-FINDINGS 1.17). See stripServerFields.
  - POST rejects an empty array (API-FINDINGS 1.18), which is why the
    destructive DELETE exists at all. See rewritePolicyWithout.
  - priority is positional and reassigned by the server on every write
    (API-FINDINGS 1.16), so the list's order is the server's business and this
    file never tries to preserve a client-side priority.
*/

/*
policyMutex serialises whole-list rewrites within this process.

Terraform's default parallelism is 10. Without this, ten Creates of ten rules
would each GET the same list, each append their own rule, and each POST a list
missing the other nine -- nine rules lost, no error anywhere, and Terraform's
state claiming all ten exist.

It serialises ONE provider process. Two concurrent `terraform apply` runs
against the same tenant can still lose rules; that is out of scope for Phase 4
and is documented as a caveat on the resources.
*/
var policyMutex sync.Mutex

/*
accessPolicyRefusedFields are the keys /v3/ia/access/policy returns on a read
and rejects on a write. Measured: POSTing an unmodified GET body answers
422 VALIDATION_INCORRECT_SCHEMA, `"fromDefault" is not allowed`
(API-FINDINGS 1.17).

id and log are deliberately ABSENT from this list. Both are accepted by the
write model, and the id is how a rewrite identifies its own rule: drop it and
the server mints a new rule instead of updating the existing one, silently
doubling the policy on every apply.
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

It returns a COPY and never mutates the caller's map. The caller is mid-rewrite:
it is holding the list it is about to re-POST, and on the delete path it is
holding a list it may decide NOT to POST at all. Editing in place would alter
that list even on the branches that never write, and the damage would only
surface on a later apply.

  - @param rule map[string]interface{} - the rule's undeclared fields, i.e. the
    generated model's AdditionalProperties
  - @param refused []string - accessPolicyRefusedFields or httpsInspectionRefusedFields

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
	// A nil slice serialises as JSON null, and the three array fields are
	// required. Sending null where the schema declares an array is a TYPE
	// error, and a type error on this endpoint answers 500 "RuleWeb#upsert
	// internal server error occurred" (API-FINDINGS 1.19) -- indistinguishable
	// from the endpoint being down, which is exactly how it was misread when it
	// was measured. Normalising here means neither resource can reach it.
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
policy -- path, array name, rule type, refusal list -- is captured here, so the
read-modify-write cycles themselves exist once.

read, write and deleteAll return the SDK's error unwrapped. That is deliberate:
appendErrorDiags recovers the server's message body with a direct type assertion
on *perimeter81Sdk.GenericOpenAPIError, so wrapping with %w would replace
`"fromDefault" is not allowed` with a bare `422 Unprocessable Entity` in the
operator's diagnostic. Callers add context in the diagnostic's summary instead.
*/
type policyListOps[R any] struct {
	// policyName names the list in errors this file raises itself.
	policyName string
	// ruleID and ruleName read the two fields the cycles need. Neither type
	// implements an interface, so they are passed as functions.
	ruleID   func(R) string
	ruleName func(R) string
	// sanitise strips the fields the write model refuses.
	sanitise func(R) R
	// read GETs the whole list.
	read func(context.Context) ([]R, error)
	// write re-POSTs the whole list. It refuses an empty one; see
	// writeAccessPolicyRules.
	write func(context.Context, []R) error
	// deleteAll clears the ENTIRE tenant policy. Only rewritePolicyWithout may
	// call it, and only on the branch documented there.
	deleteAll func(context.Context) error
}

// accessPolicyOps binds the machinery to /v3/ia/access/policy.
func accessPolicyOps(client *perimeter81Sdk.APIClient) policyListOps[perimeter81Sdk.AccessPolicyRule] {
	return policyListOps[perimeter81Sdk.AccessPolicyRule]{
		policyName: "access policy",
		ruleID:     func(r perimeter81Sdk.AccessPolicyRule) string { return r.GetId() },
		ruleName:   func(r perimeter81Sdk.AccessPolicyRule) string { return r.GetName() },
		sanitise:   sanitiseAccessPolicyRule,
		read: func(ctx context.Context) ([]perimeter81Sdk.AccessPolicyRule, error) {
			resp, _, err := client.InternetAccessPoliciesAPI.GetAccessPolicy(ctx).Execute()
			if err != nil {
				return nil, err
			}
			if resp == nil {
				return nil, nil
			}
			data := resp.GetData()
			return data.GetWebRules(), nil
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
		ruleID:     func(r perimeter81Sdk.HttpsInspectionRule) string { return r.GetId() },
		ruleName:   func(r perimeter81Sdk.HttpsInspectionRule) string { return r.GetName() },
		sanitise:   sanitiseHttpsInspectionRule,
		read: func(ctx context.Context) ([]perimeter81Sdk.HttpsInspectionRule, error) {
			resp, _, err := client.InternetAccessPoliciesAPI.GetHttpsInspectionPolicy(ctx).Execute()
			if err != nil {
				return nil, err
			}
			if resp == nil {
				return nil, nil
			}
			data := resp.GetData()
			return data.GetBypassRules(), nil
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
writeAccessPolicyRules re-POSTs the whole webRules array.

IT REFUSES AN EMPTY LIST, BEFORE ANY REQUEST LEAVES. The server rejects one with
400 VALIDATION_WEB_RULES_REQUIRED (API-FINDINGS 1.18), so an empty POST could
never succeed -- and the tempting "fix" for that is to route it to DELETE, which
would put the call that clears a tenant's entire policy on the ordinary write
path. The one situation where an empty list is legitimate is handled in
rewritePolicyWithout and nowhere else.

The caller must already hold policyMutex; this is the write half of a
read-modify-write cycle, not a standalone operation.

  - @param client *perimeter81Sdk.APIClient - the API client
  - @param rules []perimeter81Sdk.AccessPolicyRule - the complete list to store

@return error - the SDK's error unwrapped, or a refusal for an empty list
*/
func writeAccessPolicyRules(ctx context.Context, client *perimeter81Sdk.APIClient,
	rules []perimeter81Sdk.AccessPolicyRule) error {
	if len(rules) == 0 {
		return fmt.Errorf("refusing to POST an empty access policy: the server answers " +
			"400 VALIDATION_WEB_RULES_REQUIRED, and clearing the policy is DELETE's job " +
			"and only on the last-rule branch of rewritePolicyWithout")
	}
	body := perimeter81Sdk.NewUpdateAccessPolicyRulesRequest(rules)
	_, _, err := client.InternetAccessPoliciesAPI.UpdateAccessPolicy(ctx).
		UpdateAccessPolicyRulesRequest(*body).Execute()
	return err
}

// writeHttpsInspectionRules is writeAccessPolicyRules for the bypassRules array,
// whose empty-list refusal is 400 VALIDATION_BYPASS_RULES_REQUIRED. It leaves
// cleanupBypassRuleDefaultAction unset: the field is feature-gated off on the
// only tenant available and is recorded as out of scope in LEFTOVERS.md.
func writeHttpsInspectionRules(ctx context.Context, client *perimeter81Sdk.APIClient,
	rules []perimeter81Sdk.HttpsInspectionRule) error {
	if len(rules) == 0 {
		return fmt.Errorf("refusing to POST an empty HTTPS inspection policy: the server " +
			"answers 400 VALIDATION_BYPASS_RULES_REQUIRED, and clearing the policy is " +
			"DELETE's job and only on the last-rule branch of rewritePolicyWithout")
	}
	body := perimeter81Sdk.NewUpsertHttpsInspectionPolicy(rules)
	_, _, err := client.InternetAccessPoliciesAPI.UpdateHttpsInspectionPolicy(ctx).
		UpsertHttpsInspectionPolicy(*body).Execute()
	return err
}

/*
appendPolicyRule adds one rule to the tenant-wide list and returns the server's
copy of it, under policyMutex for the whole cycle.

The existing rules are sanitised as well as the new one. They arrive from the
GET carrying the fields the write model refuses, so an append that re-POSTed
them unmodified would be rejected with a 422 -- a resource that works against an
empty policy and fails against every populated one.

The new rule is identified by the id the server minted for it: the ids of the
rules that were already there are known, so the one id in the post-write list
that is new and whose name matches is ours. Ids are stable across a rewrite
(measured), so this is sound, and it is more robust than matching on name alone
because names are not unique.

The list is re-read after the write rather than taken from the POST response.
The POST response does echo the list, but this provider has not measured that,
and §1.15/§1.16 mean the stored rule differs from the sent one in any case: the
server canonicalises sources, destinations and conditions and reassigns
priority. One extra GET buys a post-state that is authoritative by construction.

@return R - the server's copy of the appended rule, carrying its assigned id
*/
func appendPolicyRule[R any](ctx context.Context, ops policyListOps[R], rule R) (R, error) {
	var zero R

	policyMutex.Lock()
	defer policyMutex.Unlock()

	before, err := ops.read(ctx)
	if err != nil {
		return zero, err
	}

	existing := make(map[string]bool, len(before))
	next := make([]R, 0, len(before)+1)
	for _, r := range before {
		existing[ops.ruleID(r)] = true
		next = append(next, ops.sanitise(r))
	}
	next = append(next, ops.sanitise(rule))

	if err := ops.write(ctx, next); err != nil {
		return zero, err
	}

	after, err := ops.read(ctx)
	if err != nil {
		return zero, err
	}

	name := ops.ruleName(rule)
	var created []R
	for _, r := range after {
		if existing[ops.ruleID(r)] || ops.ruleName(r) != name {
			continue
		}
		created = append(created, r)
	}
	if len(created) != 1 {
		return zero, fmt.Errorf("appended %q to the %s and the server's list then held %d "+
			"new rules by that name, want exactly 1; the rule's id cannot be recorded, so "+
			"Terraform would not be able to find it again",
			name, ops.policyName, len(created))
	}
	return created[0], nil
}

// appendAccessPolicyRule appends one rule to /v3/ia/access/policy. Note that the
// appended rule lands at the TOP of the policy, not the bottom: priority is the
// rule's index and the server renumbers the list on every write, so a rule added
// to the end of the array comes back at priority 0 (API-FINDINGS 1.16).
func appendAccessPolicyRule(ctx context.Context, client *perimeter81Sdk.APIClient,
	rule perimeter81Sdk.AccessPolicyRule) (perimeter81Sdk.AccessPolicyRule, error) {
	return appendPolicyRule(ctx, accessPolicyOps(client), rule)
}

// appendHttpsInspectionRule appends one rule to /v3/ia/https-inspection/policy.
// The same priority behaviour applies.
func appendHttpsInspectionRule(ctx context.Context, client *perimeter81Sdk.APIClient,
	rule perimeter81Sdk.HttpsInspectionRule) (perimeter81Sdk.HttpsInspectionRule, error) {
	return appendPolicyRule(ctx, httpsInspectionPolicyOps(client), rule)
}

/*
rewritePolicyWithout re-POSTs the rule list with one rule removed.

THE DELETE BRANCH IS NOT A SHORTCUT AND MUST NOT BE GENERALISED. POST rejects an
empty array (400 VALIDATION_WEB_RULES_REQUIRED, API-FINDINGS 1.18), so when the
rule being removed is the LAST one there is no POST that expresses it and DELETE
is the only route. DELETE clears the ENTIRE tenant policy -- the API documents it
as "all internet traffic will be allowed after deletion" -- so it is correct
here and catastrophic anywhere else.

The guard is therefore `len(remaining) == 0`, computed from the SERVER's list
rather than from Terraform state, and nothing else may reach this call.

Two things ahead of that guard are part of it, not preamble:

  - A rule whose id is not in the server's list returns early. Without that,
    destroying a resource whose rule somebody had already deleted by hand would
    reach `len(remaining) == 0` over a list this provider removed nothing from,
    and DELETE the tenant's policy on the strength of it.
  - A failed read is an error, never an empty list. These are COLLECTION
    endpoints: they do not 404 because a rule is missing, they 404 because the
    URL is wrong -- the documented failure when BASE_URL is unset and every call
    goes to the US production host. Reading that as "the policy is empty" is the
    same mistake Phase 3 shipped three times, and here it ends in a DELETE.

@return bool - whether the rule was found on the server and removed
*/
func rewritePolicyWithout[R any](ctx context.Context, ops policyListOps[R], ruleID string) (bool, error) {
	if ruleID == "" {
		// Not reachable from a healthy state, but an empty id would match a
		// rule the server had not assigned one to and could put an otherwise
		// untouched list on the DELETE branch. Refused before any request.
		return false, fmt.Errorf("refusing to rewrite the %s without a rule id", ops.policyName)
	}

	policyMutex.Lock()
	defer policyMutex.Unlock()

	current, err := ops.read(ctx)
	if err != nil {
		return false, err
	}

	remaining := make([]R, 0, len(current))
	found := false
	for _, r := range current {
		if ops.ruleID(r) == ruleID {
			found = true
			continue
		}
		remaining = append(remaining, ops.sanitise(r))
	}

	if !found {
		// The rule is already gone. Nothing is written -- in particular the
		// DELETE below is not reached, because a list we removed nothing from
		// is not ours to clear even when it is empty.
		return false, nil
	}

	if len(remaining) == 0 {
		if err := ops.deleteAll(ctx); err != nil {
			return false, err
		}
		return true, nil
	}

	if err := ops.write(ctx, remaining); err != nil {
		return false, err
	}
	return true, nil
}

// rewriteAccessPolicyWithout removes one rule from /v3/ia/access/policy. See
// rewritePolicyWithout for what happens when it is the last one.
func rewriteAccessPolicyWithout(ctx context.Context, client *perimeter81Sdk.APIClient,
	ruleID string) (bool, error) {
	return rewritePolicyWithout(ctx, accessPolicyOps(client), ruleID)
}

// rewriteHttpsInspectionPolicyWithout removes one rule from
// /v3/ia/https-inspection/policy. See rewritePolicyWithout.
func rewriteHttpsInspectionPolicyWithout(ctx context.Context, client *perimeter81Sdk.APIClient,
	ruleID string) (bool, error) {
	return rewritePolicyWithout(ctx, httpsInspectionPolicyOps(client), ruleID)
}
