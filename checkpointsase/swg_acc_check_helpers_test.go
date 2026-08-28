package checkpointsase

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
Shared machinery for the Phase 4 SWG acceptance tests -- the ones in
resource_access_policy_test.go, resource_https_inspection_policy_test.go and
resource_internet_access_status_test.go.

WHAT MAKES THESE TESTS DIFFERENT FROM EVERY OTHER ACCEPTANCE TEST IN THIS
PACKAGE, and why this file exists rather than three copies of the same helper:

Every other resource here owns an OBJECT. A user, a group, a network -- creating
one adds a row, destroying it removes that row, and a test that fails half-way
leaves one stray object behind that a human can find by name.

The three SWG surfaces own TENANT-WIDE SECURITY POSTURE:

  - checkpointsase_access_policy IS the tenant's whole webRules array. Applying
    it replaces every rule; destroying it issues DELETE /v3/ia/access/policy,
    which the API documents as "all internet traffic will be allowed after
    deletion".
  - checkpointsase_https_inspection_policy is the same over bypassRules.
  - checkpointsase_internet_access_status is one field that switches Internet
    Access, Threat Prevention and DLP on or off for the entire tenant.

So a test here cannot be made safe by naming its objects carefully. It is made
safe by two things, and both live in this file:

 1. A PRE-CHECK THAT REFUSES TO RUN ON A TENANT THAT HAS ANYTHING TO LOSE.
    testAccPreCheckAccessPolicyEmpty and its sibling fail the test before the
    first apply if the policy already holds rules. Without them the suite is one
    `terraform apply` away from deleting a production policy, and the deletion
    would look exactly like a passing test.
 2. A DESTROY CHECK THAT ASSERTS THE TENANT IS BACK TO EMPTY, distinguishing an
    empty policy (a real, expected state) from a failed read (never an empty
    list -- the Phase 3 defect that shipped three times).

NONE OF THESE TESTS MAY CALL t.Parallel(). Two of them running at once would be
two writers of one tenant-wide array, and the loser's rules would vanish with no
error anywhere -- the same reasoning recorded on testAccCheckAllNetworksIsSumOfParts.
Go runs non-parallel tests one at a time, which is exactly the isolation this
needs, so the protection is simply not opting in.
*/

/*
testAccPreCheckPolicyEmpty fails the calling test unless the tenant's policy is
empty, and is the reason this suite cannot destroy somebody's rules.

It is generic over the rule type so the two policies share one implementation:
the argument that makes the check necessary is identical for both, and two copies
would be two places for it to rot.

Called from PreCheck, which resource.Test only reaches once TF_ACC is set
(testing.go:732), so no offline run makes this call.

  - @param t *testing.T - the calling test
  - @param ops policyListOps[R] - accessPolicyOps or httpsInspectionPolicyOps, already bound to a client
  - @param resourceType string - the Terraform type name, for the diagnostic
*/
func testAccPreCheckPolicyEmpty[R any](t *testing.T, ops policyListOps[R], resourceType string) {
	t.Helper()

	rules, _, _, err := ops.read(context.Background())
	if err != nil {
		t.Fatalf("could not read the tenant's %s to check it is safe to run this test: %s. "+
			"A read failure is not an empty policy, so this test refuses to run rather than "+
			"assume it has nothing to lose.", ops.policyName, err)
	}
	if len(rules) != 0 {
		t.Fatalf("the tenant's %s already holds %d rule(s), and %s owns the WHOLE policy: "+
			"applying it would replace them and destroying it would delete them. This test "+
			"refuses to run. Empty the policy first, or point CHECKPOINT_SASE_API_KEY at a "+
			"tenant whose %s is empty.",
			ops.policyName, len(rules), resourceType, ops.policyName)
	}
}

// testAccPreCheckAccessPolicyEmpty guards every checkpointsase_access_policy
// acceptance test. See testAccPreCheckPolicyEmpty.
func testAccPreCheckAccessPolicyEmpty(t *testing.T) {
	t.Helper()
	testAccPreCheckPolicyEmpty(t, accessPolicyOps(testAccEnvClient()), "checkpointsase_access_policy")
}

// testAccPreCheckHttpsInspectionPolicyEmpty guards every
// checkpointsase_https_inspection_policy acceptance test.
func testAccPreCheckHttpsInspectionPolicyEmpty(t *testing.T) {
	t.Helper()
	testAccPreCheckPolicyEmpty(t, httpsInspectionPolicyOps(testAccEnvClient()),
		"checkpointsase_https_inspection_policy")
}

/*
testAccCheckPolicyDestroyed asserts the tenant's policy reads back EMPTY after a
destroy, and is deliberately not written as "the object is gone".

There is no 404 to look for. The policy endpoint always exists: a tenant that has
never had a rule answers 200 with an empty array, and so does a tenant whose
policy was just deleted. That is why SAP-05 and SHI-05 both specify "a GET
returning an empty list, not a 404" -- and why the error branch below returns an
error rather than treating a failed read as proof of absence. Conflating the two
would make a transport failure look like a successful destroy.

CheckDestroy receives the state as it was BEFORE the destroy (testing_new.go:32),
so the loop below does find the resources. Data sources share the type name with
their resources on these two surfaces, which is legal and conventional, so the
address prefix is what tells them apart -- a data source never needed destroying
and has nothing to assert.

  - @param s *terraform.State - the pre-destroy state
  - @param ops policyListOps[R] - the bound operations for this policy
  - @param resourceType string - the Terraform type name to look for in state

@return error
*/
func testAccCheckPolicyDestroyed[R any](s *terraform.State, ops policyListOps[R],
	resourceType string) error {
	for address, rs := range s.RootModule().Resources {
		if rs.Type != resourceType || strings.HasPrefix(address, "data.") {
			continue
		}

		rules, _, _, err := ops.read(context.Background())
		if err != nil {
			return fmt.Errorf("reading the tenant's %s to verify destroy: %w. A failed read is "+
				"not an empty policy; the tenant's state is unknown and may still hold rules",
				ops.policyName, err)
		}
		if len(rules) != 0 {
			return fmt.Errorf("the tenant's %s still holds %d rule(s) after destroy. THIS TEST "+
				"HAS LEFT RULES ON THE TENANT; list them and remove them by hand. Destroy issues "+
				"DELETE, which clears the whole policy, so a surviving rule means either the "+
				"DELETE did not happen or something else wrote to the policy while this test ran "+
				"(no test in this suite may call t.Parallel(), for exactly that reason)",
				ops.policyName, len(rules))
		}
	}
	return nil
}

// testAccCheckAccessPolicyDestroy is SAP-05's second half.
func testAccCheckAccessPolicyDestroy(s *terraform.State) error {
	return testAccCheckPolicyDestroyed(s, accessPolicyOps(testAccEnvClient()),
		"checkpointsase_access_policy")
}

// testAccCheckHttpsInspectionPolicyDestroy is SHI-05's second half.
func testAccCheckHttpsInspectionPolicyDestroy(s *terraform.State) error {
	return testAccCheckPolicyDestroyed(s, httpsInspectionPolicyOps(testAccEnvClient()),
		"checkpointsase_https_inspection_policy")
}

/*
testAccCaptureResourceAttr records one attribute's value so a LATER step can
compare against it.

The companion to testAccCaptureResourceID, and needed for the same reason: no
built-in TestCheckFunc can express "this equals what it was in the previous
step", and on these resources the id that matters is not the resource's (which is
a constant) but the server-assigned id of an individual RULE.

  - @param name string - the resource address in state
  - @param key string - the flat attribute key, e.g. "rule.0.id"
  - @param out *string - where to store it

@return resource.TestCheckFunc
*/
func testAccCaptureResourceAttr(name, key string, out *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		value, ok := attrs[key]
		if !ok {
			return fmt.Errorf("%s: %s is absent from state, so it cannot be captured", name, key)
		}
		if value == "" {
			return fmt.Errorf("%s: %s is empty in state, so capturing it would make the later "+
				"comparison vacuous", name, key)
		}
		*out = value
		return nil
	}
}

/*
testAccCheckResourceAttrMatchesCaptured asserts an attribute still holds the
value a previous step captured.

This is how SAP-02, SAP-03, SHI-02 and SHI-03 assert that a rewrite of the whole
array left the untouched rules ALONE. The server mints rule ids; a rule that came
back with a different id was deleted and recreated rather than kept, which is
invisible in every other attribute because the configuration reproduces those
exactly.

  - @param name string - the resource address in state
  - @param key string - the flat attribute key
  - @param want *string - the pointer a testAccCaptureResourceAttr filled in

@return resource.TestCheckFunc
*/
func testAccCheckResourceAttrMatchesCaptured(name, key string, want *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if *want == "" {
			return fmt.Errorf("%s: nothing was captured for %s; the earlier step's Check did "+
				"not run, so this comparison would pass for the wrong reason", name, key)
		}
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		if attrs[key] != *want {
			return fmt.Errorf("%s: %s is %q, want the captured %q — the rule did not survive "+
				"the rewrite, it was replaced", name, key, attrs[key], *want)
		}
		return nil
	}
}

/*
testAccCheckRuleNamesInOrder asserts the `rule` list holds exactly these names,
in exactly this order.

THIS IS THE ASSERTION THE WHOLE PHASE 4 DESIGN EXISTS TO MAKE. The API has no
per-rule endpoint, so a rule's precedence comes only from its position in the
array, and the array is composed by whoever builds the POST body. Under a
per-rule resource that composer would be Terraform's scheduler -- arbitrary
order, in parallel -- so the same configuration applied twice could produce two
different policies with no error and no diff. Under the shipped whole-policy
resource the composer is the configuration, and this function is what proves it
against a live server rather than against a fixture.

It takes an address rather than a resource, so the same call checks the resource
and the data source reading it back (SAP-08, SHI-08).

  - @param name string - a resource or data source address in state
  - @param names ...string - the expected rule names, in configuration order

@return resource.TestCheckFunc
*/
func testAccCheckRuleNamesInOrder(name string, names ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		count, err := dataSourceListLen(attrs, "rule")
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		if count != len(names) {
			return fmt.Errorf("%s: rule.# is %d, want %d", name, count, len(names))
		}
		got := make([]string, 0, count)
		for i := 0; i < count; i++ {
			got = append(got, attrs[fmt.Sprintf("rule.%d.name", i)])
		}
		for i, want := range names {
			if got[i] != want {
				return fmt.Errorf("%s: rules are stored as %v, want %v — configuration order is "+
					"NOT array order, which means rule precedence is not what the configuration says",
					name, got, names)
			}
		}
		return nil
	}
}

/*
testAccCheckRulePrioritiesDescend asserts the server assigned
priority = len(rules) - 1 - index across the whole list.

API-FINDINGS 1.16, measured: a client's `priority` is DISCARDED, not adjusted,
and the server renumbers the entire array on every write. `priority` is
Computed-only on both resources, so nothing in the configuration under test
mentions a priority at all -- every number checked here was invented by the
server, which is what makes this a round-trip assertion rather than an echo.

IT DELIBERATELY ASSERTS NOTHING ABOUT EVALUATION ORDER. Whether priority 0 is
consulted first or last is unmeasured; 1.16 was corrected once for exactly that
overclaim and it is tracked as LEFTOVERS L24. This checks the numbering and stops.

  - @param name string - a resource or data source address in state

@return resource.TestCheckFunc
*/
func testAccCheckRulePrioritiesDescend(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		count, err := dataSourceListLen(attrs, "rule")
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		if count == 0 {
			return fmt.Errorf("%s: rule.# is 0, so there is no priority numbering to check", name)
		}
		for i := 0; i < count; i++ {
			key := fmt.Sprintf("rule.%d.priority", i)
			raw, ok := attrs[key]
			if !ok {
				return fmt.Errorf("%s: %s is absent from state — the flattener never set the "+
					"server-assigned priority", name, key)
			}
			got, err := strconv.Atoi(raw)
			if err != nil {
				return fmt.Errorf("%s: %s = %q, which is not a number", name, key, raw)
			}
			if want := count - 1 - i; got != want {
				return fmt.Errorf("%s: %s = %d, want %d (priority descends with array position, "+
					"len-1-index, measured in API-FINDINGS 1.16)", name, key, got, want)
			}
		}
		return nil
	}
}

/*
testAccCheckControlledBySurfaced asserts a SWG data source reported
`controlled_by` as one of the two documented values.

`quantum` or `hsase`, and NOTHING in this provider branches on it (LEFTOVERS
L23). The assertion is therefore only that the value reached state and is inside
the enum -- asserting which one would pin a tenant-specific fact, and asserting
nothing would let the attribute silently stop being populated.

  - @param name string - the data source address in state

@return resource.TestCheckFunc
*/
func testAccCheckControlledBySurfaced(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		value, ok := attrs["controlled_by"]
		if !ok {
			return fmt.Errorf("%s: controlled_by is absent from state", name)
		}
		if value != "quantum" && value != "hsase" {
			return fmt.Errorf("%s: controlled_by = %q, want \"quantum\" or \"hsase\" — the only "+
				"two values the API documents", name, value)
		}
		return nil
	}
}

/*
testAccReadInternetAccessStatus reads the tenant's CURRENT Internet Access
enforcement value through the provider's own reader.

Through readInternetAccessStatus rather than a hand-rolled GET, on purpose: that
function is the one that has to cope with the enveloped response the document
does not declare (API-FINDINGS 1.22), and a helper that decoded the body itself
would let the test pass while the provider read "" from a healthy 200.

  - @param t *testing.T - the calling test

@return string - "active" or "inactive"
*/
func testAccReadInternetAccessStatus(t *testing.T) string {
	t.Helper()

	status, err := readInternetAccessStatus(context.Background(), testAccEnvClient())
	if err != nil {
		t.Fatalf("could not read the tenant's Internet Access enforcement status: %s. This test "+
			"changes that status, so it refuses to run without knowing the value it has to put "+
			"back.", err)
	}
	return status
}

/*
testAccRestoreInternetAccessStatus puts the tenant's Internet Access enforcement
status back to `want`, and is registered with t.Cleanup so it runs whether the
test passed, failed, or blew up half-way through.

THIS IS THE MOST IMPORTANT FUNCTION IN THIS FILE. ia_status is not a test
fixture: `active` enables Internet Access, Threat Prevention and DLP for the
whole tenant and `inactive` disables all three. A test that flips it and then
fails before flipping back has changed the tenant's security posture and left no
trace saying so -- and the resource's own Delete deliberately makes NO API call
(SIA-06), so `terraform destroy` cannot undo it either. t.Cleanup is the only
thing that can, which is why the restore lives here and not in a test step.

It re-reads first and writes only when the value actually differs, so the common
case -- the test finished tidily and already restored it -- costs one GET and
changes nothing. When it does write, it VERIFIES the write landed: a restore that
silently failed is worse than no restore, because the operator would have no
reason to look.

Every failure path calls t.Errorf with the value that needs setting by hand.
Failing the test is the point: a tenant left in the wrong state must not be
reported as a pass.

  - @param t *testing.T - the calling test
  - @param want string - the value read before the test started
*/
func testAccRestoreInternetAccessStatus(t *testing.T, want string) {
	t.Helper()

	client := testAccEnvClient()
	ctx := context.Background()

	if got, err := readInternetAccessStatus(ctx, client); err == nil && got == want {
		return
	}

	payload := perimeter81Sdk.NewSetIAStatusRequest()
	payload.SetIaStatus(want)
	if _, _, err := client.InternetAccessPoliciesAPI.SetIAStatus(ctx).
		SetIAStatusRequest(*payload).Execute(); err != nil {
		t.Errorf("THE TENANT WAS LEFT WITH THE WRONG INTERNET ACCESS STATUS. Restoring it to "+
			"%q failed: %s. Internet Access, Threat Prevention and DLP are not in the state "+
			"they were in before this test ran. Set ia_status = %q by hand, now.", want, err, want)
		return
	}

	got, err := readInternetAccessStatus(ctx, client)
	if err != nil {
		t.Errorf("the tenant's Internet Access status was set back to %q, but reading it back "+
			"to confirm failed: %s. Verify by hand that ia_status is %q.", want, err, want)
		return
	}
	if got != want {
		t.Errorf("THE TENANT WAS LEFT WITH THE WRONG INTERNET ACCESS STATUS. It reads %q after "+
			"a restore to %q was accepted. Internet Access, Threat Prevention and DLP are not "+
			"in the state they were in before this test ran. Set ia_status = %q by hand, now.",
			got, want, want)
	}
}

// testAccOppositeInternetAccessStatus returns the other member of the two-value
// enum. Written as a lookup rather than as `if active then inactive` so that a
// third value added to internetAccessStatusValues fails here loudly instead of
// being silently mapped onto "inactive".
func testAccOppositeInternetAccessStatus(t *testing.T, status string) string {
	t.Helper()

	switch status {
	case "active":
		return "inactive"
	case "inactive":
		return "active"
	default:
		t.Fatalf("the tenant reported ia_status = %q, which is not one of %v. This test flips "+
			"the value to its opposite and cannot work out what that is.",
			status, internetAccessStatusValues)
		return ""
	}
}
