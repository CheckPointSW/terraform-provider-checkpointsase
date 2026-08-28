package checkpointsase

import (
	"context"
	"fmt"
	"strings"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
supportOptionsRawConfig builds the cty configuration value Terraform sends for
this resource, filling every attribute the schema declares — nulls for the ones a
case does not set — so the value's type matches the resource's ImpliedType()
exactly, as Terraform's does. Attributes are read from the schema rather than
listed here, so a new attribute cannot silently fall out of these cases.

The null-vs-unknown-vs-zero distinction is the whole point of going through cty: a
map passed to terraform.NewResourceConfigRaw has already lost it, and it is what
tells `live_chat_custom_url` omitted from `live_chat_custom_url = some.url` whose
value is not yet known.
*/
func supportOptionsRawConfig(t *testing.T, configured map[string]cty.Value) cty.Value {
	t.Helper()
	resourceType := resourceSupportOptions().CoreConfigSchema().ImpliedType()

	for name := range configured {
		if !resourceType.HasAttribute(name) {
			t.Fatalf("checkpointsase_support_options has no attribute %q; the test is describing a schema that does not exist", name)
		}
	}

	attributes := map[string]cty.Value{}
	for name, attributeType := range resourceType.AttributeTypes() {
		if value, ok := configured[name]; ok {
			attributes[name] = value
			continue
		}
		attributes[name] = cty.NullVal(attributeType)
	}
	return cty.ObjectVal(attributes)
}

// supportOptionsPhoneNumbers is the value shape of the support_phone_numbers list.
// Pass no pairs for an explicitly empty list.
func supportOptionsPhoneNumbers(t *testing.T, pairs ...[2]string) cty.Value {
	t.Helper()
	elementType := resourceSupportOptions().CoreConfigSchema().ImpliedType().
		AttributeType("support_phone_numbers").ElementType()
	if len(pairs) == 0 {
		return cty.ListValEmpty(elementType)
	}
	elements := make([]cty.Value, 0, len(pairs))
	for _, pair := range pairs {
		elements = append(elements, cty.ObjectVal(map[string]cty.Value{
			"description":  cty.StringVal(pair[0]),
			"phone_number": cty.StringVal(pair[1]),
		}))
	}
	return cty.ListVal(elements)
}

/*
planSupportOptions runs the SDK's real diff machinery — including CustomizeDiff —
over a configuration, the way `terraform plan` does.

It mirrors PlanResourceChange: the same cty value becomes both the shimmed
ResourceConfig and the prior state's RawConfig, which is how the raw config
reaches a ResourceDiff in production. It therefore covers the wiring
(resourceSupportOptionsCustomizeDiff being registered at all) as well as the rule.
*/
func planSupportOptions(t *testing.T, config cty.Value) error {
	t.Helper()
	r := resourceSupportOptions()
	_, err := r.Diff(
		context.Background(),
		&terraform.InstanceState{RawConfig: config},
		terraform.NewResourceConfigShimmed(config, r.CoreConfigSchema()),
		nil,
	)
	return err
}

// testSupportOptionsResourceData builds a ResourceData over the real
// checkpointsase_support_options schema, holding the values Update reads. Unlike
// the cty path above it cannot express "set but unknown", which is precisely the
// limitation the apply-time backstop lives with.
func testSupportOptionsResourceData(t *testing.T, raw map[string]interface{}) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, resourceSupportOptions().Schema, raw)
}

/*
TestSupportOptionsCustomRuleIsRefusedAtPlanTime covers both halves of
supportOptionsCustomRule, which fail for opposite reasons — see
validateSupportOptionsCustomFields.

The required direction (custom with no companion) is a 400 the API would give
anyway; refusing it here only makes the message name the HCL attribute instead of
the JSON field. The excluded direction (a companion set for a non-custom type) is
NOT an API error at all: it is accepted, stored and echoed back unchanged, so the
plan is clean, the apply succeeds, and the setting does nothing. Nothing but this
refusal ever tells the user.
*/
func TestSupportOptionsCustomRuleIsRefusedAtPlanTime(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		configured map[string]cty.Value
		wantErr    string
	}{
		{
			name: "custom phone support with no numbers",
			configured: map[string]cty.Value{
				"phone_support_type":  cty.StringVal("custom"),
				"user_guides_enabled": cty.True,
				"live_chat_type":      cty.StringVal("hidden"),
			},
			wantErr: "phone_support_type = \"custom\" requires support_phone_numbers",
		},
		{
			name: "custom live chat with no url",
			configured: map[string]cty.Value{
				"phone_support_type":  cty.StringVal("hidden"),
				"user_guides_enabled": cty.True,
				"live_chat_type":      cty.StringVal("custom"),
			},
			wantErr: "live_chat_type = \"custom\" requires live_chat_custom_url",
		},
		{
			name: "numbers alongside hidden phone support",
			configured: map[string]cty.Value{
				"phone_support_type":    cty.StringVal("hidden"),
				"user_guides_enabled":   cty.True,
				"live_chat_type":        cty.StringVal("hidden"),
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"US Support", "+1 555 0100"}),
			},
			wantErr: "support_phone_numbers applies only when phone_support_type is \"custom\"",
		},
		{
			name: "numbers alongside the harmony sase default",
			configured: map[string]cty.Value{
				"phone_support_type":    cty.StringVal("harmonySaseDefault"),
				"user_guides_enabled":   cty.True,
				"live_chat_type":        cty.StringVal("hidden"),
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"US Support", "+1 555 0100"}),
			},
			wantErr: "support_phone_numbers applies only when phone_support_type is \"custom\"",
		},
		{
			name: "url alongside the harmony sase default chat",
			configured: map[string]cty.Value{
				"phone_support_type":   cty.StringVal("hidden"),
				"user_guides_enabled":  cty.True,
				"live_chat_type":       cty.StringVal("harmonySaseDefault"),
				"live_chat_custom_url": cty.StringVal("https://support.example.com/chat"),
			},
			wantErr: "live_chat_custom_url applies only when live_chat_type is \"custom\"",
		},
		{
			// An explicitly empty list is not "numbers alongside a non-custom
			// type". rawConfigAttrCollectionPresence reads a known-empty list as
			// absent, which is the whole reason it exists: nothing is sent for it,
			// so there is nothing to complain about, and raising the cross-field
			// error here would send the reader looking for the wrong mistake.
			name: "an explicitly empty list alongside hidden phone support is not the cross-field error",
			configured: map[string]cty.Value{
				"phone_support_type":    cty.StringVal("hidden"),
				"user_guides_enabled":   cty.True,
				"live_chat_type":        cty.StringVal("hidden"),
				"support_phone_numbers": supportOptionsPhoneNumbers(t),
			},
			wantErr: "",
		},
		{
			// The other side of reading an empty list as absent, and the case that
			// makes it load-bearing rather than cosmetic: `custom` with `[]` is a
			// 400 (supportPhoneNumbers is required, and `[]` fails minItems too),
			// and this is the only check that catches it — MinItems cannot, because
			// the config shim has already dropped the empty list.
			name: "custom phone support with an explicitly empty list",
			configured: map[string]cty.Value{
				"phone_support_type":    cty.StringVal("custom"),
				"user_guides_enabled":   cty.True,
				"live_chat_type":        cty.StringVal("hidden"),
				"support_phone_numbers": supportOptionsPhoneNumbers(t),
			},
			wantErr: "phone_support_type = \"custom\" requires support_phone_numbers",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := planSupportOptions(t, supportOptionsRawConfig(t, tc.configured))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("plan returned %v; want no error", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("plan succeeded; want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("plan error = %q; want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

/*
TestSupportOptionsCustomRuleAcceptsTheLegalCombinations is the other direction of
the same rule: every combination that IS legal has to plan cleanly, because a
cross-field check that over-refuses is worse than none — it makes a correct
configuration unusable, and the user has no way to override it.
*/
func TestSupportOptionsCustomRuleAcceptsTheLegalCombinations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		configured map[string]cty.Value
	}{
		{
			name: "both harmony sase defaults, no companions",
			configured: map[string]cty.Value{
				"phone_support_type":  cty.StringVal("harmonySaseDefault"),
				"user_guides_enabled": cty.True,
				"live_chat_type":      cty.StringVal("harmonySaseDefault"),
			},
		},
		{
			name: "both hidden, no companions",
			configured: map[string]cty.Value{
				"phone_support_type":  cty.StringVal("hidden"),
				"user_guides_enabled": cty.False,
				"live_chat_type":      cty.StringVal("hidden"),
			},
		},
		{
			name: "both custom, both companions",
			configured: map[string]cty.Value{
				"phone_support_type":    cty.StringVal("custom"),
				"user_guides_enabled":   cty.True,
				"live_chat_type":        cty.StringVal("custom"),
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"US Support", "+1 555 0100"}),
				"live_chat_custom_url":  cty.StringVal("https://support.example.com/chat"),
			},
		},
		{
			name: "custom phone support, hidden chat — the two halves are independent",
			configured: map[string]cty.Value{
				"phone_support_type":    cty.StringVal("custom"),
				"user_guides_enabled":   cty.True,
				"live_chat_type":        cty.StringVal("hidden"),
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"US Support", "+1 555 0100"}),
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := planSupportOptions(t, supportOptionsRawConfig(t, tc.configured)); err != nil {
				t.Errorf("plan returned %v; want no error — this combination is legal", err)
			}
		})
	}
}

/*
TestSupportOptionsCustomRuleTreatsUnknownAsWrittenNotAbsent is the reason
supportOptionsCustomFieldsFromRawConfig exists rather than just reading d.Get.

`live_chat_custom_url = module.support.chat_url` is a legal configuration whose
value is not known at plan time. d.Get reports "" for it, which is
indistinguishable from omitted — so a rule built on d.Get alone would refuse a
correct configuration outright, and there would be nothing the user could do about
it. Presence is about the key, so an unknown value counts as written.

The same holds for an unknown type: nothing about the combination can be
classified, so nothing is claimed. Update's backstop catches these once the values
are real.
*/
func TestSupportOptionsCustomRuleTreatsUnknownAsWrittenNotAbsent(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		configured map[string]cty.Value
	}{
		{
			name: "custom chat with an unknown url",
			configured: map[string]cty.Value{
				"phone_support_type":   cty.StringVal("hidden"),
				"user_guides_enabled":  cty.True,
				"live_chat_type":       cty.StringVal("custom"),
				"live_chat_custom_url": cty.UnknownVal(cty.String),
			},
		},
		{
			name: "custom phone support with an unknown number list",
			configured: map[string]cty.Value{
				"phone_support_type":  cty.StringVal("custom"),
				"user_guides_enabled": cty.True,
				"live_chat_type":      cty.StringVal("hidden"),
				"support_phone_numbers": cty.UnknownVal(resourceSupportOptions().CoreConfigSchema().
					ImpliedType().AttributeType("support_phone_numbers")),
			},
		},
		{
			name: "an unknown type classifies nothing",
			configured: map[string]cty.Value{
				"phone_support_type":    cty.UnknownVal(cty.String),
				"user_guides_enabled":   cty.True,
				"live_chat_type":        cty.StringVal("hidden"),
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"US Support", "+1 555 0100"}),
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := planSupportOptions(t, supportOptionsRawConfig(t, tc.configured)); err != nil {
				t.Errorf("plan returned %v; want no error — an unknown value must not be read as absent", err)
			}
		})
	}
}

/*
TestSupportOptionsCustomFieldsFromGetterIsTheApplyTimeBackstop covers the path
Update uses, where every value is known and the raw config is not available.

It is a fallback for CustomizeDiff and the only check for anything that was
unknown at plan time, so both directions of the rule have to survive the round
trip through d.Get's zero-value-for-absent semantics.
*/
func TestSupportOptionsCustomFieldsFromGetterIsTheApplyTimeBackstop(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		raw     map[string]interface{}
		wantErr string
	}{
		{
			name: "custom chat, url resolved to empty",
			raw: map[string]interface{}{
				"phone_support_type":  "hidden",
				"user_guides_enabled": true,
				"live_chat_type":      "custom",
			},
			wantErr: "live_chat_type = \"custom\" requires live_chat_custom_url",
		},
		{
			name: "custom phone support, numbers resolved to none",
			raw: map[string]interface{}{
				"phone_support_type":  "custom",
				"user_guides_enabled": true,
				"live_chat_type":      "hidden",
			},
			wantErr: "phone_support_type = \"custom\" requires support_phone_numbers",
		},
		{
			name: "url resolved to a value alongside hidden chat",
			raw: map[string]interface{}{
				"phone_support_type":   "hidden",
				"user_guides_enabled":  true,
				"live_chat_type":       "hidden",
				"live_chat_custom_url": "https://support.example.com/chat",
			},
			wantErr: "live_chat_custom_url applies only when live_chat_type is \"custom\"",
		},
		{
			name: "a legal configuration is not refused",
			raw: map[string]interface{}{
				"phone_support_type":  "harmonySaseDefault",
				"user_guides_enabled": true,
				"live_chat_type":      "harmonySaseDefault",
			},
			wantErr: "",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := testSupportOptionsResourceData(t, tc.raw)
			err := validateSupportOptionsCustomFields(supportOptionsCustomFieldsFromGetter(d))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("got %v; want no error", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("got no error; want one containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got %q; want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

/*
TestAccSupportOptions_basic is the live exercise of
checkpointsase_support_options.

READ THIS BEFORE RUNNING IT. This test writes ACCOUNT-WIDE settings. Unlike every
other acceptance test in this package it creates nothing, scopes nothing to a
throwaway network, and cannot be isolated: there is exactly one support-options
document per tenant, and while this test runs, the phone numbers, live-chat target
and user-guide switch the Harmony SASE agent shows to every end user of the target
account are whatever this test last applied.

It therefore captures the account's real values in PreCheck and restores them from
a t.Cleanup registered at the same moment. The capture is a plain SDK GET, and the
restore is a plain SDK PUT of the same five fields — request and response models
carry identical fields, so the round trip is faithful. Two consequences worth
stating rather than discovering:

  - t.Cleanup, not CheckDestroy. Cleanup runs after resource.Test returns, which is
    after the harness's own destroy, and it runs whether the test passed, failed or
    panicked. A CheckDestroy would be skipped on some failure paths, which is
    exactly when the account has been left changed.
  - If the account had never had its support options configured, the GET answers
    with DEFAULT_SUPPORT_OPTIONS rather than a 404, so the restore writes an
    explicit document holding those defaults. That is semantically identical to
    having none — getBranding merges the stored document over the same defaults —
    but it is not byte-identical, and it is the one way this test does not leave
    the account exactly as it found it.
  - A failed restore is reported as a test failure with the values needed to fix it
    by hand. Silently swallowing it is what would leave someone's support
    configuration wrong with nothing in the log.

What the steps cover, and why two are needed:

  - Step 1 (both types custom) is the only shape that exercises both companion
    fields, so it is the only one that puts supportPhoneNumbers and
    liveChatCustomUrl on the wire at all.
  - Step 2 drops both companions and flips all three required fields. This is the
    step with no offline equivalent: clearing an optional field on a whole-object
    PUT means OMITTING the key, and `supportPhoneNumbers: []` is a 400 while
    `liveChatCustomUrl: ""` is another. It also proves the read maps the resulting
    nulls back to an empty list and "" instead of leaving stale values in state.
  - Step 3 imports into a fresh state and compares it field for field against the
    state step 2 produced. After an apply, state already holds the configured
    values whether Read wrote them or not, so only an import can prove Read
    repopulates every attribute. It creates nothing.

There is no CheckDestroy: no other TestAcc test in this package defines one, and
here it could not assert anything true. Asserting the settings are gone would be
wrong (Delete deliberately writes nothing), and asserting they still exist would be
vacuous (they always do).
*/
func TestAccSupportOptions_basic(t *testing.T) {
	t.Parallel()
	var options perimeter81Sdk.SupportOptionsResponse

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccSupportOptionsCaptureAndRestore(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			// Step 1: adopt the account's support options and push a fully
			// custom configuration onto them.
			{
				Config: testAccSupportOptionsConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSupportOptionsExists("checkpointsase_support_options.support", &options),
					testAccCheckSupportOptionsAttributes(&options, &testAccSupportOptionsExpected{
						PhoneSupportType:  "custom",
						UserGuidesEnabled: true,
						LiveChatType:      "custom",
						LiveChatCustomUrl: "https://support.example.com/chat",
						PhoneNumbers: [][2]string{
							{"TF Acc US", "+1 555 0100"},
							{"TF Acc EU", "+44 20 7000 0000"},
						},
					}),
					// The API is authoritative above; these confirm Read carried
					// the same values into Terraform state, so a server/state
					// divergence cannot hide behind a green API assertion.
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "id", supportOptionsResourceID),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "phone_support_type", "custom"),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "live_chat_type", "custom"),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "user_guides_enabled", "true"),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "live_chat_custom_url", "https://support.example.com/chat"),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "support_phone_numbers.#", "2"),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "support_phone_numbers.0.description", "TF Acc US"),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "support_phone_numbers.0.phone_number", "+1 555 0100"),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "support_phone_numbers.1.description", "TF Acc EU"),
				),
			},
			// Step 2: in-place update. All three required fields change and both
			// companions are removed, which is the case that has to omit the two
			// keys rather than send an empty array and an empty string.
			{
				Config: testAccSupportOptionsUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSupportOptionsExists("checkpointsase_support_options.support", &options),
					testAccCheckSupportOptionsAttributes(&options, &testAccSupportOptionsExpected{
						PhoneSupportType:  "hidden",
						UserGuidesEnabled: false,
						LiveChatType:      "harmonySaseDefault",
					}),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "phone_support_type", "hidden"),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "live_chat_type", "harmonySaseDefault"),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "user_guides_enabled", "false"),
					// State must show both companions gone, not merely emptied of
					// content: a lingering value here would mean Read did not map
					// the server's nulls back onto them.
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "support_phone_numbers.#", "0"),
					resource.TestCheckResourceAttr("checkpointsase_support_options.support", "live_chat_custom_url", ""),
				),
			},
			// Step 3: import into a fresh state and compare it against step 2's.
			//
			// No ImportStateVerifyIgnore: nothing is excluded, deliberately.
			// ImportStateId is set explicitly to the constant id rather than left
			// to default to the resource's own id, so this step also pins the
			// documented import command.
			{
				ResourceName:      "checkpointsase_support_options.support",
				ImportState:       true,
				ImportStateId:     supportOptionsResourceID,
				ImportStateVerify: true,
			},
		},
	})
}

/*
testAccSupportOptionsClient builds an SDK client straight from the environment,
the way providerConfigure does from the provider block.

It exists because the capture has to happen before the first apply, and
testAccProvider.Meta() is nil until the test harness configures the provider —
which is after PreCheck. Both variables it reads are the ones the provider's own
schema defaults to.
*/
func testAccSupportOptionsClient() *perimeter81Sdk.APIClient {
	// Delegates to the shared helper so the two cannot drift. Same behaviour;
	// testAccEnvClient additionally reuses the provider's own client once the
	// harness has configured it.
	return testAccEnvClient()
}

/*
testAccSupportOptionsCaptureAndRestore reads the account's current support options
and registers a t.Cleanup that writes them back.

Called from PreCheck, which resource.Test only reaches when TF_ACC is set, so no
tier-1 unit run ever makes either call.

The restore is unconditional: it runs after a pass, a failure and a panic, because
the account is left changed in all three cases. A restore that fails is reported
with the values it was trying to write, since at that point a human has to put them
back.
*/
func testAccSupportOptionsCaptureAndRestore(t *testing.T) {
	t.Helper()
	client := testAccSupportOptionsClient()
	ctx := context.Background()

	before, _, err := client.SettingsAPI.GetSupportOptions(ctx).Execute()
	if err != nil {
		t.Fatalf("could not capture the account's current support options, so this test would "+
			"leave them changed with no way to put them back: %s", err)
	}
	if before == nil {
		t.Fatal("the account's current support options read back as nil, so there is nothing to restore afterwards")
	}

	t.Cleanup(func() {
		restore := perimeter81Sdk.SupportOptionsRequest{
			PhoneSupportType:    before.PhoneSupportType,
			UserGuidesEnabled:   before.UserGuidesEnabled,
			LiveChatType:        before.LiveChatType,
			SupportPhoneNumbers: before.SupportPhoneNumbers,
		}
		if before.LiveChatCustomUrl != nil {
			restore.SetLiveChatCustomUrl(*before.LiveChatCustomUrl)
		}
		if _, _, err := client.SettingsAPI.UpdateSupportOptions(context.Background()).
			SupportOptionsRequest(restore).Execute(); err != nil {
			t.Errorf("FAILED TO RESTORE the account's support options. They are still whatever this "+
				"test last applied and must be put back by hand. Wanted: phoneSupportType=%q "+
				"userGuidesEnabled=%t liveChatType=%q liveChatCustomUrl=%q supportPhoneNumbers=%v. Error: %s",
				before.PhoneSupportType, before.UserGuidesEnabled, before.LiveChatType,
				before.GetLiveChatCustomUrl(), before.SupportPhoneNumbers, err)
		}
	})
}

/*
testAccCheckSupportOptionsExists confirms the account's support options are
readable server-side through the SDK, and pins the singleton contract that the
resource id is the constant supportOptionsResourceID.

A state-only check cannot substitute for this. Create issues no POST, so a resource
id could be set from a constant alone and look perfectly healthy in state while
nothing was ever written to the account.
*/
func testAccCheckSupportOptionsExists(n string, options *perimeter81Sdk.SupportOptionsResponse) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}
		if rs.Primary.ID != supportOptionsResourceID {
			return fmt.Errorf("got resource id %q; want the constant %q — this resource is an "+
				"account-wide singleton with no server-assigned id, and every downstream reference "+
				"to it depends on the id being stable across reads",
				rs.Primary.ID, supportOptionsResourceID)
		}

		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		got, _, err := conn.SettingsAPI.GetSupportOptions(context.Background()).Execute()
		if err != nil {
			return err
		}
		if got == nil {
			return fmt.Errorf("the account's support options read back as nil")
		}
		*options = *got
		return nil
	}
}

// testAccSupportOptionsExpected describes the account's support options as the
// configuration asked for them. An empty PhoneNumbers or LiveChatCustomUrl means
// "the server must hold nothing here", which is asserted rather than skipped: the
// absent case is the one whose wire shape (an omitted key, not an empty one) is
// invisible in Terraform state.
type testAccSupportOptionsExpected struct {
	PhoneSupportType  string
	UserGuidesEnabled bool
	LiveChatType      string
	LiveChatCustomUrl string
	PhoneNumbers      [][2]string
}

/*
testAccCheckSupportOptionsAttributes compares what the API holds against what the
configuration asked for, field by field.

The two absence comparisons are the load-bearing ones. This resource replaces the
whole support-options document on every write, so if the server merged rather than
replaced — or if the provider sent an empty array where it had to omit the key —
the numbers from the previous step would still be there, and only the API's own
copy shows it.
*/
func testAccCheckSupportOptionsAttributes(got *perimeter81Sdk.SupportOptionsResponse, want *testAccSupportOptionsExpected) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		if got.PhoneSupportType != want.PhoneSupportType {
			return fmt.Errorf("got phoneSupportType %q; want %q", got.PhoneSupportType, want.PhoneSupportType)
		}
		if got.UserGuidesEnabled != want.UserGuidesEnabled {
			return fmt.Errorf("got userGuidesEnabled %t; want %t", got.UserGuidesEnabled, want.UserGuidesEnabled)
		}
		if got.LiveChatType != want.LiveChatType {
			return fmt.Errorf("got liveChatType %q; want %q", got.LiveChatType, want.LiveChatType)
		}
		if got.GetLiveChatCustomUrl() != want.LiveChatCustomUrl {
			return fmt.Errorf("got liveChatCustomUrl %q; want %q — an empty want means the key had "+
				"to be omitted from the PUT, and a stale value here means it was not",
				got.GetLiveChatCustomUrl(), want.LiveChatCustomUrl)
		}

		if len(got.SupportPhoneNumbers) != len(want.PhoneNumbers) {
			return fmt.Errorf("got %d supportPhoneNumbers %v; want %d — this resource replaces the "+
				"whole support-options document, so a mismatch means either the server did not "+
				"honour the submitted list or the provider sent an empty array instead of omitting "+
				"the key", len(got.SupportPhoneNumbers), got.SupportPhoneNumbers, len(want.PhoneNumbers))
		}
		for i, wantNumber := range want.PhoneNumbers {
			gotNumber := got.SupportPhoneNumbers[i]
			if gotNumber.Description != wantNumber[0] {
				return fmt.Errorf("supportPhoneNumbers[%d]: got description %q; want %q", i, gotNumber.Description, wantNumber[0])
			}
			if gotNumber.PhoneNumber != wantNumber[1] {
				return fmt.Errorf("supportPhoneNumbers[%d]: got phoneNumber %q; want %q", i, gotNumber.PhoneNumber, wantNumber[1])
			}
		}
		return nil
	}
}

/*
testAccSupportOptionsConfig is step 1: both types custom, so both companion fields
are on the wire.

Two phone numbers rather than one or three: one would not show that list order
survives the round trip, and three would leave nothing for a later test to add.
The numbers are documentation-range placeholders, and the chat URL points at
example.com — nothing here reaches a real support desk.
*/
func testAccSupportOptionsConfig() string {
	return `
resource "checkpointsase_support_options" "support" {
  phone_support_type  = "custom"
  user_guides_enabled = true
  live_chat_type      = "custom"

  live_chat_custom_url = "https://support.example.com/chat"

  support_phone_numbers {
    description  = "TF Acc US"
    phone_number = "+1 555 0100"
  }

  support_phone_numbers {
    description  = "TF Acc EU"
    phone_number = "+44 20 7000 0000"
  }
}
  `
}

/*
testAccSupportOptionsUpdateConfig is step 2. All three required fields change and
both companion blocks are gone, which is what makes this the step with no offline
equivalent: clearing an optional field on a whole-object PUT means omitting its
key, and both of the plausible alternatives — `supportPhoneNumbers: []` and
`liveChatCustomUrl: ""` — are 400s.

user_guides_enabled goes to false deliberately. It is a plain bool the SDK writes
unconditionally, so this is also the case that would break first if it ever gained
an omitempty: the server would then refuse the body for a missing required
property.
*/
func testAccSupportOptionsUpdateConfig() string {
	return `
resource "checkpointsase_support_options" "support" {
  phone_support_type  = "hidden"
  user_guides_enabled = false
  live_chat_type      = "harmonySaseDefault"
}
  `
}

/*
validateSupportOptionsConfig runs the schema's own validation — MinItems, MaxItems
and every ValidateFunc — over a configuration, the way `terraform validate` does,
and returns the concatenated error text.

This is a separate machine from planSupportOptions above. Schema validation runs in
ValidateResourceConfig, which precedes PlanResourceChange, so nothing here reaches
CustomizeDiff and nothing in the cross-field tests reaches these rules.
*/
func validateSupportOptionsConfig(t *testing.T, configured map[string]cty.Value) string {
	t.Helper()
	r := resourceSupportOptions()
	config := supportOptionsRawConfig(t, configured)
	diags := r.Validate(terraform.NewResourceConfigShimmed(config, r.CoreConfigSchema()))
	messages := make([]string, 0, len(diags))
	for _, d := range diags {
		if d.Severity == diag.Error {
			messages = append(messages, d.Summary+" "+d.Detail)
		}
	}
	return strings.Join(messages, "\n")
}

/*
TestSupportOptionsSchemaMirrorsTheServersFieldRules checks the per-field rules this
resource copies out of the server, because three of them are hand-transcribed
regexes and a hand-transcribed regex is wrong in the expensive direction: too
strict, and it refuses a configuration the API would have accepted, with no way for
the user to override it.

Everything asserted here was read from account-domain's
putCompanyBranding.schema.ts on 2026-08-19 — the AJV schema is the only thing that
validates this body, since the API Gateway in front of it runs
`validateRequestParametersAndHeaders`, which does not look at the body.

The accepted cases matter as much as the rejected ones. They are the exact values
the acceptance test applies, so if a pattern is too strict, this fails offline in
milliseconds instead of 400-ing against a live tenant.
*/
func TestSupportOptionsSchemaMirrorsTheServersFieldRules(t *testing.T) {
	t.Parallel()

	base := map[string]cty.Value{
		"phone_support_type":  cty.StringVal("custom"),
		"user_guides_enabled": cty.True,
		"live_chat_type":      cty.StringVal("custom"),
	}
	with := func(overrides map[string]cty.Value) map[string]cty.Value {
		merged := map[string]cty.Value{}
		for k, v := range base {
			merged[k] = v
		}
		for k, v := range overrides {
			merged[k] = v
		}
		return merged
	}

	for _, tc := range []struct {
		name       string
		configured map[string]cty.Value
		wantErr    string
	}{
		{
			// The exact values TestAccSupportOptions_basic step 1 applies.
			name: "the acceptance test's own values are accepted",
			configured: with(map[string]cty.Value{
				"support_phone_numbers": supportOptionsPhoneNumbers(t,
					[2]string{"TF Acc US", "+1 555 0100"},
					[2]string{"TF Acc EU", "+44 20 7000 0000"}),
				"live_chat_custom_url": cty.StringVal("https://support.example.com/chat"),
			}),
			wantErr: "",
		},
		{
			// MinItems does NOT fire here, and the test says so rather than
			// asserting the error a reader would expect. Measured 2026-08-19:
			// terraform.NewResourceConfigShimmed drops an empty list from the
			// ResourceConfig entirely, so schemaMap.validate finds the key absent
			// and never reaches the length check. `support_phone_numbers = []` is
			// therefore the same configuration as an omitted block, all the way
			// down — which is safe only because expandSupportPhoneNumbers omits the
			// key rather than sending `[]`, and because the cross-field rule reads
			// the empty list as absent and complains about the right thing (see
			// "custom phone support with an explicitly empty list" in
			// TestSupportOptionsCustomRuleIsRefusedAtPlanTime).
			name:       "an empty list is indistinguishable from an omitted block, so MinItems never fires",
			configured: with(map[string]cty.Value{"phone_support_type": cty.StringVal("hidden"), "support_phone_numbers": supportOptionsPhoneNumbers(t)}),
			wantErr:    "",
		},
		{
			name: "a fourth phone number is refused",
			configured: with(map[string]cty.Value{
				"support_phone_numbers": supportOptionsPhoneNumbers(t,
					[2]string{"One", "+1 555 0100"},
					[2]string{"Two", "+1 555 0101"},
					[2]string{"Three", "+1 555 0102"},
					[2]string{"Four", "+1 555 0103"}),
				"live_chat_custom_url": cty.StringVal("https://support.example.com/chat"),
			}),
			wantErr: "Too many list items",
		},
		{
			name: "a description with a blocked special character is refused",
			configured: with(map[string]cty.Value{
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"US Support!", "+1 555 0100"}),
				"live_chat_custom_url":  cty.StringVal("https://support.example.com/chat"),
			}),
			wantErr: "invalid value for support_phone_numbers.0.description",
		},
		{
			name: "a description over eighteen characters is refused",
			configured: with(map[string]cty.Value{
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"Nineteen characters", "+1 555 0100"}),
				"live_chat_custom_url":  cty.StringVal("https://support.example.com/chat"),
			}),
			wantErr: "expected length of support_phone_numbers.0.description to be in the range (1 - 18)",
		},
		{
			name: "a phone number under seven characters is refused",
			configured: with(map[string]cty.Value{
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"US Support", "12345"}),
				"live_chat_custom_url":  cty.StringVal("https://support.example.com/chat"),
			}),
			wantErr: "expected length of support_phone_numbers.0.phone_number to be in the range (7 - 18)",
		},
		{
			name: "a non-numeric phone number is refused",
			configured: with(map[string]cty.Value{
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"US Support", "call-us-now"}),
				"live_chat_custom_url":  cty.StringVal("https://support.example.com/chat"),
			}),
			wantErr: "invalid value for support_phone_numbers.0.phone_number",
		},
		{
			name: "a non-http chat url is refused",
			configured: with(map[string]cty.Value{
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"US Support", "+1 555 0100"}),
				"live_chat_custom_url":  cty.StringVal("ftp://support.example.com/chat"),
			}),
			wantErr: "invalid value for live_chat_custom_url",
		},
		{
			name: "a chat url under eight characters is refused",
			configured: with(map[string]cty.Value{
				"support_phone_numbers": supportOptionsPhoneNumbers(t, [2]string{"US Support", "+1 555 0100"}),
				"live_chat_custom_url":  cty.StringVal("http://"),
			}),
			wantErr: "expected length of live_chat_custom_url to be in the range (8 - 2048)",
		},
		{
			// The enum, from the OpenAPI document and from
			// $defs.customSupportOptionsType in the mongo validation schemas.
			// "default" is the plausible wrong guess.
			name:       "a phone support type outside the enum is refused",
			configured: with(map[string]cty.Value{"phone_support_type": cty.StringVal("default")}),
			wantErr:    "expected phone_support_type to be one of",
		},
		{
			name:       "a live chat type outside the enum is refused",
			configured: with(map[string]cty.Value{"live_chat_type": cty.StringVal("default")}),
			wantErr:    "expected live_chat_type to be one of",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := validateSupportOptionsConfig(t, tc.configured)
			if tc.wantErr == "" {
				if got != "" {
					t.Fatalf("validation returned %q; want none — this configuration is legal and a "+
						"provider-side rule that is stricter than the server's cannot be overridden", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantErr) {
				t.Errorf("validation returned %q; want it to contain %q", got, tc.wantErr)
			}
		})
	}
}
