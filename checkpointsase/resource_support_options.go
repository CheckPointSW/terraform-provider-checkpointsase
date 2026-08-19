package checkpointsase

import (
	"context"
	"fmt"
	"regexp"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
supportOptionsResourceID is this resource's Terraform id, and it is a constant on
purpose.

There is exactly one support-options object per account and the API never mints an
id for it: GET/PUT /v3/account/customize/support-options address it by path alone.
Something still has to go in d.SetId(), because an empty id means "this resource
does not exist" to Terraform.

Not a timestamp. `L16c` records that fifteen of sixteen data sources on this branch
used a timestamp as their id, that it therefore changes on every read, and that
`all_networks` was given a stable id with a comment explaining why the timestamp is
wrong. Any downstream reference to this resource's id — a `depends_on`, an output,
an interpolation — needs the id to be the same value after a refresh as before it.
A constant is the only thing that is.
*/
const supportOptionsResourceID = "support-options"

/*
The three values phone_support_type and live_chat_type admit.

These are declared here rather than taken from the SDK because the SDK has no
constants for them: the generator emitted `PhoneSupportType string` and
`LiveChatType string` on both SupportOptionsRequest and SupportOptionsResponse,
with the enum surviving only in a doc comment. The values are transcribed from
two independent sources that agree — the `enum` on both schemas in the OpenAPI
document (api/openapi.yaml) and `$defs.customSupportOptionsType` in
p81-mongo-validation-schemas' schemas-shared/molecules.types.json, which is what
the server's own AJV enum is built from (SUPPORT_OPTIONS_ENUM_VALUES in
account-domain's CompanyBrandingConstants.ts is Object.values of that same type).

Note that account-domain also contains a `SupportOptionType` enum listing only
`hidden` and `custom`. It is unused by the validator and is not the authority;
harmonySaseDefault is accepted, and is what a never-configured account reads back
as (DEFAULT_SUPPORT_OPTIONS).
*/
const (
	supportOptionsTypeHarmonySaseDefault = "harmonySaseDefault"
	supportOptionsTypeCustom             = "custom"
	supportOptionsTypeHidden             = "hidden"
)

// supportOptionsTypeValues is the StringInSlice set for both enum attributes.
var supportOptionsTypeValues = []string{
	supportOptionsTypeHarmonySaseDefault,
	supportOptionsTypeCustom,
	supportOptionsTypeHidden,
}

/*
supportOptionsCustomRule is the cross-field rule in one sentence. It is quoted by
the resource description, by both companion attributes and by every plan-time
refusal, so a reader meets the same wording wherever they hit it.
*/
const supportOptionsCustomRule = "`custom` is the only type that takes a companion field: " +
	"`phone_support_type = \"custom\"` requires `support_phone_numbers` and " +
	"`live_chat_type = \"custom\"` requires `live_chat_custom_url`, and neither companion " +
	"may be set for any other type."

/*
The three server-side patterns this resource mirrors at plan time, transcribed
from account-domain's putCompanyBranding.schema.ts (the account API's AJV schema,
which is the only thing that validates this body — the API Gateway in front of it
runs `validateRequestParametersAndHeaders`, which does not look at the body).

They are mirrored rather than left to the API because each one is a genuine 400
and the message the API returns names the JSON field, not the HCL attribute.
*/
var (
	// description: minLength 1, maxLength 18, and no special characters.
	supportOptionsPhoneDescriptionPattern = regexp.MustCompile(`^[^!@#$%^&*_=+\[\]{}\\|;:'",<>.?/~-]+$`)
	// phoneNumber: minLength 7, maxLength 18, digits with optional +, spaces,
	// dashes, dots and parentheses in the middle.
	supportOptionsPhoneNumberPattern = regexp.MustCompile(`^\+?\s?\d[\d\s\-\(\)\.]+\d$`)
	// liveChatCustomUrl: minLength 8, maxLength 2048, http(s) only.
	supportOptionsLiveChatURLPattern = regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
)

/*
resourceSupportOptions Setup the account support options CRUD operations.

This is the first resource in the provider that mutates ACCOUNT-WIDE settings
rather than an object inside one network, so two things differ from every
resource around it: there is no `network_id`, and there is nothing scoping the
blast radius of an apply to the objects Terraform created.

The lifecycle is the adopt-style singleton `firewall_policy` established. The
account's support options always exist — a tenant that has never configured them
reads back DEFAULT_SUPPORT_OPTIONS rather than a 404 — so there is nothing to
create and nothing to delete, and the API offers neither verb. Create is a GET
used as a reachability check followed by the same PUT that Update sends; Delete
removes the resource from state and calls nothing. See
resourceSupportOptionsDelete for why that is the honest behaviour here and not a
gap, and why it must not be "fixed" into a reset.

@return &schema.Resource
*/
func resourceSupportOptions() *schema.Resource {
	return &schema.Resource{
		Description: "Manages the end-user support options of a Check Point SASE **account** — the " +
			"phone, live-chat and user-guide entries the Harmony SASE agent shows to end users. " +
			"This is an account-wide singleton, not a per-network object: there is no " +
			"`network_id`, one instance covers the whole tenant, and its id is always " +
			"`support-options`. " +
			"Adopt-style, like `checkpointsase_firewall_policy`: the API has only `GET` and `PUT` " +
			"on `/v3/account/customize/support-options`, so Terraform adopts whatever the account " +
			"already has and overwrites it with your configuration. **The `PUT` is a whole-object " +
			"replace** — the server stores the request body as the complete support-options " +
			"document — so every field this resource manages is set on every apply, including the " +
			"ones you left out. " +
			"**`terraform destroy` only removes the resource from Terraform state. It does not " +
			"change the account's support options**, which keep whatever was last applied: the " +
			"API never reported what they were before Terraform adopted them, so there is nothing " +
			"to restore, and resetting them would be a silent change to a live support " +
			"configuration rather than a cleanup. " +
			supportOptionsCustomRule,
		CreateContext: resourceSupportOptionsCreate,
		ReadContext:   resourceSupportOptionsRead,
		UpdateContext: resourceSupportOptionsUpdate,
		DeleteContext: resourceSupportOptionsDelete,
		CustomizeDiff: resourceSupportOptionsCustomizeDiff,
		Schema: map[string]*schema.Schema{
			"phone_support_type": {
				Type:     schema.TypeString,
				Required: true,
				Description: "How phone support is offered to end users. `harmonySaseDefault` shows " +
					"Check Point's own support numbers, `custom` shows the numbers in " +
					"`support_phone_numbers`, and `hidden` shows none. " +
					supportOptionsCustomRule,
				ValidateFunc: validation.StringInSlice(supportOptionsTypeValues, false),
			},
			"support_phone_numbers": {
				Type:     schema.TypeList,
				Optional: true,
				MinItems: 1,
				MaxItems: 3,
				Description: "Between one and three custom support phone numbers, shown in the order " +
					"written. Set this only when `phone_support_type` is `custom`; the server " +
					"accepts it for the other two types but the agent never shows it, so this " +
					"provider refuses the combination during `plan` rather than letting you " +
					"configure something with no effect. Writing `support_phone_numbers = []` " +
					"is the same as omitting the block. " +
					supportOptionsCustomRule,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"description": {
							Type:     schema.TypeString,
							Required: true,
							Description: "Label shown beside the number, for example `US Support`. " +
								"1–18 characters, and none of " +
								"`! @ # $ % ^ & * _ = + [ ] { } \\ | ; : ' \" , < > . ? / ~ -` " +
								"— the server refuses them.",
							ValidateFunc: validation.All(
								validation.StringLenBetween(1, 18),
								validation.StringMatch(supportOptionsPhoneDescriptionPattern,
									"must be 1-18 characters and contain none of ! @ # $ % ^ & * _ = + [ ] { } \\ | ; : ' \" , < > . ? / ~ -"),
							),
						},
						"phone_number": {
							Type:     schema.TypeString,
							Required: true,
							Description: "The number itself, 7–18 characters. Digits, with an optional " +
								"leading `+` and any of space, `-`, `.`, `(`, `)` in between; it must " +
								"start and end with a digit (or `+` then a digit).",
							ValidateFunc: validation.All(
								validation.StringLenBetween(7, 18),
								validation.StringMatch(supportOptionsPhoneNumberPattern,
									"must be 7-18 characters of digits, optionally starting with + and using spaces, dashes, dots or parentheses between digits"),
							),
						},
					},
				},
			},
			"user_guides_enabled": {
				Type:     schema.TypeBool,
				Required: true,
				Description: "Whether end users see the user guides and documentation links. " +
					"Required, because the API requires it on every write and this resource " +
					"replaces the whole support-options object: there is no value that means " +
					"\"leave it as it is\".",
			},
			"live_chat_type": {
				Type:     schema.TypeString,
				Required: true,
				Description: "How live chat is offered to end users. `harmonySaseDefault` uses Check " +
					"Point's own chat, `custom` uses `live_chat_custom_url`, and `hidden` offers " +
					"none. " + supportOptionsCustomRule,
				ValidateFunc: validation.StringInSlice(supportOptionsTypeValues, false),
			},
			"live_chat_custom_url": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The chat URL end users are sent to. `http` or `https`, 8–2048 " +
					"characters. Set this only when `live_chat_type` is `custom`; as with " +
					"`support_phone_numbers` the server stores it for the other types and never " +
					"uses it, so this provider refuses the combination during `plan`. Note the " +
					"server also runs the URL through an injection blocklist that rejects `--`, " +
					"quotes, backticks and `/*`, so a host containing `--` (an IDN `xn--` label, " +
					"for example) is refused with a 400 that this provider cannot anticipate. " +
					supportOptionsCustomRule,
				ValidateFunc: validation.All(
					validation.StringLenBetween(8, 2048),
					validation.StringMatch(supportOptionsLiveChatURLPattern,
						"must be an http or https URL of 8-2048 characters"),
				),
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceSupportOptionsImportState,
		},
	}
}

/*
supportOptionsCustomFields is the four facts supportOptionsCustomRule turns on:
the two types, and whether each companion field was written at all.

Presence is tracked with attrPresence rather than by comparing against a zero
value because a cross-field rule that infers "set" from "not empty" cannot tell an
omitted attribute from one whose value is not yet known, and would then invent an
error against a configuration that is perfectly legal.
*/
type supportOptionsCustomFields struct {
	// phoneType and chatType are "" when the configuration's value is not known
	// at plan time, which means "cannot classify" rather than "empty".
	phoneType    string
	phoneNumbers attrPresence
	chatType     string
	chatURL      attrPresence
}

/*
validateSupportOptionsCustomFields enforces supportOptionsCustomRule.

Both halves of it are worth refusing, for opposite reasons, and both were read
against account-domain's putCompanyBranding.schema.ts on 2026-08-19:

  - The required direction IS a 400. The schema's `allOf` says
    `if liveChatType == "custom" then required: [liveChatCustomUrl]`, and the same
    for phoneSupportType/supportPhoneNumbers. Refusing it at plan time only
    replaces a server error with a faster and better-worded one.

  - The excluded direction is NOT a 400, and that is why it is here. The OpenAPI
    document says supportPhoneNumbers "must be null or omitted when
    phoneSupportType is not 'custom'", but nothing enforces it: AJV has no such
    constraint, CompanyBrandingService.updateBranding stores the request body
    verbatim ($set on agentCustomization.supportOptions), the collection's own
    jsonSchema accepts any 1-3 element array regardless of type, and GET merges
    the stored document over DEFAULT_SUPPORT_OPTIONS and hands it straight back.
    So the numbers are accepted, stored, echoed — and never shown to anyone. The
    round trip is clean, so this does not produce the permanent diff that the
    ICMP protocolOptions case does; it produces configuration that silently does
    nothing, which nothing but a plan-time refusal would ever tell the user about.

An unclassifiable type ("" — unknown at plan time) checks nothing rather than
guessing, which is what lets this run without NewValueKnown guards.
*/
func validateSupportOptionsCustomFields(f supportOptionsCustomFields) error {
	switch f.phoneType {
	case "":
		// Unknown at plan time, so unclassifiable. Nothing to check.
	case supportOptionsTypeCustom:
		if f.phoneNumbers == attrAbsent {
			return fmt.Errorf("phone_support_type = %q requires support_phone_numbers: the API "+
				"answers 400 (\"supportPhoneNumbers is required when phoneSupportType is "+
				"\\\"custom\\\"\") without it. %s", supportOptionsTypeCustom, supportOptionsCustomRule)
		}
	default:
		if f.phoneNumbers == attrPresent {
			return fmt.Errorf("support_phone_numbers applies only when phone_support_type is %q, "+
				"but phone_support_type is %q. The server stores the numbers and never shows "+
				"them, so this would be configuration with no effect rather than an error you "+
				"would ever see. %s", supportOptionsTypeCustom, f.phoneType, supportOptionsCustomRule)
		}
	}

	switch f.chatType {
	case "":
		// Unknown at plan time, so unclassifiable. Nothing to check.
	case supportOptionsTypeCustom:
		if f.chatURL == attrAbsent {
			return fmt.Errorf("live_chat_type = %q requires live_chat_custom_url: the API answers "+
				"400 (\"liveChatCustomUrl is required when liveChatType is \\\"custom\\\"\") "+
				"without it. %s", supportOptionsTypeCustom, supportOptionsCustomRule)
		}
	default:
		if f.chatURL == attrPresent {
			return fmt.Errorf("live_chat_custom_url applies only when live_chat_type is %q, but "+
				"live_chat_type is %q. The server stores the URL and never uses it, so this "+
				"would be configuration with no effect rather than an error you would ever "+
				"see. %s", supportOptionsTypeCustom, f.chatType, supportOptionsCustomRule)
		}
	}

	return nil
}

/*
supportOptionsCustomFieldsFromRawConfig reads the four facts out of the cty value
Terraform sent for the configuration, where an unset attribute is a null rather
than a zero and an interpolated one is unknown rather than absent. It is the only
source that can tell `live_chat_custom_url = some_other_resource.url` — set, value
not yet known — from an omitted live_chat_custom_url.

The second return value is false only when no raw config reached this diff at all,
which in this codebase means a unit test that assembled the diff itself.
*/
func supportOptionsCustomFieldsFromRawConfig(raw cty.Value) (supportOptionsCustomFields, bool) {
	if raw.IsNull() || !raw.IsKnown() || !raw.Type().IsObjectType() ||
		!raw.Type().HasAttribute("phone_support_type") {
		return supportOptionsCustomFields{}, false
	}
	return supportOptionsCustomFields{
		phoneType:    rawConfigAttrString(raw, "phone_support_type"),
		phoneNumbers: rawConfigAttrCollectionPresence(raw, "support_phone_numbers"),
		chatType:     rawConfigAttrString(raw, "live_chat_type"),
		chatURL:      rawConfigAttrPresence(raw, "live_chat_custom_url"),
	}, true
}

/*
rawConfigAttrCollectionPresence is rawConfigAttrPresence for a list, with one
difference: a list that is present and known to be empty counts as absent.

`support_phone_numbers = []` is already refused before this runs — MinItems is
checked during ValidateResourceConfig, which precedes PlanResourceChange — so
treating it as absent cannot mask anything. What it does do is keep the excluded
direction of supportOptionsCustomRule from firing on an empty list, which is a
different complaint from the one the user needs to read.

An unknown list is present: presence is about the key, not the value.
*/
func rawConfigAttrCollectionPresence(element cty.Value, name string) attrPresence {
	if !element.Type().HasAttribute(name) {
		return attrUnknownPresence
	}
	attr := element.GetAttr(name)
	if attr.IsNull() {
		return attrAbsent
	}
	if !attr.IsKnown() {
		return attrPresent
	}
	if attr.CanIterateElements() && attr.LengthInt() == 0 {
		return attrAbsent
	}
	return attrPresent
}

/*
supportOptionsGetter is the Get method *schema.ResourceDiff and
*schema.ResourceData have in common, so supportOptionsCustomFieldsFromGetter can
serve both the fallback for a diff with no raw config and the apply-time backstop
in Update.
*/
type supportOptionsGetter interface {
	Get(key string) interface{}
}

/*
supportOptionsCustomFieldsFromGetter reads the four facts from planned or applied
values, where an absent attribute is indistinguishable from its type's zero value.

That conflation is harmless for all four: neither "" nor an empty list is legal
content for any of them, so reading a zero as "absent" changes no verdict. It is
still second choice, because it cannot tell an unknown value from an absent one —
hence the raw config path above.

At apply time, however, this is the *only* source: an interpolation that was
unknown during plan has a value by then, so Update calls this as a backstop for
the combinations CustomizeDiff had to let through.
*/
func supportOptionsCustomFieldsFromGetter(g supportOptionsGetter) supportOptionsCustomFields {
	fields := supportOptionsCustomFields{}
	fields.phoneType, _ = g.Get("phone_support_type").(string)
	fields.chatType, _ = g.Get("live_chat_type").(string)
	if numbers, _ := g.Get("support_phone_numbers").([]interface{}); len(numbers) > 0 {
		fields.phoneNumbers = attrPresent
	}
	if url, _ := g.Get("live_chat_custom_url").(string); url != "" {
		fields.chatURL = attrPresent
	}
	return fields
}

/*
resourceSupportOptionsCustomizeDiff enforces supportOptionsCustomRule, which the
schema cannot express: RequiredWith/ConflictsWith are unconditional, and there is
no schema construct for "required only when this sibling holds one particular
string".

Destroy plans never reach CustomizeDiff in SDKv2, which is what we want here: a
destroy has no configuration to check.
*/
func resourceSupportOptionsCustomizeDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	fields, fromConfig := supportOptionsCustomFieldsFromRawConfig(d.GetRawConfig())
	if !fromConfig {
		fields = supportOptionsCustomFieldsFromGetter(d)
	}
	return validateSupportOptionsCustomFields(fields)
}

/*
expandSupportPhoneNumbers converts the `support_phone_numbers` blocks into the SDK
model, and returns nil — never an empty slice — when there is nothing to send.

The nil is the whole point, and it is not stylistic. SupportOptionsRequest.ToMap
writes the key when the slice is non-nil:

	if o.SupportPhoneNumbers != nil {
		toSerialize["supportPhoneNumbers"] = o.SupportPhoneNumbers
	}

so a non-nil empty slice reaches the wire as `"supportPhoneNumbers": []`, and that
is a 400: putCompanyBranding.schema.ts declares the field `type: ["array","null"]`
with `minItems: 1`, and the AccountCustomization collection's own jsonSchema
repeats the 1-3 bound, so an empty array is refused twice over. Presence on the
wire is decided by IsNil() here, not by the `omitempty` tag — which is exactly the
mistake that shipped three times in Phase 1 and is why
TestSchemaListAttributesMatchTheirEmptyArrayVerdict now demands a recorded verdict
for every list attribute.

The schema's MinItems is not a second line of defence for this, despite looking
like one. Measured 2026-08-19: terraform.NewResourceConfigShimmed drops an empty
list from the ResourceConfig entirely, so schemaMap.validate sees the key as absent
and MinItems is never reached — `support_phone_numbers = []` and an omitted block
are the same configuration all the way down. This function is the only thing
between them and a 400.
*/
func expandSupportPhoneNumbers(raw []interface{}) []perimeter81Sdk.SupportPhoneNumber {
	numbers := make([]perimeter81Sdk.SupportPhoneNumber, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		description, _ := m["description"].(string)
		phoneNumber, _ := m["phone_number"].(string)
		numbers = append(numbers, perimeter81Sdk.SupportPhoneNumber{
			Description: description,
			PhoneNumber: phoneNumber,
		})
	}
	if len(numbers) == 0 {
		return nil
	}
	return numbers
}

/*
flattenSupportPhoneNumbers converts the SDK model back into the list shape
`support_phone_numbers` holds in state.

A nil slice flattens to an empty list rather than to nil, which is what an unset
Optional list holds in state, so the read of an account with no custom numbers
produces no diff. The server always sends something for this key: getBranding and
updateBranding both return `{...DEFAULT_SUPPORT_OPTIONS, ...stored}`, and
DEFAULT_SUPPORT_OPTIONS has `supportPhoneNumbers: null`, so a stored document
that omits the key reads back as an explicit null — which the SDK decodes to a nil
slice.
*/
func flattenSupportPhoneNumbers(numbers []perimeter81Sdk.SupportPhoneNumber) []interface{} {
	flattened := make([]interface{}, 0, len(numbers))
	for _, number := range numbers {
		flattened = append(flattened, map[string]interface{}{
			"description":  number.Description,
			"phone_number": number.PhoneNumber,
		})
	}
	return flattened
}

/*
buildSupportOptionsRequest assembles the PUT body.

Factored out of resourceSupportOptionsUpdate so payload_marshal_test.go can pin
the resulting JSON. Three things about this body are invisible to any test that
does not marshal it:

  - the three scalars are always present. ToMap writes them unconditionally and
    the server requires all three, so there is no "leave this alone" — every apply
    sets every one of them, which is what makes the PUT a whole-object replace.
  - supportPhoneNumbers must be absent, not empty, when there are no numbers. See
    expandSupportPhoneNumbers.
  - liveChatCustomUrl must be absent, not "", when there is no URL. It is a
    *string in the SDK and ToMap tests the pointer, so an empty string set through
    SetLiveChatCustomUrl would marshal as `"liveChatCustomUrl": ""` and fail the
    schema's minLength 8 and its http(s) pattern.

@return perimeter81Sdk.SupportOptionsRequest
*/
func buildSupportOptionsRequest(d *schema.ResourceData) perimeter81Sdk.SupportOptionsRequest {
	raw, _ := d.Get("support_phone_numbers").([]interface{})

	payload := perimeter81Sdk.SupportOptionsRequest{
		PhoneSupportType:    d.Get("phone_support_type").(string),
		UserGuidesEnabled:   d.Get("user_guides_enabled").(bool),
		LiveChatType:        d.Get("live_chat_type").(string),
		SupportPhoneNumbers: expandSupportPhoneNumbers(raw),
	}

	if url := d.Get("live_chat_custom_url").(string); url != "" {
		payload.SetLiveChatCustomUrl(url)
	}

	return payload
}

/*
resourceSupportOptionsCreate "adopts" the account's existing support options: it
reads them as an existence check, sets the resource id, and then applies the
desired configuration through Update.

Be precise about what the existence check proves, because it is less than it looks.
There is no create endpoint — the support-options document is implicit in the
account — and GET never 404s: CompanyBrandingService.getBranding returns
DEFAULT_SUPPORT_OPTIONS for a tenant that has no AccountCustomization document at
all. So this GET is a reachability and authorization check (the route requires
`tenant.generalSettings.supportOptions:read`), not a test of whether anything is
there. It is worth making anyway: failing here reports "cannot read the account's
support options" before anything has been written, instead of failing mid-PUT.

Do NOT d.Set any attribute here. terraform-plugin-sdk's d.Get prefers a recent
d.Set over the diff/config, so a pre-Update Set would clobber the HCL values and
Update would push the account's existing values straight back.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceSupportOptionsCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	if _, _, err := client.SettingsAPI.GetSupportOptions(ctx).Execute(); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read account support options for adoption", err)
	}

	d.SetId(supportOptionsResourceID)
	return resourceSupportOptionsUpdate(ctx, d, m)
}

/*
resourceSupportOptionsRead reads the account's support options and sets every
attribute.

There is deliberately no "gone, so drift" branch on 404. Everywhere else in this
provider a 404 on Read means someone deleted the object outside Terraform, and
clearing the id is the right answer. Here nothing can delete the object: it is one
document per account, the API has no DELETE, and an account with no stored
settings still answers 200 with the defaults. A 404 from this endpoint therefore
means the route itself is wrong or the credentials address a different tenant, and
silently emptying state would turn that into a phantom "create" on the next apply
instead of an error somebody can act on.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceSupportOptionsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	options, _, err := client.SettingsAPI.GetSupportOptions(ctx).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to read account support options", err)
	}

	if err := d.Set("phone_support_type", options.PhoneSupportType); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set account support options phone_support_type", err)
	}
	if err := d.Set("user_guides_enabled", options.UserGuidesEnabled); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set account support options user_guides_enabled", err)
	}
	if err := d.Set("live_chat_type", options.LiveChatType); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set account support options live_chat_type", err)
	}
	// Both optional fields come back as an explicit null whenever they are unset,
	// because the service merges the stored document over DEFAULT_SUPPORT_OPTIONS,
	// whose supportPhoneNumbers and liveChatCustomUrl are both null. The SDK
	// decodes those to a nil slice and a nil *string, and an empty list and ""
	// are what an unset Optional list and an unset Optional string hold in state
	// — so what is written back here matches what was never configured, and the
	// next plan is clean.
	if err := d.Set("support_phone_numbers", flattenSupportPhoneNumbers(options.SupportPhoneNumbers)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set account support options support_phone_numbers", err)
	}
	if err := d.Set("live_chat_custom_url", options.GetLiveChatCustomUrl()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set account support options live_chat_custom_url", err)
	}

	return diags
}

/*
resourceSupportOptionsUpdate sends one PUT /v3/account/customize/support-options
and then reads the result back.

The PUT is SYNCHRONOUS, and that is checked rather than assumed.
UpdateSupportOptionsExecute (api_settings.go) issues the PUT and decodes the
response straight into a *SupportOptionsResponse; there is no
AsyncOperationResponse, no statusUrl and nothing to poll, and the account service
behind it writes to Mongo with a single findOneAndUpdate({returnDocument:'after'})
before responding. So the settings really have changed by the time Execute
returns. Phase 1 shipped three bugs from treating an AsyncOperationResponse as a
completed write; polling something synchronous is the mirror-image mistake and
would add a status call against an endpoint that has no status.

The response body is the updated object and is deliberately discarded in favour of
delegating to Read. The two are the same shape, so using the response would save a
GET — but then no apply would ever exercise the code path the *next* plan compares
against, which is precisely how a read-shape mismatch survives an acceptance run.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceSupportOptionsUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// Backstop for values that were unknown at plan time and so invisible to
	// CustomizeDiff.
	if err := validateSupportOptionsCustomFields(supportOptionsCustomFieldsFromGetter(d)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Invalid account support options", err)
	}

	payload := buildSupportOptionsRequest(d)

	if _, _, err := client.SettingsAPI.UpdateSupportOptions(ctx).SupportOptionsRequest(payload).Execute(); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to update account support options", err)
	}

	return resourceSupportOptionsRead(ctx, d, m)
}

/*
resourceSupportOptionsDelete removes the resource from Terraform state and makes
no API call. That is a decision, not an omission, and it is the opposite of the
one resourceFirewallPolicyDelete made — so here is why, at length, because the
cost of a later reader "finishing" this function is a silent rewrite of a live
account's support configuration.

`firewall_policy` is also an adopted, undeletable singleton, and its Delete does
write: it PUTs `policyRules: []`. The reason is specific and does not generalise.
Its rules were Terraform's own creation, and each rule holds references to
`checkpointsase_object_addresses` and `checkpointsase_object_services` objects
that cannot be deleted while a rule names them — so leaving the rules behind made
every dependent object in the same `terraform destroy` fail with
`409 CONFLICT: This object cannot be edited or deleted because it is currently in
use.` That write releases something. It is repair, not tidiness.

Account support options release nothing. No other object references them, no
`terraform destroy` fails because they still hold values, and there is no
downstream 409 waiting. So the only thing a write here could be *for* is restoring
what was there before Terraform adopted them — and this resource cannot do that:

  - It never recorded the pre-adoption values. Create reads them once, purely as a
    reachability check, and deliberately does not d.Set them (doing so would
    clobber the user's HCL before Update runs). Nothing is kept.
  - Resetting to DEFAULT_SUPPORT_OPTIONS instead — harmonySaseDefault /
    harmonySaseDefault / userGuidesEnabled true, both optional fields null — would
    look like "restore" while actually being a guess that the account had never
    been configured. For any account whose support options were set in the console
    before Terraform adopted them, that guess is wrong, and it is wrong in the
    destructive direction: the account's real phone numbers and chat URL would be
    erased by a destroy, which is the last place a user is watching closely. It
    would also do this ACCOUNT-WIDE, not inside one network.
  - Writing back what is in Terraform state is a no-op with extra steps: state
    holds what Terraform last applied, which is already what the account holds.

So there is no write that is both safe and useful, and a no-op Delete is the
honest behaviour rather than a gap. The consequence to be honest about, and it is
documented on the resource: after `terraform destroy` the account keeps whatever
support options were last applied. Destroy releases Terraform's claim on them; it
does not undo them. That is inherent to adopting a settings object the API cannot
delete.

  - @param ctx context.Context - unused; there is no request to make.
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceSupportOptionsDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	d.SetId("")
	return diags
}

/*
resourceSupportOptionsImportState imports the account's support options.

The import id is ignored on purpose. There is one support-options object per
account and the API addresses it by path, so there is nothing to look up and no id
a user could supply that would select something different — including a mistyped
one. Import therefore always adopts the same object and always stores the same
constant id, which keeps an imported resource byte-identical in state to a created
one. `terraform import checkpointsase_support_options.this support-options` is the
form to document, but any id behaves the same way.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceSupportOptionsImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	d.SetId(supportOptionsResourceID)

	diagnostics := resourceSupportOptionsRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import account support options: %s, \n %s",
					diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}
