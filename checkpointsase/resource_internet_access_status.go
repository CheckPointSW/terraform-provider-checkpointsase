package checkpointsase

import (
	"context"
	"fmt"
	"net/http"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
internetAccessStatusResourceID is this resource's Terraform id, and it is a
constant for the same reason accessPolicyResourceID and supportOptionsResourceID
are.

/v3/ia/status addresses the tenant's ONE Internet Access switch by path. There is
no id to fetch and nothing to disambiguate, but something has to go in d.SetId()
because an empty id means "this resource does not exist" to Terraform. A
timestamp would change on every read and break every depends_on, output and
interpolation pointing at it (L16c); a constant is the only value that is the
same after a refresh as before it.
*/
const internetAccessStatusResourceID = "internet-access-status"

/*
internetAccessStatusValues is the `iaStatus` enum.

Both values are transcribed from the OpenAPI document, which declares
`enum: [active, inactive]` on the request body and on both 200 responses of
/v3/ia/status. Measured (phase4-verification, W2): POST takes exactly
{"iaStatus": "active"|"inactive"} and nothing else -- one field is the entire
write surface of this endpoint.

Matched case-sensitively, like accessPolicyStatusValues: "Active" would pass a
case-insensitive plan and then be answered by the server.
*/
var internetAccessStatusValues = []string{"active", "inactive"}

/*
internetAccessStatusScope is what this setting actually switches, quoted from the
API's own description of both operations on /v3/ia/status: "This status indicates
whether Internet Access, Threat Prevention, and DLP are enabled or disabled."

It is a constant so that the resource description, the attribute description and
the destroy warning cannot drift apart, and because the count is the point.
Reading the field name alone -- ia_status, Internet Access -- suggests one
feature is being toggled. It is three, two of which are not named in the field at
all, and one of those two is the tenant's data-loss prevention. Anything in this
file that says what `inactive` does has to say all three.
*/
const internetAccessStatusScope = "Internet Access, Threat Prevention, and DLP"

/*
internetAccessStatusDestroyNote is what `terraform destroy` on this resource does
and, more importantly, what it does NOT do.

It is a constant for the same reason accessPolicyDestroyWarning is: the resource
description, the Delete diagnostic and the example all have to say the same
thing, and an operator who searches for the sentence they were shown finds it
here. See resourceInternetAccessStatusDelete for the reasoning.
*/
const internetAccessStatusDestroyNote = "`terraform destroy` on this resource makes NO API call. " +
	"It removes Terraform's claim on the setting and leaves the tenant exactly as it is — " +
	"whatever `ia_status` was last applied stays in force. Destroying this resource " +
	"deliberately does not set the tenant to `inactive`, because that would switch off " +
	internetAccessStatusScope + " for the whole tenant as a side effect of removing a " +
	"Terraform resource."

/*
resourceInternetAccessStatus manages the tenant's Internet Access security
enforcement switch.

This is Pattern B: a one-field tenant SETTING, not an object. /v3/ia/status has
GET and POST and nothing else -- no create, no delete, no id, no list. The
setting exists on every tenant before Terraform arrives and cannot be removed, so
"create" means adopt-and-set and "destroy" means stop tracking. Both are spelled
out on the functions below.

@return &schema.Resource
*/
func resourceInternetAccessStatus() *schema.Resource {
	return &schema.Resource{
		Description: "Manages the Internet Access security enforcement status of a Check Point " +
			"SASE tenant — the tenant-wide switch behind `GET`/`POST /v3/ia/status`. " +
			"**This one field controls three things.** The API describes it as indicating " +
			"\"whether " + internetAccessStatusScope + " are enabled or disabled\", so setting " +
			"`ia_status = \"inactive\"` does not merely stop web filtering: it disables " +
			"Threat Prevention and DLP for the whole tenant at the same time. Treat a change " +
			"here as a change to the tenant's security posture, not as a feature toggle. " +
			"This is a tenant setting rather than an object. It exists before Terraform " +
			"manages it and cannot be deleted, so `terraform apply` adopts the existing value " +
			"and overwrites it with yours, and only one Terraform resource in one " +
			"configuration should own it — a second one would fight the first on every apply, " +
			"and the console can change it underneath both. " +
			internetAccessStatusDestroyNote + " " +
			"Rules in `checkpointsase_access_policy` and " +
			"`checkpointsase_https_inspection_policy` can be created and changed while this " +
			"is `inactive`; they are simply not enforced. Enabling Internet Access is " +
			"therefore not a prerequisite for managing either policy. " +
			"Import with any id; the resource is a tenant-wide singleton whose id is always " +
			"`" + internetAccessStatusResourceID + "`.",
		CreateContext: resourceInternetAccessStatusWrite,
		ReadContext:   resourceInternetAccessStatusRead,
		UpdateContext: resourceInternetAccessStatusWrite,
		DeleteContext: resourceInternetAccessStatusDelete,
		Schema: map[string]*schema.Schema{
			"ia_status": {
				Type:     schema.TypeString,
				Required: true,
				Description: "Whether " + internetAccessStatusScope + " are enforced for this " +
					"tenant: `active` or `inactive`. " +
					"**`inactive` disables all three**, not only web access filtering. " +
					"Required, and deliberately without a default: this resource adopts a " +
					"setting that already has a value, and a default would let a configuration " +
					"silently change the tenant's security posture because a field was left " +
					"out. Read the current value first if you do not know it.",
				ValidateFunc: validation.StringInSlice(internetAccessStatusValues, false),
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceInternetAccessStatusImportState,
		},
	}
}

/*
readInternetAccessStatus GETs /v3/ia/status and returns the `iaStatus` value.

IT ACCEPTS BOTH OF THE TWO SHAPES THIS RESPONSE MIGHT HAVE, because the two
authorities available disagree and neither could be settled without a live call:

  - The OpenAPI document declares the 200 body FLAT -- `{"iaStatus": "active"}`
    with `additionalProperties: true` -- which is what the SDK model
    GetIAStatus200Response was generated from, so a flat body lands in the
    declared IaStatus field.
  - phase4-verification's surface table records the shape as
    `{status, data:{iaStatus}}`, i.e. the same envelope its two sibling endpoints
    on /v3/ia/ demonstrably use (AccessPolicyRulesGetResponse and
    HttpsInspectionPolicyGetResponse both declare `status` + `data`).

If the envelope is what the server sends, the generated model puts `status` and
`data` in AdditionalProperties and GetIaStatus() returns "" -- so a reader that
trusted the document alone would write an EMPTY ia_status into state on a
perfectly healthy 200, and every plan would then propose changing the tenant's
security enforcement back. That is a worse failure than an error, so both are
handled and neither is guessed at.

AN ABSENT VALUE IS AN ERROR, NOT A STATE. The field is an enum of two values and
"" is not one of them, so if neither shape yields one, this returns an error
rather than a zero value. Same discipline as the read-error-is-never-an-empty-list
rule the two policy resources follow, and for the same reason: on a settings
endpoint, silently substituting a falsy default is how a tenant gets reconfigured
by a bug rather than by a plan.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param client *perimeter81Sdk.APIClient - the API client

@return string, error - the `iaStatus` value, or an error
*/
func readInternetAccessStatus(ctx context.Context, client *perimeter81Sdk.APIClient) (string, error) {
	status, _, err := readInternetAccessStatusResponse(ctx, client)
	return status, err
}

// readInternetAccessStatusResponse is readInternetAccessStatus with the raw
// *http.Response handed back as well, which is what classifyAPIError needs to
// tell a transient 5xx from a permanent refusal. Only the retrying re-read after
// a write cares; every other caller takes the two-value wrapper above.
func readInternetAccessStatusResponse(ctx context.Context, client *perimeter81Sdk.APIClient) (
	string, *http.Response, error) {
	body, resp, err := client.InternetAccessPoliciesAPI.GetIAStatus(ctx).Execute()
	if err != nil {
		return "", resp, err
	}
	if body == nil {
		return "", resp, fmt.Errorf("GET /v3/ia/status answered with no body at all, which is " +
			"neither a value nor a documented response")
	}

	// THE ENVELOPED SHAPE IS THE REAL ONE, measured 2026-08-25:
	//   GET /v3/ia/status -> {"status":200,"data":{"iaStatus":"inactive"}}
	// The OpenAPI document declares the flat shape instead, which is why the
	// generated model has a top-level IaStatus that is always empty. Recorded as
	// API-FINDINGS 1.22.
	//
	// The flat branch is kept, and it is NOT dead defence: the document is what
	// the SDK is generated from, so the day the spec is corrected the model
	// starts populating IaStatus and this reader keeps working across that
	// change without a coordinated release. Getting this wrong is not a decode
	// error -- it yields ia_status = "" on a healthy 200, and a Required
	// attribute reading "" plans to flip the tenant's security enforcement.
	if status := body.GetIaStatus(); status != "" {
		return status, resp, nil
	}
	if status, ok := internetAccessStatusFromEnvelope(body.AdditionalProperties); ok {
		return status, resp, nil
	}

	return "", resp, fmt.Errorf("GET /v3/ia/status returned a body with no iaStatus in it, at "+
		"the top level or inside a `data` envelope: %v. The tenant's %s enforcement state is "+
		"therefore unknown, and writing an empty value into state would make the next plan "+
		"propose changing it", body.AdditionalProperties, internetAccessStatusScope)
}

/*
rereadInternetAccessStatusAfterWrite re-reads the setting after a POST that has
already succeeded, and is the singleton's half of a discipline the two policy
resources already have.

WHY IT IS NOT resourceInternetAccessStatusRead. The two are the same GET and a
different situation, and the situation is the whole point. A failed FIRST read
has changed nothing, so reporting "unable to read" is complete and accurate. A
failed read on THIS side of the write is not: the POST landed, the tenant's
Internet Access, Threat Prevention and DLP enforcement is already in the new
state, and an operator told only "unable to read" concludes the apply did not
happen. That is the largest blast radius in the phase reported as the smallest.

The retry budget, interval and classifier are policy_list.go's, deliberately --
three objects that differ here differ for no reason, and §1.19 measured this
endpoint family answering 500s.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc.
  - @param client *perimeter81Sdk.APIClient - the SDK client

@return string, error - the server's own value, or an error that leads with the fact that the write landed
*/
func rereadInternetAccessStatusAfterWrite(ctx context.Context,
	client *perimeter81Sdk.APIClient) (string, error) {
	backoff := policyReReadInterval
	remaining := policyReReadTransientBudget

	for {
		status, resp, err := readInternetAccessStatusResponse(ctx, client)
		if err == nil {
			return status, nil
		}
		if classifyAPIError(resp, err) == errKindTransient && remaining > 0 {
			remaining--
			if waitErr := sleepCtx(ctx, backoff); waitErr != nil {
				return "", fmt.Errorf("%s %s Cause: %w",
					internetAccessStatusWrittenNotReadBack, internetAccessStatusResync, waitErr)
			}
			backoff *= 2
			continue
		}
		return "", fmt.Errorf("%s %s Cause: %w",
			internetAccessStatusWrittenNotReadBack, internetAccessStatusResync, err)
	}
}

/*
internetAccessStatusWrittenNotReadBack opens every error on the far side of a
successful write, for the same reason policyWrittenNotReadBack does: the operator
has to be told the tenant CHANGED before being told what went wrong.

It names the three features rather than saying "the status", because "Internet
Access status" reads like a label and "Threat Prevention and DLP are now off"
does not.
*/
const internetAccessStatusWrittenNotReadBack = "The Internet Access status WAS written and " +
	"the tenant is now in that state -- Internet Access, Threat Prevention and DLP " +
	"enforcement have already changed -- but Terraform could not read it back, so state does " +
	"not record it."

/*
internetAccessStatusResync is what to do about it, and it is NOT
reapplyToResync.

The advice differs because the resources differ where it matters. This
resource's Delete makes no API call at all, so a tainted replace here destroys
nothing and re-POSTs the same value; there is no DELETE to walk into. What is
left is that a plain re-apply writes the tenant's security enforcement a second
time, which is unnecessary when a read-only refresh reconciles state.
*/
const internetAccessStatusResync = "The tenant's setting is already correct; only Terraform's " +
	"record of it is missing, so run `terraform refresh` (or `terraform plan`) first rather " +
	"than re-applying: this resource writes the tenant's security enforcement on every apply " +
	"and does not need to write it again. Do NOT remove the resource from the configuration " +
	"instead -- the setting is live on the tenant and nothing would be tracking it."

/*
internetAccessStatusFromEnvelope digs `iaStatus` out of a `{"data": {...}}`
wrapper, which is where it lands in AdditionalProperties if the server envelopes
this response the way it envelopes the two policy endpoints.

Returns ok=false for every shape that is not exactly that, so the caller can tell
"the envelope was there and held a value" from "there was no value anywhere" --
which are the two branches it has to report differently.

  - @param extra map[string]interface{} - GetIAStatus200Response.AdditionalProperties

@return string, bool - the value and whether one was found
*/
func internetAccessStatusFromEnvelope(extra map[string]interface{}) (string, bool) {
	data, ok := extra["data"].(map[string]interface{})
	if !ok {
		return "", false
	}
	status, ok := data["iaStatus"].(string)
	if !ok || status == "" {
		return "", false
	}
	return status, true
}

/*
resourceInternetAccessStatusWrite is BOTH CreateContext and UpdateContext.

There is one endpoint and one field. POST /v3/ia/status sets `iaStatus` to
whatever it is given, whether or not that differs from what is stored, so
"start managing this setting" and "change this setting" are byte-for-byte the
same request. Two functions would be two copies of one call, and the only thing
that could ever differ between them is a bug.

Create does NOT read first. The support-options singleton does, as a
reachability check before adopting, but there the create is a PUT of a
multi-field document assembled from several attributes; here the write is one
enum value and a failed POST reports the same unreachability just as clearly,
one request earlier.

The response body is discarded in favour of delegating to Read, for the reason
recorded on resourceSupportOptionsUpdate: the POST response and the GET response
are the same shape, so using the former would save a call but would leave the
GET decode path -- the one every subsequent plan compares against -- unexercised
by any apply.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceInternetAccessStatusWrite(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	payload := perimeter81Sdk.NewSetIAStatusRequest()
	payload.SetIaStatus(d.Get("ia_status").(string))

	if _, _, err := client.InternetAccessPoliciesAPI.SetIAStatus(ctx).
		SetIAStatusRequest(*payload).Execute(); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to set the tenant's Internet Access security enforcement status", err)
	}

	// The id is set only after the write has landed, so a failed apply does not
	// leave a resource in state claiming a setting it never changed.
	d.SetId(internetAccessStatusResourceID)

	// NOT resourceInternetAccessStatusRead. Delegating to it was the original
	// shape and it reported a failed read-back as though nothing had happened;
	// see rereadInternetAccessStatusAfterWrite for why that is the wrong report
	// on the far side of a write that switches three security features for the
	// whole tenant.
	status, err := rereadInternetAccessStatusAfterWrite(ctx, client)
	if err != nil {
		d.Partial(true)
		// appendErrorDiagsWithGuidance, not appendErrorDiags: see its doc comment
		// for what the latter discards on this path.
		return appendErrorDiagsWithGuidance(diags,
			"The Internet Access status WAS written and could not be read back",
			internetAccessStatusWrittenNotReadBack+" "+internetAccessStatusResync, err)
	}

	if err := d.Set("ia_status", status); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to record the tenant's Internet Access security enforcement status", err)
	}

	return diags
}

/*
resourceInternetAccessStatusRead reads the tenant's Internet Access status back
into state.

There is deliberately no "gone, so drift" branch on 404, for the reason recorded
on resourceSupportOptionsRead: nothing can delete this setting. It is one value
per tenant, the API has no DELETE for it, and a tenant that has never touched it
still answers with one of the two enum values. A 404 here therefore means the
route is wrong or BASE_URL is unset and the call went to the US production host,
and clearing the id would turn that into a phantom "create" -- which for THIS
resource means a POST that changes the tenant's security enforcement -- instead
of an error somebody can act on.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceInternetAccessStatusRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	status, err := readInternetAccessStatus(ctx, client)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to read the tenant's Internet Access security enforcement status", err)
	}

	if err := d.Set("ia_status", status); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags,
			"Unable to set the tenant's Internet Access security enforcement status", err)
	}

	return diags
}

/*
resourceInternetAccessStatusDelete REMOVES THE RESOURCE FROM STATE AND MAKES NO
API CALL. That is a decision, and it is the opposite of the one
resourceAccessPolicyDelete took two files away, so here is why at length --
because the cost of a later reader "finishing" this function is switching off
Internet Access, Threat Prevention and DLP for a whole tenant.

checkpointsase_access_policy destroys by calling the endpoint's DELETE, and that
is right there: the resource owns the whole rule list, the list is Terraform's
own creation, and destroying the resource genuinely means the rules are gone.

This resource owns no object. It owns the VALUE of a switch that existed before
Terraform and survives it, so there is nothing for a delete to remove and only
three things a write could be for, none of which hold:

  - Setting `inactive`. This is the reading the field name invites and it is the
    dangerous one. It would disable Internet Access, Threat Prevention and DLP
    for the entire tenant as a side effect of `terraform destroy` on a resource
    whose only job was to record a value -- security enforcement switched off
    with no plan line saying so, at the moment an operator is least likely to be
    watching for a posture change. The API has no DELETE for /v3/ia/status
    precisely because there is nothing to delete.
  - Restoring the pre-adoption value. This resource never recorded one. Create
    does not read before it writes, and even if it did, storing "what it was
    before Terraform" is not something Terraform state is for.
  - Writing back what is in state. That is a no-op with an extra request: state
    holds what was last applied, which is what the tenant already has.

So the honest behaviour is to make no request, and to say so out loud rather
than leaving an operator to infer it from a destroy that printed nothing. The
warning below is the "explains itself" half; TestInternetAccessStatusDeleteMakesNoRequest
is the half that stays true when somebody edits this function.

  - @param _ context.Context - unused; there is no request to make.
  - @param d *schema.ResourceData - the terraform resource data
  - @param _ interface{} - unused; the client is never called.

@return diag.Diagnostics
*/
func resourceInternetAccessStatusDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	diags = appendWarningDiags(diags,
		"The tenant's Internet Access security enforcement status was left unchanged",
		fmt.Sprintf("Terraform has stopped managing it, but made no API call: the tenant's "+
			"ia_status is still %q and %s remain in that state. This resource manages a "+
			"tenant setting that cannot be deleted, and setting it to \"inactive\" on destroy "+
			"would switch off all three as a side effect of removing a Terraform resource. "+
			"If you want them off, apply ia_status = \"inactive\" before destroying.",
			d.Get("ia_status").(string), internetAccessStatusScope))

	d.SetId("")
	return diags
}

/*
resourceInternetAccessStatusImportState adopts the tenant's current setting.

The import id is ignored, for the reason recorded on
resourceSupportOptionsImportState and resourceAccessPolicyImportState: there is
one value per tenant addressed by path, so no id a user could type selects
something different -- including a mistyped one. Import stores the same constant
id a created resource holds, so an imported resource is byte-identical in state
to a created one.

Import makes exactly one request, the GET. It never writes, so importing cannot
change the tenant's enforcement state -- but the FIRST apply after an import
will, if the configuration's ia_status differs from what was imported. Run
`terraform plan` and read it.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceInternetAccessStatusImportState(ctx context.Context, d *schema.ResourceData,
	m interface{}) ([]*schema.ResourceData, error) {
	d.SetId(internetAccessStatusResourceID)

	diagnostics := resourceInternetAccessStatusRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import the tenant's Internet Access security "+
					"enforcement status: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}
