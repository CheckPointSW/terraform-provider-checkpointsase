package checkpointsase

import (
	"context"
	"fmt"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
applicationAccessGrantRule is the sentence both `users` and `groups` carry in their descriptions,
and the reason validateApplicationAccessGrant exists. It is stated once so the schema, the plan-time
error and the apply-time error cannot drift apart.
*/
const applicationAccessGrantRule = "At least one of `users` or `groups` must be non-empty: " +
	"the API refuses an application that grants access to nobody."

/*
validateApplicationAccessGrant enforces the one rule the schema cannot express: `users` and
`groups` are each individually optional, but they cannot both be empty.

This is NOT the "omit the key rather than sending an empty array" pattern that
resource_firewall_policy.go deals with, and treating it as one is why the first live application
create failed twice over. On the server (applicationCreateBase.dto.ts) the two fields are:

	users?:  @ValidateIf((_, value) => value !== undefined) @NotEquals(null) @IsArray()
	         @ArrayUnique() @IsString({each: true}) @UsersMinSize(1)   = []
	groups?: @IsOptional() @IsArray() @ArrayUnique() @IsString({each: true})  = []

Three consequences, each of which rules out an alternative fix:

  - Omitting the key does not help. Both properties carry a `= []` class initialiser, so
    plainToInstance fills them in before validation runs; a body with neither key validates
    exactly as one with `"users": [], "groups": []` and fails identically with
    `users must contain at least 1 elements`.
  - Sending null does not help either, and is worse. `users` is guarded by @NotEquals(null), and
    its @ValidateIf only skips on `undefined`, so an explicit null is a validation error rather
    than an absent value.
  - UsersMinSize is a cross-field rule, not a min-size on `users`: it enforces
    len(users) >= 1 only while `groups` is absent or empty, and passes unconditionally once
    `groups` has a member. So `"users": []` alongside a non-empty `groups` is accepted — which is
    why the provider keeps sending both keys as arrays and only refuses the both-empty case.

Because the API cannot express "an application nobody may reach", the only place to catch this is
before the request: at plan time in resourceApplicationCustomizeDiff, and again in Create as a
backstop for lists whose values were unknown while planning. Create is the only path — this
resource has no Update.
*/
func validateApplicationAccessGrant(users, groups []interface{}) error {
	if len(users) > 0 || len(groups) > 0 {
		return nil
	}
	return fmt.Errorf("%s Set `users`, or `groups`, or both — an empty list counts as unset, "+
		"and the server reports the both-empty case as \"users must contain at least 1 elements\" "+
		"regardless of which of the two you left out", applicationAccessGrantRule)
}

/*
resourceApplicationCustomizeDiff refuses at plan time the one configuration the API refuses at
apply time: an application granted to neither a user nor a group.

The NewValueKnown guards are the load-bearing part. A configuration like
`users = [checkpointsase_something.x.id]` has an unknown list at plan time, which d.Get reports as
empty — checking it anyway would reject a configuration that is going to be perfectly valid. When
either list is still unknown the check is skipped here and left to the Create backstop, which runs
once both values are resolved.
*/
func resourceApplicationCustomizeDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	if !d.NewValueKnown("users") || !d.NewValueKnown("groups") {
		return nil
	}
	users, _ := d.Get("users").([]interface{})
	groups, _ := d.Get("groups").([]interface{})
	return validateApplicationAccessGrant(users, groups)
}

/*
resourceApplication Setup the Application Resource CRUD operations.
Note: there is no update or delete endpoint — all fields are ForceNew.

@return &schema.Resource
*/
func resourceApplication() *schema.Resource {
	return &schema.Resource{
		Description: "Manages an Application in Check Point SASE. " +
			"**All attributes are immutable**: any change to a field on this resource " +
			"forces full replacement (destroy + re-create), not in-place update. " +
			"**`terraform destroy` only removes the resource from state, and warns " +
			"that it did so.** The Harmony SASE Public API exposes no delete endpoint " +
			"for applications, so the application continues to exist on the server. " +
			"Delete it manually via the Infinity Portal if needed.",
		CreateContext: resourceApplicationCreate,
		ReadContext:   resourceApplicationRead,
		DeleteContext: resourceApplicationDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The application name.",
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "The application type. The v2.3 API supports creating " +
					"applications of these types only: `http`, `https`, `rdp`. " +
					"(Existing `ssh` and `vnc` applications can be read but not " +
					"created through the Public API.)",
				ValidateFunc: validation.StringInSlice([]string{"http", "https", "rdp"}, false),
			},
			"network": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The network ID to associate with this application.",
			},
			"host": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The application host address.",
			},
			"port": {
				Type:         schema.TypeInt,
				Required:     true,
				ForceNew:     true,
				Description:  "The application port number (1–65535).",
				ValidateFunc: validation.IsPortNumber,
			},
			"users": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Description: "List of user IDs allowed to access this application. " +
					applicationAccessGrantRule,
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"groups": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Description: "List of group IDs allowed to access this application. " +
					applicationAccessGrantRule,
				Elem: &schema.Schema{Type: schema.TypeString},
			},
		},
		CustomizeDiff: resourceApplicationCustomizeDiff,
		Importer: &schema.ResourceImporter{
			StateContext: resourceApplicationImportState,
		},
		// No Update timeout: this resource has no UpdateContext (every
		// attribute is ForceNew — see the type-level doc comment above), so
		// Terraform never calls an update operation to bound.
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(asyncResourceTimeout),
			Delete: schema.DefaultTimeout(asyncResourceTimeout),
		},
	}
}

/*
resourceApplicationImportState Import an application by its ID.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceApplicationImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	diagnostics := resourceApplicationRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import application: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}

/*
buildApplicationHost builds a CommonCreateApplicationHost (fixed variant) from a host string value.
*/
func buildApplicationHost(host string) perimeter81Sdk.CommonCreateApplicationHost {
	hostValue := perimeter81Sdk.StringAsFixedHostValue(&host)
	fixedHost := perimeter81Sdk.FixedHost{
		Source: "fixed",
		Value:  hostValue,
	}
	return perimeter81Sdk.FixedHostAsCommonCreateApplicationHost(&fixedHost)
}

/*
buildApplicationPort builds a CommonCreateApplicationPort (fixed variant) from a port int32 value.
*/
func buildApplicationPort(port int32) perimeter81Sdk.CommonCreateApplicationPort {
	fixedPort := perimeter81Sdk.FixedPort{
		Source: "fixed",
		Value:  port,
	}
	return perimeter81Sdk.FixedPortAsCommonCreateApplicationPort(&fixedPort)
}

/*
buildCreateApplicationRequest assembles the CreateApplicationRequest oneOf for one application type.

Factored out of resourceApplicationCreate so payload_marshal_test.go can marshal the exact body the
provider sends. That matters specifically for `users` and `groups`: all three variants declare them
without omitempty and their generated ToMap writes both keys unconditionally, so the difference
between `[]`, `null` and an absent key is decided here and is invisible to any schema-shape test.
A golden body is the only offline check that the provider still sends two arrays.

The three cases differ only in the variant type, its attributes object, and whether the model has
Headers or Auth — `users` and `groups` are assigned identically in every branch, which is why they
are parameters rather than being read from d in three places.

@return perimeter81Sdk.CreateApplicationRequest - the request body
@return error - set only for an application type the v3 API cannot create
*/
func buildCreateApplicationRequest(appType, appName, networkId, host string, port int32, users, groups []string) (perimeter81Sdk.CreateApplicationRequest, error) {
	hostPayload := buildApplicationHost(host)
	portPayload := buildApplicationPort(port)

	switch appType {
	case "http":
		return perimeter81Sdk.CreateApplicationRequest{
			HttpCreateApplication: &perimeter81Sdk.HttpCreateApplication{
				Name:       appName,
				Type:       appType,
				Network:    networkId,
				Host:       hostPayload,
				Port:       portPayload,
				Users:      users,
				Groups:     groups,
				Headers:    map[string]interface{}{},
				Attributes: perimeter81Sdk.HttpAttributes{},
			},
		}, nil
	case "https":
		return perimeter81Sdk.CreateApplicationRequest{
			HttpsCreateApplication: &perimeter81Sdk.HttpsCreateApplication{
				Name:       appName,
				Type:       appType,
				Network:    networkId,
				Host:       hostPayload,
				Port:       portPayload,
				Users:      users,
				Groups:     groups,
				Headers:    map[string]interface{}{},
				Attributes: perimeter81Sdk.HttpsAttributes{},
			},
		}, nil
	case "rdp":
		// The provider always creates RDP applications with auth disabled.
		// AuthEnabled is *bool in v3 (the server omits it on read responses
		// even though the spec marks it required), so take the address of a
		// named local rather than a literal.
		authDisabled := false
		return perimeter81Sdk.CreateApplicationRequest{
			RdpCreateApplication: &perimeter81Sdk.RdpCreateApplication{
				Name:       appName,
				Type:       appType,
				Network:    networkId,
				Host:       hostPayload,
				Port:       portPayload,
				Users:      users,
				Groups:     groups,
				Attributes: perimeter81Sdk.RdpAttributes{},
				Auth:       perimeter81Sdk.ApplicationAuth{AuthEnabled: &authDisabled},
			},
		}, nil
	default:
		return perimeter81Sdk.CreateApplicationRequest{},
			fmt.Errorf("type must be 'http', 'https', or 'rdp', got: %s", appType)
	}
}

/*
resourceApplicationCreate Create an Application.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceApplicationCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	appName := d.Get("name").(string)
	appType := d.Get("type").(string)
	networkId := d.Get("network").(string)
	host := d.Get("host").(string)
	port := int32(d.Get("port").(int))
	// Backstop for lists that were unknown at plan time and so invisible to CustomizeDiff.
	usersRaw := d.Get("users").([]interface{})
	groupsRaw := d.Get("groups").([]interface{})
	if err := validateApplicationAccessGrant(usersRaw, groupsRaw); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Invalid Application access grant", err)
	}

	// Both keys are sent as arrays, always, and never as null — see
	// validateApplicationAccessGrant. flattenStringsArrayData returns a non-nil empty slice for an
	// unset attribute, and the generated ToMap for all three Create models writes users and groups
	// unconditionally, so `[]` (not an absent key, and not null) is the wire shape for "no members".
	// That is the shape the server accepts once the other list has a member.
	users := flattenStringsArrayData(usersRaw)
	groups := flattenStringsArrayData(groupsRaw)

	payload, err := buildCreateApplicationRequest(appType, appName, networkId, host, port, users, groups)
	if err != nil {
		return appendErrorDiags(diags, "Unsupported application type", err)
	}

	status, _, err := client.ApplicationsAPI.CreateApplication(ctx).CreateApplicationRequest(payload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Application", err)
	}

	statusId := getIdFromUrl(status.GetStatusUrl())
	resource, err := pollApplicationStatusForResource(ctx, client, statusId, applicationPollInterval)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to get Application status", err)
	}
	applicationId := getIdFromUrl(resource)
	if applicationId == "" {
		// Async result didn't carry a resource URL. Fall back to
		// listing applications and finding by name.
		appName := d.Get("name").(string)
		resp, _, lerr := client.ApplicationsAPI.GetApplications(ctx).Execute()
		if lerr == nil && resp != nil {
			for _, a := range resp.Data {
				if a.Name == appName {
					applicationId = a.Id
					break
				}
			}
		}
		if applicationId == "" {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to extract Application id post-Create",
				fmt.Errorf("async status completed but result.resource was empty and list-by-name found no match for name=%s", appName))
		}
	}

	d.SetId(applicationId)
	return resourceApplicationRead(ctx, d, m)
}

/*
resourceApplicationRead Read an Application.
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceApplicationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	applicationId := d.Id()
	appData, _, err := client.ApplicationsAPI.GetApplicationById(ctx, applicationId).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to find Application", err)
	}

	// Extract the common fields from whichever sub-application variant
	// the union dispatcher routed the response into. The schema fields
	// (name/type/host/network/port/users/groups) are identical across
	// http/https/rdp variants for our purposes.
	var (
		appName, appType, appHost, appNetwork string
		appPort                               int
		appUsers                              []string
		appGroups                             []string
	)
	switch {
	case appData.HttpApplication != nil:
		a := appData.HttpApplication
		appName, appType, appHost = a.Name, a.Type, a.Host.Value
		appNetwork = a.Network.Id
		if a.Port.Value.Int32 != nil {
			appPort = int(*a.Port.Value.Int32)
		}
		for _, u := range a.Users {
			if u.Id != nil {
				appUsers = append(appUsers, *u.Id)
			}
		}
		for _, g := range a.Groups {
			if g.Id != nil {
				appGroups = append(appGroups, *g.Id)
			}
		}
	case appData.HttpsApplication != nil:
		a := appData.HttpsApplication
		appName, appType, appHost = a.Name, a.Type, a.Host.Value
		appNetwork = a.Network.Id
		if a.Port.Value.Int32 != nil {
			appPort = int(*a.Port.Value.Int32)
		}
		for _, u := range a.Users {
			if u.Id != nil {
				appUsers = append(appUsers, *u.Id)
			}
		}
		for _, g := range a.Groups {
			if g.Id != nil {
				appGroups = append(appGroups, *g.Id)
			}
		}
	case appData.RdpApplication != nil:
		a := appData.RdpApplication
		appName, appType, appHost = a.Name, a.Type, a.Host.Value
		appNetwork = a.Network.Id
		if a.Port.Value.Int32 != nil {
			appPort = int(*a.Port.Value.Int32)
		}
		for _, u := range a.Users {
			if u.Id != nil {
				appUsers = append(appUsers, *u.Id)
			}
		}
		for _, g := range a.Groups {
			if g.Id != nil {
				appGroups = append(appGroups, *g.Id)
			}
		}
	}

	if err := d.Set("name", appName); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Application name", err)
	}
	if err := d.Set("type", appType); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Application type", err)
	}
	if err := d.Set("host", appHost); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Application host", err)
	}
	if err := d.Set("network", appNetwork); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Application network", err)
	}
	if appPort != 0 {
		if err := d.Set("port", appPort); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set Application port", err)
		}
	}
	if err := d.Set("users", appUsers); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Application users", err)
	}
	// groups was read back by nothing at all until 2026-08-25, which is
	// LEFTOVERS L1 / test row APP-D03. The field was invisible rather than
	// merely unread: while no fixture set `groups`, both sides of an
	// ImportStateVerify comparison were empty and the missing d.Set could not
	// be detected. Phase 3's fixture put a real group in the configuration,
	// TestAccApplication_basic's import step started failing with `groups.#`
	// and `groups.0` missing, and the gap became measurable.
	//
	// THIS CHANGES BEHAVIOUR ON UPGRADE. State that previously held whatever
	// the configuration said now holds what the server reports. Where the two
	// agree -- the normal case -- nothing moves. Where they disagree, the next
	// plan surfaces a diff that was always real and was simply never shown.
	// That is the correct direction, and it is why the v3 plan lists this fix
	// as drift-producing and requires a migration-guide entry.
	if err := d.Set("groups", appGroups); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Application groups", err)
	}

	return diags
}

/*
resourceApplicationDelete removes the application from Terraform state and makes
NO API call, because there is no call it could make.

# Why no request

The Public API exposes no DELETE for applications, and none can be authorised.
Measured 2026-09-09 against a production tenant (P81-144746):

	GET    /v3/applications/{id} -> 404  NETWORKAPPLICATION_NOT_FOUND
	DELETE /v3/applications/{id} -> 403  explicit deny in an identity-based policy
	PUT    /v3/applications/{id} -> 403  explicit deny in an identity-based policy

GET reaches the service; DELETE and PUT are stopped at the gateway authorizer.
Nor is this a key-scoping mistake that a better key would fix: minting a key with
APPLICATION_DELETE or APPLICATION_UPDATE is refused with 422, and the tenant's
own allowed-scope list contains only APPLICATION_READ and APPLICATION_CREATE. So
a request from here could only ever return 403.

# Why a warning rather than silence, which is the bug being fixed

Until this warning existed the function was `d.SetId(""); return nil`, and a
destroy therefore printed "Destroy complete!" for an application that is still on
the tenant, still reachable by every user and group it grants. A customer reads
that message as "the application is gone". The provider was right that it could
not delete; it was wrong to report that it had. The warning is the whole fix.

The name and the id are both in the message on purpose: they are what an operator
types into the Infinity Portal to finish the job by hand, and a warning that
cannot be acted on is barely better than the silence it replaced. Both are read
before SetId clears the id.

# Why a warning rather than an error

Erroring would break `terraform destroy` for every existing configuration in
order to report something the customer cannot do anything about from Terraform —
no key can reach a delete, so there is no corrected run that would succeed. The
agreed behaviour (P81-144746, 2026-09-14) is to inform and drop from state.

The same reasoning rules out refusing at plan time, and the SDK rules it out
twice over: a destroy plan returns from PlanResourceChange before any provider
code runs (grpc_provider.go, `if proposedNewStateVal.IsNull()`), so CustomizeDiff
is never reached on a destroy and there is no hook to warn from.

# The replacement case, which this same message covers

Every attribute on this resource is ForceNew, so any change plans a replacement
whose destroy half is this function. A replacement that completes leaves the
customer holding the old application AND the new one, with no cleanup path, and
repeated runs accumulate. Delete runs in both paths, so the message says so
rather than leaving a replacement to look identical to a plain destroy.

The wording is deliberately order-neutral and makes no claim that the
replacement exists, because from in here neither is knowable. Under the default
destroy-before-create the new application has not been created yet when this
runs, and if its create then fails it never will; under
`lifecycle { create_before_destroy = true }` it already exists. This function
cannot tell those apart, nor whether a create still to come will succeed, so it
states only what it knows: the application it is releasing is the old one, and
that one is staying.

TestApplicationDeleteWarnsAndMakesNoRequest is the half of this that stays true
when somebody edits the function.

  - @param _ context.Context - unused; there is no request to make.
  - @param d *schema.ResourceData - the terraform resource data
  - @param _ interface{} - unused; the client is never called.

@return diag.Diagnostics
*/
func resourceApplicationDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	// Read both before SetId: the id is gone after it, and a warning naming
	// neither the name nor the id cannot be acted on.
	appName := d.Get("name").(string)
	applicationId := d.Id()

	diags = appendWarningDiags(diags,
		fmt.Sprintf("Application %q was left on the tenant", appName),
		fmt.Sprintf("Terraform has stopped tracking application %q (id %s) and made no API "+
			"call. The Harmony SASE Public API exposes no DELETE for applications, so it is "+
			"still on the tenant and still reachable by the users and groups it grants. "+
			"Delete it manually in the Infinity Portal if you no longer want it.\n\n"+
			"If this destroy is part of a replacement (every attribute on this resource is "+
			"immutable, so any change forces one), the application named above is the OLD "+
			"one, and it stays on the tenant whether or not the replacement is created. A "+
			"replacement that completes therefore leaves two applications behind.",
			appName, applicationId))

	d.SetId("")
	return diags
}
