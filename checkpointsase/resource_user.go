package checkpointsase

import (
	"context"
	"fmt"
	"regexp"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
resourceUser Setup the User resource CRUD operations

NO UpdateContext, DELIBERATELY. /v3/users exposes POST, GET (collection) and
DELETE only -- there is no PUT and no PATCH. Every attribute is therefore
ForceNew and any change is a replace. An UpdateContext here could only re-POST,
which would create a second user and leave the first one orphaned in the tenant
while Terraform believed it had updated one object.

Read is list-and-filter: /v3/users has no GET-by-id either, so Read fetches the
collection and matches on the stored id via readByIDFromList.

@return &schema.Resource
*/
func resourceUser() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a member of the Check Point SASE tenant. Creating this resource " +
			"invites the user by email; the invitation is what `invite_message` carries. " +
			"The API has no update endpoint for users, so every attribute forces " +
			"replacement — changing an email address deletes the user and invites the new " +
			"address. Use `checkpointsase_group_membership` to place a user in a group.",
		CreateContext: resourceUserCreate,
		ReadContext:   resourceUserRead,
		DeleteContext: resourceUserDelete,
		Schema: map[string]*schema.Schema{
			"email": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Email address of the user to invite. Changing this replaces the user.",
				ValidateFunc: validation.StringMatch(
					regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`),
					"must be an email address, e.g. someone@example.com",
				),
			},
			"invite_message": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "Message included in the invitation email. Required by the API on " +
					"every create, even when `email_verified` is true and no invitation is sent.",
			},
			"idp_type": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "database",
				Description: "Identity provider backing the account. `database` is Check Point SASE's " +
					"own directory; the others federate to an external IdP.",
				ValidateFunc: validation.StringInSlice(
					[]string{"database", "saml", "gsuite", "okta", "azureAD", "adLdap"}, false),
			},
			"email_verified": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
				ForceNew: true,
				Description: "Set to `true` to skip email verification when creating the user. " +
					"Reads back as the account's current verification state, which the user " +
					"can change outside Terraform by verifying their address.",
			},
			"access_groups": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Description: "IDs of access groups to place the user in at creation time. An empty " +
					"list is accepted and means no access groups.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"profile_data": {
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				MaxItems:    1,
				Description: "Optional profile fields sent with the invitation.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"first_name": {
							Type:        schema.TypeString,
							Optional:    true,
							ForceNew:    true,
							Description: "Given name. Up to 30 characters; letters, spaces, apostrophes and hyphens.",
							ValidateFunc: validation.All(
								validation.StringLenBetween(1, 30),
								validation.StringMatch(regexp.MustCompile(`^[a-zA-Z '-]+$`),
									"may contain only letters, spaces, apostrophes and hyphens"),
							),
						},
						"last_name": {
							Type:        schema.TypeString,
							Optional:    true,
							ForceNew:    true,
							Description: "Family name. Up to 30 characters; letters, spaces, apostrophes and hyphens.",
							ValidateFunc: validation.All(
								validation.StringLenBetween(1, 30),
								validation.StringMatch(regexp.MustCompile(`^[a-zA-Z '-]+$`),
									"may contain only letters, spaces, apostrophes and hyphens"),
							),
						},
						"role_name": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
							Description: "Free-text profile field sent as `profileData.roleName`. The API " +
								"documents no meaning for it and defaults it to an empty string. Not " +
								"the same field as the computed top-level `role_name`, which names the " +
								"user's assigned role.",
						},
						"phone": {
							Type:        schema.TypeString,
							Optional:    true,
							ForceNew:    true,
							Description: "Phone number, 9–15 digits with an optional leading `+`.",
							ValidateFunc: validation.StringMatch(
								regexp.MustCompile(`^\+?[0-9]{9,15}$`),
								"must be 9–15 digits, optionally prefixed with +"),
						},
					},
				},
			},

			// --- computed ------------------------------------------------------
			"username": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "User name as the server records it.",
			},
			"first_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Given name as the server records it, which may differ from `profile_data.first_name` if the user edited their own profile.",
			},
			"last_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Family name as the server records it.",
			},
			"initials": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Initials the console derives from the user's name.",
			},
			"role": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the role assigned to the user.",
			},
			"role_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Display name of the role assigned to the user.",
			},
			"roles": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Display names of every role assigned to the user, built-in and custom.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"terminated": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the account has been deleted. A user this resource manages reads back `false`.",
			},
			"invitation_attempts": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "How many invitations the server has sent to this address.",
			},
			"invitation_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Token embedded in the invitation link. Marked sensitive: it grants whoever holds it the ability to complete this user's enrolment.",
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceUserImportState,
		},
	}
}

/*
resourceUserImportState Import a user by its ID
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceUserImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	diagnostics := resourceUserRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import user: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	// Read clears the id when the user is absent; an import that silently
	// produced an empty resource would report success and write nothing.
	if d.Id() == "" {
		return nil, fmt.Errorf("no user with that id exists in this tenant")
	}
	// invite_message is write-only: CreateUserDto carries it, and the User read
	// model has an inviteMessage field that the server does not populate for
	// users created through the API. It is Required, so an import that left it
	// unset would show a permanent diff. Set it from the imported object if the
	// server did send one; otherwise leave it empty and let the operator supply
	// the value that matches their config.
	return []*schema.ResourceData{d}, nil
}

/*
resourceUserCreate Create a user
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceUserCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	email := d.Get("email").(string)
	inviteMessage := d.Get("invite_message").(string)
	idpType := d.Get("idp_type").(string)
	emailVerified := d.Get("email_verified").(bool)

	payload := perimeter81Sdk.CreateUserDto{
		Email:         email,
		InviteMessage: inviteMessage,
		IdpType:       &idpType,
		EmailVerified: &emailVerified,
		AccessGroups:  flattenStringsArrayData(d.Get("access_groups").([]interface{})),
		ProfileData:   expandUserProfile(d.Get("profile_data").([]interface{})),
	}

	user, _, err := client.TeamAPI.CreateUser(ctx).CreateUserDto(payload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create user", err)
	}

	// Id exists only because overlay entry A21a adds it: the upstream User
	// schema declares no id, because BaseModel is @ApiExcludeClass(). A nil
	// here means the entry stopped working, not that the user was not created,
	// so say so rather than writing an empty id into state.
	if user.Id == nil {
		return appendErrorDiags(diags, "User created but the response carried no id",
			fmt.Errorf("POST /v3/users returned no id for %s; the user may exist in the "+
				"tenant and must be removed by hand. Check overlay entry A21a", email))
	}
	d.SetId(user.GetId())
	return resourceUserRead(ctx, d, m)
}

/*
resourceUserRead Read a user by list-and-filter
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceUserRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// /v3/users has no GET-by-id, so this is the whole collection. Limit is
	// requested at the documented maximum: the default is 500 and a tenant with
	// more members than that would drop this user off page 1 and make Terraform
	// recreate a user that already exists. L15 records the same class of bug in
	// three older data sources.
	users, resp, err := client.TeamAPI.ListUsers(ctx).Page(1).Limit(1000).Execute()
	if err != nil {
		if isNotFound(resp, err) {
			d.SetId("")
			return diags
		}
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to list users", err)
	}

	user, found := readByIDFromList(users.Data, d.Id(), func(u perimeter81Sdk.User) string {
		return u.GetId()
	})
	if !found {
		// Absent from the collection: treat as removed out of band so Terraform
		// plans a recreate rather than failing (USR-D01).
		d.SetId("")
		return diags
	}

	// EVERY field below goes through a nil-safe Get* accessor, without
	// exception. Overlay entry A21b removes User.required entirely -- not just
	// trims it -- because an Active-Directory-synced account can lack a `mail`
	// attribute, so even `email` cannot be relied on. Every field in the
	// generated model is therefore a pointer, and assigning one directly would
	// put a Go address into Terraform state. Same correction Phase 1 applied
	// when v3 flipped Address.Name to *string; see the comment in
	// resource_object_addresses.go.
	for key, value := range map[string]interface{}{
		"email":               user.GetEmail(),
		"email_verified":      user.GetEmailVerified(),
		"username":            user.GetUsername(),
		"first_name":          user.GetFirstName(),
		"last_name":           user.GetLastName(),
		"initials":            user.GetInitials(),
		"role":                user.GetRole(),
		"role_name":           user.GetRoleName(),
		"terminated":          user.GetTerminated(),
		"invitation_attempts": int(user.GetInvitationAttempts()),
		"invitation_token":    user.GetInvitationToken(),
	} {
		if err := d.Set(key, value); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set user "+key, err)
		}
	}
	if err := d.Set("roles", user.Roles); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set user roles", err)
	}

	return diags
}

/*
resourceUserDelete Delete a user
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceUserDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	_, resp, err := client.TeamAPI.DeleteUser(ctx, d.Id()).Execute()
	if err != nil && !isNotFound(resp, err) {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete user", err)
	}
	// A 404 means somebody already deleted the user; destroy has nothing left
	// to do and reporting a failure would leave the resource stuck in state
	// forever (USR-N03).

	d.SetId("")
	return nil
}
