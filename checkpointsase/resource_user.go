package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

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
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				// THE SERVER FOLDS THE ADDRESS TO LOWERCASE, so the provider has
				// to agree with it about the canonical form. Measured live on
				// 2026-08-20: POST /v3/users with "tf-acc-IRaJCqyhVx@example.com"
				// stored and returned "tf-acc-irajcqyhvx@example.com", and derived
				// `username` from the folded value. API-FINDINGS.md 1.12.
				//
				// The consequence of not doing this is not cosmetic. Read writes
				// the folded value into state, the configuration still holds the
				// original, and because `email` is ForceNew EVERY subsequent plan
				// proposes destroying and re-inviting any user whose address
				// contains a capital letter -- forever. Observed live:
				//   ~ email = "...uknwejlupb@..." -> "...uKNWejLupb@..."  # forces replacement
				//
				// The description this replaces told the operator to "keep the
				// configuration in whichever case the tenant stores". That advice
				// was unfollowable: the folding rule is undocumented, so there was
				// no way to know what case to write.
				//
				// StateFunc RATHER THAN DiffSuppressFunc, deliberately. Both stop
				// the spurious replacement, but they differ in what they leave
				// behind. DiffSuppressFunc hides a difference that is really
				// there, leaving `terraform plan` silent about the address stored
				// not being the address written. StateFunc canonicalises before
				// the comparison, so state matches the server, the plan shows the
				// value that will actually exist, and two configurations differing
				// only in case are treated as the same address -- which is what
				// the server thinks too.
				StateFunc: func(v interface{}) string {
					return strings.ToLower(v.(string))
				},
				Description: "Email address of the user to invite. Changing this replaces the user: " +
					"the account is deleted and the new address is invited. Stored in lowercase, " +
					"because the API folds the address it receives — `Someone@example.com` and " +
					"`someone@example.com` are the same user, and both read back folded.",
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
					"every create, even when `email_verified` is true and no invitation is sent. " +
					"Write-only: the server does not report it back, so it is absent from the " +
					"state of an imported user and the first plan after an import ignores it.",
				// Write-only, so an imported user has no value in state at all.
				// See suppressDiffOnEmptyOldValue and resourceUserImportState:
				// without this, importing a user and then applying the config
				// that describes it would DELETE and re-invite that user.
				DiffSuppressFunc: suppressDiffOnEmptyOldValue,
			},
			"idp_type": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "database",
				Description: "Identity provider backing the account. `database` is Check Point SASE's " +
					"own directory; the others federate to an external IdP. Write-only: the read " +
					"model exposes `idProviders`/`idProviderGroups` and no `idpType`, so this is " +
					"absent from the state of an imported user.",
				ValidateFunc: validation.StringInSlice(
					[]string{"database", "saml", "gsuite", "okta", "azureAD", "adLdap"}, false),
				// Same shape and same hazard as invite_message: absent from an
				// imported user's state, and ForceNew.
				DiffSuppressFunc: suppressDiffOnEmptyOldValue,
			},
			"email_verified": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
				// DELIBERATELY NOT Computed, and deliberately never read back.
				// The name covers two different things: on CreateUserDto it is a
				// create-time instruction ("skip the verification email"), on the
				// User read model it is an observation ("has this person verified
				// their address"). Populating the second into the first is what
				// made an ordinary user verifying her own address flip this
				// attribute from false to true, and — because it is ForceNew —
				// made the next no-op apply delete and re-invite her.
				Description: "Create-time instruction, **not** the account's current verification " +
					"state. `true` marks the address verified up front and skips the verification " +
					"step; `false` (the default) invites the user and lets them verify. The value " +
					"is never read back from the server, because the user verifying their own " +
					"address would otherwise look like drift on an attribute that forces " +
					"replacement. To observe whether an address has actually been verified, read " +
					"`email_verified` from the `checkpointsase_users` data source, which has no " +
					"diff to trigger. Changing this value replaces the user.",
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
				Type:     schema.TypeBool,
				Computed: true,
				Description: "Whether the account has been soft-deleted. `DELETE /v3/users/{id}` does " +
					"not remove the record: the account keeps appearing in the collection with " +
					"`terminated` set to `true`. A user this resource manages therefore always " +
					"reads back `false` — a terminated account is treated as absent, so the " +
					"resource leaves state and the next plan proposes a fresh invitation. Read " +
					"`terminated` from the `checkpointsase_users` data source to see " +
					"soft-deleted accounts, which it deliberately still lists.",
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
	// invite_message IS DELIBERATELY NEVER READ BACK, here or in Read.
	//
	// The read model does carry an inviteMessage field, so setting it would be
	// possible -- and wrong. The attribute is Required AND ForceNew, so if the
	// server ever returned a value differing by even one character from the
	// operator's config, the resulting drift would not be a cosmetic diff: it
	// would force the user to be DELETED AND RE-INVITED on the next apply. An
	// attribute that can trigger a replacement is only safe to populate from
	// the server when the round-trip is known to be exact, and this one is not.
	//
	// The cost is NOT merely cosmetic, and an earlier version of this comment
	// was wrong to call it a one-time annoyance. An imported user carries no
	// invite_message in state -- and no idp_type either, for the same reason:
	// the read model has no idpType field at all. Both attributes are ForceNew,
	// so the first plan after an import would see "" -> the configured value on
	// each of them and DESTROY the imported user.
	//
	// What makes the tradeoff safe is the DiffSuppressFunc on both attributes
	// (suppressDiffOnEmptyOldValue): on a resource that already exists, an empty
	// `old` is exactly and only the post-import state, so suppressing that one
	// transition removes the replacement without masking a real change -- a user
	// this provider created always has the config value in state. The condition
	// includes `d.Id() != ""` for a reason worth reading before touching it:
	// without it, the same suppression also fires during CREATE (where every
	// `old` is empty) and the provider POSTs an empty invitation message.
	//
	// USR-I01 lists these in ImportStateVerifyIgnore as well: DiffSuppressFunc
	// governs plans, while ImportStateVerify compares the raw attribute maps.
	// email_verified is in that list too, for the third variant of the same
	// problem -- it IS returned by the server, but is deliberately not read
	// back; see its schema entry.
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
	//
	// The `user == nil` half is not theoretical: CreateUserExecute leaves its
	// return value nil when the body decodes as a literal `null` with a 2xx
	// status (client.go decode returns nil for a successful Unmarshal), and
	// dereferencing it would panic the provider instead of producing this
	// diagnostic.
	if user == nil || user.Id == nil {
		return appendErrorDiags(diags, "User created but the response carried no id",
			fmt.Errorf("POST /v3/users returned no id for %s; the user may exist in the "+
				"tenant and must be removed by hand. Check overlay entry A21a", email))
	}
	d.SetId(user.GetId())
	return resourceUserRead(ctx, d, m)
}

/*
userListPageSize is the page size findUserByID requests.

It is a page SIZE, not a ceiling: the loop below walks every page, so this value
only trades request count against response size. 500 is the endpoint's own
default, which is the size the server is known to serve without complaint.
*/
const userListPageSize = 500

/*
findUserByID answers "is this user still in the tenant", which is NOT the same
question as "is this id still in the collection".

DELETE /v3/users/{id} IS A SOFT DELETE. Measured against the tenant, not read
anywhere in the spec: the DELETE answers 200 and the account stays in
GET /v3/users with `terminated: true`, and itemsTotal keeps counting it. Three
probe users deleted that way were all still listed afterwards. So a terminated
record is reported ABSENT here, and the check lives in this function rather than
in resourceUserRead so that every caller asking the existence question inherits
it -- Read, and the parent-survival assertion in resource_group_membership_test.go,
which likewise must not count a soft-deleted account as a surviving parent.

Without this, findUserByID matched the terminated record, Read reported it found,
and the id stayed in state FOREVER: a user deleted from the console never
surfaced as drift (USR-D01), and an account the tenant no longer had kept
planning empty. TestUserReadTreatsATerminatedUserAsAbsent is the gate.

GROUPS ARE THE OTHER WAY ROUND and findGroupByID deliberately has no equivalent
check: a deleted group disappears from GET /v3/groups outright, the read model
has no `terminated` field at all, and inventing one there would only add a
condition that can never fire. TestGroupReadHasNoTerminatedCheck pins that
asymmetry.

Two callers need the UNFILTERED view and go to findUserRecordByID instead:
testAccCheckUserDestroy, which must accept absent OR terminated and so has to be
able to see the terminated record, and this function. The `checkpointsase_users`
DATA SOURCE is not affected either way -- it calls ListUsers directly and
exposes `terminated` as an attribute of every row, which is the right behaviour
for a read-only listing that has a column for exactly this state.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc.
  - @param client *perimeter81Sdk.APIClient - the configured SDK client
  - @param id string - the user id held in Terraform state

@return (perimeter81Sdk.User, bool, *http.Response, error) - the user and whether it is
present and live, plus the last response and error so callers can classify a failure
with isNotFound
*/
func findUserByID(ctx context.Context, client *perimeter81Sdk.APIClient, id string) (perimeter81Sdk.User, bool, *http.Response, error) {
	user, found, resp, err := findUserRecordByID(ctx, client, id)
	if found && user.GetTerminated() {
		// GetTerminated, not *user.Terminated: A21b makes every User field
		// optional, so the pointer is nil whenever the key is absent, and the
		// nil-safe accessor reads that as false. An absent key must mean "live"
		// -- reading it as terminated would clear the id for every user in a
		// tenant whose list omits the field.
		var zero perimeter81Sdk.User
		return zero, false, resp, nil
	}
	return user, found, resp, err
}

/*
findUserRecordByID walks /v3/users page by page looking for one id and reports
whatever it finds, terminated accounts included.

Callers almost never want this: use findUserByID, which applies the soft-delete
rule above. This one exists for testAccCheckUserDestroy, which has to accept a
terminated record and therefore has to be able to see one.

PAGING IS NOT OPTIONAL HERE. /v3/users has no GET-by-id, so the only way to
answer "does this user still exist" is to read the collection -- and raising the
limit instead of paging is the L15 bug transplanted somewhere it does real
damage. In a read-only data source an unpaginated read returns a short list. In
Read, a user who happens to sit past the first page reads back as absent,
Terraform clears the id, plans a create, and either the POST collides on the
address or the tenant ends up with a second account for the same person.

Stops at the first exact match. Otherwise stops when the server says there are
no further pages, or when a page comes back empty -- the second condition is
what keeps the loop finite if totalPage is ever wrong.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc.
  - @param client *perimeter81Sdk.APIClient - the configured SDK client
  - @param id string - the user id held in Terraform state

@return (perimeter81Sdk.User, bool, *http.Response, error) - the record and whether it was
in the collection, plus the last response and error so callers can classify a failure
with isNotFound
*/
func findUserRecordByID(ctx context.Context, client *perimeter81Sdk.APIClient, id string) (perimeter81Sdk.User, bool, *http.Response, error) {
	var zero perimeter81Sdk.User
	if id == "" {
		// readByIDFromList would refuse an empty id anyway; not issuing the
		// request at all keeps an empty state out of the API's logs.
		return zero, false, nil, nil
	}
	for page := int32(1); ; page++ {
		users, resp, err := client.TeamAPI.ListUsers(ctx).Page(page).Limit(userListPageSize).Execute()
		if err != nil {
			return zero, false, resp, err
		}
		if users == nil {
			// A 2xx whose body decodes to JSON null leaves the SDK returning a
			// nil pointer with no error, and every field access below would
			// panic -- a provider crash with a stack trace, not a diagnostic.
			// Treat it as "not on this page and no further pages", which makes
			// Read report drift rather than dying.
			return zero, false, resp, nil
		}
		if user, found := readByIDFromList(users.Data, id, func(u perimeter81Sdk.User) string {
			return u.GetId()
		}); found {
			return user, true, resp, nil
		}
		if len(users.Data) == 0 || page >= users.TotalPage {
			return zero, false, resp, nil
		}
	}
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

	user, found, resp, err := findUserByID(ctx, client, d.Id())
	if err != nil {
		if isNotFound(resp, err) {
			d.SetId("")
			return diags
		}
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to list users", err)
	}
	if !found {
		// Absent from the collection: treat as removed out of band so Terraform
		// plans a recreate rather than failing (USR-D01).
		d.SetId("")
		return diags
	}

	// email_verified is ABSENT from this map on purpose -- see the schema. It is
	// a create-time instruction, not an observation, and reading the server's
	// observation back into a ForceNew attribute is what turned "the invitee
	// verified her address" into "delete the invitee".
	//
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
	//
	// THIS IS A SOFT DELETE, measured against the tenant and undocumented in the
	// spec: the 200 does not remove the record. The account stays in
	// GET /v3/users with terminated: true, and itemsTotal keeps counting it.
	// Nothing more is needed HERE -- the id leaves state either way -- but it is
	// why findUserByID treats a terminated record as absent and why
	// testAccCheckUserDestroy accepts "absent OR terminated" rather than
	// asserting the id is gone from the collection. Groups are hard-deleted; see
	// the note on findUserByID.

	d.SetId("")
	return nil
}
