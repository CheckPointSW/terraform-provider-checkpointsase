package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
groupXSSSafeCharacters is `xssSafeCharacters` from createGroup.dto.ts, ported
verbatim. Both `name` and `description` are matched against it there.

The class is UNICODE, not ASCII: \p{L} covers letters in every script, \p{M}
combining marks and \p{Nd} decimal digits, which Go's regexp supports natively
with no flag. A `[a-zA-Z]`-style transliteration would reject "Ingénierie" and
"研究開発" at plan time for configurations the server accepts.

The escaping differs from the TypeScript source only where Go's syntax requires
it: \\ is one literal backslash, and \[ \] \- are the bracket and hyphen that
would otherwise be class syntax. The set of accepted characters is identical.
*/
const groupXSSSafeCharacters = `[\p{L}\p{M}\p{Nd}\s._()'/\\,|&{}~!@#$%^*\[\]\-:]`

/*
groupCharacterRuleMessage is the operator-facing half of the two patterns below.

validation.StringMatch passes this string as an ARGUMENT to %s rather than as a
format string, so a literal per-cent sign is written once, not doubled.
*/
const groupCharacterRuleMessage = "may contain letters (in any script), combining marks, digits, " +
	"whitespace and the punctuation . _ ( ) ' / \\ , | & { } ~ ! @ # $ % ^ * [ ] - :"

var (
	// ^...{1,64}$ -- Matches(`^${xssSafeCharacters}{1,64}$`, 'u') on name.
	groupNamePattern = regexp.MustCompile(`^` + groupXSSSafeCharacters + `{1,64}$`)
	// ^...+$ -- the same class on description, with no length bound.
	groupDescriptionPattern = regexp.MustCompile(`^` + groupXSSSafeCharacters + `+$`)
)

/*
resourceGroup Setup the Group resource CRUD operations

NO UpdateContext, DELIBERATELY, for the same reason as checkpointsase_user:
/v3/groups exposes POST, GET (collection) and DELETE only -- no PUT, no PATCH.
Every attribute is therefore ForceNew and any change is a replace. An
UpdateContext could only re-POST, which would create a second group and leave
the first one orphaned in the tenant while Terraform believed it had renamed one.

Read is list-and-filter: /v3/groups has no GET-by-id either, so Read walks the
collection and matches on the stored id via readByIDFromList. See findGroupByID
for why that walk is paginated rather than a single large page.

@return &schema.Resource
*/
func resourceGroup() *schema.Resource {
	return &schema.Resource{
		Description: "Manages an access group in the Check Point SASE tenant. The API has no " +
			"update endpoint for groups, so every attribute forces replacement — and a " +
			"replacement is not a rename: the old group is deleted, which drops every " +
			"membership in it. Members are managed with `checkpointsase_group_membership`, " +
			"one resource per member, so Terraform recreates them after a replacement.",
		CreateContext: resourceGroupCreate,
		ReadContext:   resourceGroupRead,
		DeleteContext: resourceGroupDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "Name of the group, 1–64 characters. Changing it replaces the group, " +
					"which drops every membership in it — use a `checkpointsase_group_membership` " +
					"for each member so Terraform recreates them.",
				ValidateFunc: validation.All(
					validation.StringLenBetween(1, 64),
					validation.StringMatch(groupNamePattern, groupCharacterRuleMessage),
				),
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Description: "Optional description. Same character restrictions as `name`, with no " +
					"length limit. Write-only: the `Group` read model carries no `description` " +
					"field at all, so the server never reports it back and an imported group has " +
					"no value for it in state.",
				ValidateFunc: validation.StringMatch(groupDescriptionPattern,
					groupCharacterRuleMessage+". An explicitly empty string is not accepted: "+
						"CreateGroupDto.description is @IsOptional() AND @IsNotEmpty(), so omit "+
						"the argument instead"),
				// WRITE-ONLY, AND THE READ MODEL HAS NO FIELD FOR IT.
				//
				// Not a stylistic choice like resource_user.go's invite_message:
				// perimeter-81-client-sdk/model_group.go declares name, isDefault,
				// applications, networks, vpnLocations, users and id, and NOTHING
				// else. There is no description to read back, so an imported group
				// has none in state.
				//
				// This attribute is ForceNew, so without the suppression the FIRST
				// plan after an import sees "" -> the configured description and
				// plans a REPLACEMENT: import a group, apply the config that
				// describes it, and the group is deleted along with every
				// membership in it. See suppressDiffOnEmptyOldValue -- its
				// `d.Id() != ""` condition is what keeps Create unaffected.
				//
				// groupImportStateVerifyIgnore lists it as well: DiffSuppressFunc
				// governs plans, while ImportStateVerify compares raw attribute
				// maps.
				DiffSuppressFunc: suppressDiffOnEmptyOldValue,
			},

			// --- computed ------------------------------------------------------
			"is_default": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether this is the tenant's default group. A group created by Terraform reads back `false`.",
			},
			"applications": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "IDs of the applications this group has access to. Granted from the application side, by `checkpointsase_application.groups`, so it is read-only here.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"networks": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "IDs of the networks this group has access to.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"vpn_locations": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "IDs of the VPN locations this group has access to.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"users": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "IDs of the group's members. Managed with `checkpointsase_group_membership`, one resource per member, so it is read-only here.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceGroupImportState,
		},
	}
}

/*
resourceGroupImportState Import a group by its ID
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceGroupImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	diagnostics := resourceGroupRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import group: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	// Read clears the id when the group is absent; an import that silently
	// produced an empty resource would report success and write nothing.
	if d.Id() == "" {
		return nil, fmt.Errorf("no group with that id exists in this tenant")
	}
	// description IS NOT SET HERE, and cannot be: the Group read model has no
	// description field (model_group.go). The task brief and V3-TERRAFORM-TEST-PLAN
	// row GRP-I01 both expect Read to populate it; both are wrong about the
	// schema, and an ImportStateVerify written on that assumption fails on its
	// first live run. What makes the gap safe is the DiffSuppressFunc on the
	// attribute plus its entry in groupImportStateVerifyIgnore; see both.
	return []*schema.ResourceData{d}, nil
}

/*
resourceGroupCreate Create a group
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceGroupCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	name := d.Get("name").(string)

	// CreateGroupDto.Name is a plain string, not a pointer: A22b trimmed the
	// required list on the Group READ model only, and this is a different
	// schema.
	payload := perimeter81Sdk.CreateGroupDto{Name: name}

	// OMITTED WHEN EMPTY, NOT SENT EMPTY. createGroup.dto.ts carries BOTH
	// @IsOptional() and @IsNotEmpty() on description, so `"description": ""` is
	// a 400 while an absent key is accepted. Description is a *string precisely
	// so the key can be dropped; setting it to a pointer-to-"" would send the
	// rejected form. Same pattern as expandUserProfile.
	if description := d.Get("description").(string); description != "" {
		payload.Description = &description
	}

	group, _, err := client.TeamAPI.CreateGroup(ctx).CreateGroupDto(payload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create group", err)
	}

	// Id exists only because overlay entry A22a adds it: the upstream Group
	// schema declares no id, because BaseModel is @ApiExcludeClass(). A nil here
	// means the entry stopped working, not that the group was not created, so
	// say so rather than writing an empty id into state.
	//
	// The `group == nil` half is not theoretical: CreateGroupExecute leaves its
	// return value nil when the body decodes as a literal `null` with a 2xx
	// status (client.go decode returns nil for a successful Unmarshal), and
	// dereferencing it would panic the provider instead of producing this
	// diagnostic.
	if group == nil || group.Id == nil {
		return appendErrorDiags(diags, "Group created but the response carried no id",
			fmt.Errorf("POST /v3/groups returned no id for %s; the group may exist in the "+
				"tenant and must be removed by hand. Check overlay entry A22a", name))
	}
	d.SetId(group.GetId())
	return resourceGroupRead(ctx, d, m)
}

/*
groupListPageSize is the page size findGroupByID requests.

It is a page SIZE, not a ceiling: the loop below walks every page, so this value
only trades request count against response size. 500 is the endpoint's own
default (v3.yaml, GET /v3/groups), which is the size the server is known to serve
without complaint.
*/
const groupListPageSize = 500

/*
findGroupByID walks /v3/groups page by page looking for one id.

Deliberately alongside its callers rather than in utils.go, mirroring
findUserByID in resource_user.go: utils.go holds the helpers shared across
resources (readByIDFromList, isNotFound), while this one is specific to one
endpoint and has exactly two callers, Read and testAccCheckGroupDestroy.

PAGING IS NOT OPTIONAL HERE, and it matters more than it does for users.
/v3/groups has no GET-by-id, so the only way to answer "does this group still
exist" is to read the collection -- and raising the limit instead of paging only
moves the ceiling. A group that happens to sit past the first page reads back as
absent, Read clears the id, Terraform plans a create, and the live group is
either duplicated or DELETED AND RECREATED -- which silently drops every
membership in it, because memberships live on the group's id.

Stops at the first exact match. Otherwise stops when the server says there are no
further pages, or when a page comes back empty -- the second condition is what
keeps the loop finite if totalPage is ever wrong.

  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc.
  - @param client *perimeter81Sdk.APIClient - the configured SDK client
  - @param id string - the group id held in Terraform state

@return (perimeter81Sdk.Group, bool, *http.Response, error) - the group and whether it was
found, plus the last response and error so callers can classify a failure with isNotFound
*/
func findGroupByID(ctx context.Context, client *perimeter81Sdk.APIClient, id string) (perimeter81Sdk.Group, bool, *http.Response, error) {
	var zero perimeter81Sdk.Group
	if id == "" {
		// readByIDFromList would refuse an empty id anyway; not issuing the
		// request at all keeps an empty state out of the API's logs.
		return zero, false, nil, nil
	}
	for page := int32(1); ; page++ {
		groups, resp, err := client.TeamAPI.ListGroups(ctx).Page(page).Limit(groupListPageSize).Execute()
		if err != nil {
			return zero, false, resp, err
		}
		if groups == nil {
			// A 2xx whose body decodes to JSON null leaves the SDK returning a
			// nil pointer with no error, and every field access below would
			// panic -- a provider crash with a stack trace, not a diagnostic.
			// Treat it as "not on this page and no further pages", which makes
			// Read report drift rather than dying.
			return zero, false, resp, nil
		}
		if group, found := readByIDFromList(groups.Data, id, func(g perimeter81Sdk.Group) string {
			return g.GetId()
		}); found {
			return group, true, resp, nil
		}
		if len(groups.Data) == 0 || page >= groups.TotalPage {
			return zero, false, resp, nil
		}
	}
}

/*
resourceGroupRead Read a group by list-and-filter
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceGroupRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	group, found, resp, err := findGroupByID(ctx, client, d.Id())
	if err != nil {
		if isNotFound(resp, err) {
			d.SetId("")
			return diags
		}
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to list groups", err)
	}
	if !found {
		// Absent from the collection: treat as removed out of band so Terraform
		// plans a recreate rather than failing (GRP-D01).
		d.SetId("")
		return diags
	}

	// description is ABSENT from this function on purpose -- there is no field
	// for it on the read model. See the schema entry and resourceGroupImportState.
	//
	// name and is_default go through nil-safe Get* accessors, without exception.
	// Overlay entry A22b removes Group.required ENTIRELY, so every scalar in the
	// generated model is a pointer -- name included -- and assigning one directly
	// would put a Go address into Terraform state.
	for key, value := range map[string]interface{}{
		"name":       group.GetName(),
		"is_default": group.GetIsDefault(),
	} {
		if err := d.Set(key, value); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set group "+key, err)
		}
	}

	// The four membership projections. A22b makes each of them optional, so a
	// nil slice is reachable for all four, and the requirement is that state
	// holds an EMPTY LIST rather than a null: `users` in particular is what
	// Task 5's Read compares against.
	//
	// The nil -> []string{} step is belt-and-braces, and the comment says so
	// rather than overstating it: measured, d.Set normalises a typed nil slice to
	// the same state a []string{} produces (MapFieldWriter.setList decodes it to
	// a zero-length slice and writes `<key>.# = 0`), so removing the check does
	// not change today's behaviour. It is kept because it makes the required end
	// state local and obvious, and because the moment one of these becomes a
	// nested or flattened value the normalisation stops applying.
	// TestGroupReadCoercesNilListsToEmpty pins the end state, not this check.
	//
	// Deliberately NOT setStringListIfPresent: that helper preserves the prior
	// state when the server reports nothing, which is right for a list the user
	// configured and wrong here. These are read-only projections, so "the last
	// member was removed" must read back as empty rather than keeping a member
	// that is gone.
	for key, values := range map[string][]string{
		"applications":  group.Applications,
		"networks":      group.Networks,
		"vpn_locations": group.VpnLocations,
		"users":         group.Users,
	} {
		list := values
		if list == nil {
			list = []string{}
		}
		if err := d.Set(key, list); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set group "+key, err)
		}
	}

	return diags
}

/*
resourceGroupDelete Delete a group
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceGroupDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	_, resp, err := client.TeamAPI.DeleteGroup(ctx, d.Id()).Execute()
	if err != nil && !isNotFound(resp, err) {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete group", err)
	}
	// A 404 means somebody already deleted the group; destroy has nothing left
	// to do and reporting a failure would leave the resource stuck in state
	// forever (GRP-N03). The swallow is narrow on purpose -- a 500 must still
	// fail, or a merely broken server would look like a successful destroy.

	d.SetId("")
	return nil
}
