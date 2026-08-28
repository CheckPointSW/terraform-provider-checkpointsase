package checkpointsase

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
groupMembershipIDSeparator joins the two path parameters into one Terraform id.

":" is safe rather than merely conventional: both groupId and userId are
EnglishNumericId in the API document, whose pattern is ^[a-zA-Z0-9_\-]*$, so
neither half can contain a colon and SplitN cannot mis-split. A "-" separator
would have been ambiguous, because "-" IS in that character class -- and so is
"_", which rules that out too.
*/
const groupMembershipIDSeparator = ":"

/*
groupMembershipIDHalf is the charset each half of the id must match.

It is EnglishNumericId from the API document less the empty case: the document's
own pattern is ^[a-zA-Z0-9_\-]*$, which permits "". Anything outside this class
cannot be an id the server assigned, and accepting it means issuing a request
against a path segment that never existed. The reachable case is WHITESPACE: a
copy-paste into `terraform import` carries a trailing space or a newline, and
" grp1" would otherwise be sent as %20grp1 -- a 404 the operator cannot explain,
or worse, a match against nothing while Terraform reports drift forever.
*/
var groupMembershipIDHalf = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

/*
resourceGroupMembership Setup the Group Membership join resource.

There is no membership object and no endpoint that returns one: the API exposes
only POST and DELETE on /v3/groups/{groupId}/member/{userId}. Read therefore
inspects the parent group's own `users` list, which is why this resource depends
on Group being readable at all.

NO UpdateContext: there is nothing to update. Changing either id is a different
membership, so both are ForceNew.

THIS RESOURCE MUST NEVER CALL DeleteGroup OR DeleteUser. Its Delete removes one
pairing; the parents belong to their own resources. Test row GRP-04 removes only
this resource and asserts both parents survive, and
TestGroupMembershipNeverDeletesItsParents fails the build if either call appears
in this file -- a join resource that deleted a parent would satisfy every
read-back assertion and show up only as a destroyed user or group.

@return &schema.Resource
*/
func resourceGroupMembership() *schema.Resource {
	return &schema.Resource{
		Description: "Places one user in one group. The API models membership as a pairing rather " +
			"than an object, so this is a join resource: its id is `<group_id>:<user_id>`, it " +
			"has no attributes of its own, and destroying it removes only the membership — " +
			"the user and the group both survive. Use one resource per member; " +
			"`checkpointsase_group.users` reads the resulting list back.",
		CreateContext: resourceGroupMembershipCreate,
		ReadContext:   resourceGroupMembershipRead,
		DeleteContext: resourceGroupMembershipDelete,
		Schema: map[string]*schema.Schema{
			"group_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "ID of the group to add the user to. Reference the group resource's " +
					"`id` rather than hardcoding it: the reference is what puts an edge in " +
					"Terraform's dependency graph, so the membership is removed before the group.",
			},
			"user_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "ID of the user to add. Reference the user resource's `id` for the " +
					"same reason as `group_id`.",
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceGroupMembershipImportState,
		},
	}
}

/*
resourceGroupMembershipCreate Add a member to a group
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceGroupMembershipCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	groupID := d.Get("group_id").(string)
	userID := d.Get("user_id").(string)

	// NOT idempotent-on-404, unlike Delete below. A 404 here means the group or
	// the user does not exist, so there is nothing to be idempotent about: the
	// membership was not created and writing an id would put a pairing into
	// state that the tenant does not have (GRP-N04).
	if _, _, err := client.TeamAPI.AddGroupMember(ctx, groupID, userID).Execute(); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to add member to group", err)
	}

	// After the POST, never before: an id set ahead of a failed request would
	// leave Terraform tracking a membership that does not exist.
	d.SetId(groupID + groupMembershipIDSeparator + userID)
	return resourceGroupMembershipRead(ctx, d, m)
}

/*
resourceGroupMembershipRead Read a membership by inspecting the parent group
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceGroupMembershipRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	groupID, userID, err := parseGroupMembershipID(d.Id())
	if err != nil {
		return appendErrorDiags(diags, "Unable to parse group membership id", err)
	}

	// findGroupByID, not a single ListGroups call: it paginates. A group on
	// page 2 of a large tenant would otherwise read as absent, and this Read
	// would report the membership as drift and recreate it.
	// No isNotFound branch: see the note in resourceUserRead. A 404 here is a
	// wrong URL, not a vanished group; the group being gone arrives as
	// found == false below.
	group, found, _, err := findGroupByID(ctx, client, groupID)
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to list groups", err)
	}
	if !found {
		// The group itself is gone, so the membership is too. Drift, not an
		// error: Terraform plans a recreate, and the group resource (if the
		// group is managed) plans its own.
		d.SetId("")
		return diags
	}

	// Group.Users may be nil -- overlay entry A22b makes every Group field
	// optional -- and ranging over a nil slice is zero iterations, which is the
	// right answer: a group with no members contains nobody.
	member := false
	for _, id := range group.Users {
		if id == userID {
			member = true
			break
		}
	}
	if !member {
		// Removed out of band (GRP-D02's precondition).
		d.SetId("")
		return diags
	}

	// Both attributes come from the id rather than from the response, which is
	// what makes an import work and what makes this resource need no
	// DiffSuppressFunc: neither value can be missing from a successful Read, so
	// there is no empty-old-value case for suppressDiffOnEmptyOldValue to cover.
	if err := d.Set("group_id", groupID); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set group membership group_id", err)
	}
	if err := d.Set("user_id", userID); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set group membership user_id", err)
	}
	return diags
}

/*
resourceGroupMembershipDelete Remove a member from a group
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceGroupMembershipDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// Parsed before any request is issued: a malformed id must not become a
	// request against an empty path segment, which would address a different
	// endpoint entirely.
	groupID, userID, err := parseGroupMembershipID(d.Id())
	if err != nil {
		return appendErrorDiags(diags, "Unable to parse group membership id", err)
	}

	// RemoveGroupMember, never DeleteGroup or DeleteUser. GRP-04 asserts both
	// parents outlive this call.
	_, resp, err := client.TeamAPI.RemoveGroupMember(ctx, groupID, userID).Execute()
	if err != nil && !isNotFound(resp, err) && !isMembershipAlreadyAbsent(resp, err) {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to remove member from group", err)
	}
	// Two answers mean "the pairing is already gone", and only one of them is a
	// 404. Either way destroy has nothing left to do (GRP-D02): the member was
	// removed out of band, or the group itself was deleted.
	//
	// A 404 covers the two siblings on this route, USER_NOT_FOUND and
	// GROUP_NOT_FOUND. Removing a member who is not in the group answers 409
	// instead -- see isMembershipAlreadyAbsent -- which is why the guard as
	// originally written could never fire on the case GRP-D02 actually exercises.
	//
	// Both swallows are NARROW on purpose: a 500 still fails, and so does any
	// other 409, or a merely broken server would look like a successful destroy
	// and the membership would leave state while surviving in the tenant.

	d.SetId("")
	return nil
}

/*
membershipAlreadyAbsentMarker is the marker the server returns when the pairing
this Delete targets is already gone.

MEASURED against the tenant, and documented nowhere:

	first remove (real)    -> 200
	second remove (absent) -> 409 {"message":"USER_ALREADY_NOT_IN_GROUP",
	                               "messageCode":"CONFLICT","status":409}

The two siblings on the same route both answer 404 -- USER_NOT_FOUND when the
user does not exist, GROUP_NOT_FOUND when the group does not -- which is exactly
why "the member is not in the group" being a 409 was invisible offline and only
showed up on the first live probe.
*/
const membershipAlreadyAbsentMarker = "USER_ALREADY_NOT_IN_GROUP"

/*
isMembershipAlreadyAbsent reports whether a failed RemoveGroupMember means the
pairing was already gone.

KEYED ON THE MARKER, NOT ON THE STATUS, and the status alone is emphatically not
enough. classifyAPIError maps 409 to errKindConflict and that mapping is right in
general: a 409 is the server refusing because of state, and DELETE
/v3/gum/custom-roles/{id} returns one to say the role still has users assigned.
Swallowing THAT would report a successful destroy for an object that still
exists, and the operator would find the role in the console with no resource left
in state to remove it. So isNotFound is deliberately NOT widened -- this
condition is scoped to one endpoint, in the file that owns it, and matched on the
body.

A body with no marker in it -- including an unreadable or empty one -- is not
evidence of anything and must still fail.

The comparison is case-insensitive purely for tolerance: the marker is a
distinctive SCREAMING_SNAKE token that appears nowhere else, so there is no
false-positive room, and a server that changed its case should not resurrect the
defect.

  - @param resp *http.Response - the response the SDK returned, possibly nil
  - @param err error - the error the SDK returned

@return bool
*/
func isMembershipAlreadyAbsent(resp *http.Response, err error) bool {
	if classifyAPIError(resp, err) != errKindConflict {
		return false
	}
	var apiErr *perimeter81Sdk.GenericOpenAPIError
	if !errors.As(err, &apiErr) {
		// No body to inspect, so no evidence. errors.As rather than a bare type
		// assertion so a future wrapped error still reaches the check.
		return false
	}
	return strings.Contains(strings.ToUpper(string(apiErr.Body())), membershipAlreadyAbsentMarker)
}

/*
resourceGroupMembershipImportState Import a membership from a "<groupId>:<userId>" id
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return []*schema.ResourceData, error
*/
func resourceGroupMembershipImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	// Checked here as well as in Read so that the operator's mistake is reported
	// as a malformed import argument before any request is issued, rather than
	// as whatever the API says about an id it was never meant to see.
	if _, _, err := parseGroupMembershipID(d.Id()); err != nil {
		return nil, err
	}
	diagnostics := resourceGroupMembershipRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import group membership: %s, \n %s",
					diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	// Read clears the id when the group is absent or the user is not in it; an
	// import that silently produced an empty resource would report success and
	// write nothing.
	if d.Id() == "" {
		return nil, fmt.Errorf("no such membership: the group does not exist, or that user is not a member of it")
	}
	return []*schema.ResourceData{d}, nil
}

/*
parseGroupMembershipID splits a "<groupId>:<userId>" resource id.

SplitN with n=2 rather than Split, and both halves checked non-empty, so that a
malformed import argument fails with an actionable message instead of issuing a
request against an empty path segment -- which would hit a different endpoint
entirely. url.PathEscape does not save this: an empty segment is escaped to an
empty segment, so DELETE /v3/groups//member/usr-1 is what would go out.

  - @param id string - the composite resource id

@return (string, string, error) - groupId, userId, and why the id was rejected
*/
func parseGroupMembershipID(id string) (string, string, error) {
	parts := strings.SplitN(id, groupMembershipIDSeparator, 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("group membership id %q is not in the form "+
			"<group_id>%s<user_id>", id, groupMembershipIDSeparator)
	}
	// Which half is wrong, and what it was. " grp1:usr1" and "grp1:usr1\n" are
	// both one paste away, and "invalid id" would send the operator looking at
	// the wrong end of it.
	for _, half := range []struct{ name, value string }{
		{"group_id", parts[0]},
		{"user_id", parts[1]},
	} {
		if !groupMembershipIDHalf.MatchString(half.value) {
			return "", "", fmt.Errorf("group membership id %q has an unusable %s (%q): ids are "+
				"letters, digits, underscores and hyphens only, with no surrounding whitespace",
				id, half.name, half.value)
		}
	}
	return parts[0], parts[1], nil
}
