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
usersDataSourceDefaultLimit is the page size this data source asks for when the
practitioner does not say. It is the API's own documented default for
GET /v3/users, so sending it explicitly changes nothing on the wire while making
the value visible in state and in the plan.
*/
const usersDataSourceDefaultLimit = 500

/*
usersDataSourceDefaultPage is the page this data source asks for when the
practitioner does not say.

Sent explicitly rather than left to the server: the whole reason `page` is an
argument here is L15 — three older data sources accept the server's default page
silently and drop the rest of the collection — and "whatever the server felt like
returning" is not a page number a practitioner can reason about.
*/
const usersDataSourceDefaultPage = 1

/*
dataSourceUsers Query the tenant's users

PAGINATION IS EXPOSED, NOT HIDDEN. L15 records three older data sources whose
operations accept page and limit, which pass neither and never loop, so each
silently returns one default page of a collection with no indication the rest
exists. This one takes both arguments and echoes the server's own `page`,
`total_page` and `items_total` back, so a truncated read is visible in state
rather than invisible.

THE SORT ARGUMENT IS A MAP HERE AND A STRING ON checkpointsase_groups, AND THAT
ASYMMETRY MUST NOT BE "FIXED". GET /v3/users declares sort as a deepObject
(`sort[email]=asc`) and the generated builder is Sort(map[string]string);
GET /v3/groups declares a bare string and its builder is Sort(string). Giving
either one the other's shape would fabricate query surface the server ignores.
See TestUsersDataSourceSortIsAMapAndGroupsSortIsAString.

@return &schema.Resource
*/
func dataSourceUsers() *schema.Resource {
	return &schema.Resource{
		Description: "List the members of the Check Point SASE tenant. The endpoint is " +
			"paginated and this data source does not hide it: `page` and `limit` are " +
			"arguments and the server's own `page`, `total_page` and `items_total` are " +
			"returned alongside the rows, so a partial read is visible rather than " +
			"silent. Use `checkpointsase_user` (the resource) to invite or remove a " +
			"member.",
		ReadContext: dataSourceUsersRead,
		Schema: map[string]*schema.Schema{
			"where": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Server-side filter expression, passed through to the API's `where` " +
					"query parameter verbatim. The API documents no grammar for it.",
			},
			// page IS BOTH AN ARGUMENT AND THE SERVER'S ANSWER, which is why it is
			// Optional AND Computed with no Default rather than the two separate
			// entries the task brief asked for -- two entries called "page" in one
			// map literal is a compile error, and the second of them (Computed) is
			// the one the test rows care about.
			//
			// Optional+Computed is what makes USR-05's "page reads back as 1" an
			// assertion that can fail: the value in state is the page the SERVER
			// says it served, not an echo of this provider's own default. A
			// mismatch between the two is reported as a warning by the read.
			"page": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
				Description: "Page number to fetch, starting at 1. Defaults to 1. After a read this " +
					"holds the page the server reports having served, which is not necessarily " +
					"the one that was asked for — a difference is reported as a warning.",
				ValidateFunc: validation.IntAtLeast(1),
			},
			"limit": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      usersDataSourceDefaultLimit,
				Description:  "Records per page, 1–1000. The API's own default is 500.",
				ValidateFunc: validation.IntBetween(1, 1000),
			},
			"sort": {
				Type:     schema.TypeMap,
				Optional: true,
				Description: "Sort order, as a field-to-direction map — for example " +
					"`{ email = \"asc\" }`. Each direction must be `asc` or `desc`. " +
					"Sent as `sort[email]=asc`.",
				Elem:             &schema.Schema{Type: schema.TypeString},
				ValidateDiagFunc: validateSortDirections,
			},

			// --- results ------------------------------------------------------
			// TWO FIELDS THE User MODEL CARRIES ARE DELIBERATELY ABSENT HERE, for
			// two different reasons. Both are decisions, not oversights.
			//
			// invitation_token, because it is dangerous. A data source over every
			// user in the tenant has no business handing out every pending user's
			// enrolment token, and Terraform writes data source attributes to
			// state in plaintext whatever the Sensitive marker says -- so marking
			// it would not have made it safe. checkpointsase_user (the resource)
			// does expose it, marked Sensitive, because there the scope is one
			// account the operator is managing on purpose rather than every
			// account in the tenant. TestTenantWideCollectionsExposeNoSecretAttribute
			// pins the omission, and derives it from the provider's canonical
			// secret-name list rather than from this one name.
			//
			// invitation_attempts, because it is not identity. Nothing about the
			// API forces this one out -- the resource exposes it and it is not
			// sensitive -- so it is a judgement, and the rule being kept is that
			// this row describes WHO a member is, not how their enrolment went.
			// The one question a per-row retry counter answers on a tenant-wide
			// read ("who never accepted?") is answered better by email_verified,
			// which is here. The alternative was one more integer per row in the
			// state file for every user in the tenant, consulted by almost no
			// read. Keeping the whole invitation cluster out is one rule rather
			// than two exceptions; read invitation_attempts from
			// checkpointsase_user for an account you are actually managing.
			"data": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The users on the requested page.",
				Elem: &schema.Resource{Schema: map[string]*schema.Schema{
					"id":             {Type: schema.TypeString, Computed: true, Description: "Unique identifier of the user."},
					"email":          {Type: schema.TypeString, Computed: true, Description: "Email address of the user. Empty where the account carries none — a directory-synced account can lack a `mail` attribute."},
					"email_verified": {Type: schema.TypeBool, Computed: true, Description: "Whether the user has verified their email address."},
					"username":       {Type: schema.TypeString, Computed: true, Description: "User name as the server records it."},
					"first_name":     {Type: schema.TypeString, Computed: true, Description: "Given name."},
					"last_name":      {Type: schema.TypeString, Computed: true, Description: "Family name."},
					"initials":       {Type: schema.TypeString, Computed: true, Description: "Initials the console derives from the user's name."},
					"role":           {Type: schema.TypeString, Computed: true, Description: "ID of the role assigned to the user."},
					"role_name":      {Type: schema.TypeString, Computed: true, Description: "Display name of the role assigned to the user."},
					"roles": {
						Type:        schema.TypeList,
						Computed:    true,
						Description: "Display names of every role assigned to the user, built-in and custom.",
						Elem:        &schema.Schema{Type: schema.TypeString},
					},
					"terminated": {Type: schema.TypeBool, Computed: true, Description: "Whether the account has been deleted."},
				}},
			},
			"total_page":  {Type: schema.TypeInt, Computed: true, Description: "Total number of pages available."},
			"items_total": {Type: schema.TypeInt, Computed: true, Description: "Total number of users in the tenant."},
		},
	}
}

/*
dataSourceUsersRead Use the SDK to query one page of /v3/users
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func dataSourceUsersRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	where := d.Get("where").(string)
	limit := d.Get("limit").(int)
	// page is Optional+Computed, so d.Get returns 0 when the configuration omits
	// it and the value in state is the server's answer from a previous read.
	// GetOk is not usable either -- it reports false for a stored 0 AND for a
	// legitimately configured value it considers a zero value -- so the default
	// is applied here rather than by the schema.
	page := usersDataSourceDefaultPage
	if raw, ok := d.GetOk("page"); ok {
		page = raw.(int)
	}
	sortOrder := expandSortDirections(d.Get("sort"))

	request := client.TeamAPI.ListUsers(ctx).
		Page(int32(page)).
		Limit(int32(limit))
	if where != "" {
		request = request.Where(where)
	}
	if len(sortOrder) > 0 {
		// Reaches the wire as sort[email]=asc only because of the deepObject fix
		// in the SDK's client.go; before it, this map went out as
		// ?sort=map[email:asc] and the server ignored it entirely. Pinned offline
		// by TestUsersDataSourceSendsSortAsADeepObject.
		request = request.Sort(sortOrder)
	}

	users, _, err := request.Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, fmt.Sprintf(
			"Unable to get users (page %d, limit %d)", page, limit), err)
	}
	if users == nil {
		// A 2xx whose body decodes to JSON null leaves the SDK returning a nil
		// pointer with no error, and every field access below would panic --
		// a provider crash with a stack trace instead of a diagnostic.
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to get users",
			fmt.Errorf("GET /v3/users returned a success status with no body to read"))
	}

	if err := d.Set("data", flattenUsersData(users.Data)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set users data", err)
	}
	for key, value := range map[string]interface{}{
		"page":        int(users.Page),
		"total_page":  int(users.TotalPage),
		"items_total": int(users.ItemsTotal),
	} {
		if err := d.Set(key, value); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set users "+key, err)
		}
	}
	// A server that ignores `page` returns page 1 forever, which is L15's defect
	// with the argument present rather than absent. Saying so is the whole value
	// of echoing the server's own number back instead of the requested one.
	if int(users.Page) != page {
		diags = appendWarningDiags(diags,
			"The users page returned is not the page requested",
			fmt.Sprintf("GET /v3/users was asked for page %d and reported serving page %d. "+
				"`data` holds the page the server served, not the one requested.",
				page, users.Page))
	}

	// A stable ID, not a timestamp (L16c). It is DERIVED FROM THE ARGUMENTS
	// rather than constant, which is the mirror-image defect
	// testAccCheckDataSourceIDsDiffer exists for: a data source that takes
	// filters and hardcodes one ID gives two instances holding different results
	// the same identity. Same construction as
	// updatableObjectsDataSourceID.
	d.SetId(usersDataSourceID(where, page, limit, sortOrder))
	return diags
}

/*
usersDataSourceID returns a stable ID for one configuration of this data source.
The same arguments always produce the same ID, and different arguments produce
different ones.
*/
func usersDataSourceID(where string, page, limit int, sortOrder map[string]string) string {
	const base = "checkpointsase_users"
	if where == "" && page == usersDataSourceDefaultPage &&
		limit == usersDataSourceDefaultLimit && len(sortOrder) == 0 {
		return base
	}
	return base + "-" + dataSourceArgumentDigest(
		"where="+where,
		fmt.Sprintf("page=%d", page),
		fmt.Sprintf("limit=%d", limit),
		"sort="+canonicalSortDirections(sortOrder),
	)
}

/*
flattenUsersData flattens the User SDK models into a Terraform list.

DELIBERATELY HERE AND NOT IN utils.go, which is where the task brief's file list
put it -- see the matching note on flattenGroupsData for the reasoning. One
caller, and data_source_web_categories.go sets the precedent.

EVERY FIELD GOES THROUGH A NIL-SAFE Get* ACCESSOR, WITHOUT EXCEPTION, email
included. Overlay entry A21b removes User.required ENTIRELY rather than trimming
it, because a directory-synced account can lack a `mail` attribute, so every
scalar on the generated model is a pointer and assigning one directly would put a
Go address into Terraform state.

invitation_token is absent from the map because it is absent from the schema; see
the comment on `data` in dataSourceUsers.

The Roles coercion goes through coerceNilStringsToEmpty, the same helper
flattenGroupsData uses for its four lists; it was three hand-rolled lines here
until 2026-08-20, which is one implementation of one idea too many.

THE COERCION IS BELT-AND-BRACES RATHER THAN LOAD-BEARING: measured 2026-08-20,
schema.ResourceData.Set normalises a nil slice to an empty list on its own,
including for a list nested inside a list element, so state holds [] with or
without it. It is kept because it makes the intent legible where Roles is
omitempty and nil is routine. Do not write a comment or a test claiming state
would hold a null without it -- three assertions in this phase were built on that
belief and all three have been corrected, the last of them a test that could not
fail.
*/
func flattenUsersData(users []perimeter81Sdk.User) []interface{} {
	result := make([]interface{}, len(users))
	for i, user := range users {
		result[i] = map[string]interface{}{
			"id":             user.GetId(),
			"email":          user.GetEmail(),
			"email_verified": user.GetEmailVerified(),
			"username":       user.GetUsername(),
			"first_name":     user.GetFirstName(),
			"last_name":      user.GetLastName(),
			"initials":       user.GetInitials(),
			"role":           user.GetRole(),
			"role_name":      user.GetRoleName(),
			"roles":          coerceNilStringsToEmpty(user.Roles),
			"terminated":     user.GetTerminated(),
		}
	}
	return result
}
