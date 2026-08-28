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
groupsDataSourceDefaultLimit and groupsDataSourceDefaultPage mirror
checkpointsase_users. 500 is the API's own documented default page size for
GET /v3/groups, so sending it explicitly changes nothing on the wire while making
the value visible in state and in the plan.
*/
const (
	groupsDataSourceDefaultLimit = 500
	groupsDataSourceDefaultPage  = 1
)

/*
dataSourceGroups Query the tenant's access groups

DELIBERATELY NOT SYMMETRIC WITH checkpointsase_users, in two ways, because the
two endpoints are not:

  - `sort` IS A PLAIN STRING HERE. GET /v3/groups documents it as a bare "Sort
    order" and the generated builder is Sort(string); GET /v3/users declares a
    deepObject and its builder is Sort(map[string]string). Harmonising them would
    fabricate query surface one side of the API ignores. See
    TestUsersDataSourceSortIsAMapAndGroupsSortIsAString.
  - THERE IS NO `where` ARGUMENT, because the operation declares no such
    parameter.

THERE IS ALSO NO `description` ATTRIBUTE, and that is not an omission.
perimeter-81-client-sdk/model_group.go declares exactly seven fields -- name,
isDefault, applications, networks, vpnLocations, users, id -- and no description
among them. CreateGroupDto accepts one on the way in and nothing ever returns it
(API-FINDINGS.md 1.7), so an attribute here could only ever read back empty. The
task brief lists it; the generated model wins.

Pagination is exposed rather than hidden, for the reason recorded on
dataSourceUsers and in L15.

@return &schema.Resource
*/
func dataSourceGroups() *schema.Resource {
	return &schema.Resource{
		Description: "List the access groups in the Check Point SASE tenant. The endpoint is " +
			"paginated and this data source does not hide it: `page` and `limit` are " +
			"arguments and the server's own `page`, `total_page` and `items_total` are " +
			"returned alongside the rows. There is no `description` attribute — the API's " +
			"group read model carries no such field, so nothing could be reported into " +
			"it. Use `checkpointsase_group` (the resource) to create or remove a group.",
		ReadContext: dataSourceGroupsRead,
		Schema: map[string]*schema.Schema{
			// Optional AND Computed, with no Default, for the same reason as
			// checkpointsase_users.page: the argument and the server's answer are
			// one attribute, so what lands in state is the page the SERVER says it
			// served. Two map entries called "page" would not compile, and the
			// Computed one is the half GRP-07 asserts on.
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
				Default:      groupsDataSourceDefaultLimit,
				Description:  "Records per page, 1–1000. The API's own default is 500.",
				ValidateFunc: validation.IntBetween(1, 1000),
			},
			"sort": {
				Type:     schema.TypeString,
				Optional: true,
				// NO ValidateFunc, DELIBERATELY. The API documents this parameter
				// as "Sort order" and nothing else: no field list, no direction
				// vocabulary, no grammar. checkpointsase_users can validate its
				// sort because that one is an object of asc/desc enums, which is a
				// documented rule. Inventing one here -- guessing at "name:asc",
				// "name asc" or "-name" -- would refuse a spelling the server
				// takes and lock a practitioner out of it at plan time, for no
				// gain: an unrecognised value costs an immediate 400 on a read
				// that creates nothing. Same reasoning as
				// checkpointsase_updatable_objects.type.
				Description: "Sort order, passed through to the API's `sort` query parameter " +
					"verbatim. Not validated locally: the API documents no grammar for it, " +
					"so refusing a value here would be a guess. Note this is a plain " +
					"string, unlike `checkpointsase_users.sort`, which the API declares as " +
					"a field-to-direction object.",
			},

			// --- results ------------------------------------------------------
			"data": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The groups on the requested page.",
				Elem: &schema.Resource{Schema: map[string]*schema.Schema{
					"id":         {Type: schema.TypeString, Computed: true, Description: "Unique identifier of the group."},
					"name":       {Type: schema.TypeString, Computed: true, Description: "Name of the group."},
					"is_default": {Type: schema.TypeBool, Computed: true, Description: "Whether this is the tenant's default group."},
					"applications": {
						Type:        schema.TypeList,
						Computed:    true,
						Description: "IDs of the applications this group has access to.",
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
						Description: "IDs of the group's members. Managed with `checkpointsase_group_membership`.",
						Elem:        &schema.Schema{Type: schema.TypeString},
					},
				}},
			},
			"total_page":  {Type: schema.TypeInt, Computed: true, Description: "Total number of pages available."},
			"items_total": {Type: schema.TypeInt, Computed: true, Description: "Total number of groups in the tenant."},
		},
	}
}

/*
dataSourceGroupsRead Use the SDK to query one page of /v3/groups
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func dataSourceGroupsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	limit := d.Get("limit").(int)
	sortOrder := d.Get("sort").(string)
	// See the same block in dataSourceUsersRead for why the default is applied
	// here rather than by the schema.
	page := groupsDataSourceDefaultPage
	if raw, ok := d.GetOk("page"); ok {
		page = raw.(int)
	}

	request := client.TeamAPI.ListGroups(ctx).
		Page(int32(page)).
		Limit(int32(limit))
	if sortOrder != "" {
		request = request.Sort(sortOrder)
	}

	groups, _, err := request.Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, fmt.Sprintf(
			"Unable to get groups (page %d, limit %d)", page, limit), err)
	}
	if groups == nil {
		// A 2xx whose body decodes to JSON null leaves the SDK returning a nil
		// pointer with no error; every field access below would panic.
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to get groups",
			fmt.Errorf("GET /v3/groups returned a success status with no body to read"))
	}

	if err := d.Set("data", flattenGroupsData(groups.Data)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set groups data", err)
	}
	for key, value := range map[string]interface{}{
		"page":        int(groups.Page),
		"total_page":  int(groups.TotalPage),
		"items_total": int(groups.ItemsTotal),
	} {
		if err := d.Set(key, value); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to set groups "+key, err)
		}
	}
	if int(groups.Page) != page {
		diags = appendWarningDiags(diags,
			"The groups page returned is not the page requested",
			fmt.Sprintf("GET /v3/groups was asked for page %d and reported serving page %d. "+
				"`data` holds the page the server served, not the one requested.",
				page, groups.Page))
	}

	// Derived from the arguments, not constant -- see the note on
	// usersDataSourceID.
	d.SetId(groupsDataSourceID(page, limit, sortOrder))
	return diags
}

/*
groupsDataSourceID returns a stable ID for one configuration of this data source.
*/
func groupsDataSourceID(page, limit int, sortOrder string) string {
	const base = "checkpointsase_groups"
	if page == groupsDataSourceDefaultPage && limit == groupsDataSourceDefaultLimit && sortOrder == "" {
		return base
	}
	return base + "-" + dataSourceArgumentDigest(
		fmt.Sprintf("page=%d", page),
		fmt.Sprintf("limit=%d", limit),
		"sort="+sortOrder,
	)
}

/*
flattenGroupsData flattens the Group SDK models into a Terraform list.

DELIBERATELY HERE AND NOT IN utils.go, which is where the task brief's file list
put it. It has exactly one caller, and data_source_web_categories.go -- the newest
data source and the one this pair is modelled on -- keeps flattenWebCategories
beside its own read for the same reason. utils.go is past 1900 lines and is for
things more than one file needs; the six helpers this task genuinely shares
(validateSortDirections, expandSortDirections, canonicalSortDirections,
sortedMapKeys, dataSourceArgumentDigest, coerceNilStringsToEmpty) did go there.

Every field goes through a nil-safe Get* accessor: overlay entry A22b removes
Group.required ENTIRELY, so a record may carry nothing but an id and every scalar
on the generated model is a pointer.

THERE IS NO description KEY, because there is no such field on the model and no
such attribute in the schema; see the note on dataSourceGroups.

The four list coercions are belt-and-braces rather than load-bearing, exactly as
in flattenUsersData and flattenWebCategories: schema.ResourceData.Set normalises a
nil slice to an empty list by itself (measured 2026-08-20), including for a list
nested inside a list element. They are kept because all four fields are omitempty
and nil is the routine case for a group with no projections, so saying so at the
point of use is worth four lines.

THE TEST THAT ACTUALLY GUARDS THIS FUNCTION IS
TestFlattenGroupsDataCoercesNilLists, and it is worth knowing why. The
"applications" key was deleted from the map below as an experiment on 2026-08-20:
every EMPTINESS assertion on state still passed, because d.Set fills a schema key
the flatten function omitted with the zero value and `data.0.applications.# = 0`
appears either way. Only the test that inspects THIS FUNCTION'S RETURN VALUE
caught it, reporting `"applications" is absent from the flattened row`.

TestGroupsDataSourceReadEchoesTheServersPagination now catches it too, and the
difference is instructive: its fixture was changed from a group with no
projections to one carrying four DISTINCT NON-EMPTY lists, so it asserts contents
rather than emptiness. Under the same key deletion it reports
`data.0.applications.# = "0", want "2" -- the flatten function is not carrying
this list through`. So if a key here needs covering, cover it against known
contents; an emptiness check on state cannot see a dropped key at all, and three
assertions in this phase were written before that was understood.
*/
func flattenGroupsData(groups []perimeter81Sdk.Group) []interface{} {
	result := make([]interface{}, len(groups))
	for i, group := range groups {
		result[i] = map[string]interface{}{
			"id":            group.GetId(),
			"name":          group.GetName(),
			"is_default":    group.GetIsDefault(),
			"applications":  coerceNilStringsToEmpty(group.Applications),
			"networks":      coerceNilStringsToEmpty(group.Networks),
			"vpn_locations": coerceNilStringsToEmpty(group.VpnLocations),
			"users":         coerceNilStringsToEmpty(group.Users),
		}
	}
	return result
}
