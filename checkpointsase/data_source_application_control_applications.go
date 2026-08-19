package checkpointsase

import (
	"context"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
dataSourceApplicationControlApplications Query the Application Control catalog

GET /v3/objects/application-control/application takes no parameters other than
the auth header — no page, no limit, no sort, no filter. Exposing any would
invent surface the server ignores, so this is a plain list read.

Not to be confused with the checkpointsase_applications data source, which lists
the Application Access applications a tenant has created. This one is a
read-only product catalog of the applications Application Control can recognise;
nothing a tenant does changes it.

@return &schema.Resource
*/
func dataSourceApplicationControlApplications() *schema.Resource {
	return &schema.Resource{
		Description: "List the applications Check Point SASE's Application Control can " +
			"recognise, for use in Internet Access (SWG) policy. This is a read-only " +
			"product catalog and is the same for every tenant — it is not the list of " +
			"Application Access applications a tenant has created, which is " +
			"`checkpointsase_applications`. The endpoint accepts no filter or pagination " +
			"parameters, so this data source returns the whole catalog in one read.",
		ReadContext: dataSourceApplicationControlApplicationsRead,
		Schema: map[string]*schema.Schema{
			"applications": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The list of Application Control applications.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The unique ID of the Application Control application.",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The display name of the Application Control application.",
						},
					},
				},
			},
		},
	}
}

/*
dataSourceApplicationControlApplicationsRead Use the SDK to query the Application Control catalog
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func dataSourceApplicationControlApplicationsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	applications, _, err := client.ObjectsAPI.GetApplicationControlApplications(ctx).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to get Application Control applications", err)
	}

	if err := d.Set("applications", flattenApplicationControlApplications(applications.Data)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Application Control applications data", err)
	}

	// A stable ID, not a timestamp — see L16c, and the comment in
	// dataSourceWebCategoriesRead.
	d.SetId("checkpointsase_application_control_applications")
	return diags
}

/*
flattenApplicationControlApplications flattens the ApplicationControlApplication
SDK models into a Terraform list.

Id and Name are both non-pointer required fields, and
ApplicationControlApplication.UnmarshalJSON enforces their presence, so a
response missing either fails to decode before this function runs.
*/
func flattenApplicationControlApplications(applications []perimeter81Sdk.ApplicationControlApplication) []interface{} {
	result := make([]interface{}, len(applications))
	for i, application := range applications {
		result[i] = map[string]interface{}{
			"id":   application.Id,
			"name": application.Name,
		}
	}
	return result
}
