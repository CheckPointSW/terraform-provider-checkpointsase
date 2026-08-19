package checkpointsase

import (
	"context"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
dataSourceWebCategories Query the Web category catalog

GET /v3/objects/web-category takes no parameters at all: no page, no limit, no
sort, no filter. That is not an omission in this data source — the operation in
the OpenAPI document declares exactly one parameter, the auth header, so
exposing pagination or a filter here would invent surface the server ignores.

@return &schema.Resource
*/
func dataSourceWebCategories() *schema.Resource {
	return &schema.Resource{
		Description: "List the Web categories Check Point SASE recognises, for use in " +
			"Internet Access (SWG) policy. This is a read-only product catalog: it is " +
			"the same for every tenant and no tenant operation adds to or removes from " +
			"it. The endpoint accepts no filter or pagination parameters, so this data " +
			"source returns the whole catalog in one read.",
		ReadContext: dataSourceWebCategoriesRead,
		Schema: map[string]*schema.Schema{
			"web_categories": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The list of Web categories.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The unique ID of the Web category.",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The display name of the Web category.",
						},
						"codes": {
							Type:     schema.TypeList,
							Computed: true,
							Description: "The Web category code identifiers. A category can map to " +
								"more than one code, so this is a list rather than a single value.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
		},
	}
}

/*
dataSourceWebCategoriesRead Use the SDK to query the Web category catalog
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func dataSourceWebCategoriesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	categories, _, err := client.ObjectsAPI.GetWebCategories(ctx).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to get Web categories", err)
	}

	if err := d.Set("web_categories", flattenWebCategories(categories.Data)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set Web categories data", err)
	}

	// A stable ID, not a timestamp. L16c records that fifteen of the sixteen
	// data sources written before this one use time.Now(), which changes on
	// every read and so defeats any downstream reference to the data source's
	// own id. The catalog takes no arguments, so one instance of this data
	// source is interchangeable with any other and a constant is honest.
	d.SetId("checkpointsase_web_categories")
	return diags
}

/*
flattenWebCategories flattens the WebCategory SDK models into a Terraform list.

Id and Name are non-pointer required fields on the model and
WebCategory.UnmarshalJSON enforces their presence, so a response omitting either
fails to decode before this function is reached and both keys are written
unconditionally.

CODES IS DIFFERENT, AND THE NIL CHECK BELOW IS LOAD-BEARING — DO NOT REMOVE IT.
The v3 document declares codes required too, but the server does not send it:
measured live on 2026-08-19, GET /v3/objects/web-category returned a full
catalog in which every entry carried exactly id and name and the string "codes"
appeared nowhere (e.g. {"id":"100000034","name":"Real Estate"}). While codes was
in the generated requiredProperties list that response failed to decode
ENTIRELY, and this data source reported "Unable to get Web categories" on a
valid 200. Overlay entry A20-web-category-codes-not-required makes it optional
in the SDK, which is the layer the defect is in; the consequence here is that
Codes is nil on every real response today, so coercing it to an empty []string
is what puts a list rather than a null into state.
TestWebCategoryDecodesWithoutCodes pins all of this.
*/
func flattenWebCategories(categories []perimeter81Sdk.WebCategory) []interface{} {
	result := make([]interface{}, len(categories))
	for i, category := range categories {
		codes := category.Codes
		if codes == nil {
			codes = []string{}
		}
		result[i] = map[string]interface{}{
			"id":    category.Id,
			"name":  category.Name,
			"codes": codes,
		}
	}
	return result
}
