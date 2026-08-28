package checkpointsase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	// updatableObjectsPageSize is the largest page the endpoint documents:
	// `limit` is `minimum: 1, maximum: 1000` and the response's `data` array is
	// `maxItems: 1000`. Asking for the maximum keeps the number of round trips
	// to the minimum the API allows.
	updatableObjectsPageSize = 1000

	// updatableObjectsMaxPages bounds the paging loop. At the page size above
	// that is 500,000 objects, orders of magnitude more than the Check Point
	// updatable-object catalog holds. It exists so that a server which returns
	// a full page forever cannot hang a plan; reaching it produces a warning
	// rather than a silent stop.
	updatableObjectsMaxPages = 500
)

/*
dataSourceUpdatableObjects Query the Check Point updatable objects catalog

This is the only one of the three Objects catalogs with a query surface, and the
only one that is paginated. Both facts are handled deliberately here.

# Why page and limit are not arguments

L15 records three existing data sources (`applications`, `enhanced_tunnels`,
`enhanced_route_table`) whose operations accept page and limit, which pass
neither and never loop, and so silently return whatever one default page holds.
`enhanced_tunnels` is the worst of them: it writes total_page into state while
ignoring it, so state can claim total_page = 4 next to a list holding one page.

This data source loops to exhaustion instead, so page and limit would be
meaningless as arguments — there is only ever one answer, the whole filtered set.
`items_total` is exposed so the completeness of the result is checkable rather
than assumed: after an exhaustive read it must equal the length of
`updatable_objects`, and the read emits a warning when it does not. `page` and
`total_page` are deliberately NOT exposed, because after paging to exhaustion
they describe the last request rather than the result, which is exactly the
metadata-contradicts-data defect L15 calls out.

@return &schema.Resource
*/
func dataSourceUpdatableObjects() *schema.Resource {
	return &schema.Resource{
		Description: "List the Check Point updatable objects available to this tenant — the " +
			"externally-maintained address groups (cloud provider ranges, SaaS endpoints " +
			"and similar) that Split Tunneling and Internet Access policy can reference. " +
			"The endpoint is paginated; this data source pages through to exhaustion, so " +
			"`updatable_objects` always holds the complete filtered set and there is no " +
			"`page` or `limit` argument. Compare `items_total` with the length of " +
			"`updatable_objects` to confirm nothing was missed.",
		ReadContext: dataSourceUpdatableObjectsRead,
		Schema: map[string]*schema.Schema{
			// --- filters, passed straight through to the query string ---------
			"name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Return only updatable objects whose name matches this value.",
			},
			"cp_id": {
				Type:     schema.TypeList,
				Optional: true,
				Description: "Return only updatable objects whose Check Point object ID is in " +
					"this list. The endpoint documents a maximum of 100 entries.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"type": {
				Type:     schema.TypeString,
				Optional: true,
				// Deliberately NOT constrained with validation.StringInSlice.
				// The v3 OpenAPI document declares the enum
				// splitTunneling/internetAccess, but perimeter81-public-api's
				// own UpdatableObjectsController describes the same parameter as
				// "type (ST or SWG)" and its response type object as {ST, SWG}.
				// Neither repo is authoritative for the /v3 route — the
				// controller there is registered for v2.3 and proxies the
				// request through verbatim — and the two vocabularies could not
				// be told apart without a live call. Refusing one of them at
				// plan time could lock a practitioner out of the spelling the
				// server actually takes, and an unrecognised value costs only an
				// immediate 400 on a read that creates nothing.
				Description: "Return only updatable objects compatible with one feature " +
					"category. The API documents `splitTunneling` and `internetAccess`. " +
					"Not validated locally: perimeter81-public-api describes the same " +
					"parameter as `ST`/`SWG`, and the provider does not claim to know " +
					"which spelling the server takes. An unrecognised value is rejected " +
					"by the server on the read.",
			},
			"sort": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Sort the results by a field and order, in the form the API " +
					"documents for its `sort` query parameter.",
			},

			// --- results ------------------------------------------------------
			"items_total": {
				Type:     schema.TypeInt,
				Computed: true,
				Description: "The total number of updatable objects matching the filters. Because " +
					"this data source pages to exhaustion, the server's own total must equal " +
					"the length of `updatable_objects`; a mismatch means the catalog changed " +
					"mid-read and is reported as a warning. The endpoint's schema makes the " +
					"total optional, so where the response omits it this is the number of " +
					"rows read rather than a zero that would contradict the list beside it.",
			},
			"updatable_objects": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The complete list of matching updatable objects.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cp_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The Check Point object ID of the updatable object.",
						},
						"vendor_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The vendor identifier of the updatable object.",
						},
						"vendor_parent_id": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "The vendor identifier of this object's parent, for the " +
								"hierarchical catalogs. Empty for a top-level object.",
						},
						"vendor_children_ids": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "The vendor identifiers of this object's children.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The display name of the updatable object.",
						},
						"inherit_description": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Whether this object inherits its description from its parent.",
						},
						"inherit_info_text": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Whether this object inherits its info text from its parent.",
						},
						"inherit_info_url": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Whether this object inherits its info URL from its parent.",
						},
						"data_objects_count": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "The number of data objects (address ranges) this updatable object resolves to.",
						},
						"split_tunneling": {
							Type:     schema.TypeBool,
							Computed: true,
							Description: "Whether this object can be used in Split Tunneling " +
								"configuration. Read from the response's `type` object; `false` " +
								"means the server did not report the object as compatible, which " +
								"is not distinguishable from the field being absent.",
						},
						"internet_access": {
							Type:     schema.TypeBool,
							Computed: true,
							Description: "Whether this object can be used in Internet Access policy. " +
								"Read from the response's `type` object; `false` means the server " +
								"did not report the object as compatible, which is not " +
								"distinguishable from the field being absent.",
						},
					},
				},
			},
		},
	}
}

/*
dataSourceUpdatableObjectsRead Use the SDK to query every page of the updatable objects catalog
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func dataSourceUpdatableObjectsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	name := d.Get("name").(string)
	objectType := d.Get("type").(string)
	sort := d.Get("sort").(string)
	cpIDs := flattenStringsArrayData(d.Get("cp_id").([]interface{}))

	var (
		rows []perimeter81Sdk.GetUpdatableObjects200ResponseDataInner
		seen = map[string]bool{}

		itemsTotal int32
		// The response model makes every field an optional pointer, itemsTotal
		// included, so "the server said 0" and "the server said nothing" are
		// different facts and only the first can be cross-checked against the
		// rows read.
		itemsTotalReported bool

		lastPage int32
		// Whether the loop stopped because it ran out of pages rather than
		// because it ran out of iterations. Checking lastPage against the
		// maximum instead would misreport a catalog whose last page happens to
		// be exactly updatableObjectsMaxPages.
		exhausted bool
	)

	for page := int32(1); page <= updatableObjectsMaxPages; page++ {
		request := client.ObjectsAPI.GetUpdatableObjects(ctx).
			Page(page).
			Limit(updatableObjectsPageSize)
		if name != "" {
			request = request.Name(name)
		}
		if objectType != "" {
			request = request.Type_(objectType)
		}
		if sort != "" {
			request = request.Sort(sort)
		}
		if len(cpIDs) > 0 {
			request = request.CpId(cpIDs)
		}

		response, _, err := request.Execute()
		if err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, fmt.Sprintf(
				"Unable to get updatable objects (page %d, limit %d)",
				page, updatableObjectsPageSize), err)
		}
		lastPage = page

		// itemsTotal describes the whole filtered set, so the first page's value
		// is the one to keep: a later page's value would be a second, possibly
		// newer reading of the same number and comparing it against rows
		// gathered across every page would confuse a mid-read change with a
		// paging bug.
		if page == 1 {
			if total, ok := response.GetItemsTotalOk(); ok && total != nil {
				itemsTotal, itemsTotalReported = *total, true
			}
		}

		if len(response.Data) == 0 {
			exhausted = true
			break
		}

		// The endpoint's page parameter has never been exercised live from this
		// provider, so the loop verifies rather than assumes it works. A server
		// that ignored page would return page 1 forever, and the loop would
		// append the same rows until updatableObjectsMaxPages — turning an
		// unexercised parameter into a plan that appears to hang and state full
		// of duplicates. Progress is therefore checked BEFORE the rows are
		// kept.
		if page > 1 && countNewUpdatableObjects(response.Data, seen) == 0 {
			diags = appendWarningDiags(diags,
				"Updatable objects pagination made no progress",
				fmt.Sprintf("Page %d of /v3/objects/updatable-objects returned %d rows, none of "+
					"them new. The server appears to be ignoring the page parameter. Reading "+
					"stopped with %d object(s); the server reports %s in total. Treat "+
					"updatable_objects as incomplete.",
					page, len(response.Data), len(rows),
					reportedTotalForMessage(itemsTotal, itemsTotalReported)))
			break
		}
		for _, row := range response.Data {
			seen[updatableObjectKey(row)] = true
		}
		rows = append(rows, response.Data...)

		// Prefer the server's own page count. Falling back to a short page is
		// only needed if totalPage is absent, which the model permits: every
		// field on GetUpdatableObjects200Response is an optional pointer.
		if totalPage, ok := response.GetTotalPageOk(); ok {
			if page >= *totalPage {
				exhausted = true
				break
			}
		} else if len(response.Data) < updatableObjectsPageSize {
			exhausted = true
			break
		}
	}

	if !exhausted && lastPage >= updatableObjectsMaxPages {
		diags = appendWarningDiags(diags,
			"Updatable objects read hit its page limit",
			fmt.Sprintf("Stopped after %d pages of %d, holding %d object(s). The server reports "+
				"%s in total. Treat updatable_objects as incomplete.",
				updatableObjectsMaxPages, updatableObjectsPageSize, len(rows),
				reportedTotalForMessage(itemsTotal, itemsTotalReported)))
	}

	// The cross-check only means something when the server supplied a total.
	// Where it did not, items_total falls back to the number of rows read rather
	// than to a hardcoded 0 that would contradict the list beside it — the
	// metadata-contradicts-data shape L15 objects to — and there is no warning,
	// because a missing total degrades a diagnostic rather than truncating the
	// result: the loop terminates on totalPage or on a short page either way,
	// and the no-progress guard above covers a server that ignores page.
	if itemsTotalReported {
		if itemsTotal != int32(len(rows)) {
			diags = appendWarningDiags(diags,
				"Updatable objects count disagrees with the server's total",
				fmt.Sprintf("Read %d object(s) across %d page(s), but the server reported "+
					"itemsTotal = %d. This data source pages to exhaustion, so the two should "+
					"agree; a difference usually means the catalog changed between page "+
					"requests. Re-run to get a consistent read.",
					len(rows), lastPage, itemsTotal))
		}
	} else {
		itemsTotal = int32(len(rows))
	}

	if err := d.Set("updatable_objects", flattenUpdatableObjects(rows)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set updatable objects data", err)
	}
	if err := d.Set("items_total", int(itemsTotal)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set updatable objects items_total", err)
	}

	// A stable ID, not a timestamp (L16c). Unlike the two unparameterised
	// catalogs, two instances of this data source can hold different results,
	// so the ID is derived from the filters: constant for a given
	// configuration, distinct between configurations. The digest keeps it short
	// when cp_id carries up to 100 IDs.
	d.SetId(updatableObjectsDataSourceID(name, objectType, sort, cpIDs))
	return diags
}

/*
reportedTotalForMessage renders itemsTotal for a warning message, distinguishing
a server that said zero from a server that said nothing. Both would print as "0"
otherwise, which would send a reader looking for a truncation that never
happened.
*/
func reportedTotalForMessage(itemsTotal int32, reported bool) string {
	if !reported {
		return "no total (the response omitted itemsTotal)"
	}
	return strconv.FormatInt(int64(itemsTotal), 10)
}

/*
updatableObjectKey builds a per-row identity used only to detect a page that
repeats rows already read. Every field on the model is an optional pointer, so
no single one can be relied on: the key concatenates the three that identify an
object, and a row where all three are absent contributes an empty key, which
still compares correctly.
*/
func updatableObjectKey(row perimeter81Sdk.GetUpdatableObjects200ResponseDataInner) string {
	return strings.Join([]string{row.GetCpId(), row.GetVendorId(), row.GetName()}, "\x00")
}

/*
countNewUpdatableObjects reports how many of the rows have not been read already.
*/
func countNewUpdatableObjects(rows []perimeter81Sdk.GetUpdatableObjects200ResponseDataInner, seen map[string]bool) int {
	fresh := 0
	for _, row := range rows {
		if !seen[updatableObjectKey(row)] {
			fresh++
		}
	}
	return fresh
}

/*
updatableObjectsDataSourceID returns a stable ID for one configuration of this
data source. The same filters always produce the same ID, and different filters
produce different ones.
*/
func updatableObjectsDataSourceID(name, objectType, sort string, cpIDs []string) string {
	const base = "checkpointsase_updatable_objects"
	if name == "" && objectType == "" && sort == "" && len(cpIDs) == 0 {
		return base
	}
	canonical := strings.Join([]string{
		"name=" + name,
		"type=" + objectType,
		"sort=" + sort,
		"cp_id=" + strings.Join(cpIDs, ","),
	}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	return base + "-" + hex.EncodeToString(digest[:6])
}

/*
flattenUpdatableObjects flattens the GetUpdatableObjects200ResponseDataInner SDK
models into a Terraform list.

Every field on the model is an optional pointer, so the Get* accessors are used
throughout: they return the zero value for an absent field, which is what
Terraform stores anyway. That makes "absent" and "present and zero"
indistinguishable in state for the booleans and for data_objects_count; the
attribute descriptions say so rather than the provider pretending otherwise.

The response's nested `type` object is flattened into two sibling booleans
rather than a one-element nested block. It carries exactly two documented
fields, and a MaxItems-1 wrapper would force practitioners to write
`o.type[0].split_tunneling` for no gain.
*/
func flattenUpdatableObjects(rows []perimeter81Sdk.GetUpdatableObjects200ResponseDataInner) []interface{} {
	result := make([]interface{}, len(rows))
	for i, row := range rows {
		children := row.GetVendorChildrenIds()
		if children == nil {
			children = []string{}
		}
		result[i] = map[string]interface{}{
			"cp_id":               row.GetCpId(),
			"vendor_id":           row.GetVendorId(),
			"vendor_parent_id":    row.GetVendorParentId(),
			"vendor_children_ids": children,
			"name":                row.GetName(),
			"inherit_description": row.GetInheritDescription(),
			"inherit_info_text":   row.GetInheritInfoText(),
			"inherit_info_url":    row.GetInheritInfoUrl(),
			"data_objects_count":  int(row.GetDataObjectsCount()),
			"split_tunneling":     updatableObjectTypeFlag(row.Type, "splitTunneling", "ST"),
			"internet_access":     updatableObjectTypeFlag(row.Type, "internetAccess", "SWG"),
		}
	}
	return result
}

/*
updatableObjectTypeFlag reads one feature-compatibility flag out of an updatable
object's `type` object, accepting either of the two spellings the field is
documented with.

This is not defensive padding. The v3 OpenAPI document — and therefore the
generated model — declares `type` as `{splitTunneling, internetAccess}`, both
optional booleans. perimeter81-public-api's own UpdatableObject interface
declares the same field as `{ST, SWG}`. The controller there does not transform
the payload (ObjectsService.listUpdatableObjects casts the upstream JSON and
returns it verbatim), so nothing in either repo settles which keys reach the
wire, and both models permit the other's keys: the schema is
`additionalProperties: true`, so the generated struct routes unknown keys into
AdditionalProperties instead of failing.

The failure mode this avoids is silent, which is why it is worth the fifteen
lines: had the flatten read only the typed fields, an ST/SWG response would have
left both booleans false for every object in the catalog and looked exactly like
a catalog where nothing is compatible with anything.
*/
func updatableObjectTypeFlag(objectType *perimeter81Sdk.GetUpdatableObjects200ResponseDataInnerType, canonicalKey, legacyKey string) bool {
	if objectType == nil {
		return false
	}

	switch canonicalKey {
	case "splitTunneling":
		if value, ok := objectType.GetSplitTunnelingOk(); ok && value != nil {
			return *value
		}
	case "internetAccess":
		if value, ok := objectType.GetInternetAccessOk(); ok && value != nil {
			return *value
		}
	}

	if value, ok := objectType.AdditionalProperties[legacyKey].(bool); ok {
		return value
	}
	return false
}
