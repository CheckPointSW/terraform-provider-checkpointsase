package checkpointsase

import (
	"context"
	"fmt"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

/*
resourceObjectAddressesCustomizeDiff enforces two plan-time rules ValidateFunc
cannot express because they need value_type, a sibling attribute: the value
list's element count must match what value_type allows (exactly 1 for `ip` /
`cidr` / `fqdn`, 1+ for `list`), and a `cidr` entry's value must be a
well-formed CIDR block, matching the guard network.subnet already has via
validation.IsCIDR. Without this, both gaps let a bad configuration through
`terraform plan` and on to the server, which returns a 422.

Mirrors resourceObjectServicesCustomizeDiff's use of GetRawConfig; unlike that
resource's protocols list of blocks, value_type and value are plain top-level
attributes here, so no per-element raw-config fallback is needed.
*/
func resourceObjectAddressesCustomizeDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	rawConfig := d.GetRawConfig()
	if rawConfig.IsNull() {
		return nil
	}

	valueTypeVal := rawConfig.GetAttr("value_type")
	valueVal := rawConfig.GetAttr("value")
	// IsKnown, not IsWhollyKnown: a list's own length is known even when one
	// of its elements is an unresolved interpolation, so the count check
	// below must not be skipped just because a value inside it is unknown.
	if !valueTypeVal.IsKnown() || !valueVal.IsKnown() {
		return nil
	}
	if valueTypeVal.IsNull() || valueVal.IsNull() {
		return nil
	}

	valueType := valueTypeVal.AsString()
	count := valueVal.LengthInt()

	switch valueType {
	case "ip", "cidr", "fqdn":
		if count != 1 {
			return fmt.Errorf("value: value_type %q requires exactly 1 value, got %d", valueType, count)
		}
	case "list":
		if count == 0 {
			return fmt.Errorf("value: value_type %q requires at least 1 value, got %d", valueType, count)
		}
	}

	if valueType == "cidr" {
		element := valueVal.Index(cty.NumberIntVal(0))
		if !element.IsKnown() {
			// Not yet resolved; the CIDR check is deferred to the next plan.
			return nil
		}
		if element.IsNull() {
			return fmt.Errorf("value[0]: must not be null")
		}
		if _, errs := validation.IsCIDR(element.AsString(), "value"); len(errs) > 0 {
			return fmt.Errorf("value[0]: %v", errs[0])
		}
	}

	return nil
}

/*
resourceObjectAddresses Setup the Object Addresses Resource CRUD operations

@return &schema.Resource
*/
func resourceObjectAddresses() *schema.Resource {
	return &schema.Resource{
		Description: "Manages an address object in Check Point SASE's shared object library. " +
			"Address objects are reusable references to a single IP, a list of IPs, a CIDR " +
			"block, or an FQDN; they're typically referenced from firewall policy rules " +
			"and service definitions. Use `checkpointsase_object_services` for the parallel " +
			"service-object resource.",
		CreateContext: resourceObjectAddressesCreate,
		ReadContext:   resourceObjectAddressesRead,
		UpdateContext: resourceObjectAddressesUpdate,
		DeleteContext: resourceObjectAddressesDelete,
		CustomizeDiff: resourceObjectAddressesCustomizeDiff,
		Schema: map[string]*schema.Schema{
			"last_updated": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Timestamp of the last update to this resource.",
			},
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Display name of the address object. Must be 3–100 characters.",
				ValidateFunc: validation.StringLenBetween(3, 100),
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional description of the address object.",
			},
			"value_type": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Category of the `value` list. Must be `ip` (single IP), `list` (multiple IPs), `cidr` (single CIDR block), or `fqdn` (single domain name).",
				ValidateFunc: validation.StringInSlice([]string{"ip", "list", "cidr", "fqdn"}, false),
			},
			"ip_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Deprecated:  "Has no effect on the v2.3 server. The Public API hardcodes `ipv4` server-side and strips this field from both request and response. Will be removed in a future major release.",
				Description: "IP version (e.g. `ipv4`). Not transmitted to or returned by the v2.3 server — values you set here are silently discarded.",
			},
			"value": {
				Type:        schema.TypeList,
				Required:    true,
				MinItems:    1,
				Description: "Address values. Shape depends on `value_type`: exactly 1 element for `ip` / `cidr` / `fqdn`, 1+ elements for `list`.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceObjectAddressesImportState,
		},
	}
}

/*
resourceObjectAddressesImportState Import an object addresses entry by its ID
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceObjectAddressesImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	importId := d.Id()
	diagnostics := resourceObjectAddressesRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import object Addresses: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	// Read clears the id when the address is absent and returns no error
	// diagnostic (see its not-found branch). Without this check, an import
	// of a nonexistent id would report success and write an empty resource
	// into state.
	if d.Id() == "" {
		return nil, fmt.Errorf("no object address %q exists in this tenant", importId)
	}
	return []*schema.ResourceData{d}, nil
}

/*
resourceObjectAddressesCreate Create a Object Addresses
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceObjectAddressesCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// intialize the client and the context if not exists
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// get the object services data from the terraform resource data and flatten what need to be flattened for the api
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	valueType := d.Get("value_type").(string)
	value := flattenStringsArrayData(d.Get("value").([]interface{}))

	// v3's Address flips Name/ValueType from required string to *string;
	// take addresses of the locals rather than inlining type assertions.
	objectAddressesPayload := perimeter81Sdk.Address{
		Name:        &name,
		Description: &description,
		ValueType:   &valueType,
		Value:       value,
	}
	// create the Object Addresses and check for errors
	// Execute() returns *DBAddress (top-level Id + nested Attributes
	// Address), not *Address — see model_db_address.go.
	objectAddresses, _, err := client.ObjectsAPI.CreateAddress(ctx).Address(objectAddressesPayload).Execute()

	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Object Addresses", err)
	}

	d.SetId(objectAddresses.GetId())
	return resourceObjectAddressesRead(ctx, d, m)
}

/*
resourceObjectAddressesRead Read a Object Addresses
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceObjectAddressesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// intialize the client and the context if not exists
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// get the object addresses and check for errors
	objectsAddresses, _, err := client.ObjectsAPI.GetAddresses(ctx).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to find object addresses", err)
	}
	currentObjectAddresses := getCurrentObjectAddressesInArray(objectsAddresses, d.Id())
	if currentObjectAddresses == nil {
		// Resource not present in the list endpoint response. Treat as
		// removed-out-of-band so terraform plans a recreate next cycle.
		d.SetId("")
		return diags
	}

	// v3 flipped Name/ValueType from required string to *string; use the
	// Get* accessors (nil-safe) instead of assigning the pointer itself,
	// which would otherwise store a pointer value via d.Set instead of a string.
	if err := d.Set("name", currentObjectAddresses.GetName()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set object addresses name", err)
	}
	if err := d.Set("description", currentObjectAddresses.GetDescription()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set object addresses description", err)
	}
	if err := d.Set("value_type", currentObjectAddresses.GetValueType()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set object addresses value_type", err)
	}
	if err := d.Set("value", currentObjectAddresses.Value); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set object addresses value", err)
	}

	return diags
}

/*
resourceObjectAddressesUpdate Update an Object Addresses entry
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceObjectAddressesUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	// intialize the client and the context if not exists
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	if d.HasChanges("value", "description", "name", "ip_version", "value_type") {

		// get the object addresses data from the terraform resource data and flatten what need to be flattened for the api
		objectAddressesId := d.Id()
		name := d.Get("name").(string)
		description := d.Get("description").(string)
		valueType := d.Get("value_type").(string)
		value := flattenStringsArrayData(d.Get("value").([]interface{}))

		// prepare the object addresses data for the api service
		updateObjectAddressesPayload := perimeter81Sdk.Address{
			Name:        &name,
			Description: &description,
			ValueType:   &valueType,
			Value:       value,
		}
		//update the object addresses and check for errors
		_, _, err := client.ObjectsAPI.UpdateAddress(ctx, objectAddressesId).Address(updateObjectAddressesPayload).Execute()
		if err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to update object addresses", err)
		}
	}

	return resourceObjectAddressesRead(ctx, d, m)
}

/*
resourceObjectAddressesDelete Delete an Object Addresses entry
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceObjectAddressesDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// intialize the client and the context if not exists
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// delete the object Addresses and check for errors
	resp, err := client.ObjectsAPI.DeleteAddress(ctx, d.Id()).Execute()

	// A 404 means somebody already deleted the address object; destroy has
	// nothing left to do and reporting a failure would leave the resource stuck
	// in state forever, needing a manual `terraform state rm` (OA-N02). This is
	// the same treatment resourceUserDelete and resourceGroupDelete give their
	// own 404s.
	if err != nil && !isNotFound(resp, err) {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete object addresses", err)
	}

	d.SetId("")
	return nil
}
