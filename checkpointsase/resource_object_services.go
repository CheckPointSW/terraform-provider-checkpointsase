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
objectServicesProtocolRule is the protocol-conditional rule in one sentence. It
is quoted by the resource description, by protocol_options — the attribute whose
existence is the surprising half of it — and by every plan-time refusal, so a
reader meets the same wording wherever they hit it.
*/
const objectServicesProtocolRule = "An `icmp` entry sets `protocol_options` and " +
	"neither `value_type` nor `value`; a `tcp` or `udp` entry sets `value_type` " +
	"and `value` and not `protocol_options`."

/*
attrPresence is whether a configuration wrote an attribute at all, which is the
only question objectServicesProtocolRule turns on: none of the three conditional
attributes has a legal value that is also its type's zero value, except
protocol_options, where 0 is the ICMP code "Echo Reply". Anything that infers
"set" from "not the zero value" therefore cannot tell `protocol_options = 0`
from an omitted one — it must either miss a real error or invent one.
*/
type attrPresence int

const (
	// attrAbsent: the configuration does not set this attribute.
	attrAbsent attrPresence = iota
	// attrPresent: the configuration sets it. The value may still be unknown at
	// plan time; presence is answered either way, which is what lets this check
	// run without NewValueKnown guards and without a Create-time backstop.
	attrPresent
	// attrUnknownPresence: the source consulted cannot tell present from absent.
	// Only objectServicesProtocolEntriesFromDiff produces it, and the rule
	// treats it as "claim nothing" rather than as an error.
	attrUnknownPresence
)

// objectServicesProtocolEntry is one protocols[] element reduced to the facts
// objectServicesProtocolRule turns on. index is the element's position in the
// configured list and is carried explicitly, because an entry that cannot be
// classified is dropped and the remaining messages must still name the right
// element.
type objectServicesProtocolEntry struct {
	index     int
	protocol  string
	valueType attrPresence
	value     attrPresence
	options   attrPresence
}

/*
validateObjectServicesProtocols enforces objectServicesProtocolRule, returning
the first offending entry named by its index — "protocols[1]" being the only
handle a user has on an element of an unnamed list.

The reason to refuse these combinations at plan time is NOT that the API answers
400 for them. Mostly it does not, and that is worse. Read against
perimeter81-public-api on 2026-08-19:

  - CreateServicesTransformer rewrites an icmp entry to
    `{protocol, protocolOptions: String(protocolOptions), valueType: 'single'}`,
    dropping `value` outright, and getSingleServiceTransformed returns only
    `{protocol, protocolOptions}` for icmp. So `value = [443]` on an icmp entry
    is accepted, silently discarded, and then absent from the read — a permanent
    diff rather than an error. `value_type = "single"` or `"range"` on an icmp
    entry does 400, from the same transformer's arity check, so one mistake
    fails two different ways depending on which half of it the user wrote.
  - protocolOptions is @ValidateIf(protocol === 'icmp'), so on a tcp/udp entry it
    is neither validated nor stored, and the read comes back without it.
    `protocol_options = 8` on a tcp entry diffs forever in the same way.
  - createProtocolOptions maps anything it cannot parse — an absent
    protocolOptions included, via String(undefined) — to
    {code: -1, description: 'Any'}. An icmp entry with no code is therefore
    accepted and quietly becomes "Any", and since state would then hold -1 where
    the plan held the unset 0, that too is a standing diff. Hence
    protocol_options is required for icmp rather than defaulted.

This is the defect class that cost Phase 1 live runs twice (EnhancedTunnel's read
shape, the firewall oneOf): a body the server accepts and echoes back different.
*/
func validateObjectServicesProtocols(entries []objectServicesProtocolEntry) error {
	for _, e := range entries {
		switch {
		case e.protocol == "":
			// Unknown at plan time, so unclassifiable. Nothing to check.
		case e.protocol == "icmp":
			if e.valueType == attrPresent || e.value == attrPresent {
				return fmt.Errorf("protocols[%d]: an icmp entry cannot set value_type or value — ICMP "+
					"has no ports, and the server drops them without complaining, so the entry would "+
					"read back different from the configuration. Set protocol_options instead. %s",
					e.index, objectServicesProtocolRule)
			}
			if e.options == attrAbsent {
				return fmt.Errorf("protocols[%d]: an icmp entry requires protocol_options — the server "+
					"turns an absent code into -1 (\"Any\") without saying so. Write "+
					"protocol_options = -1 if Any is what you want", e.index)
			}
		default:
			if e.options == attrPresent {
				return fmt.Errorf("protocols[%d]: protocol_options applies only to icmp entries, but "+
					"protocol is %q. The server ignores it here and never returns it, so it would "+
					"diff forever. %s", e.index, e.protocol, objectServicesProtocolRule)
			}
			if e.valueType != attrPresent || e.value != attrPresent {
				return fmt.Errorf("protocols[%d]: a %s entry requires both value_type and value. %s",
					e.index, e.protocol, objectServicesProtocolRule)
			}
		}
	}
	return nil
}

/*
objectServicesProtocolEntriesFromRawConfig reads the presence facts out of the
cty value Terraform sent for the configuration, where an unset attribute is a
null rather than a zero. It is the only source that can tell
`protocol_options = 0` from an omitted protocol_options.

Terraform populates the raw config on every plan, create as well as update:
PlanResourceChange puts the config on the prior state and helper/schema copies
it onto the diff. The second return value is false only when no raw config
reached this diff at all — a caller that assembled the diff itself, which in
this codebase means a unit test that did not supply one.
*/
func objectServicesProtocolEntriesFromRawConfig(raw cty.Value) ([]objectServicesProtocolEntry, bool) {
	if raw.IsNull() || !raw.IsKnown() || !raw.Type().IsObjectType() || !raw.Type().HasAttribute("protocols") {
		return nil, false
	}
	protocols := raw.GetAttr("protocols")
	// A protocols list that is absent or wholly unknown says nothing about its
	// elements, which is an answer rather than a failure to answer: falling
	// through to the diff here would read the same absence as an empty list.
	// Required and MinItems catch a genuinely missing list.
	if protocols.IsNull() || !protocols.IsKnown() || !protocols.CanIterateElements() {
		return nil, true
	}

	var entries []objectServicesProtocolEntry
	index := -1
	for it := protocols.ElementIterator(); it.Next(); {
		index++
		_, element := it.Element()
		if element.IsNull() || !element.IsKnown() || !element.Type().IsObjectType() {
			continue
		}
		entries = append(entries, objectServicesProtocolEntry{
			index:     index,
			protocol:  rawConfigAttrString(element, "protocol"),
			valueType: rawConfigAttrPresence(element, "value_type"),
			value:     rawConfigAttrPresence(element, "value"),
			options:   rawConfigAttrPresence(element, "protocol_options"),
		})
	}
	return entries, true
}

// rawConfigAttrPresence reports whether name was written in the configuration object
// element. An unknown value counts as present: presence is about the key, not
// about the value, which is why an interpolated port list does not have to be
// resolved before this check can run.
func rawConfigAttrPresence(element cty.Value, name string) attrPresence {
	if !element.Type().HasAttribute(name) {
		return attrUnknownPresence
	}
	if element.GetAttr(name).IsNull() {
		return attrAbsent
	}
	return attrPresent
}

// rawConfigAttrString returns name's configured string value, or "" when it is
// absent, unknown or not a string — all of which mean "cannot classify this
// entry" to the caller.
func rawConfigAttrString(element cty.Value, name string) string {
	if !element.Type().HasAttribute(name) || element.Type().AttributeType(name) != cty.String {
		return ""
	}
	attr := element.GetAttr(name)
	if attr.IsNull() || !attr.IsKnown() {
		return ""
	}
	return attr.AsString()
}

/*
objectServicesProtocolEntriesFromDiff is the fallback for a diff that carries no
raw config. It reads the planned values, where an absent attribute is
indistinguishable from its type's zero value.

That conflation is harmless for value_type and value — "" and [] are not legal
content either, so treating them as absent changes no verdict — and it is not
harmless for protocol_options, whose zero value is the legal code 0. So a zero
there is reported as attrUnknownPresence: this path still catches
`protocol_options = 8` on a tcp entry, and it never invents an error against a
configuration that legitimately asked for code 0. It also cannot catch an icmp
entry with no code at all, which is why it is a fallback and not the
implementation.
*/
func objectServicesProtocolEntriesFromDiff(d *schema.ResourceDiff) []objectServicesProtocolEntry {
	raw, _ := d.Get("protocols").([]interface{})
	entries := make([]objectServicesProtocolEntry, 0, len(raw))
	for index, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		protocol, _ := m["protocol"].(string)
		valueType, _ := m["value_type"].(string)
		value, _ := m["value"].([]interface{})
		options, _ := m["protocol_options"].(int)

		entry := objectServicesProtocolEntry{index: index, protocol: protocol, options: attrUnknownPresence}
		if valueType != "" {
			entry.valueType = attrPresent
		}
		if len(value) > 0 {
			entry.value = attrPresent
		}
		if options != 0 {
			entry.options = attrPresent
		}
		entries = append(entries, entry)
	}
	return entries
}

/*
resourceObjectServicesCustomizeDiff enforces objectServicesProtocolRule, which
the schema cannot express. ValidateFunc cannot see a sibling attribute, and
ExactlyOneOf/ConflictsWith cannot index into a list element — every path form
that tries is refused by InternalValidate, which
TestFirewallPolicySchemaCannotExpressTheXOR pins for exactly this shape (a list
of blocks with a cross-attribute constraint inside the element).

Destroy plans never reach CustomizeDiff in SDKv2, which is what we want here:
a destroy sends no protocols at all.
*/
func resourceObjectServicesCustomizeDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	entries, fromConfig := objectServicesProtocolEntriesFromRawConfig(d.GetRawConfig())
	if !fromConfig {
		entries = objectServicesProtocolEntriesFromDiff(d)
	}
	return validateObjectServicesProtocols(entries)
}

/*
resourceObjectServices Setup the Object Services Resource CRUD operations

@return &schema.Resource
*/
func resourceObjectServices() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a service object in Check Point SASE's shared object library. " +
			"Service objects are reusable references to one or more transport-layer " +
			"protocol + port combinations; they're typically referenced from firewall " +
			"policy rules. Use `checkpointsase_object_addresses` for the parallel " +
			"address-object resource. " +
			"Every `protocols` entry is one of two shapes, and they do not mix. " +
			objectServicesProtocolRule,
		CreateContext: resourceObjectServicesCreate,
		ReadContext:   resourceObjectServicesRead,
		UpdateContext: resourceObjectServicesUpdate,
		DeleteContext: resourceObjectServicesDelete,
		CustomizeDiff: resourceObjectServicesCustomizeDiff,
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
				Description:  "Display name of the service object. Must be 3–100 characters.",
				ValidateFunc: validation.StringLenBetween(3, 100),
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional description of the service object.",
			},
			"protocols": {
				Type:        schema.TypeList,
				Required:    true,
				MinItems:    1,
				Description: "List of protocol+port combinations covered by this service object. At least one entry is required.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"protocol": {
							Type:         schema.TypeString,
							Required:     true,
							Description:  "Transport protocol. Must be `tcp`, `udp`, or `icmp`.",
							ValidateFunc: validation.StringInSlice([]string{"tcp", "udp", "icmp"}, false),
						},
						"value_type": {
							Type:     schema.TypeString,
							Optional: true,
							Description: "Shape of the `value` list. Must be `single` (one port), `range` " +
								"(exactly two ports, low–high), or `list` (multiple discrete ports). " +
								"Required for `tcp` and `udp`, and must be omitted for `icmp`, " +
								"which has no ports.",
							ValidateFunc: validation.StringInSlice([]string{"single", "range", "list"}, false),
						},
						"value": {
							Type:     schema.TypeList,
							Optional: true,
							MinItems: 1,
							Description: "Port numbers. Shape depends on `value_type`: 1 element for " +
								"`single`, 2 elements (start, end) for `range`, 1+ for `list`. Each " +
								"value must be a valid port (1–65535). Required for `tcp` and `udp`, " +
								"and must be omitted for `icmp`, which has no ports.",
							Elem: &schema.Schema{
								Type:         schema.TypeInt,
								ValidateFunc: validation.IsPortNumber,
							},
						},
						"protocol_options": {
							Type:     schema.TypeInt,
							Optional: true,
							Description: "ICMP message type, as a numeric code. Required when `protocol` " +
								"is `icmp`, and rejected otherwise. Allowed: -1 (Any), 0 (Echo Reply), " +
								"3, 5, 8 (Echo), 9, 10, 11, 12, 13, 14, 40, 42, 43. There is no default: " +
								"the server turns an absent code into -1 (\"Any\") without saying so, so " +
								"this provider makes you write it. The server also returns a " +
								"human-readable description alongside the code; it is derived from the " +
								"code and is deliberately not exposed here, because it would be a " +
								"computed value whose only behaviour is to drift. " +
								objectServicesProtocolRule,
							ValidateFunc: validation.IntInSlice([]int{-1, 0, 3, 5, 8, 9, 10, 11, 12, 13, 14, 40, 42, 43}),
						},
					}},
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceObjectServicesImportState,
		},
	}
}

/*
resourceObjectServicesImportState Import an object services entry by its ID
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceObjectServicesImportState(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	diagnostics := resourceObjectServicesRead(ctx, d, m)
	if diagnostics.HasError() {
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == diag.Error {
				return nil, fmt.Errorf("could not import object services: %s, \n %s", diagnostic.Summary, diagnostic.Detail)
			}
		}
	}
	return []*schema.ResourceData{d}, nil
}

/*
resourceObjectServicesCreate Create a Object Services
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceObjectServicesCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// intialize the client and the context if not exists
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	name := d.Get("name").(string)
	description := d.Get("description").(string)
	protocolsPayload := flattenProtocolsData(d.Get("protocols").([]interface{}))

	createObjectsServicesPayload := perimeter81Sdk.ObjectsServicesRequestObj{
		Name:        name,
		Description: &description,
		Protocols:   protocolsPayload,
	}
	newObjectServices, _, err := client.ObjectsAPI.PostObjectsServices(ctx).ObjectsServicesRequestObj(createObjectsServicesPayload).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to create Object Services", err)
	}

	d.SetId(newObjectServices.GetId())
	return resourceObjectServicesRead(ctx, d, m)
}

/*
resourceObjectServicesRead Read a Object Services
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceObjectServicesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// Look up by id, not by name. On terraform import only d.Id() is seeded,
	// so a by-name lookup would panic; it also misbehaves if the service is
	// renamed server-side.
	objectsServices, _, err := client.ObjectsAPI.GetObjectsServices(ctx).Execute()
	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to fetch object services", err)
	}
	var match *perimeter81Sdk.ObjectsServicesResponseObj
	for i := range objectsServices.Data {
		if objectsServices.Data[i].Id != nil && *objectsServices.Data[i].Id == d.Id() {
			match = &objectsServices.Data[i]
			break
		}
	}
	if match == nil {
		// Resource gone server-side — let terraform schedule a recreate.
		d.SetId("")
		return diags
	}

	if err := d.Set("name", match.Name); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set object services name", err)
	}
	if err := d.Set("description", match.GetDescription()); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set object services description", err)
	}
	if err := d.Set("protocols", flattenObjectServicesProtocols(match.Protocols)); err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to set object services protocol data", err)
	}

	return diags
}

/*
resourceObjectServicesUpdate Update an Object Services entry
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceObjectServicesUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// intialize the client and the context if not exists
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	if d.HasChanges("name", "description", "protocols") {
		objectServicesId := d.Id()
		name := d.Get("name").(string)
		description := d.Get("description").(string)
		protocolsPayload := flattenProtocolsData(d.Get("protocols").([]interface{}))
		updateObjectServicesPayload := perimeter81Sdk.ObjectsServicesRequestObj{
			Name:        name,
			Description: &description,
			Protocols:   protocolsPayload,
		}
		if _, _, err := client.ObjectsAPI.PutObjectsServices(ctx, objectServicesId).ObjectsServicesRequestObj(updateObjectServicesPayload).Execute(); err != nil {
			d.Partial(true)
			return appendErrorDiags(diags, "Unable to update object services", err)
		}
	}

	return resourceObjectServicesRead(ctx, d, m)
}

/*
resourceObjectServicesDelete Delete an Object Services entry
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data
  - @param m interface{} - the terraform meta data that contains the client

@return diag.Diagnostics
*/
func resourceObjectServicesDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// intialize the client and the context if not exists
	var diags diag.Diagnostics
	client := m.(*perimeter81Sdk.APIClient)

	// delete the object services and check for errors
	_, err := client.ObjectsAPI.DeleteObjectsServices(ctx, d.Id()).Execute()

	if err != nil {
		d.Partial(true)
		return appendErrorDiags(diags, "Unable to delete object services", err)
	}

	d.SetId("")
	return nil
}
