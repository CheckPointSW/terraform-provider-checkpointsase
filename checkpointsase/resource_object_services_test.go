package checkpointsase

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccObjectServices_basic(t *testing.T) {
	t.Parallel()
	var objectServices perimeter81Sdk.ObjectsServicesResponseObj

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccObjectServicesConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckObjectServicesExists("checkpointsase_object_services.os", &objectServices),
					testAccCheckObjectServicesAttributes(&objectServices, &testAccObjectServicesExpectedAttributes{
						Name:        "test-os",
						Description: "10.30.0.90/16",
						ValueType:   "single",
						Value:       []int32{22},
					}),
				),
			},
			{
				Config: testAccObjectServicesUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckObjectServicesExists("checkpointsase_object_services.os", &objectServices),
					testAccCheckObjectServicesAttributes(&objectServices, &testAccObjectServicesExpectedAttributes{
						Name:        "test-os-updated",
						Description: "10.30.0.91/16",
						ValueType:   "list",
						Value:       []int32{23, 24},
					}),
				),
			},
		},
	})
}

func testAccCheckObjectServicesExists(n string, objectServices *perimeter81Sdk.ObjectsServicesResponseObj) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}

		ObjectServicesID := rs.Primary.ID
		if ObjectServicesID == "" {
			return fmt.Errorf("No ObjectServices ID is set")
		}
		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		ctx := context.Background()
		objectsServices, _, err := conn.ObjectsAPI.GetObjectsServices(ctx).Execute()
		if err != nil {
			return fmt.Errorf("No ObjectServices found")
		}
		// Match by name since the list API does not return IDs
		name := rs.Primary.Attributes["name"]
		currentObjectServices := getCurrentObjectServicesInArray(objectsServices, name)
		if currentObjectServices == nil {
			return fmt.Errorf("ObjectServices with name %q not found", name)
		}

		*objectServices = *currentObjectServices
		return nil
	}
}

type testAccObjectServicesExpectedAttributes struct {
	Name        string
	Description string
	ValueType   string
	Value       []int32
}

func testAccCheckObjectServicesAttributes(objectServices *perimeter81Sdk.ObjectsServicesResponseObj, want *testAccObjectServicesExpectedAttributes) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if objectServices.Name != want.Name {
			return fmt.Errorf("got name %q; want %q", objectServices.Name, want.Name)
		}

		if objectServices.GetDescription() != want.Description {
			return fmt.Errorf("got description %q; want %q", objectServices.GetDescription(), want.Description)
		}

		if len(objectServices.Protocols) == 0 {
			return fmt.Errorf("got no protocols; want at least one")
		}

		proto := objectServices.Protocols[0]
		gotValueType := proto.GetValueType()
		gotValue := proto.Value

		if gotValueType != want.ValueType {
			return fmt.Errorf("got value_type %q; want %q", gotValueType, want.ValueType)
		}
		if !testComparableArraiesEq(gotValue, want.Value) {
			return fmt.Errorf("got value %v; want %v", gotValue, want.Value)
		}

		return nil
	}
}

func testAccObjectServicesConfig() string {
	config := `
resource "checkpointsase_object_services" "os" {
  name = "test-os"
  description = "10.30.0.90/16"

  protocols {
    protocol = "tcp"
    value_type = "single"
    value = [22]
  }
}
  `
	return config
}

func testAccObjectServicesUpdateConfig() string {
	config := `
resource "checkpointsase_object_services" "os" {
  name = "test-os-updated"
  description = "10.30.0.91/16"

  protocols {
    protocol = "udp"
    value_type = "list"
    value = [23, 24]
  }
}
  `
	return config
}

/*
objectServicesRawConfig builds the cty configuration value Terraform sends for
this resource, filling every attribute the schema declares — nulls for the ones
a case does not set — so the value's type matches the resource's ImpliedType()
exactly, as Terraform's does. Attributes are read from the schema rather than
listed here, so a new attribute cannot silently fall out of these cases.

The null-vs-zero distinction is the whole point of going through cty: a map
passed to terraform.NewResourceConfigRaw has already lost it.
*/
func objectServicesRawConfig(t *testing.T, protocols ...map[string]cty.Value) cty.Value {
	t.Helper()
	resourceType := resourceObjectServices().CoreConfigSchema().ImpliedType()
	protocolType := resourceType.AttributeType("protocols").ElementType()

	elements := make([]cty.Value, 0, len(protocols))
	for _, configured := range protocols {
		attributes := map[string]cty.Value{}
		for name, attributeType := range protocolType.AttributeTypes() {
			if value, ok := configured[name]; ok {
				attributes[name] = value
				continue
			}
			attributes[name] = cty.NullVal(attributeType)
		}
		for name := range configured {
			if !protocolType.HasAttribute(name) {
				t.Fatalf("protocols has no attribute %q; the test is describing a schema that does not exist", name)
			}
		}
		elements = append(elements, cty.ObjectVal(attributes))
	}

	protocolsValue := cty.ListValEmpty(protocolType)
	if len(elements) > 0 {
		protocolsValue = cty.ListVal(elements)
	}

	attributes := map[string]cty.Value{}
	for name, attributeType := range resourceType.AttributeTypes() {
		attributes[name] = cty.NullVal(attributeType)
	}
	attributes["name"] = cty.StringVal("fake-svc")
	attributes["protocols"] = protocolsValue
	return cty.ObjectVal(attributes)
}

/*
planObjectServices runs the SDK's real diff machinery — including CustomizeDiff —
over a configuration, the way `terraform plan` does.

It mirrors PlanResourceChange: the same cty value becomes both the shimmed
ResourceConfig and the prior state's RawConfig, which is how the raw config
reaches a ResourceDiff in production. A nil prior state is not usable here — it
is what leaves GetRawConfig null, and that degraded path has its own test below.
*/
func planObjectServices(t *testing.T, config cty.Value) error {
	t.Helper()
	r := resourceObjectServices()
	_, err := r.Diff(
		context.Background(),
		&terraform.InstanceState{RawConfig: config},
		terraform.NewResourceConfigShimmed(config, r.CoreConfigSchema()),
		nil,
	)
	return err
}

// objectServicesPorts is the value shape of a tcp/udp entry's port list.
func objectServicesPorts(ports ...int) cty.Value {
	values := make([]cty.Value, len(ports))
	for i, port := range ports {
		values[i] = cty.NumberIntVal(int64(port))
	}
	return cty.ListVal(values)
}

/*
TestObjectServicesProtocolRuleIsRefusedAtPlanTime is the unit test for the
refusal that replaces a wrong body the API would mostly accept — see
validateObjectServicesProtocols for what the server does with each of these
instead of erroring. It goes through the resource's real Diff, so it covers the
wiring (CustomizeDiff being registered at all) as well as the rule.

Every expectation asserts on the index in the message, not merely that an error
happened. `protocols` is an unnamed list, so "protocols[1]" is the only handle
its second entry has, and a message without it sends the reader to re-read their
whole configuration.
*/
func TestObjectServicesProtocolRuleIsRefusedAtPlanTime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		protocols []map[string]cty.Value
		wantErr   string
	}{
		{
			name: "icmp with a code is accepted",
			protocols: []map[string]cty.Value{{
				"protocol":         cty.StringVal("icmp"),
				"protocol_options": cty.NumberIntVal(8),
			}},
		},
		{
			name: "icmp with code 0 is accepted, because 0 is Echo Reply",
			protocols: []map[string]cty.Value{{
				"protocol":         cty.StringVal("icmp"),
				"protocol_options": cty.NumberIntVal(0),
			}},
		},
		{
			name: "icmp with code -1 is accepted, because -1 is Any",
			protocols: []map[string]cty.Value{{
				"protocol":         cty.StringVal("icmp"),
				"protocol_options": cty.NumberIntVal(-1),
			}},
		},
		{
			name: "tcp with ports is accepted",
			protocols: []map[string]cty.Value{{
				"protocol":   cty.StringVal("tcp"),
				"value_type": cty.StringVal("single"),
				"value":      objectServicesPorts(443),
			}},
		},
		{
			name: "one object carrying both shapes is accepted",
			protocols: []map[string]cty.Value{
				{
					"protocol":         cty.StringVal("icmp"),
					"protocol_options": cty.NumberIntVal(8),
				},
				{
					"protocol":   cty.StringVal("tcp"),
					"value_type": cty.StringVal("single"),
					"value":      objectServicesPorts(443),
				},
			},
		},
		{
			name: "icmp with value",
			protocols: []map[string]cty.Value{{
				"protocol":         cty.StringVal("icmp"),
				"protocol_options": cty.NumberIntVal(8),
				"value":            objectServicesPorts(443),
			}},
			wantErr: "protocols[0]: an icmp entry cannot set value_type or value",
		},
		{
			name: "icmp with value_type only",
			protocols: []map[string]cty.Value{{
				"protocol":         cty.StringVal("icmp"),
				"protocol_options": cty.NumberIntVal(8),
				"value_type":       cty.StringVal("single"),
			}},
			wantErr: "protocols[0]: an icmp entry cannot set value_type or value",
		},
		{
			name: "icmp without a code",
			protocols: []map[string]cty.Value{{
				"protocol": cty.StringVal("icmp"),
			}},
			wantErr: "protocols[0]: an icmp entry requires protocol_options",
		},
		{
			name: "tcp with a code",
			protocols: []map[string]cty.Value{{
				"protocol":         cty.StringVal("tcp"),
				"value_type":       cty.StringVal("single"),
				"value":            objectServicesPorts(443),
				"protocol_options": cty.NumberIntVal(8),
			}},
			wantErr: `protocols[0]: protocol_options applies only to icmp entries, but protocol is "tcp"`,
		},
		{
			// The case the schema no longer catches: protocol_options is a
			// TypeInt, so an explicit 0 is invisible to anything reading the
			// planned value, and only the raw config can see it was written.
			name: "tcp with the code 0 written out",
			protocols: []map[string]cty.Value{{
				"protocol":         cty.StringVal("tcp"),
				"value_type":       cty.StringVal("single"),
				"value":            objectServicesPorts(443),
				"protocol_options": cty.NumberIntVal(0),
			}},
			wantErr: `protocols[0]: protocol_options applies only to icmp entries, but protocol is "tcp"`,
		},
		{
			// value_type and value stopped being Required so that an icmp entry
			// could omit them. These two cases are what has to replace that.
			name: "udp with no ports at all",
			protocols: []map[string]cty.Value{{
				"protocol": cty.StringVal("udp"),
			}},
			wantErr: "protocols[0]: a udp entry requires both value_type and value",
		},
		{
			name: "tcp with value but no value_type",
			protocols: []map[string]cty.Value{{
				"protocol": cty.StringVal("tcp"),
				"value":    objectServicesPorts(443),
			}},
			wantErr: "protocols[0]: a tcp entry requires both value_type and value",
		},
		{
			name: "tcp with value_type but no value",
			protocols: []map[string]cty.Value{{
				"protocol":   cty.StringVal("tcp"),
				"value_type": cty.StringVal("single"),
			}},
			wantErr: "protocols[0]: a tcp entry requires both value_type and value",
		},
		{
			name: "the offending entry is named by its own index",
			protocols: []map[string]cty.Value{
				{
					"protocol":   cty.StringVal("tcp"),
					"value_type": cty.StringVal("single"),
					"value":      objectServicesPorts(443),
				},
				{
					"protocol": cty.StringVal("icmp"),
				},
			},
			wantErr: "protocols[1]: an icmp entry requires protocol_options",
		},
		{
			// A port list interpolated from another resource is unknown while
			// planning. The rule turns on whether the attribute was written, not
			// on its value, so an unknown value is still a present one and this
			// must not be refused as "requires value".
			name: "tcp whose ports are not resolved yet",
			protocols: []map[string]cty.Value{{
				"protocol":   cty.StringVal("tcp"),
				"value_type": cty.StringVal("single"),
				"value":      cty.UnknownVal(cty.List(cty.Number)),
			}},
		},
		{
			name: "icmp whose code is not resolved yet",
			protocols: []map[string]cty.Value{{
				"protocol":         cty.StringVal("icmp"),
				"protocol_options": cty.UnknownVal(cty.Number),
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := planObjectServices(t, objectServicesRawConfig(t, tc.protocols...))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("this configuration is valid but the plan refused it: %v", err)
			case tc.wantErr == "":
				return
			case err == nil:
				t.Fatalf("this configuration planned cleanly; it must fail with %q", tc.wantErr)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("the plan error does not say %q, so it cannot be acted on:\n%v", tc.wantErr, err)
			}
		})
	}
}

/*
TestObjectServicesProtocolRuleWithoutARawConfig pins what the fallback in
objectServicesProtocolEntriesFromDiff can and cannot do, so the degradation is a
recorded property rather than a surprise.

Terraform always supplies a raw config on a plan, so this path is reached only by
a caller that assembles a diff itself — schema.Resource.Diff with a nil state.
What matters is the direction of its blindness: it still refuses a code written
on a tcp entry, and it never invents an error against a configuration that is
legal. The icmp-without-a-code case therefore passes here and is caught only by
the test above.
*/
func TestObjectServicesProtocolRuleWithoutARawConfig(t *testing.T) {
	for _, tc := range []struct {
		name      string
		protocols []interface{}
		wantErr   string
	}{
		{
			name: "tcp with a non-zero code is still refused",
			protocols: []interface{}{map[string]interface{}{
				"protocol": "tcp", "value_type": "single", "value": []interface{}{443},
				"protocol_options": 8,
			}},
			wantErr: "protocols[0]: protocol_options applies only to icmp entries",
		},
		{
			name: "icmp with ports is still refused",
			protocols: []interface{}{map[string]interface{}{
				"protocol": "icmp", "protocol_options": 8, "value": []interface{}{443},
			}},
			wantErr: "protocols[0]: an icmp entry cannot set value_type or value",
		},
		{
			name: "tcp with no ports is still refused",
			protocols: []interface{}{map[string]interface{}{
				"protocol": "tcp",
			}},
			wantErr: "protocols[0]: a tcp entry requires both value_type and value",
		},
		{
			// KNOWN blind spot: an omitted TypeInt and a configured 0 are the
			// same value once the raw config is gone.
			name: "icmp with no code is NOT caught here",
			protocols: []interface{}{map[string]interface{}{
				"protocol": "icmp",
			}},
		},
		{
			// The mirror of it, and the reason the fallback reports a zero as
			// indeterminate rather than as present: refusing this would refuse a
			// legal configuration.
			name: "tcp with the code 0 written out is NOT caught here",
			protocols: []interface{}{map[string]interface{}{
				"protocol": "tcp", "value_type": "single", "value": []interface{}{443},
				"protocol_options": 0,
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resourceObjectServices().Diff(
				context.Background(),
				nil,
				terraform.NewResourceConfigRaw(map[string]interface{}{
					"name":      "fake-svc",
					"protocols": tc.protocols,
				}),
				nil,
			)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("the fallback invented an error for a configuration it cannot judge: %v", err)
			case tc.wantErr == "":
				return
			case err == nil:
				t.Fatalf("the fallback accepted this; it must fail with %q", tc.wantErr)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("the plan error does not say %q:\n%v", tc.wantErr, err)
			}
		})
	}
}

/*
TestObjectServicesPortAttributesStayConstrained covers what schema validation
must still do after value_type and value stopped being Required in order to let
an icmp entry omit them.

Making an attribute Optional loosens more than the case it was loosened for, and
these are the parts that must not have moved: the empty port list is still
refused (`value = []` is `property Value cant be empty`, a 400), the enums are
still closed, and an ICMP code outside VALID_ICMP_CODES still fails during plan
rather than being silently rewritten to -1 by createProtocolOptions.
*/
func TestObjectServicesPortAttributesStayConstrained(t *testing.T) {
	r := resourceObjectServices()
	protocols := r.Schema["protocols"].Elem.(*schemaResource).Schema

	for _, name := range []string{"value_type", "value", "protocol_options"} {
		attr, ok := protocols[name]
		if !ok {
			t.Fatalf("protocols has no %s attribute", name)
		}
		if attr.Required {
			t.Errorf("%s must not be Required: an icmp entry has no ports, and a tcp entry has no code", name)
		}
		if !attr.Optional {
			t.Errorf("%s must be Optional", name)
		}
		if !strings.Contains(attr.Description, "icmp") {
			t.Errorf("%s does not mention icmp, and its being conditional is the only surprising thing about it:\n%s", name, attr.Description)
		}
	}
	// The verdict recorded for protocols.value in listAttributeEmptyPolicy is
	// mustReject, which MinItems is how the provider honours. Optional changes
	// when it is checked (only if the key is present), not whether.
	if got := protocols["value"].MinItems; got != 1 {
		t.Errorf("value MinItems = %d, want 1: an omitted value is legal for icmp, but a written-out empty one is a 400", got)
	}

	for _, tc := range []struct {
		name      string
		protocols []interface{}
		wantErr   bool
	}{
		{
			name:      "icmp entry with neither value_type nor value",
			protocols: []interface{}{map[string]interface{}{"protocol": "icmp", "protocol_options": 8}},
		},
		{
			name:      "tcp entry with ports",
			protocols: []interface{}{map[string]interface{}{"protocol": "tcp", "value_type": "single", "value": []interface{}{443}}},
		},
		{
			name:      "empty port list",
			protocols: []interface{}{map[string]interface{}{"protocol": "tcp", "value_type": "single", "value": []interface{}{}}},
			wantErr:   true,
		},
		{
			name:      "port out of range",
			protocols: []interface{}{map[string]interface{}{"protocol": "tcp", "value_type": "single", "value": []interface{}{70000}}},
			wantErr:   true,
		},
		{
			name:      "unknown protocol",
			protocols: []interface{}{map[string]interface{}{"protocol": "sctp", "value_type": "single", "value": []interface{}{443}}},
			wantErr:   true,
		},
		{
			name:      "unknown value_type",
			protocols: []interface{}{map[string]interface{}{"protocol": "tcp", "value_type": "every", "value": []interface{}{443}}},
			wantErr:   true,
		},
		{
			name:      "ICMP code outside VALID_ICMP_CODES",
			protocols: []interface{}{map[string]interface{}{"protocol": "icmp", "protocol_options": 7}},
			wantErr:   true,
		},
		{
			name:      "no protocols at all",
			protocols: []interface{}{},
			wantErr:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := r.Validate(terraform.NewResourceConfigRaw(map[string]interface{}{
				"name":      "fake-svc",
				"protocols": tc.protocols,
			}))
			if diags.HasError() != tc.wantErr {
				t.Errorf("Validate HasError = %t, want %t: %v", diags.HasError(), tc.wantErr, diags)
			}
		})
	}
}

/*
TestObjectServicesFlattenReadsTheCodeNotTheDescription is the read half of the
round trip. The response's protocolOptions is {code, description} while state
holds only the code, so this pins which field is read back and that the other one
does not leak into state under any name.

The tcp case is here because ProtocolOptions is a pointer that is nil for every
tcp/udp entry, and the flattened map must still carry the key: 0 is what an unset
TypeInt holds, so writing 0 is what keeps a tcp entry from diffing.
*/
func TestObjectServicesFlattenReadsTheCodeNotTheDescription(t *testing.T) {
	code := int32(8)
	description := "Echo"
	valueType := "single"

	got := flattenObjectServicesProtocols([]perimeter81Sdk.ObjectsServicesProtocolResponseObj{
		{
			Protocol:        "icmp",
			ProtocolOptions: &perimeter81Sdk.ObjectServiceProtocolOptionsICMPresponse{Code: &code, Description: &description},
		},
		{
			Protocol:  "tcp",
			ValueType: &valueType,
			Value:     []int32{443},
		},
	})

	want := []interface{}{
		map[string]interface{}{
			"protocol":         "icmp",
			"value_type":       "",
			"value":            []int32(nil),
			"protocol_options": 8,
		},
		map[string]interface{}{
			"protocol":         "tcp",
			"value_type":       "single",
			"value":            []int32{443},
			"protocol_options": 0,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("flattened protocols do not match.\ngot:  %#v\nwant: %#v", got, want)
	}
	for _, entry := range got {
		for key, value := range entry.(map[string]interface{}) {
			if str, ok := value.(string); ok && str == description {
				t.Errorf("the ICMP description reached state as %q; it is derived from the code and would only drift", key)
			}
		}
	}
}

/*
TestAccObjectServices_icmp is the live half of ICMP support: one service object
carrying both entry shapes, so a single apply exercises the icmp branch and the
tcp branch of expand and flatten together.

Three things are being watched here that the offline tests cannot see:

  - the API really does return protocolOptions as {code, description} for the
    code that was sent as a bare number, and the code survives the round trip.
  - the framework's own post-apply plan check. protocol_options is where a
    read/write asymmetry would show up as a permanent diff, and an empty plan
    after apply is the only evidence that it does not.
  - list order. The entries are asserted at the indices they were written at, so
    a server that reordered protocols would fail here rather than quietly
    diffing on every future plan.

The second step changes the code from 8 (Echo) to -1 (Any), which is the update
path for the icmp branch and also the one code the server's ProtocolOptions map
has no entry for — createProtocolOptions reaches it through its fallback.
*/
func TestAccObjectServices_icmp(t *testing.T) {
	t.Parallel()
	var objectServices perimeter81Sdk.ObjectsServicesResponseObj

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccObjectServicesICMPConfig(8),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckObjectServicesExists("checkpointsase_object_services.icmp", &objectServices),
					testAccCheckObjectServicesICMPAttributes(&objectServices, 8),
					resource.TestCheckResourceAttr("checkpointsase_object_services.icmp", "protocols.0.protocol", "icmp"),
					resource.TestCheckResourceAttr("checkpointsase_object_services.icmp", "protocols.0.protocol_options", "8"),
					resource.TestCheckResourceAttr("checkpointsase_object_services.icmp", "protocols.0.value.#", "0"),
					resource.TestCheckResourceAttr("checkpointsase_object_services.icmp", "protocols.1.protocol", "tcp"),
					resource.TestCheckResourceAttr("checkpointsase_object_services.icmp", "protocols.1.value.0", "443"),
					resource.TestCheckResourceAttr("checkpointsase_object_services.icmp", "protocols.1.protocol_options", "0"),
				),
			},
			{
				Config: testAccObjectServicesICMPConfig(-1),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckObjectServicesExists("checkpointsase_object_services.icmp", &objectServices),
					testAccCheckObjectServicesICMPAttributes(&objectServices, -1),
					resource.TestCheckResourceAttr("checkpointsase_object_services.icmp", "protocols.0.protocol_options", "-1"),
				),
			},
		},
	})
}

/*
testAccCheckObjectServicesICMPAttributes asserts on what the API returned rather
than on what Terraform stored, so the two are checked independently: the state
assertions in the step above would pass on their own even if the provider had
written the config value back over an unread response.
*/
func testAccCheckObjectServicesICMPAttributes(objectServices *perimeter81Sdk.ObjectsServicesResponseObj, wantCode int32) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if len(objectServices.Protocols) != 2 {
			return fmt.Errorf("got %d protocols; want 2 (one icmp, one tcp)", len(objectServices.Protocols))
		}

		icmp := objectServices.Protocols[0]
		if icmp.Protocol != "icmp" {
			return fmt.Errorf("got protocols[0].protocol %q; want %q — the server reordered the list, which would diff on every plan", icmp.Protocol, "icmp")
		}
		options, ok := icmp.GetProtocolOptionsOk()
		if !ok {
			return fmt.Errorf("the icmp entry came back with no protocolOptions at all")
		}
		if got := options.GetCode(); got != wantCode {
			return fmt.Errorf("got protocolOptions.code %d; want %d", got, wantCode)
		}
		// The description is derived from the code and is deliberately not
		// exposed; assert it is present so the decision not to expose it stays
		// a decision rather than a mistake.
		if options.GetDescription() == "" {
			return fmt.Errorf("the icmp entry came back with an empty protocolOptions.description; the server always derives one from the code")
		}

		tcp := objectServices.Protocols[1]
		if tcp.Protocol != "tcp" {
			return fmt.Errorf("got protocols[1].protocol %q; want %q", tcp.Protocol, "tcp")
		}
		if got := tcp.GetValueType(); got != "single" {
			return fmt.Errorf("got protocols[1].valueType %q; want %q", got, "single")
		}
		if !testComparableArraiesEq(tcp.Value, []int32{443}) {
			return fmt.Errorf("got protocols[1].value %v; want %v", tcp.Value, []int32{443})
		}
		if tcp.ProtocolOptions != nil {
			return fmt.Errorf("the tcp entry came back with protocolOptions %+v; the server does not store one for tcp, so anything here means the provider sent it", tcp.ProtocolOptions)
		}
		return nil
	}
}

func testAccObjectServicesICMPConfig(code int) string {
	return fmt.Sprintf(`
resource "checkpointsase_object_services" "icmp" {
  name        = "test-os-icmp"
  description = "icmp plus tcp in one object"

  protocols {
    protocol         = "icmp"
    protocol_options = %d
  }

  protocols {
    protocol   = "tcp"
    value_type = "single"
    value      = [443]
  }
}
  `, code)
}
