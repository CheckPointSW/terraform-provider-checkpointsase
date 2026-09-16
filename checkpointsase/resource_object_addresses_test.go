package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccObjectAddresses_basic(t *testing.T) {
	t.Parallel()
	var objectAddress perimeter81Sdk.Address

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccObjectAddressConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckObjectAddressExists("checkpointsase_object_addresses.os", &objectAddress),
					testAccCheckObjectAddressesAttributes(&objectAddress, &testAccObjectAddressExpectedAttributes{
						Name:        "test-os",
						Description: "10.30.0.90/16",
						ValueType:   "ip",
						Value:       []string{"193.168.3.1"},
					}),
				),
			},
			{
				Config: testAccObjectAddressUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckObjectAddressExists("checkpointsase_object_addresses.oa", &objectAddress),
					testAccCheckObjectAddressesAttributes(&objectAddress, &testAccObjectAddressExpectedAttributes{
						Name:        "test-os-updated",
						Description: "10.30.0.91/16",
						ValueType:   "list",
						Value:       []string{"193.168.3.2"},
					}),
				),
			},
		},
	})
}

func testAccCheckObjectAddressExists(n string, objectAddress *perimeter81Sdk.Address) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}

		ObjectAddressID := rs.Primary.ID
		if ObjectAddressID == "" {
			return fmt.Errorf("No ObjectAddresses ID is set")
		}
		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		ctx := context.Background()
		objectsAddresses, _, err := conn.ObjectsAPI.GetAddresses(ctx).Execute()
		if err != nil {
			return fmt.Errorf("No ObjectAddresses found")
		}
		currentObjectAddress := getCurrentObjectAddressesInArray(objectsAddresses, ObjectAddressID)
		if currentObjectAddress == nil {
			return fmt.Errorf("ObjectAddress with ID %q not found", ObjectAddressID)
		}

		*objectAddress = *currentObjectAddress
		return nil
	}
}

type testAccObjectAddressExpectedAttributes struct {
	Name        string
	Description string
	ValueType   string
	Value       []string
}

func testAccCheckObjectAddressesAttributes(objectAddress *perimeter81Sdk.Address, want *testAccObjectAddressExpectedAttributes) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if objectAddress.GetName() != want.Name {
			return fmt.Errorf("got name %q; want %q", objectAddress.GetName(), want.Name)
		}

		if objectAddress.GetDescription() != want.Description {
			return fmt.Errorf("got description %q; want %q", objectAddress.GetDescription(), want.Description)
		}

		if objectAddress.GetValueType() != want.ValueType {
			return fmt.Errorf("got value type %q; want %q", objectAddress.GetValueType(), want.ValueType)
		}

		if !testComparableArraiesEq(objectAddress.Value, want.Value) {
			return fmt.Errorf("got value %q; want %q", objectAddress.Value, want.Value)
		}

		return nil
	}
}

func testAccObjectAddressConfig() string {
	config := `
resource "checkpointsase_object_addresses" "os" {
  name = "test-os"
  description = "10.30.0.90/16"
  value_type = "ip"
  value = ["193.168.3.1"]
}
  `
	return config
}

func testAccObjectAddressUpdateConfig() string {
	config := `
resource "checkpointsase_object_addresses" "oa" {
  name = "test-os-updated"
  description = "10.30.0.91/16"
  value_type = "list"
  value = ["193.168.3.2"]
}
  `
	return config
}

/*
TestObjectAddressesDeleteSwallowsA404ButNothingElse is the gate on OA-N02.

Before Phase 6, Delete reported any error from the endpoint, including a 404. So
destroying an address object that somebody had already removed — out of band, or
on a retried destroy after a partial failure — failed the apply and left the
resource in state, needing a manual `terraform state rm` to recover. A destroy
whose goal state is "absent" should treat "already absent" as success.

The 500 row is the half that matters as much: swallowing a 404 must not become
swallowing everything. A server error still has to fail the destroy, because the
object may well still be there.

Modelled on TestUserDeleteSwallowsA404ButNothingElse, which pins the same
contract on the identity resources.
*/
func TestObjectAddressesDeleteSwallowsA404ButNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantErr    bool
		wantIDGone bool
	}{
		{"404 means somebody already deleted it", http.StatusNotFound,
			`{"message":"address not found"}`, false, true},
		{"200 is an ordinary destroy", http.StatusOK,
			`{"id":"addr-1"}`, false, true},
		{"500 must not be mistaken for success", http.StatusInternalServerError,
			`{"message":"boom"}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath = r.Method, r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			d := schema.TestResourceDataRaw(t, resourceObjectAddresses().Schema, map[string]interface{}{})
			d.SetId("addr-1")

			diags := resourceObjectAddressesDelete(context.Background(), d, newTestUserAPIClient(srv.URL))

			if gotMethod != http.MethodDelete {
				t.Errorf("request method was %q, want DELETE", gotMethod)
			}
			if gotPath == "" {
				t.Error("no request reached the server; Delete must issue the DELETE")
			}
			if diags.HasError() != tc.wantErr {
				t.Errorf("HasError = %v, want %v: %v", diags.HasError(), tc.wantErr, diags)
			}
			if gone := d.Id() == ""; gone != tc.wantIDGone {
				t.Errorf("id cleared = %v, want %v (id is %q)", gone, tc.wantIDGone, d.Id())
			}
		})
	}
}

/*
objectAddressesRawConfig builds the cty configuration value Terraform sends for
this resource, filling every attribute the schema declares — nulls for the ones
a case does not set — so the value's type matches the resource's ImpliedType()
exactly, as Terraform's does. Modelled on objectServicesRawConfig.
*/
func objectAddressesRawConfig(t *testing.T, valueType string, values ...string) cty.Value {
	t.Helper()
	resourceType := resourceObjectAddresses().CoreConfigSchema().ImpliedType()

	valueElements := make([]cty.Value, len(values))
	for i, v := range values {
		valueElements[i] = cty.StringVal(v)
	}
	valueValue := cty.ListValEmpty(cty.String)
	if len(valueElements) > 0 {
		valueValue = cty.ListVal(valueElements)
	}

	attributes := map[string]cty.Value{}
	for name, attributeType := range resourceType.AttributeTypes() {
		attributes[name] = cty.NullVal(attributeType)
	}
	attributes["name"] = cty.StringVal("fake-addr")
	attributes["value_type"] = cty.StringVal(valueType)
	attributes["value"] = valueValue
	return cty.ObjectVal(attributes)
}

/*
planObjectAddresses runs the SDK's real diff machinery — including CustomizeDiff
— over a configuration, the way `terraform plan` does. Modelled on
planObjectServices.
*/
func planObjectAddresses(t *testing.T, config cty.Value) error {
	t.Helper()
	r := resourceObjectAddresses()
	_, err := r.Diff(
		context.Background(),
		&terraform.InstanceState{RawConfig: config},
		terraform.NewResourceConfigShimmed(config, r.CoreConfigSchema()),
		nil,
	)
	return err
}

/*
TestObjectAddressesValueRulesAreRefusedAtPlanTime is the unit test for P81-144755:
`value` had no plan-time CIDR validation for a `cidr` entry (unlike
`network.subnet`), and nothing checked the value count against `value_type`. Both
gaps let a bad configuration through `terraform plan` and on to the server, which
returns a 422.
*/
func TestObjectAddressesValueRulesAreRefusedAtPlanTime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		valueType string
		values    []string
		wantErr   string
	}{
		{name: "ip with one value is accepted", valueType: "ip", values: []string{"193.168.3.1"}},
		{
			name:      "ip with two values is rejected",
			valueType: "ip",
			values:    []string{"193.168.3.1", "193.168.3.2"},
			wantErr:   `value_type "ip" requires exactly 1 value, got 2`,
		},
		{name: "cidr with a valid cidr is accepted", valueType: "cidr", values: []string{"10.50.0.0/16"}},
		{
			name:      "cidr with a malformed cidr is rejected",
			valueType: "cidr",
			values:    []string{"10.50.0.0/99"},
			wantErr:   `to be a valid IPv4 Value`,
		},
		{
			name:      "cidr with two values is rejected on count before ever reaching IsCIDR",
			valueType: "cidr",
			values:    []string{"10.50.0.0/16", "10.60.0.0/16"},
			wantErr:   `value_type "cidr" requires exactly 1 value, got 2`,
		},
		{name: "fqdn with one value is accepted", valueType: "fqdn", values: []string{"example.com"}},
		{
			name:      "fqdn with two values is rejected",
			valueType: "fqdn",
			values:    []string{"a.example.com", "b.example.com"},
			wantErr:   `value_type "fqdn" requires exactly 1 value, got 2`,
		},
		{name: "list with one value is accepted", valueType: "list", values: []string{"193.168.3.1"}},
		{name: "list with several values is accepted", valueType: "list", values: []string{"193.168.3.1", "193.168.3.2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := planObjectAddresses(t, objectAddressesRawConfig(t, tc.valueType, tc.values...))
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
