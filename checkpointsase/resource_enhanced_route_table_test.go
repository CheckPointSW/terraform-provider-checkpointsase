package checkpointsase

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
There is no acceptance test for checkpointsase_enhanced_route_table any more,
and there cannot be one: the resource has no working mode.

There used to be one — TestAccEnhancedRouteTable_basic — and it built a network,
a static tunnel and a `type = "static"` route entry. It could never have passed.
Measured live 2026-08-17: the API creates a route entry for a tunnel at the
moment the tunnel itself is created, carrying that tunnel's
remoteGatewaySubnets, and a second POST for the same tunnel comes back
422 "routes position 1 contains a duplicate value" — even for a different
subnet, because the duplicate key is the tunnel, not the subnet. Every tunnel
Terraform can build has a route already, so Create always failed at step 1. The
test was removed rather than left as coverage for something the provider now
refuses on purpose, and its fixtures and check helpers went with it; nothing
else referenced them.

The same run measured a dynamic tunnel and got identical results, which is why
the refusal is no longer conditional on `type`. The dynamic path never had an
acceptance test, and writing one now would only assert that the API says no.

What is covered here instead is the part that is now the provider's own
behaviour rather than the server's: the plan-time refusal, and the wording of
the message that refusal produces. Both run offline in milliseconds.
*/

// planEnhancedRouteTable runs the SDK's real diff machinery — including
// CustomizeDiff — over a configuration, exactly as `terraform plan` would.
// A nil prior state is a create; a populated one is a plan against an
// existing resource.
func planEnhancedRouteTable(t *testing.T, state *terraform.InstanceState, config map[string]interface{}) (*terraform.InstanceDiff, error) {
	t.Helper()
	return resourceEnhancedRouteTable().Diff(
		context.Background(),
		state,
		terraform.NewResourceConfigRaw(config),
		nil,
	)
}

/*
TestEnhancedRouteTableIsRejectedAtPlanTime is the regression test for the whole
point of the change: a user who writes this resource at all must be told so by
`terraform plan`, before anything is sent to the API — whichever route type
they wrote.

Before this, `static` planned cleanly and the apply died part-way through on a
422 about duplicate values that named neither the cause nor the fix. Then
`static` was refused and `dynamic` was left planning cleanly, on the untested
assumption that it worked; it does not, and it died the same way.

The dynamic case is the one to watch. It is easy to "fix" the resource by
letting a plausible-looking configuration through again, and the API will
accept none of them.
*/
func TestEnhancedRouteTableIsRejectedAtPlanTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config map[string]interface{}
	}{
		{
			name: "static",
			config: map[string]interface{}{
				"network_id": "fake-network-1",
				"type":       "static",
				"tunnel_id":  "fake-static-tunnel-1",
				"subnets":    []interface{}{"192.0.2.0/24"},
			},
		},
		{
			name: "dynamic",
			config: map[string]interface{}{
				"network_id": "fake-network-1",
				"type":       "dynamic",
				"tunnel_ids": []interface{}{"fake-dynamic-tunnel-1"},
				"subnets":    []interface{}{"192.0.2.0/24"},
			},
		},
		{
			// A `type` computed from another resource is unknown at plan and
			// reads as "" here. The refusal is unconditional precisely so that
			// this case does not slip through to apply.
			name: "type not known until apply",
			config: map[string]interface{}{
				"network_id": "fake-network-1",
				"subnets":    []interface{}{"192.0.2.0/24"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := planEnhancedRouteTable(t, nil, tc.config)
			if err == nil {
				t.Fatal("planning this route succeeded; it must fail at plan time, not at apply")
			}
			if err.Error() != enhancedRouteTableCannotCreateRoutes {
				t.Errorf("the plan failed with the wrong error:\n%v", err)
			}
		})
	}
}

/*
TestEnhancedRouteTableIsRejectedForAnExistingEntry covers the case the refusal
would be easy to miss: someone who already has an entry in state, from an import
or from an earlier provider version.

The refusal is not create-only. Two Terraform resources writing one server value
means each plan reports drift from the other's last apply, forever, so adopting
an existing entry is not a supported halfway house either. Removing the resource
is still possible — SDKv2 short-circuits destroy plans before CustomizeDiff runs
— so this does not trap anyone.
*/
func TestEnhancedRouteTableIsRejectedForAnExistingEntry(t *testing.T) {
	for _, tc := range []struct {
		name       string
		attributes map[string]string
		config     map[string]interface{}
	}{
		{
			name: "static",
			attributes: map[string]string{
				"id":         "fake-route-1",
				"network_id": "fake-network-1",
				"type":       "static",
				"tunnel_id":  "fake-static-tunnel-1",
				"subnets.#":  "1",
				"subnets.0":  "192.0.2.0/24",
			},
			config: map[string]interface{}{
				"network_id": "fake-network-1",
				"type":       "static",
				"tunnel_id":  "fake-static-tunnel-1",
				"subnets":    []interface{}{"192.0.2.0/24"},
			},
		},
		{
			name: "dynamic",
			attributes: map[string]string{
				"id":            "fake-route-2",
				"network_id":    "fake-network-1",
				"type":          "dynamic",
				"tunnel_ids.#":  "1",
				"tunnel_ids.0":  "fake-dynamic-tunnel-1",
				"subnets.#":     "1",
				"subnets.0":     "192.0.2.0/24",
				"propagated":    "false",
				"last_updated":  "",
				"tunnel_id":     "",
				"timeouts.%":    "0",
				"timeouts.read": "",
			},
			config: map[string]interface{}{
				"network_id": "fake-network-1",
				"type":       "dynamic",
				"tunnel_ids": []interface{}{"fake-dynamic-tunnel-1"},
				"subnets":    []interface{}{"192.0.2.0/24"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior := &terraform.InstanceState{
				ID:         tc.attributes["id"],
				Attributes: tc.attributes,
			}
			_, err := planEnhancedRouteTable(t, prior, tc.config)
			if err == nil {
				t.Fatal("planning an existing route succeeded; the refusal must not be create-only")
			}
			if err.Error() != enhancedRouteTableCannotCreateRoutes {
				t.Errorf("the plan failed with the wrong error:\n%v", err)
			}
		})
	}
}

/*
TestEnhancedRouteTableMessageTellsTheUserWhatToDo pins the message itself,
because the message is the deliverable. It is the only thing most users will
ever see of this finding, and it replaces a 422 they could not act on.

Each assertion is a thing the user needs in order to fix their config without
reading anything else: that neither type works, where the route actually lives,
which resource to set it on, which attribute, how to read the result back, and
that the resource should then go.
*/
func TestEnhancedRouteTableMessageTellsTheUserWhatToDo(t *testing.T) {
	for _, want := range []string{
		// What is wrong, and that it is not one mode of the resource but all
		// of it.
		"cannot create routes",
		`type = "static"`,
		`type = "dynamic"`,
		// Why — the route is not a separate object.
		"not a separate object",
		"belongs to its tunnel",
		// Exactly what to do instead: this attribute, on either of these two
		// resources. Naming only one would leave half the users stuck.
		"remote_gateway_subnets",
		"checkpointsase_enhanced_static_tunnel",
		"checkpointsase_enhanced_dynamic_tunnel",
		// How to see the result: the data source of the same name, shown as
		// `data "..."` so it cannot be mistaken for this resource.
		"data source",
		`data "checkpointsase_enhanced_route_table"`,
		// And the last step, so nobody leaves a permanently failing block in
		// their configuration.
		"remove this resource",
	} {
		if !strings.Contains(enhancedRouteTableCannotCreateRoutes, want) {
			t.Errorf("the plan-time message no longer mentions %q:\n%s", want, enhancedRouteTableCannotCreateRoutes)
		}
	}

	// The claim this test exists to stop coming back. Every earlier version of
	// the message ended by reassuring the reader that dynamic was fine.
	for _, unwanted := range []string{
		"is not affected",
		"still works",
		"only `dynamic`",
		"Only `dynamic`",
	} {
		if strings.Contains(enhancedRouteTableCannotCreateRoutes, unwanted) {
			t.Errorf("the plan-time message still claims dynamic works (%q):\n%s", unwanted, enhancedRouteTableCannotCreateRoutes)
		}
	}

	// The message is read by users who have never seen this repository. Internal
	// tracking identifiers, file paths and ticket numbers do not belong in it.
	for _, unwanted := range []string{"task", "Task", "TODO", "superpowers", ".go"} {
		if strings.Contains(enhancedRouteTableCannotCreateRoutes, unwanted) {
			t.Errorf("the plan-time message leaks internal detail %q:\n%s", unwanted, enhancedRouteTableCannotCreateRoutes)
		}
	}
}

/*
TestEnhancedRouteTableSchemaDoesNotClaimDynamicWorks guards the other half of
the surface a user reads: the schema descriptions, which become the published
registry documentation via `go generate`.

The resource Description, `type`, `tunnel_id` and `tunnel_ids` all used to say
or imply that the dynamic path was supported. The generated docs are derived
from exactly these strings, so pinning them here also pins docs/.
*/
func TestEnhancedRouteTableSchemaDoesNotClaimDynamicWorks(t *testing.T) {
	resource := resourceEnhancedRouteTable()

	descriptions := map[string]string{"(resource)": resource.Description}
	for _, name := range []string{"type", "tunnel_id", "tunnel_ids"} {
		s, ok := resource.Schema[name]
		if !ok {
			t.Fatalf("the schema no longer has a %q attribute", name)
		}
		descriptions[name] = s.Description
	}

	for name, description := range descriptions {
		for _, unwanted := range []string{
			"Only `type = \"dynamic\"` with `tunnel_ids` is supported",
			"Only `dynamic` is supported",
			"has not been measured",
		} {
			if strings.Contains(description, unwanted) {
				t.Errorf("the %s description still claims dynamic works (%q):\n%s", name, unwanted, description)
			}
		}
	}

	// The resource Description is the registry landing page for this resource.
	// It has to lead with the refusal, not bury it.
	for _, want := range []string{"cannot create routes", "rejected during `terraform plan`", "data source"} {
		if !strings.Contains(resource.Description, want) {
			t.Errorf("the resource description no longer mentions %q:\n%s", want, resource.Description)
		}
	}
}
