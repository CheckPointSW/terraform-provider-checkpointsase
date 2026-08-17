package checkpointsase

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
There is no acceptance test for checkpointsase_enhanced_route_table any more.

There used to be one — TestAccEnhancedRouteTable_basic — and it built a network,
a static tunnel and a `type = "static"` route entry. It could never have passed.
Measured live 2026-08-17: the API creates a route entry for a static tunnel at
the moment the tunnel itself is created, carrying that tunnel's
remoteGatewaySubnets, and a second POST for the same tunnel comes back
422 "routes position 1 contains a duplicate value" — even for a different
subnet, because the duplicate key is the tunnel, not the subnet. Every static
tunnel Terraform can build has a route already, so Create always failed at
step 1. The test was removed rather than left as coverage for something the
provider now refuses on purpose, and its fixtures and check helpers went with
it; nothing else referenced them.

The dynamic path has no acceptance test either, and did not have one before.
Writing one would need a dynamic tunnel whose BGP endpoints the API accepts, and
the coupling question below is unresolved, so this is an honest gap and not a
silently dropped case.

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
TestEnhancedRouteTableStaticIsRejectedAtPlanTime is the regression test for the
whole point of the change: a user who writes `type = "static"` must be told so
by `terraform plan`, before anything is sent to the API.

Before this, the config planned cleanly and the apply died part-way through on a
422 about duplicate values that named neither the cause nor the fix.
*/
func TestEnhancedRouteTableStaticIsRejectedAtPlanTime(t *testing.T) {
	_, err := planEnhancedRouteTable(t, nil, map[string]interface{}{
		"network_id": "fake-network-1",
		"type":       "static",
		"tunnel_id":  "fake-static-tunnel-1",
		"subnets":    []interface{}{"192.0.2.0/24"},
	})
	if err == nil {
		t.Fatal("planning a static route succeeded; it must fail at plan time, not at apply")
	}
	if err.Error() != enhancedRouteTableStaticNotSupported {
		t.Errorf("the plan failed with the wrong error:\n%v", err)
	}
}

/*
TestEnhancedRouteTableStaticIsRejectedForAnExistingEntry covers the case the
refusal would be easy to miss: someone who already has a static entry in state,
from an import or from an earlier provider version.

The refusal is not create-only. Two Terraform resources writing one server value
means each plan reports drift from the other's last apply, forever, so adopting
an existing entry is not a supported halfway house either. Removing the resource
is still possible — SDKv2 short-circuits destroy plans before CustomizeDiff runs
— so this does not trap anyone.
*/
func TestEnhancedRouteTableStaticIsRejectedForAnExistingEntry(t *testing.T) {
	prior := &terraform.InstanceState{
		ID: "fake-route-1",
		Attributes: map[string]string{
			"id":         "fake-route-1",
			"network_id": "fake-network-1",
			"type":       "static",
			"tunnel_id":  "fake-static-tunnel-1",
			"subnets.#":  "1",
			"subnets.0":  "192.0.2.0/24",
		},
	}
	_, err := planEnhancedRouteTable(t, prior, map[string]interface{}{
		"network_id": "fake-network-1",
		"type":       "static",
		"tunnel_id":  "fake-static-tunnel-1",
		"subnets":    []interface{}{"192.0.2.0/24"},
	})
	if err == nil {
		t.Fatal("planning an existing static route succeeded; the refusal must not be create-only")
	}
	if err.Error() != enhancedRouteTableStaticNotSupported {
		t.Errorf("the plan failed with the wrong error:\n%v", err)
	}
}

/*
TestEnhancedRouteTableDynamicStillPlans is the other half, and the reason the
block is a CustomizeDiff on `type` rather than something broader.

Dynamic tunnels also carry remote_gateway_subnets in their shared settings, so
the same coupling is plausible for them — but it has NOT been measured, and this
resource is not going to refuse a configuration on the strength of an inference.
If that measurement is ever taken and the coupling is there, this test is the
one that has to change, deliberately.
*/
func TestEnhancedRouteTableDynamicStillPlans(t *testing.T) {
	diff, err := planEnhancedRouteTable(t, nil, map[string]interface{}{
		"network_id": "fake-network-1",
		"type":       "dynamic",
		"tunnel_ids": []interface{}{"fake-dynamic-tunnel-1"},
		"subnets":    []interface{}{"192.0.2.0/24"},
	})
	if err != nil {
		t.Fatalf("planning a dynamic route failed, but only static is unsupported: %v", err)
	}
	if diff == nil || diff.Empty() {
		t.Fatal("planning a dynamic route from no prior state produced no changes")
	}
}

/*
TestEnhancedRouteTableStaticMessageTellsTheUserWhatToDo pins the message itself,
because the message is the deliverable. It is the only thing most users will
ever see of this finding, and it replaces a 422 they could not act on.

Each assertion is a thing the user needs in order to fix their config without
reading anything else: where the route actually lives, which resource to set it
on, which attribute, and how to read the result back. An edit that drops one of
these turns the message back into "no".
*/
func TestEnhancedRouteTableStaticMessageTellsTheUserWhatToDo(t *testing.T) {
	for _, want := range []string{
		// What is wrong.
		`does not support type = "static"`,
		// Why — the route is not a separate object.
		"part of the tunnel, not a separate object",
		// Exactly what to do instead: this attribute, on this resource.
		"remote_gateway_subnets",
		"checkpointsase_enhanced_static_tunnel",
		// How to see the result: the data source of the same name, shown as
		// `data "..."` so it cannot be mistaken for this resource.
		"data source",
		`data "checkpointsase_enhanced_route_table"`,
		// What is not affected, so nobody assumes the resource is dead.
		`type = "dynamic"`,
	} {
		if !strings.Contains(enhancedRouteTableStaticNotSupported, want) {
			t.Errorf("the plan-time message no longer mentions %q:\n%s", want, enhancedRouteTableStaticNotSupported)
		}
	}

	// The message is read by users who have never seen this repository. Internal
	// tracking identifiers, file paths and ticket numbers do not belong in it.
	for _, unwanted := range []string{"task", "Task", "TODO", "superpowers", ".go"} {
		if strings.Contains(enhancedRouteTableStaticNotSupported, unwanted) {
			t.Errorf("the plan-time message leaks internal detail %q:\n%s", unwanted, enhancedRouteTableStaticNotSupported)
		}
	}
}
