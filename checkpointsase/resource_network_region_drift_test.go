package checkpointsase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
Regression coverage for P81-145407: resourceNetworkRead used to build the
`region` list from prior state rather than from the API response, so the
tenant's real footprint never reached the diff. A region deleted out of band
(console, or DELETE /v3/networks/standard/{id}/regions/{regionId}) left its
stale entry -- dead region_id included -- sitting in state, and `terraform plan`
proposed nothing at all. The operator was told the estate matched the
configuration while a whole region, and the gateway in it, was gone.

The read is now the only thing that had to change: once a removed region drops
out of state, the list is shorter than the config and resourceNetworkUpdate's
existing resourceRegionCreate path puts it back.

Ordering is load-bearing here, not cosmetic. `region` is a TypeList, so
rebuilding it in raw API order would show a reshuffle on every plan of an
untouched network. The reconciler walks prior state first for exactly that
reason, and TestNetworkReadPreservesStateOrder pins it.
*/

// standardNetworkRegionJSON renders one NetworkRegion. Every property in
// model_network_region.go's requiredProperties loop has to be present or the
// fixture fails to decode and the test measures the fixture, not the provider.
func standardNetworkRegionJSON(id, name string) string {
	return `{"createdAt":"2026-01-01T00:00:00Z","network":"net-1","dns":"` + name +
		`.net.example","name":"` + name + `","instances":[],"id":"` + id + `","tenantId":"tn-1"}`
}

// standardNetworkServer answers the two calls resourceNetworkRead makes: the
// network itself, and the tenant-wide cloud-region catalogue. The catalogue
// path is a suffix of the network path, so it has to be matched first.
func standardNetworkServer(t *testing.T, regionsJSON ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/harmony-sase-regions") {
			_, _ = w.Write([]byte(`[
			  {"id":"cp-us-east","displayName":"US East","name":"us-east"},
			  {"id":"cp-eu-west","displayName":"EU West","name":"eu-west"}
			]`))
			return
		}
		_, _ = w.Write([]byte(`{
		  "createdAt":"2026-01-01T00:00:00Z","dns":"net.example","subnet":"10.0.0.0/16",
		  "accessType":"standard","applications":[],"tags":[],"name":"under-test",
		  "isDefault":false,"id":"net-1","tenantId":"tn-1","regions":[` +
			strings.Join(regionsJSON, ",") + `]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// stateRegion builds one prior-state `region` block.
func stateRegion(cpRegionId, regionId string, idle bool) map[string]interface{} {
	return map[string]interface{}{"cpregion_id": cpRegionId, "region_id": regionId, "idle": idle}
}

// readNetworkWithRegions runs the real read against the fixture and returns the
// resulting `region` list.
func readNetworkWithRegions(t *testing.T, srv *httptest.Server, state []interface{}) []map[string]interface{} {
	t.Helper()
	d := schema.TestResourceDataRaw(t, resourceNetwork().Schema, map[string]interface{}{"region": state})
	d.SetId("net-1")

	if diags := resourceNetworkRead(context.Background(), d, newTestUserAPIClient(srv.URL)); diags.HasError() {
		t.Fatalf("read failed: %s", diagsText(diags))
	}

	raw := d.Get("region").([]interface{})
	got := make([]map[string]interface{}, len(raw))
	for i, entry := range raw {
		got[i] = entry.(map[string]interface{})
	}
	return got
}

// cpRegionIds is the footprint the read left in state, in order.
func cpRegionIds(regions []map[string]interface{}) []string {
	ids := make([]string, len(regions))
	for i, region := range regions {
		ids[i] = region["cpregion_id"].(string)
	}
	return ids
}

func assertCpRegionIds(t *testing.T, got []map[string]interface{}, want ...string) {
	t.Helper()
	gotIds := cpRegionIds(got)
	if len(gotIds) != len(want) {
		t.Fatalf("footprint = %v, want %v", gotIds, want)
	}
	for i := range want {
		if gotIds[i] != want[i] {
			t.Fatalf("footprint = %v, want %v", gotIds, want)
		}
	}
}

// The bug. Two regions in state, one left on the tenant: the read must report
// the loss, so the plan proposes putting it back.
func TestNetworkReadReportsRegionRemovedOnTenant(t *testing.T) {
	srv := standardNetworkServer(t, standardNetworkRegionJSON("reg-us", "US East"))

	got := readNetworkWithRegions(t, srv, []interface{}{
		stateRegion("cp-us-east", "reg-us", false),
		stateRegion("cp-eu-west", "reg-eu", false),
	})

	assertCpRegionIds(t, got, "cp-us-east")
}

// The inverse, found while verifying the ticket. checkpointsase_network is the
// sole owner of a standard network's footprint -- there is no standalone
// region resource for standard networks, only checkpointsase_enhanced_region --
// so a region the config never declared is drift too, and the plan should
// propose removing it.
func TestNetworkReadReportsRegionAddedOnTenant(t *testing.T) {
	srv := standardNetworkServer(t,
		standardNetworkRegionJSON("reg-us", "US East"),
		standardNetworkRegionJSON("reg-eu", "EU West"))

	got := readNetworkWithRegions(t, srv, []interface{}{
		stateRegion("cp-us-east", "reg-us", false),
	})

	assertCpRegionIds(t, got, "cp-us-east", "cp-eu-west")
}

// An untouched network must read back unchanged, with the computed fields
// populated from the response.
func TestNetworkReadLeavesUnchangedFootprintAlone(t *testing.T) {
	srv := standardNetworkServer(t,
		standardNetworkRegionJSON("reg-us", "US East"),
		standardNetworkRegionJSON("reg-eu", "EU West"))

	got := readNetworkWithRegions(t, srv, []interface{}{
		stateRegion("cp-us-east", "reg-us", false),
		stateRegion("cp-eu-west", "reg-eu", false),
	})

	assertCpRegionIds(t, got, "cp-us-east", "cp-eu-west")
	if got[0]["region_id"] != "reg-us" || got[0]["name"] != "US East" || got[0]["dns"] != "US East.net.example" {
		t.Errorf("region[0] computed fields not populated from the response: %#v", got[0])
	}
}

// `region` is a TypeList, so the read must not reorder a footprint it agrees
// with: config order wins, or every plan of an untouched network shows a
// reshuffle.
func TestNetworkReadPreservesStateOrder(t *testing.T) {
	// API reports US first; state (and therefore config) declares EU first.
	srv := standardNetworkServer(t,
		standardNetworkRegionJSON("reg-us", "US East"),
		standardNetworkRegionJSON("reg-eu", "EU West"))

	got := readNetworkWithRegions(t, srv, []interface{}{
		stateRegion("cp-eu-west", "reg-eu", false),
		stateRegion("cp-us-east", "reg-us", false),
	})

	assertCpRegionIds(t, got, "cp-eu-west", "cp-us-east")
}

// The import path: state is empty, so the whole footprint comes from the API.
// This is what importRegions used to do on its own.
func TestNetworkReadImportsWholeFootprintFromEmptyState(t *testing.T) {
	srv := standardNetworkServer(t,
		standardNetworkRegionJSON("reg-us", "US East"),
		standardNetworkRegionJSON("reg-eu", "EU West"))

	got := readNetworkWithRegions(t, srv, []interface{}{})

	assertCpRegionIds(t, got, "cp-us-east", "cp-eu-west")
	for i, region := range got {
		if region["idle"].(bool) {
			t.Errorf("region[%d] imported idle=true; no read model carries idle, so it must default false", i)
		}
	}
}

// `idle` has no read model (same documented gap as checkpointsase_gateway's
// `idle`), so the read cannot refresh it and must carry the state value
// forward. Dropping it would make every config declaring idle=true diff on
// every plan.
func TestNetworkReadCarriesIdleForward(t *testing.T) {
	srv := standardNetworkServer(t,
		standardNetworkRegionJSON("reg-us", "US East"),
		standardNetworkRegionJSON("reg-eu", "EU West"))

	got := readNetworkWithRegions(t, srv, []interface{}{
		stateRegion("cp-us-east", "reg-us", true),
		stateRegion("cp-eu-west", "reg-eu", false),
	})

	if !got[0]["idle"].(bool) {
		t.Errorf("region[0] idle = false after read, want the state value true")
	}
	if got[1]["idle"].(bool) {
		t.Errorf("region[1] idle = true after read, want the state value false")
	}
}
