package checkpointsase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
Regression coverage for P81-145227: a checkpointsase_network,
checkpointsase_enhanced_static_tunnel, or checkpointsase_enhanced_dynamic_tunnel
deleted out of band (console, or DELETE outside Terraform) must be reported as
drift on the next Read -- d.SetId("") with no error diagnostic -- so the plan
proposes recreating it. Before the fix, any error from the fetch, 404 included,
was funneled straight into appendErrorDiags, which wedged the workspace: plan
and destroy both exited 1 and the only recovery was a manual
`terraform state rm`.

A non-404 error (e.g. 500) must still fail: that is a transient/server problem,
not evidence the resource is gone, and clearing the id on one would silently
drop a live resource from state.
*/

// fixedStatusServer answers every request with the given status and body.
func fixedStatusServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResourceNetworkReadClearsIdOn404(t *testing.T) {
	srv := fixedStatusServer(t, http.StatusNotFound, `{"message":"network doesnt exists","messageCode":"NOT_FOUND","status":404}`)

	d := schema.TestResourceDataRaw(t, resourceNetwork().Schema, map[string]interface{}{})
	d.SetId("net-gone")

	diags := resourceNetworkRead(context.Background(), d, newTestUserAPIClient(srv.URL))
	if diags.HasError() {
		t.Fatalf("a 404 must be reported as drift, not as an error: %s", diagsText(diags))
	}
	if d.Id() != "" {
		t.Errorf("d.Id() = %q after a 404, want empty", d.Id())
	}
}

func TestResourceNetworkReadKeepsIdOnServerError(t *testing.T) {
	srv := fixedStatusServer(t, http.StatusInternalServerError, `{"message":"boom"}`)

	d := schema.TestResourceDataRaw(t, resourceNetwork().Schema, map[string]interface{}{})
	d.SetId("net-1")

	diags := resourceNetworkRead(context.Background(), d, newTestUserAPIClient(srv.URL))
	if !diags.HasError() {
		t.Fatalf("a 500 must be an error, not drift")
	}
	if d.Id() != "net-1" {
		t.Errorf("d.Id() = %q after a 500, want it kept", d.Id())
	}
}

func TestResourceEnhancedStaticTunnelReadClearsIdOn404(t *testing.T) {
	srv := fixedStatusServer(t, http.StatusNotFound, `{"message":"Static tunnel not found","status":404}`)

	d := schema.TestResourceDataRaw(t, resourceEnhancedStaticTunnel().Schema,
		map[string]interface{}{"network_id": "net-1"})
	d.SetId("tunnel-gone")

	diags := resourceEnhancedStaticTunnelRead(context.Background(), d, newTestUserAPIClient(srv.URL))
	if diags.HasError() {
		t.Fatalf("a 404 must be reported as drift, not as an error: %s", diagsText(diags))
	}
	if d.Id() != "" {
		t.Errorf("d.Id() = %q after a 404, want empty", d.Id())
	}
}

func TestResourceEnhancedStaticTunnelReadKeepsIdOnServerError(t *testing.T) {
	srv := fixedStatusServer(t, http.StatusInternalServerError, `{"message":"boom"}`)

	d := schema.TestResourceDataRaw(t, resourceEnhancedStaticTunnel().Schema,
		map[string]interface{}{"network_id": "net-1"})
	d.SetId("tunnel-1")

	diags := resourceEnhancedStaticTunnelRead(context.Background(), d, newTestUserAPIClient(srv.URL))
	if !diags.HasError() {
		t.Fatalf("a 500 must be an error, not drift")
	}
	if d.Id() != "tunnel-1" {
		t.Errorf("d.Id() = %q after a 500, want it kept", d.Id())
	}
}

func TestResourceEnhancedDynamicTunnelReadClearsIdOn404(t *testing.T) {
	srv := fixedStatusServer(t, http.StatusNotFound, `{"message":"Tunnel with Id KWpRHJ35Ao not found.","status":404}`)

	d := schema.TestResourceDataRaw(t, resourceEnhancedDynamicTunnel().Schema,
		map[string]interface{}{"network_id": "net-1"})
	d.SetId("dyn-tunnel-gone")

	diags := resourceEnhancedDynamicTunnelRead(context.Background(), d, newTestUserAPIClient(srv.URL))
	if diags.HasError() {
		t.Fatalf("a 404 must be reported as drift, not as an error: %s", diagsText(diags))
	}
	if d.Id() != "" {
		t.Errorf("d.Id() = %q after a 404, want empty", d.Id())
	}
}

func TestResourceEnhancedDynamicTunnelReadKeepsIdOnServerError(t *testing.T) {
	srv := fixedStatusServer(t, http.StatusInternalServerError, `{"message":"boom"}`)

	d := schema.TestResourceDataRaw(t, resourceEnhancedDynamicTunnel().Schema,
		map[string]interface{}{"network_id": "net-1"})
	d.SetId("dyn-tunnel-1")

	diags := resourceEnhancedDynamicTunnelRead(context.Background(), d, newTestUserAPIClient(srv.URL))
	if !diags.HasError() {
		t.Fatalf("a 500 must be an error, not drift")
	}
	if d.Id() != "dyn-tunnel-1" {
		t.Errorf("d.Id() = %q after a 500, want it kept", d.Id())
	}
}
