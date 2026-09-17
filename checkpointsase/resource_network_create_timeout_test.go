package checkpointsase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
Regression coverage for P81-146570: a checkpointsase_network create that hits
its ctx deadline while the async status poll is still reporting completed:
false leaves the network live on the tenant (the backend keeps provisioning
it) but, before this fix, never called d.SetId(). With no id in state,
terraform destroy could never reach the orphan again.

The status endpoint here never reports completed: true, so the poll only
ever returns via the ctx deadline -- exactly the "provider gave up waiting,
backend kept going" shape from the ticket -- and the fix must capture the id
from the last-seen result.resource on that path.
*/
func networkCreateTimeoutServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/networks/standard", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"statusUrl":"/v3/networks/standard/status/status-id"}`))
	})
	mux.HandleFunc("/v3/networks/standard/status/status-id", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"completed":false,"result":{"resource":"/v3/networks/standard/net-999"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestResourceNetworkCreateSetsIdOnCtxTimeoutWhenResourceIsKnown(t *testing.T) {
	srv := networkCreateTimeoutServer(t)

	d := schema.TestResourceDataRaw(t, resourceNetwork().Schema, map[string]interface{}{
		"network": []interface{}{
			map[string]interface{}{"name": "tf-net-timeout"},
		},
		"region": []interface{}{
			map[string]interface{}{"cpregion_id": "region-1"},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	diags := resourceNetworkCreate(ctx, d, newTestUserAPIClient(srv.URL))
	if !diags.HasError() {
		t.Fatalf("a ctx-deadline timeout must still be reported as an error")
	}
	if d.Id() != "net-999" {
		t.Errorf("d.Id() = %q, want %q so the orphaned network is reachable by a later plan/destroy", d.Id(), "net-999")
	}
}

func TestResourceNetworkCreateLeavesIdEmptyOnCtxTimeoutWithNoKnownResource(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/networks/standard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"statusUrl":"/v3/networks/standard/status/status-id"}`))
	})
	mux.HandleFunc("/v3/networks/standard/status/status-id", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// No result at all yet -- the backend hasn't reported a resource, so
		// there is nothing safe to adopt.
		_, _ = w.Write([]byte(`{"completed":false}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	d := schema.TestResourceDataRaw(t, resourceNetwork().Schema, map[string]interface{}{
		"network": []interface{}{
			map[string]interface{}{"name": "tf-net-timeout"},
		},
		"region": []interface{}{
			map[string]interface{}{"cpregion_id": "region-1"},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	diags := resourceNetworkCreate(ctx, d, newTestUserAPIClient(srv.URL))
	if !diags.HasError() {
		t.Fatalf("a ctx-deadline timeout must still be reported as an error")
	}
	if d.Id() != "" {
		t.Errorf("d.Id() = %q, want empty: no resource was ever reported, so nothing should be adopted", d.Id())
	}
}
