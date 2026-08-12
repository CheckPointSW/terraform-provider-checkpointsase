package checkpointsase

import (
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
)

// TestFlattenTunnelDataDoesNotLeakPointers guards against a *string SDK field
// being assigned straight into the map[string]interface{} that flattenTunnelData
// returns, which corrupts Terraform state (the pointer's address gets diffed
// instead of the value). It exercises both the present and omitted cases,
// since a raw dereference would panic on the latter.
func TestFlattenTunnelDataDoesNotLeakPointers(t *testing.T) {
	pass := "super-secret-psk"
	remoteID := "remote-id-fixture"
	// RemoteID is unrelated to the passphrase leak under test, but flattenTunnelData
	// dereferences tunnelItem.RemoteID.String unconditionally, so it must be non-nil
	// here or every case panics before reaching the passphrase assertion below.
	remote := perimeter81Sdk.RemoteID{String: &remoteID}
	for _, tc := range []struct {
		name string
		in   *perimeter81Sdk.IPSecRedundantTunnel
		want string
	}{
		{"present", &perimeter81Sdk.IPSecRedundantTunnel{Passphrase: &pass, RemoteID: &remote}, pass},
		{"omitted", &perimeter81Sdk.IPSecRedundantTunnel{RemoteID: &remote}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := flattenTunnelData(tc.in)
			if len(out) != 1 {
				t.Fatalf("got %d entries, want 1", len(out))
			}
			m, ok := out[0].(map[string]interface{})
			if !ok {
				t.Fatalf("entry is %T, want map[string]interface{}", out[0])
			}
			got, ok := m["passphrase"].(string)
			if !ok {
				t.Fatalf("passphrase is %T, want string — a pointer here corrupts state", m["passphrase"])
			}
			if got != tc.want {
				t.Errorf("passphrase = %q, want %q", got, tc.want)
			}
		})
	}
}
