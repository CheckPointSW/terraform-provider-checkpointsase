package checkpointsase

import (
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
)

// TestFlattenTunnelDataDoesNotLeakPointers is a regression test for two bugs in
// flattenTunnelData:
//   - Passphrase (*string) was assigned straight into the map[string]interface{}
//     that flattenTunnelData returns, corrupting Terraform state with a pointer
//     instead of the value.
//   - RemoteID is a union type wrapping *string, and the outer *RemoteID pointer
//     was dereferenced without a nil check, panicking whenever the server omits
//     remoteID.
//
// The "present" and "omitted" cases leave RemoteID unset (nil), which is exactly
// the shape that panicked before the fix. The third case covers the other half of
// the two-level nil check: a non-nil RemoteID wrapper with a nil inner string.
func TestFlattenTunnelDataDoesNotLeakPointers(t *testing.T) {
	pass := "super-secret-psk"
	for _, tc := range []struct {
		name           string
		in             *perimeter81Sdk.IPSecRedundantTunnel
		wantPassphrase string
		wantRemoteID   string
	}{
		{"present", &perimeter81Sdk.IPSecRedundantTunnel{Passphrase: &pass}, pass, ""},
		{"omitted", &perimeter81Sdk.IPSecRedundantTunnel{}, "", ""},
		{"remote id wrapper present but inner string omitted", &perimeter81Sdk.IPSecRedundantTunnel{RemoteID: &perimeter81Sdk.RemoteID{}}, "", ""},
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
			gotPassphrase, ok := m["passphrase"].(string)
			if !ok {
				t.Fatalf("passphrase is %T, want string — a pointer here corrupts state", m["passphrase"])
			}
			if gotPassphrase != tc.wantPassphrase {
				t.Errorf("passphrase = %q, want %q", gotPassphrase, tc.wantPassphrase)
			}
			gotRemoteID, ok := m["remote_id"].(string)
			if !ok {
				t.Fatalf("remote_id is %T, want string", m["remote_id"])
			}
			if gotRemoteID != tc.wantRemoteID {
				t.Errorf("remote_id = %q, want %q", gotRemoteID, tc.wantRemoteID)
			}
		})
	}
}
