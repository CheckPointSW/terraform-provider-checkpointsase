package checkpointsase

import (
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
			out := flattenTunnelData(tc.in, nil)
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

// TestSetIfPresentPreservesCredentialsAcrossAPlainRead is a regression test
// for the OpenVPN Read bug: resourceOpenvpnRead used to call
// d.Set("access_key_id", tunnel.GetAccessKeyId()) and
// d.Set("secret_access_key", tunnel.GetSecretAccessKey()) unconditionally.
// The v3 API only returns those credentials on create and on rotation — a
// plain read (e.g. `terraform refresh`) gets neither back, and the SDK's
// nil-safe getters turned that omission into "", so the unconditional d.Set
// blanked the terraform state's only durable copy of the tunnel's
// credentials.
//
// resourceOpenvpnRead itself can't be exercised here without a live/mocked
// *perimeter81Sdk.APIClient, so this test drives the extracted guard
// (setIfPresent) directly against a *schema.ResourceData built with
// schema.TestResourceDataRaw and pre-populated exactly the way a real
// resource's state would be after a prior create/rotation — then replays a
// plain read that reports neither credential present and asserts the prior
// values survive.
func TestSetIfPresentPreservesCredentialsAcrossAPlainRead(t *testing.T) {
	// Obviously-fake fixture values — not real credentials.
	const priorAccessKeyID = "AKID-EXISTING-FAKE"
	const priorSecretAccessKey = "existing-fake-secret"

	d := schema.TestResourceDataRaw(t, resourceOpenvpn().Schema, map[string]interface{}{
		"access_key_id":     priorAccessKeyID,
		"secret_access_key": priorSecretAccessKey,
	})

	// Simulate a plain read where the API reported neither credential —
	// i.e. tunnel.HasAccessKeyId() / tunnel.HasSecretAccessKey() are both
	// false, exactly like a StandardGetOpenVPNTunnel response after create.
	if err := setIfPresent(d, "access_key_id", "", false); err != nil {
		t.Fatalf("setIfPresent(access_key_id, absent): %v", err)
	}
	if err := setIfPresent(d, "secret_access_key", "", false); err != nil {
		t.Fatalf("setIfPresent(secret_access_key, absent): %v", err)
	}

	if got := d.Get("access_key_id").(string); got != priorAccessKeyID {
		t.Errorf("access_key_id = %q, want %q (a read that gets nothing back must not blank the prior value)", got, priorAccessKeyID)
	}
	if got := d.Get("secret_access_key").(string); got != priorSecretAccessKey {
		t.Errorf("secret_access_key = %q, want %q (a read that gets nothing back must not blank the prior value)", got, priorSecretAccessKey)
	}

	// PRESENT BUT EMPTY. This is what the server actually does after create: it
	// sends secretAccessKey back as "" rather than omitting it, so the SDK's
	// generated HasSecretAccessKey() reports true. Found live — the first version
	// of this guard keyed only on `present` and so let Read overwrite the stored
	// credential with "", which is precisely what it was written to prevent.
	if err := setIfPresent(d, "secret_access_key", "", true); err != nil {
		t.Fatalf("setIfPresent(secret_access_key, present-but-empty): %v", err)
	}
	if got := d.Get("secret_access_key").(string); got != priorSecretAccessKey {
		t.Errorf("secret_access_key = %q, want %q (a present-but-empty value must not blank the prior value)", got, priorSecretAccessKey)
	}

	// The other half of the guard: when the API does report a real value (e.g. a
	// rotation just happened), it must still be written.
	const rotatedSecret = "rotated-fake-secret" // fixture value, not a real credential
	if err := setIfPresent(d, "secret_access_key", rotatedSecret, true); err != nil {
		t.Fatalf("setIfPresent(secret_access_key, present): %v", err)
	}
	if got := d.Get("secret_access_key").(string); got != rotatedSecret {
		t.Errorf("secret_access_key = %q, want %q (a value the API does report must still be written)", got, rotatedSecret)
	}
}

// TestFlattenTunnelDataPreservesPassphraseWhenAPIOmitsIt is a regression test
// for the same class of bug in the IPSec redundant tunnel sibling:
// flattenTunnelData used to assign tunnelItem.GetPassphrase() straight into
// state even when the API omitted passphrase entirely, blanking a field
// that — because tunnel1/tunnel2 are ForceNew — would then show up as a
// diff and force a destroy/recreate of a live tunnel pair on the next plan.
func TestFlattenTunnelDataPreservesPassphraseWhenAPIOmitsIt(t *testing.T) {
	priorTunnel := []interface{}{map[string]interface{}{
		"passphrase": "existing-fake-psk",
	}}

	out := flattenTunnelData(&perimeter81Sdk.IPSecRedundantTunnel{}, priorTunnel)
	if len(out) != 1 {
		t.Fatalf("got %d entries, want 1", len(out))
	}
	m, ok := out[0].(map[string]interface{})
	if !ok {
		t.Fatalf("entry is %T, want map[string]interface{}", out[0])
	}
	if got := m["passphrase"]; got != "existing-fake-psk" {
		t.Errorf("passphrase = %v, want %q (an omitted API value must not blank the prior state)", got, "existing-fake-psk")
	}

	// When the API does report a passphrase, it must win over the prior value.
	newPass := "rotated-fake-psk"
	out = flattenTunnelData(&perimeter81Sdk.IPSecRedundantTunnel{Passphrase: &newPass}, priorTunnel)
	m, ok = out[0].(map[string]interface{})
	if !ok {
		t.Fatalf("entry is %T, want map[string]interface{}", out[0])
	}
	if got := m["passphrase"]; got != newPass {
		t.Errorf("passphrase = %v, want %q (a value the API does report must still be written)", got, newPass)
	}
}

// TestReadByIDFromListMatchesExactly pins the whole contract of the helper the
// three Phase 3 resources read through. The prefix case is the one that matters:
// a prefix match would hand one resource another resource's attributes, and
// Terraform would then persist that as if the Read had succeeded. Test row
// OS-N06 exists for exactly this failure.
func TestReadByIDFromListMatchesExactly(t *testing.T) {
	type item struct {
		id   string
		name string
	}
	idOf := func(i item) string { return i.id }
	items := []item{{"abc", "first"}, {"abcdef", "second"}, {"", "no id at all"}}

	got, found := readByIDFromList(items, "abc", idOf)
	if !found || got.name != "first" {
		t.Errorf("exact match: got (%+v, %v), want ({abc first}, true)", got, found)
	}

	got, found = readByIDFromList(items, "abcdef", idOf)
	if !found || got.name != "second" {
		t.Errorf("the longer id must match its own element, not the shorter one: got (%+v, %v)", got, found)
	}

	if _, found = readByIDFromList(items, "abcd", idOf); found {
		t.Error("a prefix of a real id matched; matching must be exact equality")
	}

	if _, found = readByIDFromList(items, "first", idOf); found {
		t.Error("a name matched; matching must be on the id only")
	}

	if _, found = readByIDFromList(items, "zzz", idOf); found {
		t.Error("an absent id was reported as found; callers rely on false to apply the drift convention")
	}
}

// TestReadByIDFromListRejectsAnEmptyID is separate because it guards a specific
// hazard introduced by A21a/A22a: id is optional on User and Group, so idOf can
// legitimately return "". Without the guard, a resource whose stored id was
// somehow empty would silently adopt the first id-less record in the list.
func TestReadByIDFromListRejectsAnEmptyID(t *testing.T) {
	type item struct{ id string }
	idOf := func(i item) string { return i.id }

	if _, found := readByIDFromList([]item{{""}, {"real"}}, "", idOf); found {
		t.Error("an empty id matched an id-less element; an empty id must never match anything")
	}
	if _, found := readByIDFromList([]item{}, "anything", idOf); found {
		t.Error("an empty collection reported a match")
	}
	if _, found := readByIDFromList(nil, "anything", idOf); found {
		t.Error("a nil collection reported a match")
	}
}

// TestReadByIDFromListReturnsTheZeroValueWhenAbsent pins that callers can use
// the returned value unconditionally after checking found, without a nil deref.
func TestReadByIDFromListReturnsTheZeroValueWhenAbsent(t *testing.T) {
	type item struct{ id, name string }
	got, found := readByIDFromList([]item{{"a", "x"}}, "b", func(i item) string { return i.id })
	if found {
		t.Fatal("unexpected match")
	}
	if got.id != "" || got.name != "" {
		t.Errorf("want the zero value on miss, got %+v", got)
	}
}
