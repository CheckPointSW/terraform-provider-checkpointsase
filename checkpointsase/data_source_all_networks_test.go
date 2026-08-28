package checkpointsase

import "testing"

// The v3 spec deletes GET /networks, so this data source merges the standard
// and enhanced lists client-side. The merge itself is pure and unit-testable.
func TestFlattenAllNetworksMergesBothSourcesAndTagsKind(t *testing.T) {
	rows := flattenAllNetworks(
		[]allNetworkRow{{ID: "std1", Name: "standard-one", Subnet: "10.0.0.0/16"}},
		[]allNetworkRow{{ID: "enh1", Name: "enhanced-one", Subnet: "10.1.0.0/16"}},
	)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	first := rows[0].(map[string]interface{})
	second := rows[1].(map[string]interface{})
	if first["id"] != "std1" || first["network_kind"] != "standard" {
		t.Errorf("first row = %v, want the standard network tagged standard", first)
	}
	if second["id"] != "enh1" || second["network_kind"] != "enhanced" {
		t.Errorf("second row = %v, want the enhanced network tagged enhanced", second)
	}
}

func TestFlattenAllNetworksHandlesEmptyInputs(t *testing.T) {
	if rows := flattenAllNetworks(nil, nil); len(rows) != 0 {
		t.Errorf("got %d rows, want 0", len(rows))
	}
}

func TestFlattenAllNetworksPreservesEveryDocumentedAttribute(t *testing.T) {
	rows := flattenAllNetworks([]allNetworkRow{{
		ID: "n1", Name: "n", Tags: []string{"a"}, DNS: "d", Subnet: "10.0.0.0/8",
		AccessType: "vpn", IsDefault: true, TenantID: "t1",
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-02T00:00:00Z",
	}}, nil)
	row := rows[0].(map[string]interface{})
	for _, key := range []string{
		"id", "name", "tags", "dns", "subnet", "access_type",
		"is_default", "tenant_id", "created_at", "updated_at", "network_kind",
	} {
		if _, ok := row[key]; !ok {
			t.Errorf("row is missing attribute %q", key)
		}
	}
}
