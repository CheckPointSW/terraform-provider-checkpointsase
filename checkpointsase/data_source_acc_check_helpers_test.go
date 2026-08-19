package checkpointsase

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// Shared assertion helpers for the data source acceptance tests
// (data_source_tenant_wide_test.go, data_source_standard_network_scoped_test.go,
// data_source_enhanced_network_scoped_test.go).
//
// The four pre-existing data source tests assert only "the data source appears
// in state", which cannot fail for any data source that returns 200 with an
// empty body. These helpers exist so the new tests can assert the shape of the
// flattened list AND, where the tenant is guaranteed to hold content, one
// specific element of it — without hardcoding tenant-specific values.
//
// Terraform state is a flat map of dotted keys. A list attribute `networks`
// holding two elements each with an `id` is stored as:
//
//	networks.#    = "2"
//	networks.0.id = "..."
//	networks.1.id = "..."
//
// so every helper below is expressed in terms of that flat map. Reading state
// directly rather than going through resource.TestCheckResourceAttr avoids the
// ambiguity around count keys (an unset list and an empty list are not
// distinguishable in state, and neither is a defect).

// dataSourceAttrs returns the flat attribute map Terraform recorded for a data
// source or resource instance.
func dataSourceAttrs(s *terraform.State, name string) (map[string]string, error) {
	rs, ok := s.RootModule().Resources[name]
	if !ok {
		return nil, fmt.Errorf("not found in state: %s", name)
	}
	if rs.Primary == nil {
		return nil, fmt.Errorf("%s has no primary instance in state", name)
	}
	return rs.Primary.Attributes, nil
}

// dataSourceListLen reads the element count of a list attribute out of the flat
// state map.
//
// An empty list is written as "<attr>.# = 0"; a list the provider never set at
// all is absent from the map entirely. Both mean "no elements" and neither is
// distinguishable by a practitioner, so both answer 0. A present-but-garbage
// count is an error, because that would mean state is corrupt.
func dataSourceListLen(attrs map[string]string, attr string) (int, error) {
	raw, ok := attrs[attr+".#"]
	if !ok {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s.# = %q, which is not a number", attr, raw)
	}
	return n, nil
}

// testAccCheckDataSourceListPresent asserts that a list attribute exists in
// state as a countable list. This is the honest assertion for a data source
// whose content depends on tenant state: it proves the read succeeded and that
// the provider wrote a list-shaped value, without asserting a count the tenant
// does not guarantee.
func testAccCheckDataSourceListPresent(name, attr string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		if _, ok := attrs[attr+".#"]; !ok {
			return fmt.Errorf("%s: %s is absent from state — the provider never set the list attribute", name, attr)
		}
		if _, err := dataSourceListLen(attrs, attr); err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		return nil
	}
}

// testAccCheckDataSourceListMinLen asserts a list attribute has at least min
// elements. Only used where the content is server-provided and cannot be
// emptied by a tenant operation (the region catalogues, the built-in service
// objects) or where the test itself created the content.
func testAccCheckDataSourceListMinLen(name, attr string, min int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		got, err := dataSourceListLen(attrs, attr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		if got < min {
			return fmt.Errorf("%s: %s has %d elements, want at least %d", name, attr, got, min)
		}
		return nil
	}
}

// testAccCheckDataSourceElemFieldsSet asserts that the element at index has a
// non-empty value for each named field. Fails if the list is shorter than
// index+1, so it is only for lists whose length is already guaranteed.
func testAccCheckDataSourceElemFieldsSet(name, attr string, index int, fields ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		got, err := dataSourceListLen(attrs, attr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		if got <= index {
			return fmt.Errorf("%s: %s has %d elements, so element %d cannot be checked", name, attr, got, index)
		}
		return checkElemFieldsSet(name, attrs, attr, index, fields)
	}
}

// testAccCheckDataSourceFirstElemFieldsSetIfAny asserts the named fields of the
// first element are non-empty, but passes when the list is empty.
//
// This is the right check for a data source the tenant may legitimately have no
// content for: it cannot fail on an empty tenant, and it still catches a
// flatten function that returns elements with the wrong keys or with values it
// failed to map. Asserting a count instead would fail today for a reason that
// is not a defect, and would silently change meaning once unrelated content
// appears in the tenant.
func testAccCheckDataSourceFirstElemFieldsSetIfAny(name, attr string, fields ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		got, err := dataSourceListLen(attrs, attr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		if got == 0 {
			return nil
		}
		return checkElemFieldsSet(name, attrs, attr, 0, fields)
	}
}

// testAccCheckDataSourceEveryElemFieldIn asserts that every element's field
// holds one of the allowed values. Vacuously true for an empty list, which is
// deliberate: it constrains the values the flatten function produces without
// depending on how many there are.
func testAccCheckDataSourceEveryElemFieldIn(name, attr, field string, allowed ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		got, err := dataSourceListLen(attrs, attr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		for i := 0; i < got; i++ {
			key := fmt.Sprintf("%s.%d.%s", attr, i, field)
			value := attrs[key]
			found := false
			for _, want := range allowed {
				if value == want {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s: %s = %q, want one of %v", name, key, value, allowed)
			}
		}
		return nil
	}
}

// testAccCheckDataSourceEveryElemFieldEqualsResourceID asserts that every
// element's field equals the primary ID of resourceName. Used on the
// network-scoped data sources: every row a network-scoped read returns must
// belong to the network that was asked for, which is the one thing that
// distinguishes a correct meta mapping from a plausible-looking wrong one.
func testAccCheckDataSourceEveryElemFieldEqualsResourceID(name, attr, field, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		wantID, err := primaryIDFromState(s, resourceName)
		if err != nil {
			return err
		}
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		got, err := dataSourceListLen(attrs, attr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		for i := 0; i < got; i++ {
			key := fmt.Sprintf("%s.%d.%s", attr, i, field)
			if attrs[key] != wantID {
				return fmt.Errorf("%s: %s = %q, want %q (the ID of %s)", name, key, attrs[key], wantID, resourceName)
			}
		}
		return nil
	}
}

// testAccCheckDataSourceMemberByResourceID locates the single element of a list
// attribute whose keyField equals the primary ID of resourceName, then asserts
// that each name in setFields is non-empty on that element and that each entry
// in wantFields matches exactly.
//
// Locating the element by the ID Terraform recorded — rather than assuming
// index 0 — is what makes this usable against a live tenant whose list order
// and length are not ours to control. It gives the strongest assertion
// available for a tenant-wide list: the object we just created is in it, and
// the fields the flatten function claims to map are actually populated.
func testAccCheckDataSourceMemberByResourceID(
	name, attr, keyField, resourceName string,
	setFields []string,
	wantFields map[string]string,
) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		wantID, err := primaryIDFromState(s, resourceName)
		if err != nil {
			return err
		}
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		count, err := dataSourceListLen(attrs, attr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}

		matches := []int{}
		for i := 0; i < count; i++ {
			if attrs[fmt.Sprintf("%s.%d.%s", attr, i, keyField)] == wantID {
				matches = append(matches, i)
			}
		}
		switch len(matches) {
		case 1:
		case 0:
			return fmt.Errorf(
				"%s: no element of %s has %s = %q (the ID of %s); %s has %d elements",
				name, attr, keyField, wantID, resourceName, attr, count)
		default:
			return fmt.Errorf(
				"%s: %d elements of %s have %s = %q (the ID of %s), want exactly 1 — the list is duplicating rows",
				name, len(matches), attr, keyField, wantID, resourceName)
		}
		index := matches[0]

		if err := checkElemFieldsSet(name, attrs, attr, index, setFields); err != nil {
			return err
		}
		for _, field := range sortedKeys(wantFields) {
			key := fmt.Sprintf("%s.%d.%s", attr, index, field)
			if attrs[key] != wantFields[field] {
				return fmt.Errorf("%s: %s = %q, want %q", name, key, attrs[key], wantFields[field])
			}
		}
		return nil
	}
}

// testAccCheckDataSourceListLenMatchesTotal asserts that a paginated data
// source's element count agrees with the total it reports.
//
// totalAttr is parsed as a float rather than string-compared: the pagination
// fields are schema.TypeFloat, so whether state renders 1 as "1" or "1.0" is a
// formatting detail of the SDK's flatmap writer, not something a test should
// assert on. Comparing the parsed number keeps the assertion about the thing
// that can actually regress — a provider that reports a total disagreeing with
// the rows it returned, which is what a mishandled page parameter looks like.
func testAccCheckDataSourceListLenMatchesTotal(name, listAttr, totalAttr string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, name)
		if err != nil {
			return err
		}
		count, err := dataSourceListLen(attrs, listAttr)
		if err != nil {
			return fmt.Errorf("%s: %s", name, err)
		}
		raw, ok := attrs[totalAttr]
		if !ok {
			return fmt.Errorf("%s: %s is absent from state", name, totalAttr)
		}
		total, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("%s: %s = %q, which is not a number", name, totalAttr, raw)
		}
		if int(total) != count {
			return fmt.Errorf("%s: %s = %v but %s has %d elements — the reported total disagrees with the rows returned",
				name, totalAttr, total, listAttr, count)
		}
		return nil
	}
}

// testAccCheckAllNetworksIsSumOfParts asserts that the client-side merge in
// checkpointsase_all_networks returned exactly as many rows as the two list
// endpoints it merges, and that every row carries a valid network_kind.
//
// This is the only assertion available for the merge that does not depend on
// how much content the tenant holds: it holds for an empty tenant and for a
// full one, and it fails if the merge drops a list, double-counts one, or
// mistags a row's origin.
//
// The tests using it must NOT call t.Parallel(): the three data sources are
// three separate API reads, so a network created or deleted between them by
// another test would break the equality for a reason that is not a defect. Go
// runs non-parallel tests one at a time while every t.Parallel() test is
// paused, which is exactly the isolation this needs.
func testAccCheckAllNetworksIsSumOfParts(allName, standardName, enhancedName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		counts := map[string]int{}
		for _, ds := range []struct{ label, name string }{
			{"all", allName}, {"standard", standardName}, {"enhanced", enhancedName},
		} {
			attrs, err := dataSourceAttrs(s, ds.name)
			if err != nil {
				return err
			}
			n, err := dataSourceListLen(attrs, "networks")
			if err != nil {
				return fmt.Errorf("%s: %s", ds.name, err)
			}
			counts[ds.label] = n
		}

		if counts["all"] != counts["standard"]+counts["enhanced"] {
			return fmt.Errorf(
				"%s returned %d networks but %s returned %d and %s returned %d (%d+%d=%d): "+
					"either the client-side merge is wrong, or the tenant changed between the three reads "+
					"(if the latter, this test must not run in parallel with one that creates networks)",
				allName, counts["all"], standardName, counts["standard"], enhancedName, counts["enhanced"],
				counts["standard"], counts["enhanced"], counts["standard"]+counts["enhanced"])
		}

		attrs, err := dataSourceAttrs(s, allName)
		if err != nil {
			return err
		}
		kinds := map[string]int{}
		for i := 0; i < counts["all"]; i++ {
			kinds[attrs[fmt.Sprintf("networks.%d.network_kind", i)]]++
		}
		if kinds["standard"] != counts["standard"] {
			return fmt.Errorf("%s tagged %d rows network_kind=standard, want %d",
				allName, kinds["standard"], counts["standard"])
		}
		if kinds["enhanced"] != counts["enhanced"] {
			return fmt.Errorf("%s tagged %d rows network_kind=enhanced, want %d",
				allName, kinds["enhanced"], counts["enhanced"])
		}
		return nil
	}
}

// testAccCheckDataSourceIDsDiffer asserts two data source instances did not end
// up with the same Terraform ID.
//
// The companion to L16c. That item is about an ID that changes when it should
// not — a timestamp, which defeats downstream references. The mirror-image
// defect is an ID that stays the same when the configuration differs: a data
// source that takes filter arguments and hardcodes a constant ID gives two
// instances holding different results one identity. Both are wrong, and a
// constant ID only fixes the first.
func testAccCheckDataSourceIDsDiffer(nameA, nameB string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ids := map[string]string{}
		for _, name := range []string{nameA, nameB} {
			rs, ok := s.RootModule().Resources[name]
			if !ok {
				return fmt.Errorf("not found in state: %s", name)
			}
			if rs.Primary == nil || rs.Primary.ID == "" {
				return fmt.Errorf("%s has no ID in state", name)
			}
			ids[name] = rs.Primary.ID
		}
		if ids[nameA] == ids[nameB] {
			return fmt.Errorf(
				"%s and %s both have the ID %q, but their configurations differ — a data source "+
					"with arguments must derive its ID from them, or two instances holding "+
					"different results share one identity",
				nameA, nameB, ids[nameA])
		}
		return nil
	}
}

// checkElemFieldsSet asserts each named field of one list element is present
// and non-empty.
func checkElemFieldsSet(name string, attrs map[string]string, attr string, index int, fields []string) error {
	for _, field := range fields {
		key := fmt.Sprintf("%s.%d.%s", attr, index, field)
		value, ok := attrs[key]
		if !ok {
			return fmt.Errorf("%s: %s is absent from state — the flatten function does not set this key", name, key)
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s: %s is empty — the flatten function set the key but mapped no value into it", name, key)
		}
	}
	return nil
}

// primaryIDFromState returns the ID Terraform recorded for a managed resource.
func primaryIDFromState(s *terraform.State, resourceName string) (string, error) {
	rs, ok := s.RootModule().Resources[resourceName]
	if !ok {
		return "", fmt.Errorf("not found in state: %s", resourceName)
	}
	if rs.Primary == nil || rs.Primary.ID == "" {
		return "", fmt.Errorf("%s has no ID in state", resourceName)
	}
	return rs.Primary.ID, nil
}

// sortedKeys keeps the wantFields assertions deterministic so a failure always
// names the same attribute first across runs.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
