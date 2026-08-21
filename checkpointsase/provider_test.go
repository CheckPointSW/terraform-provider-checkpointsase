package checkpointsase

import (
	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var testAccProviders map[string]*schema.Provider
var testAccProvider *schema.Provider

// testAccProviderFactories is required by any test step that mixes an
// ExternalProviders step with a local-build step.
var testAccProviderFactories map[string]func() (*schema.Provider, error)

func init() {
	testAccProvider = Provider()
	// The local name must match the resource prefix, otherwise configurations
	// in acceptance tests cannot resolve checkpointsase_* types.
	testAccProviders = map[string]*schema.Provider{
		"checkpointsase": testAccProvider,
	}
	testAccProviderFactories = map[string]func() (*schema.Provider, error){
		"checkpointsase": func() (*schema.Provider, error) { return Provider(), nil },
	}
}

func TestProvider(t *testing.T) {
	t.Parallel()
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = Provider()
}

/*
testAccEnvClient builds an SDK client straight from the environment, exactly as
providerConfigure builds one from the provider block.

USE THIS IN CheckDestroy AND IN ANY HELPER THAT RUNS OUTSIDE A TEST STEP, never
testAccProvider.Meta(). Meta() is nil both before the harness configures the
provider and on the failure path afterwards, and a CheckDestroy that panics is
worse than one that fails: on 2026-08-20 a nil Meta() panic in
testAccCheckUserDestroy aborted a live run before it printed the real cause of
the failure underneath it, which then took a separate single-test run to find.
A destroy check matters most exactly when the test under it has already failed.

Both variables are the ones the provider's own schema defaults to.
*/
func testAccEnvClient() *perimeter81Sdk.APIClient {
	if meta := testAccProvider.Meta(); meta != nil {
		if client, ok := meta.(*perimeter81Sdk.APIClient); ok {
			return client
		}
	}
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = perimeter81Sdk.BaseURLUS
	}
	return perimeter81Sdk.NewAPIClient(
		perimeter81Sdk.NewConfiguration(os.Getenv("CHECKPOINT_SASE_API_KEY"), baseURL))
}

/*
testAccPreCheck holds only what EVERY acceptance test needs, which is the API
key and nothing else.

IT USED TO ALSO DEMAND CHECKPOINT_SASE_TEST_REGION_ID, and that made the suite
unrunnable for anyone whose tests never touch a region. Measured 2026-08-20: all
seventeen identity acceptance tests failed here, before the first API call, on a
variable that none of user, group, group_membership, users or groups reads. A
universal pre-check may only enforce a universal dependency; anything narrower
belongs in a narrower function, next to testAccPreCheckSecondaryRegion.
*/
func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("CHECKPOINT_SASE_API_KEY"); v == "" {
		t.Fatal("CHECKPOINT_SASE_API_KEY must be set for acceptance tests")
	}
}

/*
testAccPreCheckRegion is required by the tests that interpolate testAccRegionID()
into their configuration — a STANDARD Harmony SASE region ID.

Note which tests deliberately do NOT call it: every fixture built on
checkpointsase_enhanced_*. Enhanced networks draw from a different region
catalogue from the standard resources (4 entries against 13 on the test tenant),
so CHECKPOINT_SASE_TEST_REGION_ID is not a valid harmony_sase_region_id there and
those fixtures take regions[0] from the checkpointsase_enhanced_regions data
source instead — see the comments on TestAccEnhancedNetwork_basic and
testAccDataSourceEnhancedNetworkScopedConfig. Adding the check to them would
demand a variable whose value they cannot use, which is the defect this split
exists to remove.
*/
func testAccPreCheckRegion(t *testing.T) {
	if v := os.Getenv("CHECKPOINT_SASE_TEST_REGION_ID"); v == "" {
		t.Fatal("CHECKPOINT_SASE_TEST_REGION_ID must be set for acceptance tests. " +
			"Harmony SASE region IDs are tenant-specific; list the valid IDs for the " +
			"target tenant via the checkpointsase_regions data source or " +
			"GET /v3/networks/standard/harmony-sase-regions.")
	}
}

// testAccPreCheckSecondaryRegion is required by tests that exercise two
// distinct regions (e.g. adding/removing a region from a network). It is
// intentionally separate from testAccPreCheck so tests that only need one
// region don't require CHECKPOINT_SASE_TEST_REGION_ID_2 to be set.
func testAccPreCheckSecondaryRegion(t *testing.T) {
	if v := os.Getenv("CHECKPOINT_SASE_TEST_REGION_ID_2"); v == "" {
		t.Fatal("CHECKPOINT_SASE_TEST_REGION_ID_2 must be set for acceptance tests " +
			"that require a second, distinct region. Harmony SASE region IDs are " +
			"tenant-specific; list the valid IDs for the target tenant via the " +
			"checkpointsase_regions data source or GET /v3/networks/standard/harmony-sase-regions.")
	}
}

// testAccRegionID returns the STANDARD Harmony SASE region ID used by
// acceptance tests that create standard networks/regions. It is tenant-specific,
// so it is sourced from the environment rather than hardcoded;
// testAccPreCheckRegion enforces that it is set, and every caller of this
// function must call that pre-check. It is NOT valid as an enhanced-network
// harmony_sase_region_id — see testAccPreCheckRegion.
func testAccRegionID() string {
	return os.Getenv("CHECKPOINT_SASE_TEST_REGION_ID")
}

// testAccRegionID2 returns a second, distinct Harmony SASE region ID for
// acceptance tests that need two regions. testAccPreCheckSecondaryRegion
// enforces that it is set before any such test runs.
func testAccRegionID2() string {
	return os.Getenv("CHECKPOINT_SASE_TEST_REGION_ID_2")
}
