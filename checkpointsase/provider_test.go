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

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("CHECKPOINT_SASE_API_KEY"); v == "" {
		t.Fatal("CHECKPOINT_SASE_API_KEY must be set for acceptance tests")
	}
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

// testAccPreCheckGroup is required by tests that create an application. The
// API refuses an application granting access to nobody: `users` carries a
// cross-field @UsersMinSize(1) that fires whenever `groups` is empty, so at
// least one of the two must be non-empty. Both are tenant-specific directory
// object IDs that this suite cannot create, so the ID comes from the
// environment — the same treatment region IDs get, and for the same reason.
//
// Kept separate from testAccPreCheck so the other twenty-odd acceptance tests
// do not require a group ID they never use.
func testAccPreCheckGroup(t *testing.T) {
	if v := os.Getenv("CHECKPOINT_SASE_TEST_GROUP_ID"); v == "" {
		t.Fatal("CHECKPOINT_SASE_TEST_GROUP_ID must be set for acceptance tests that " +
			"create an application. The API requires an application to grant access to " +
			"at least one user or group, and group IDs are tenant-specific: list them " +
			"with GET /v3/groups. Most tenants have an \"All Users\" group that serves.")
	}
}

// testAccGroupID returns the group ID used by application acceptance tests.
// testAccPreCheckGroup enforces that it is set before any such test runs.
func testAccGroupID() string {
	return os.Getenv("CHECKPOINT_SASE_TEST_GROUP_ID")
}

// testAccRegionID returns the Harmony SASE region ID used by acceptance
// tests that create networks/regions. It is tenant-specific, so it is
// sourced from the environment rather than hardcoded; testAccPreCheck
// enforces that it is set before any test runs.
func testAccRegionID() string {
	return os.Getenv("CHECKPOINT_SASE_TEST_REGION_ID")
}

// testAccRegionID2 returns a second, distinct Harmony SASE region ID for
// acceptance tests that need two regions. testAccPreCheckSecondaryRegion
// enforces that it is set before any such test runs.
func testAccRegionID2() string {
	return os.Getenv("CHECKPOINT_SASE_TEST_REGION_ID_2")
}
