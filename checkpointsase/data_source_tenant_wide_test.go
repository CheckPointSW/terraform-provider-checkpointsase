package checkpointsase

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// TestAccDataSourceTenantWide_basic is the first live exercise of the seven
// data sources that take no arguments: checkpointsase_status,
// checkpointsase_standard_networks, checkpointsase_enhanced_networks,
// checkpointsase_all_networks, checkpointsase_enhanced_regions,
// checkpointsase_applications and checkpointsase_customer_certificates.
//
// All seven are tenant-wide reads, so they go in one config and one step. That
// is not a shortcut: creating a network per data source would cost 10-15
// minutes each on this API for reads that need no network at all. This test
// creates nothing and should finish in seconds.
//
// # What is asserted, and what deliberately is not
//
// The target tenant was measured on 2026-08-19 and holds 13 standard region
// catalogue entries, 4 enhanced region catalogue entries, 25 built-in service
// objects, and zero of everything else — zero standard networks, zero enhanced
// networks, zero applications, zero address objects, zero customer
// certificates.
//
// So only the region catalogues are asserted non-empty here. They are
// server-provided product data that no tenant operation can empty, and
// checkpointsase_enhanced_network already depends on regions[0] existing.
//
// For the five that are currently zero, a count assertion would be wrong in
// both directions: `> 0` fails today for a reason that is not a defect, and
// `== 0` breaks the moment an unrelated run leaves a network behind, which
// would make this test's meaning depend on tenant history. Those get a shape
// assertion (the list attribute exists in state) plus a conditional assertion
// on the first element's fields that engages as soon as the tenant does hold
// content — so the flatten functions are covered without the test's outcome
// depending on how much is in the tenant.
//
// checkpointsase_all_networks gets the one content-independent assertion worth
// having: its row count must equal standard + enhanced, and its network_kind
// tags must split the same way. That holds on an empty tenant and on a full
// one, and it fails if the client-side merge drops a list, double-counts one,
// or mistags a row.
//
// No t.Parallel(): the merge assertion compares three separate API reads
// against each other, so a network created by another test between them would
// break the equality for a reason that is not a defect. Go runs non-parallel
// tests one at a time while every t.Parallel() test is paused, which gives
// this test the tenant to itself.
func TestAccDataSourceTenantWide_basic(t *testing.T) {
	const (
		status      = "data.checkpointsase_status.api"
		standard    = "data.checkpointsase_standard_networks.tenant"
		enhanced    = "data.checkpointsase_enhanced_networks.tenant"
		all         = "data.checkpointsase_all_networks.tenant"
		enhRegions  = "data.checkpointsase_enhanced_regions.catalog"
		apps        = "data.checkpointsase_applications.tenant"
		certificate = "data.checkpointsase_customer_certificates.tenant"
	)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceTenantWideConfig(),
				Check: resource.ComposeTestCheckFunc(
					// checkpointsase_status — the documented contract is the
					// literal string "Ok", and dataSourceStatusRead itself
					// depends on that spelling: it recognises a plain-text
					// "Ok" body the SDK cannot JSON-decode and turns it into
					// success. Asserting the exact value therefore covers both
					// the happy path and that fallback; asserting only "set"
					// would not distinguish "Ok" from an error string.
					resource.TestCheckResourceAttrSet(status, "status"),
					resource.TestCheckResourceAttr(status, "status", "Ok"),

					// checkpointsase_enhanced_regions — server-provided
					// catalogue, 4 entries measured. Every field asserted here
					// is a non-pointer string in HarmonySaseRegion, so an empty
					// value means the flatten function failed to map it rather
					// than the server omitting it.
					testAccCheckDataSourceListMinLen(enhRegions, "regions", 1),
					testAccCheckDataSourceElemFieldsSet(enhRegions, "regions", 0,
						"id", "name", "display_name", "country_code", "continent_code"),

					// checkpointsase_standard_networks — zero on this tenant.
					// Shape only; Test B asserts content against a network it
					// creates itself.
					testAccCheckDataSourceListPresent(standard, "networks"),
					testAccCheckDataSourceFirstElemFieldsSetIfAny(standard, "networks",
						"id", "name", "subnet", "dns", "access_type", "tenant_id"),

					// checkpointsase_enhanced_networks — zero on this tenant.
					// Shape only; Test C asserts content against a network it
					// creates itself.
					testAccCheckDataSourceListPresent(enhanced, "networks"),
					testAccCheckDataSourceFirstElemFieldsSetIfAny(enhanced, "networks",
						"id", "name", "subnet", "dns", "access_type", "tenant_id"),

					// checkpointsase_all_networks — the merge invariant.
					testAccCheckDataSourceListPresent(all, "networks"),
					testAccCheckAllNetworksIsSumOfParts(all, standard, enhanced),
					testAccCheckDataSourceEveryElemFieldIn(all, "networks", "network_kind",
						"standard", "enhanced"),
					testAccCheckDataSourceFirstElemFieldsSetIfAny(all, "networks",
						"id", "name", "subnet", "dns", "access_type", "tenant_id", "network_kind"),

					// checkpointsase_applications — zero on this tenant, and
					// L14 forbids creating one to change that: an application
					// cannot be deleted through the API and pins its network
					// permanently. So this data source can only ever be read
					// against whatever the tenant already has, which today is
					// nothing. Shape plus a conditional element check is the
					// most that can honestly be asserted.
					testAccCheckDataSourceListPresent(apps, "applications"),
					testAccCheckDataSourceFirstElemFieldsSetIfAny(apps, "applications",
						"id", "name", "type", "network_id", "host"),

					// checkpointsase_customer_certificates — zero on this
					// tenant. Certificates cannot be uploaded through this
					// provider at all, so there is no way for a test to
					// create the content a count assertion would need.
					//
					// expires_at is deliberately excluded from the field
					// check: flattenCustomerCertificates formats a non-pointer
					// time.Time, so it renders the zero time rather than an
					// empty string and a "non-empty" assertion on it could
					// never fail.
					testAccCheckDataSourceListPresent(certificate, "certificates"),
					testAccCheckDataSourceFirstElemFieldsSetIfAny(certificate, "certificates",
						"id", "display_name"),
				),
			},
		},
	})
}

func testAccDataSourceTenantWideConfig() string {
	return `
data "checkpointsase_status" "api" {}

data "checkpointsase_standard_networks" "tenant" {}

data "checkpointsase_enhanced_networks" "tenant" {}

data "checkpointsase_all_networks" "tenant" {}

data "checkpointsase_enhanced_regions" "catalog" {}

data "checkpointsase_applications" "tenant" {}

data "checkpointsase_customer_certificates" "tenant" {}
  `
}
