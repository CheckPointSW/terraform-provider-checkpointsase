package checkpointsase

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

/*
The ACCEPTANCE coverage for the two standard private-DNS data sources that does
not need a network.

The POSITIVE rows, SPD-01 and SPD-02, are not here: they ride on the single
standard network TestAccDataSourceStandardNetworkScoped_basic already builds, per
the Phase 5 plan, rather than creating a fifth one — a standard network takes 10
to 15 minutes to come up and nothing about a read needs one of its own.

What IS here is SPD-N01 and SPD-N02, which need no network at all: they name ids
that match nothing. Keeping them out of the network-scoped test is deliberate as
well as cheap. A step with ExpectError inside a test whose other steps share one
long-lived resource makes every later step's starting state depend on how the
failing step unwound; here there is nothing to unwind.

resource.Test skips both of these unless TF_ACC=1, so the TestAcc prefix on them
is accurate. Every offline test for these data sources is in
data_source_standard_private_dns_test.go under a name that says what it does.
*/

/*
TestAccDataSourceStandardPrivateDNS_notFound covers SPD-N01 and SPD-N02: a
`network_id` (and `region_id`) that matches nothing must FAIL the plan with a
diagnostic naming 404, not return an empty result.

That is the whole point of the row. A resource Read that 404s clears its id and
lets the next plan propose a recreation; a data source has no id to clear, so
swallowing the 404 would leave every downstream reference silently reading a zero
value — an apply proceeding on data that was never fetched.

THE PATTERN IS ANCHORED ON THE PROVIDER'S OWN SUMMARY, following
TestAccCheckpointsaseGroupMembership_nonexistentGroup, and for the same reason:
a bare `404` alternation is satisfied by an authentication failure or a routing
mistake, so the row would pass without ever reaching the endpoint it names.
"Unable to read standard network private DNS" is attached by
dataSourceStandardNetworkPrivateDNSRead and by nothing else.

The status term is secondary because appendErrorDiags prefers the response BODY
over the status line. On the standard path that body is measured — probe P10,
2026-08-26: {"message":"network doesnt exists","messageCode":"NOT_FOUND",
"status":404} — so `404` is present as `"status":404`. `NOT_FOUND` and the prose
alternatives are there so that a server which changes its wording, or validates
the id format first and answers 400, still satisfies the row. IF A LIVE RUN FAILS
ON THE SECOND TERM ALONE, READ THE BODY IT REPORTS AND WIDEN THAT TERM — do not
remove the summary anchor.

The ids are shaped like real ones rather than like obvious junk, so the server
reaches its lookup rather than rejecting the format. THE REGION STEP IS STILL THE
FIRST NEGATIVE REQUEST ANYTHING HAS MADE TO THE STANDARD REGION PRIVATE-DNS
ENDPOINT. That path has now been read successfully once (API-FINDINGS.md 1.36,
2026-08-26) but never with an id that names nothing, so whether a wrong region id
inside a real network answers 404 at all — or is distinguishable from a wrong
network id — is unknown. A failure here is INFORMATION FIRST and a provider defect
second. Read what the server said before changing any code.
*/
func TestAccDataSourceStandardPrivateDNS_notFound(t *testing.T) {
	t.Parallel()

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: `
data "checkpointsase_standard_network_private_dns" "missing" {
  network_id = "000000000000000000000000"
}
`,
				ExpectError: regexp.MustCompile(
					`(?s)Unable to read standard network private DNS` +
						`.*(?i:404|400|not.?found|doesnt exist|does not exist|no such)`),
			},
			{
				Config: `
data "checkpointsase_standard_region_private_dns" "missing" {
  network_id = "000000000000000000000000"
  region_id  = "000000000000000000000001"
}
`,
				ExpectError: regexp.MustCompile(
					`(?s)Unable to read standard region private DNS` +
						`.*(?i:404|400|not.?found|doesnt exist|does not exist|no such)`),
			},
		},
	})
}

/*
testAccCheckStandardPrivateDNSShape asserts the invariants of a standard
private-DNS read that hold WHATEVER the object's configuration is.

IT DELIBERATELY DOES NOT ASSERT A PARTICULAR CONFIGURATION, and that is the point
rather than timidity. The standard family has no write endpoint, so the provider
cannot put a network into a known private-DNS state before reading it; the only
honest live assertions are the ones true of every legal body. Asserting
`enabled = false` would be asserting something about the TENANT — and the test
tenant is explicitly not clean: two probe networks from Phase 5's measurement run
survive on it and one of them has private DNS enabled.

What it does assert, and what each one catches:

  - `enabled` is a real boolean. TestCheckResourceAttrSet cannot do this job for a
    bool: "false" is set, so the assertion passes for an attribute that was never
    written.
  - `attributes.#` is 0 or 1. Both are normal. Anything above 1 means the
    flattener emitted a list where the API has a single object.
  - if `attributes.#` is 1 then both `servers.#` and `search_domains.#` are
    present. A missing COUNT key means the attribute was never set at all, which
    is what a mis-spelled map key produces — silently, and with no error anywhere.
  - every element of `servers` carries a non-empty `address` and a set `is_tls`.
    CustomDnsServer (swagger.yaml:4429-4442) requires BOTH, on the READ model, so
    this holds of every legal body; and it is vacuous for an empty list, so it
    cannot fire for a configuration reason. This is where a flattener that
    dropped a key, or set one and mapped nothing into it, shows up. Mutation M10
    (`flattenCustomDnsServers` dropping `is_tls`) is its offline twin.

`enabled` PREDICTS NOTHING ABOUT THE SHAPE, IN EITHER DIRECTION, AND BOTH HALVES
OF THAT ARE DELIBERATE.

DO NOT TIGHTEN THIS INTO "disabled means no attributes". 1.31 measured an object
nobody has configured returning NO `attributes` key, and 1.36 measured a standard
REGION nobody has configured returning `attributes` PRESENT with a fully populated
`dns_policy`. That third disabled shape is what the tenant actually returns.

DO NOT TIGHTEN IT THE OTHER WAY EITHER, into "enabled means one `attributes` block
holding at least one server". This check used to assert exactly that, citing
swagger.yaml:4492 — and 4492 is `CustomDnsUpdateAttributes.servers`, the
description on the PUT body (:4471-4492). The standard READ decodes
CustomDnsResponse (:4419) → CustomDnsAttributesResponse (:4409) → its base
CustomDnsAttributes (:4387), whose `servers` is an OPTIONAL array with uniqueItems
and maxItems: 4 and no minimum, conditional or otherwise; and CustomDns (:4376)
requires `enabled` alone, so `{"enabled": true}` with no `attributes` key is a
legal response. API-FINDINGS.md 1.35 is why the distinction bites on this family
and on no other in this repo: the standard pair declares no put, post or patch, so
the v3 write validator never sees these objects — the console is the only writer,
and the provider cannot know what wrote the body it is reading. Those two rows
were offline-green and could only ever have fired LIVE, against a legal response,
as "the block was dropped on the way into state".
TestStandardPrivateDNSShapeCheckMatchesTheReadModel now pins both halves.

A failure of any row here is INFORMATION FIRST and a provider defect second, in
the same words this file gives the region 404: read what the server said before
changing any code.
*/
func testAccCheckStandardPrivateDNSShape(address string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs, err := dataSourceAttrs(s, address)
		if err != nil {
			return err
		}

		enabled, ok := attrs["enabled"]
		if !ok {
			return fmt.Errorf("%s has no `enabled` attribute at all", address)
		}
		if enabled != "true" && enabled != "false" {
			return fmt.Errorf("%s enabled = %q, want \"true\" or \"false\"", address, enabled)
		}

		count, err := dataSourceListLen(attrs, "attributes")
		if err != nil {
			return fmt.Errorf("%s: %w", address, err)
		}
		if count > 1 {
			return fmt.Errorf("%s attributes.# = %d. The API returns a single `attributes` "+
				"object or none, so anything above 1 means the flattener built a list where "+
				"there is one value", address, count)
		}

		if count == 1 {
			for _, key := range []string{"attributes.0.servers.#", "attributes.0.search_domains.#"} {
				if _, ok := attrs[key]; !ok {
					return fmt.Errorf("%s has no %s. A missing COUNT key means the attribute "+
						"was never set — which is what a mis-spelled flattener key produces, "+
						"with no error anywhere", address, key)
				}
			}
			servers, err := dataSourceListLen(attrs, "attributes.0.servers")
			if err != nil {
				return fmt.Errorf("%s: %w", address, err)
			}
			for i := 0; i < servers; i++ {
				if err := checkElemFieldsSet(
					address, attrs, "attributes.0.servers", i, []string{"address", "is_tls"},
				); err != nil {
					return fmt.Errorf("%w. CustomDnsServer requires BOTH address and isTLS on "+
						"the read model (swagger.yaml:4429-4442), so an element missing one is "+
						"the flattener rather than the tenant", err)
				}
			}
		}
		return nil
	}
}

/*
testAccCheckStandardNetworkPrivateDNSIDIsDerived and
testAccCheckStandardRegionPrivateDNSIDIsDerived recompute each data source's id
from the arguments in state and compare.

NOT TestCheckResourceAttrSet, and not a regexp. This project has shipped a data
source with a CONSTANT id, which passes any "is it set" check while giving two
instances pointed at different networks one Terraform identity; and the older
network-scoped data sources use a UNIX TIMESTAMP, which passes the same check
while changing on every read and defeating downstream references (L16c).
Recomputing is the only assertion that refuses both.
*/
func testAccCheckStandardNetworkPrivateDNSIDIsDerived(address string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[address]
		if !ok {
			return fmt.Errorf("%s is not in state", address)
		}
		networkId := rs.Primary.Attributes[privateDNSAttrNetworkID]
		if networkId == "" {
			return fmt.Errorf("%s holds no network_id, so its id cannot be checked", address)
		}
		// COMPUTED WITH THE PRODUCTION HELPER, AND THAT LIMITS WHAT THIS PROVES.
		// The id is a SHA-256 digest of length-prefixed arguments, so there is no
		// independent literal to compare against -- rebuilding the digest by hand
		// here would just be a second copy of the same function, and hardcoding a
		// hex string would pin the tenant's ids rather than the derivation. So this
		// row catches an id that is CONSTANT, EMPTY or built from the wrong
		// attribute; it CANNOT catch a change to the digest itself. The derivation
		// is pinned offline instead, by
		// TestStandardPrivateDNSIdsAreDerivedFromTheArguments, which is where a
		// digest change shows up.
		if want := standardNetworkPrivateDNSID(networkId); rs.Primary.ID != want {
			return fmt.Errorf("%s has id %q, want %q — the id must derive from network_id, "+
				"not be a constant and not be a timestamp", address, rs.Primary.ID, want)
		}
		return nil
	}
}

func testAccCheckStandardRegionPrivateDNSIDIsDerived(address string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[address]
		if !ok {
			return fmt.Errorf("%s is not in state", address)
		}
		networkId := rs.Primary.Attributes[privateDNSAttrNetworkID]
		regionId := rs.Primary.Attributes[privateDNSAttrRegionID]
		if networkId == "" || regionId == "" {
			return fmt.Errorf("%s holds network_id=%q region_id=%q; both are needed to rebuild "+
				"its id", address, networkId, regionId)
		}
		// Same limit as the network check above: digest in, digest out, so this
		// catches a constant or a wrong-attribute id and not a digest change.
		if want := standardRegionPrivateDNSID(networkId, regionId); rs.Primary.ID != want {
			return fmt.Errorf("%s has id %q, want %q — the id must derive from BOTH arguments, "+
				"so that two regions of one network do not share an identity",
				address, rs.Primary.ID, want)
		}
		return nil
	}
}
