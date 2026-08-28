package checkpointsase

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// walkSchema visits every attribute, recursing into nested blocks, and reports
// each one as a dotted path.
func walkSchema(prefix string, m map[string]*schema.Schema, visit func(path string, s *schema.Schema)) {
	for name, s := range m {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		visit(path, s)
		if res, ok := s.Elem.(*schema.Resource); ok {
			walkSchema(path, res.Schema, visit)
		}
	}
}

func allRegistered() map[string]map[string]*schema.Schema {
	p := Provider()
	out := map[string]map[string]*schema.Schema{}
	for name, r := range p.ResourcesMap {
		out["resource."+name] = r.Schema
	}
	for name, d := range p.DataSourcesMap {
		out["data."+name] = d.Schema
	}
	return out
}

// tfplugindocs renders attribute documentation from Description, so an empty
// one silently ships a blank row in the registry docs.
func TestSchemaEveryAttributeHasADescription(t *testing.T) {
	var missing []string
	for owner, s := range allRegistered() {
		walkSchema("", s, func(path string, attr *schema.Schema) {
			if strings.TrimSpace(attr.Description) == "" {
				missing = append(missing, fmt.Sprintf("%s: %s", owner, path))
			}
		})
	}
	if len(missing) > 0 {
		t.Errorf("%d attribute(s) without a Description:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// normalizeAttributeName lowercases a schema attribute name and strips
// underscores and hyphens, so that "requestconfigtoken", "request_config_token"
// and "requestConfigToken" all collapse to the same key. This lets secretNames
// be written in whichever style is most readable without changing what the
// lookup catches - the leaf name extracted from a schema is compared against
// this same normalized form, not against the literal set keys.
func normalizeAttributeName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}

/*
secretAttributeNames is the provider's canonical list of attribute names that
carry secret material, in whichever spelling reads best -- the lookups below
normalise both sides, so "request_config_token" and "requestConfigToken" collapse
to one key.

PACKAGE-LEVEL RATHER THAN LOCAL, so that the two rules derived from it cannot
drift apart. TestSchemaSecretAttributesAreMarkedSensitive demands the Sensitive
marker wherever one of these appears;
TestTenantWideCollectionsExposeNoSecretAttribute demands ABSENCE from a data
source that reads every object in the tenant, because the marker only redacts CLI
and log output and does nothing about the plaintext copy in state. A name added
here now gets both rules at once, which is the point: an "enrollment_token" added
to this list but only to a local literal in one test would be caught by the weaker
of the two rules and pass the stronger one.
*/
var secretAttributeNames = map[string]bool{
	"passphrase": true, "secret_access_key": true, "access_key_id": true,
	"vault": true, "private_key": true, "api_key": true,
	"customer_root_ca": true, "request_config_token": true,
	// An invitation token completes a user's enrolment for whoever holds it.
	"invitation_token": true,
}

// normalizedSecretAttributeNames is secretAttributeNames keyed by the same
// normalisation the schema walk applies to a leaf name.
func normalizedSecretAttributeNames() map[string]bool {
	normalized := make(map[string]bool, len(secretAttributeNames))
	for name := range secretAttributeNames {
		normalized[normalizeAttributeName(name)] = true
	}
	return normalized
}

// Terraform writes Sensitive attributes to state in plaintext; the marker only
// redacts CLI and log output. Two attributes shipped without it in v2.3 and
// leaked WireGuard private key material into provider logs.
func TestSchemaSecretAttributesAreMarkedSensitive(t *testing.T) {
	normalizedSecretNames := normalizedSecretAttributeNames()
	var unmarked []string
	for owner, s := range allRegistered() {
		walkSchema("", s, func(path string, attr *schema.Schema) {
			leaf := path
			if i := strings.LastIndex(path, "."); i >= 0 {
				leaf = path[i+1:]
			}
			if normalizedSecretNames[normalizeAttributeName(leaf)] && !attr.Sensitive {
				// Report the original attribute path, not the normalized
				// form, so the failure message stays actionable.
				unmarked = append(unmarked, fmt.Sprintf("%s: %s", owner, path))
			}
		})
	}
	if len(unmarked) > 0 {
		t.Errorf("%d secret attribute(s) missing Sensitive: true:\n  %s",
			len(unmarked), strings.Join(unmarked, "\n  "))
	}
}

// A server-assigned timestamp that is also Optional lets users write a value
// into HCL that is silently ignored.
func TestSchemaServerAssignedTimestampsAreComputedOnly(t *testing.T) {
	timestamps := map[string]bool{"created_at": true, "updated_at": true}
	var writable []string
	for owner, s := range allRegistered() {
		if strings.HasPrefix(owner, "data.") {
			continue
		}
		walkSchema("", s, func(path string, attr *schema.Schema) {
			leaf := path
			if i := strings.LastIndex(path, "."); i >= 0 {
				leaf = path[i+1:]
			}
			if timestamps[leaf] && (attr.Optional || attr.Required) {
				writable = append(writable, fmt.Sprintf("%s: %s", owner, path))
			}
		})
	}
	if len(writable) > 0 {
		// Was a Skipf while this was deferred to Phase 6. Phase 6 fixed the six
		// offenders (wireguard, openvpn and ipsec_single created_at/updated_at),
		// so this is now a GATE. A Skipf here would let a regression pass green,
		// which is the failure mode this file exists to prevent.
		t.Errorf("%d server-assigned timestamp(s) are user-writable, which lets a "+
			"user write a value into HCL that is silently ignored:\n  %s",
			len(writable), strings.Join(writable, "\n  "))
	}
}

func TestSchemaEveryResourceHasATopLevelDescription(t *testing.T) {
	p := Provider()
	var missing []string
	for name, r := range p.ResourcesMap {
		if strings.TrimSpace(r.Description) == "" {
			missing = append(missing, "resource."+name)
		}
	}
	for name, d := range p.DataSourcesMap {
		if strings.TrimSpace(d.Description) == "" {
			missing = append(missing, "data."+name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d registered type(s) without a top-level Description:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

/*
p81GatewaySubnetsAttributes is the enumerated answer to "which registered types
actually carry p81_gateway_subnets", found by walking the provider rather than
assumed. Writing it down as an exact set means a new resource carrying the
attribute has to be added here on purpose, along with the CIDR validation and
the wording that belongs with it, instead of quietly shipping with neither.

data.checkpointsase_enhanced_tunnels also exposes p81_gateway_subnets and is
deliberately absent: it is Computed, so no user-supplied value ever reaches it
and there is nothing to validate.
*/
var p81GatewaySubnetsAttributes = map[string][]string{
	"resource.checkpointsase_enhanced_static_tunnel":  {"p81_gateway_subnets"},
	"resource.checkpointsase_enhanced_dynamic_tunnel": {"p81_gateway_subnets"},
	"resource.checkpointsase_ipsec_single":            {"p81_gateway_subnets"},
	"resource.checkpointsase_ipsec_redundant":         {"shared_settings.p81_gateway_subnets"},
}

/*
TestSchemaP81GatewaySubnetsValidateCIDRFormat covers the half of the server's
p81_gateway_subnets rule that a plan can actually check.

The whole rule — "0.0.0.0/0 or the network Subnet", measured live 2026-08-17 as
a 409 on the enhanced static-tunnel endpoint — is NOT enforced, and this test
does not pretend it is: the permitted subnet belongs to another resource and is
routinely unknown while planning, so a validator asserting it would fail valid
configurations. See p81GatewaySubnetsEnhancedRule in utils.go.

What is asserted here is that a malformed CIDR fails during plan rather than at
apply, on every writable copy of the attribute, and that 0.0.0.0/0 — one of the
only two values the enhanced endpoints accept — still passes.
*/
func TestSchemaP81GatewaySubnetsValidateCIDRFormat(t *testing.T) {
	seen := map[string][]string{}
	for owner, s := range allRegistered() {
		if strings.HasPrefix(owner, "data.") {
			continue
		}
		walkSchema("", s, func(path string, attr *schema.Schema) {
			leaf := path
			if i := strings.LastIndex(path, "."); i >= 0 {
				leaf = path[i+1:]
			}
			if leaf != "p81_gateway_subnets" {
				return
			}
			seen[owner] = append(seen[owner], path)

			elem, ok := attr.Elem.(*schema.Schema)
			if !ok {
				t.Errorf("%s: %s has no element schema to validate", owner, path)
				return
			}
			if elem.ValidateFunc == nil {
				t.Errorf("%s: %s elements have no ValidateFunc; a typo reaches the API instead of failing the plan", owner, path)
				return
			}
			if _, errs := elem.ValidateFunc("not-a-cidr", path); len(errs) == 0 {
				t.Errorf("%s: %s accepted the malformed CIDR %q at plan time", owner, path, "not-a-cidr")
			}
			// 0.0.0.0/0 is one of exactly two values the enhanced endpoints
			// accept, so a validator that rejected it would be worse than none.
			if _, errs := elem.ValidateFunc("0.0.0.0/0", path); len(errs) != 0 {
				t.Errorf("%s: %s rejected the default route %q, which the server accepts: %v", owner, path, "0.0.0.0/0", errs)
			}
		})
	}

	for owner, want := range p81GatewaySubnetsAttributes {
		got := seen[owner]
		if len(got) == 0 {
			t.Errorf("%s no longer carries p81_gateway_subnets; update p81GatewaySubnetsAttributes", owner)
			continue
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s carries p81_gateway_subnets at %v; expected %v", owner, got, want)
		}
	}
	for owner, got := range seen {
		if _, known := p81GatewaySubnetsAttributes[owner]; !known {
			t.Errorf("%s carries p81_gateway_subnets at %v but is not listed in p81GatewaySubnetsAttributes — decide what its description and validation should say", owner, got)
		}
	}
}

/*
TestSchemaP81GatewaySubnetsDocumentTheServerRule pins the wording, because the
wording is the only place the unenforceable half of the rule exists.

A reader who hits the 409 has no way to discover "0.0.0.0/0 or the network
Subnet" other than this description, so it quotes the server's own message
verbatim — making clear whose rule it is — and says outright that the plan
checks format only. Dropping either turns a documented constraint back into a
surprise at apply time.
*/
func TestSchemaP81GatewaySubnetsDocumentTheServerRule(t *testing.T) {
	enhanced := []string{
		"checkpointsase_enhanced_static_tunnel",
		"checkpointsase_enhanced_dynamic_tunnel",
	}
	wants := []string{
		// The server's message, quoted so the reader knows it is the API's rule.
		`The list of Harmony SASE Subnets can only be "0.0.0.0/0" or the network Subnet`,
		// The status code, so it is recognisable when it arrives.
		"409",
		// Where the other permitted value comes from.
		"subnet",
		// The honest limit of what the plan checks.
		"CIDR format only",
	}

	resources := Provider().ResourcesMap
	for _, name := range enhanced {
		r, ok := resources[name]
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		attr, ok := r.Schema["p81_gateway_subnets"]
		if !ok {
			t.Fatalf("%s no longer has p81_gateway_subnets", name)
		}
		for _, want := range wants {
			if !strings.Contains(attr.Description, want) {
				t.Errorf("%s.p81_gateway_subnets description no longer states %q:\n%s", name, want, attr.Description)
			}
		}
	}
}

/*
listEmptyVerdict is whether the server accepts an empty array for one list attribute.

The distinction exists because "an optional array must be omitted, never sent as []" is true of some
fields and false of others, and nothing on the provider side can tell them apart. Three separate
release blockers on this branch were the same mistake — firewall_policy sources/destinations,
firewall_policy services, and the applications access grant — each found by a live run costing 15
minutes or more. The map below is the swept result, so the fourth is found by `go test` instead.
*/
type listEmptyVerdict int

const (
	// mustReject: the server refuses [], so the provider must refuse it at plan time.
	mustReject listEmptyVerdict = iota
	// mayBeEmpty: the server accepts [], so the provider must not add MinItems.
	mayBeEmpty
)

/*
listAttributeEmptyPolicy records, for every list AND set attribute in the provider, whether the
server accepts an empty array for it. The verdict for each entry comes from reading the field's validation
decorators in perimeter81-public-api, not from inference:

  - @IsOptional() with @ArrayMinSize(1) means the minimum applies only when the key is present, so an
    empty array is a 400 and the key must be omitted or carry a member. mustReject.
  - @IsOptional() with no minimum, or a validator that is vacuously true over zero elements, means []
    is legal — and for anything a user can clear, [] is the *only* way to clear it, so refusing it at
    plan time would be a bug of its own. mayBeEmpty.

Adding MinItems to a mayBeEmpty attribute is the failure mode the second half of this map guards
against: it looks like finishing the sweep and it silently removes the user's ability to empty a list.
*/
var listAttributeEmptyPolicy = map[string]struct {
	verdict listEmptyVerdict
	why     string
}{
	// --- mustReject: @ArrayMinSize(1) or an equivalent explicit minimum -------------------------
	// ipSecPhase.model.ts: auth/encryption/keyExchangeMethod are each @ArrayUnique()
	// @ArrayMinSize(1) @IsEnum(..., {each:true}) @IsOptional(), on every create *and* update path
	// (PartialType does not recurse into the nested phase DTOs).
	"resource.checkpointsase_enhanced_dynamic_tunnel.phase1.auth":                 {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_dynamic_tunnel.phase1.encryption":           {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_dynamic_tunnel.phase1.key_exchange_method":  {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_dynamic_tunnel.phase2.auth":                 {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_dynamic_tunnel.phase2.encryption":           {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_dynamic_tunnel.phase2.key_exchange_method":  {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_static_tunnel.phase1.auth":                  {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_static_tunnel.phase1.encryption":            {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_static_tunnel.phase1.key_exchange_method":   {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_static_tunnel.phase2.auth":                  {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_static_tunnel.phase2.encryption":            {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_enhanced_static_tunnel.phase2.key_exchange_method":   {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_ipsec_single.phase1.auth":                            {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_ipsec_single.phase1.encryption":                      {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_ipsec_single.phase2.auth":                            {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_ipsec_single.phase2.encryption":                      {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_ipsec_redundant.advanced_settings.phase1.auth":       {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_ipsec_redundant.advanced_settings.phase1.encryption": {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_ipsec_redundant.advanced_settings.phase2.auth":       {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_ipsec_redundant.advanced_settings.phase2.encryption": {mustReject, "ipSecPhase.model.ts @ArrayMinSize(1)"},
	// baseWireguardTunnel.ts: @ArrayUnique() @IsIPRange({each:true}) @ArrayMinSize(1). The update DTO
	// is PartialType of it, which adds @IsOptional() and keeps the minimum — the classic pair. The
	// provider cannot omit it either way: WireGuradDetails.ToMap writes remoteSubnets
	// unconditionally, so plan time is the only place this can be caught.
	"resource.checkpointsase_wireguard.remote_subnets": {mustReject, "baseWireguardTunnel.ts @ArrayMinSize(1)"},
	// enhancedRouteTable.dto.ts: @IsArray() @ArrayMinSize(1), on the update DTO as well as create.
	"resource.checkpointsase_enhanced_route_table.subnets": {mustReject, "enhancedRouteTable.dto.ts @ArrayMinSize(1)"},
	// address.model.ts: @IsArray() @IsValidAddressValue(...). The custom validator requires exactly
	// one element for ip/cidr/fqdn and at least one for list, so [] fails for every valueType.
	"resource.checkpointsase_object_addresses.value": {mustReject, "address.model.ts @IsValidAddressValue"},
	// service.model.ts: protocols is @IsNotEmpty() @IsArray() @ArrayMinSize(1); protocols[].value is
	// @ArrayMinSize(1) for every protocol but icmp, and createServicesTransformer rejects an empty
	// value outright with 'property Value cant be empty'.
	//
	// protocols[].value became Optional when icmp support landed, and the verdict is deliberately
	// unchanged. MinItems is only reached for a key the configuration actually set: schemaMap.validate
	// returns as soon as c.Get reports the key absent, and Terraform's config shim drops nulls, so an
	// icmp entry that omits value never meets the minimum, while `value = []` on any entry still fails
	// during plan. Optional changed when the check runs, not whether it runs — dropping MinItems here
	// would hand `value = []` to the API as a 400 instead.
	//
	// The icmp code itself needs no entry: protocol_options is a TypeInt, not a list.
	"resource.checkpointsase_object_services.protocols":       {mustReject, "service.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_object_services.protocols.value": {mustReject, "service.model.ts @ArrayMinSize(1) + transformer; Optional for icmp, but never empty when present"},
	// sourcesAndDestinations.model.ts / networkPolicyRule.model.ts: @IsOptional() @ArrayMinSize(1).
	// Fixed in aefd8dc; listed so the sweep's own result is complete rather than partial.
	"resource.checkpointsase_firewall_policy.policy_rules.services":               {mustReject, "networkPolicyRule.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_firewall_policy.policy_rules.sources.addresses":      {mustReject, "sourcesAndDestinations.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_firewall_policy.policy_rules.sources.users":          {mustReject, "sourcesAndDestinations.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_firewall_policy.policy_rules.sources.groups":         {mustReject, "sourcesAndDestinations.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_firewall_policy.policy_rules.destinations.addresses": {mustReject, "sourcesAndDestinations.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_firewall_policy.policy_rules.destinations.users":     {mustReject, "sourcesAndDestinations.model.ts @ArrayMinSize(1)"},
	"resource.checkpointsase_firewall_policy.policy_rules.destinations.groups":    {mustReject, "sourcesAndDestinations.model.ts @ArrayMinSize(1)"},
	// support_phone_numbers is the first entry in this map whose validator is NOT in
	// perimeter81-public-api. /v3/account/customize/support-options is proxied straight
	// through to the account-domain service, so the authority is account-domain's
	// src/account-lambda-company-branding/src/schemas/putCompanyBranding.schema.ts, an
	// AJV schema rather than a class-validator model: supportPhoneNumbers is
	// `type: ["array","null"], minItems: 1, maxItems: 3`. Read 2026-08-19.
	//
	// So [] fails minItems and null/omitted is the way to say "none" — and it fails
	// twice, because the AccountCustomization collection's own $jsonSchema
	// (p81-mongo-validation-schemas/schemas/AccountCustomization.json) repeats the
	// anyOf[null, array minItems 1 maxItems 3] bound on the stored document.
	// SupportOptionsRequest.ToMap writes the key whenever the slice is non-nil, so
	// expandSupportPhoneNumbers returns nil rather than an empty slice — that, not MinItems,
	// is what keeps `[]` off the wire. Measured 2026-08-19: terraform.NewResourceConfigShimmed
	// drops an empty list from the ResourceConfig entirely, so schemaMap.validate sees the key
	// as absent and MinItems is never reached for this attribute at all. It is still the right
	// verdict and still recorded as mustReject: the server refuses `[]`, and a later refactor
	// that made the expand path return an empty slice would need MinItems to be the backstop
	// it is here.
	"resource.checkpointsase_support_options.support_phone_numbers": {mustReject, "putCompanyBranding.schema.ts minItems 1 (account-domain, not public-api)"},
	// checkpointsase_access_policy.rule is the tenant's whole webRules array. MEASURED, not read
	// off a validator: POST /v3/ia/access/policy with {"webRules": []} answers
	// 400 VALIDATION_WEB_RULES_REQUIRED, "webRules must contain at least one rule"
	// (API-FINDINGS 1.18), which matches minItems: 1 on the request schema in v3.yaml. An empty
	// list can therefore never succeed, and the tempting "fix" for that is to route it to the
	// DELETE that clears the tenant's entire policy -- so it has to fail at plan time. Emptying
	// the policy is `terraform destroy`, which calls that DELETE deliberately.
	"resource.checkpointsase_access_policy.rule": {mustReject, "measured: 400 VALIDATION_WEB_RULES_REQUIRED on an empty webRules array (API-FINDINGS 1.18)"},

	// --- mayBeEmpty: the access policy's buckets, all `minItems: 0` in the stored schema -------
	// p81-mongo-validation-schemas schemas-shared/molecules.types.json declares `value` as
	// `bsonType: array, minItems: 0` on every one of usersObject, groupsObject, addressObject,
	// customUrls, categories, applicationControlsObject and updatableObjects -- an explicit zero,
	// not an omission. API-FINDINGS 1.15 measured the same thing from the other side: the server
	// answers an empty `sources`/`destinations` by EXPANDING it into one empty bucket per legal
	// type, which it could not do if an empty bucket were illegal.
	//
	// It is also the only way to say "any". perimeter81-swg-api's own component fixtures spell
	// "any source" as buckets with empty values (test/customMocks/component/data.ts,
	// webRulesWithAnySource), so MinItems here would refuse the configuration that means
	// "unrestricted" -- which is the default a user is most likely to write.
	"resource.checkpointsase_access_policy.rule.sources.users":                                 {mayBeEmpty, "molecules.types.json usersObject.value minItems 0"},
	"resource.checkpointsase_access_policy.rule.sources.groups":                                {mayBeEmpty, "molecules.types.json groupsObject.value minItems 0"},
	"resource.checkpointsase_access_policy.rule.sources.addresses":                             {mayBeEmpty, "molecules.types.json addressObject.value minItems 0"},
	"resource.checkpointsase_access_policy.rule.destinations.custom_urls":                      {mayBeEmpty, "molecules.types.json customUrls.value minItems 0"},
	"resource.checkpointsase_access_policy.rule.destinations.categories":                       {mayBeEmpty, "molecules.types.json categories.value minItems 0"},
	"resource.checkpointsase_access_policy.rule.destinations.application_control_applications": {mayBeEmpty, "molecules.types.json applicationControlsObject.value minItems 0"},
	"resource.checkpointsase_access_policy.rule.destinations.updatable_objects":                {mayBeEmpty, "molecules.types.json updatableObjects.value minItems 0"},
	// RuleWeb.json: conditions[].value[].weekdays is `bsonType: array, uniqueItems: true` with NO
	// minItems, so [] validates. It is also unreachable in practice -- `weekdays` is Required and
	// Terraform's config shim drops an empty list, so schemaMap.validate sees the key as absent
	// and reports the missing argument instead. The verdict is still the honest one: nothing on
	// the server refuses an empty weekdays array, so nothing here should either.
	"resource.checkpointsase_access_policy.rule.conditions.weekdays": {mayBeEmpty, "RuleWeb.json conditions[].value[].weekdays has uniqueItems but no minItems"},
	// The two MaxItems-1 wrapper blocks, and the conditions list itself. `conditions` is the
	// value of the API's single `datetime` bucket; RuleWeb.json puts no minItems on it, and
	// API-FINDINGS 1.15 measured `conditions: []` accepted -- it is in fact the form the server
	// canonicalises FROM.
	//
	// Note what mayBeEmpty does and does not say for the two wrapper blocks. It is about the
	// NUMBER OF BLOCKS -- zero blocks is legal and is how "any source" is spelled. A block that
	// is present but EMPTY is a different thing and is refused by
	// resourceAccessPolicyCustomizeDiff, because the server returns an unrestricted rule as
	// empty buckets which read back as no block at all, so the two spellings could never
	// converge. MinItems could not express that: an empty block is still one block.
	"resource.checkpointsase_access_policy.rule.sources":      {mayBeEmpty, "MaxItems 1 wrapper block; ZERO blocks means any source, an empty block is refused in CustomizeDiff"},
	"resource.checkpointsase_access_policy.rule.destinations": {mayBeEmpty, "MaxItems 1 wrapper block; ZERO blocks means any destination, an empty block is refused in CustomizeDiff"},
	"resource.checkpointsase_access_policy.rule.conditions":   {mayBeEmpty, "measured: conditions: [] accepted (API-FINDINGS 1.15); RuleWeb.json sets no minItems"},

	// --- the HTTPS-inspection policy: same shape, different vocabulary -------------------------
	// checkpointsase_https_inspection_policy.rule is the tenant's whole bypassRules array.
	// MEASURED, not read off a validator: POST /v3/ia/https-inspection/policy with an empty array
	// answers 400 VALIDATION_BYPASS_RULES_REQUIRED (API-FINDINGS 1.18: "Empty array rejected
	// identically"), which matches `minItems: 1` on UpsertHttpsInspectionPolicy.bypassRules in the
	// OpenAPI document. Same consequence as the access policy's: an empty list can never succeed,
	// and the tempting "fix" is to route it to the DELETE that clears the tenant's whole policy, so
	// it has to fail at plan time. Emptying the policy is `terraform destroy`.
	"resource.checkpointsase_https_inspection_policy.rule": {mustReject, "measured: 400 VALIDATION_BYPASS_RULES_REQUIRED on an empty bypassRules array (API-FINDINGS 1.18); minItems 1 in the OpenAPI document"},
	// Every leaf bucket, from p81-mongo-validation-schemas schemas-shared/molecules.types.json,
	// which declares `value` as `bsonType: array, minItems: 0` on every object RuleBypass's
	// $defs.ruleBypassSources and $defs.ruleBypassDestinations compose -- an explicit zero, not an
	// omission. perimeter81-swg-api's own component fixtures spell "any source" as buckets with
	// empty values (bypassRulesWithAnySource / bypassRulesWithAnyDestinations), so MinItems here
	// would refuse the configuration that means "unrestricted".
	"resource.checkpointsase_https_inspection_policy.rule.sources.users":                                 {mayBeEmpty, "molecules.types.json usersObject.value minItems 0"},
	"resource.checkpointsase_https_inspection_policy.rule.sources.groups":                                {mayBeEmpty, "molecules.types.json groupsObject.value minItems 0"},
	"resource.checkpointsase_https_inspection_policy.rule.sources.applications":                          {mayBeEmpty, "molecules.types.json applicationsObject.value minItems 0"},
	"resource.checkpointsase_https_inspection_policy.rule.sources.addresses":                             {mayBeEmpty, "molecules.types.json addressObject.value minItems 0"},
	"resource.checkpointsase_https_inspection_policy.rule.destinations.categories":                       {mayBeEmpty, "molecules.types.json categories.value minItems 0"},
	"resource.checkpointsase_https_inspection_policy.rule.destinations.domains":                          {mayBeEmpty, "molecules.types.json domains.value minItems 0"},
	"resource.checkpointsase_https_inspection_policy.rule.destinations.addresses":                        {mayBeEmpty, "molecules.types.json addressObject.value minItems 0"},
	"resource.checkpointsase_https_inspection_policy.rule.destinations.updatable_objects":                {mayBeEmpty, "molecules.types.json updatableObjects.value minItems 0"},
	"resource.checkpointsase_https_inspection_policy.rule.destinations.application_control_applications": {mayBeEmpty, "molecules.types.json applicationControlsObject.value minItems 0"},
	// The two MaxItems-1 wrapper blocks. mayBeEmpty is about the NUMBER OF BLOCKS -- zero blocks is
	// legal and is how "any source" is spelled. A block that is present but EMPTY is a different
	// thing and is refused by resourceHttpsInspectionPolicyCustomizeDiff, because the server returns
	// an unrestricted rule as empty buckets which read back as no block at all, so the two spellings
	// could never converge. MinItems could not express that: an empty block is still one block.
	"resource.checkpointsase_https_inspection_policy.rule.sources":      {mayBeEmpty, "MaxItems 1 wrapper block; ZERO blocks means any source, an empty block is refused in CustomizeDiff"},
	"resource.checkpointsase_https_inspection_policy.rule.destinations": {mayBeEmpty, "MaxItems 1 wrapper block; ZERO blocks means any destination, an empty block is refused in CustomizeDiff"},

	// --- mayBeEmpty: [] is legal, and for most of these it is the only way to clear -------------
	// baseNetwork.dto.ts: tags is @IsString({each:true}) @IsOptional() with no minimum. The enhanced
	// update handler backfills with `tags ??= network.tags`, which only fires on null/undefined — so
	// `tags = []` is exactly how a user removes every tag, and omitting the key would silently keep
	// the old ones. This is the counterexample to "an empty array is always wrong".
	"resource.checkpointsase_network.network.tags":  {mayBeEmpty, "baseNetwork.dto.ts optional, [] clears"},
	"resource.checkpointsase_enhanced_network.tags": {mayBeEmpty, "baseNetwork.dto.ts optional, [] clears"},
	// ipSecShared.model.ts: @ArrayUnique() @IsIPRange({each:true}). Neither is an array-length check
	// — IsIPRange with each:true has nothing to validate over zero elements, and [] is trivially
	// unique — so an empty list validates. The key itself is required (both decorators fail on
	// undefined), which is why the provider always sends it.
	"resource.checkpointsase_enhanced_dynamic_tunnel.p81_gateway_subnets":            {mayBeEmpty, "ipSecShared.model.ts no length check"},
	"resource.checkpointsase_enhanced_dynamic_tunnel.remote_gateway_subnets":         {mayBeEmpty, "ipSecShared.model.ts no length check"},
	"resource.checkpointsase_enhanced_static_tunnel.p81_gateway_subnets":             {mayBeEmpty, "ipSecShared.model.ts no length check"},
	"resource.checkpointsase_enhanced_static_tunnel.remote_gateway_subnets":          {mayBeEmpty, "ipSecShared.model.ts no length check"},
	"resource.checkpointsase_ipsec_single.p81_gateway_subnets":                       {mayBeEmpty, "ipSecShared.model.ts no length check"},
	"resource.checkpointsase_ipsec_single.remote_gateway_subnets":                    {mayBeEmpty, "ipSecShared.model.ts no length check"},
	"resource.checkpointsase_ipsec_redundant.shared_settings.p81_gateway_subnets":    {mayBeEmpty, "ipSecShared.model.ts no length check"},
	"resource.checkpointsase_ipsec_redundant.shared_settings.remote_gateway_subnets": {mayBeEmpty, "ipSecShared.model.ts no length check"},
	// ipSecPhase.model.ts gives dh @ArrayMinSize(0) — a deliberate carve-out, and the one place in
	// the tunnels tree where an empty array is explicitly blessed. Note keyExchangeMethod, its v2.3
	// replacement, went back to @ArrayMinSize(1); the two are not interchangeable.
	"resource.checkpointsase_ipsec_single.phase1.dh":                      {mayBeEmpty, "ipSecPhase.model.ts @ArrayMinSize(0)"},
	"resource.checkpointsase_ipsec_single.phase2.dh":                      {mayBeEmpty, "ipSecPhase.model.ts @ArrayMinSize(0)"},
	"resource.checkpointsase_ipsec_redundant.advanced_settings.phase1.dh": {mayBeEmpty, "ipSecPhase.model.ts @ArrayMinSize(0)"},
	"resource.checkpointsase_ipsec_redundant.advanced_settings.phase2.dh": {mayBeEmpty, "ipSecPhase.model.ts @ArrayMinSize(0)"},
	// networkPolicyGranularUpdate.model.ts: policyRules is @IsNestedArray with no minimum. [] is not
	// merely tolerated here, it is load-bearing — resourceFirewallPolicyDelete sends exactly
	// `policyRules: []` to release the objects the rules pin. MinItems here would break destroy.
	"resource.checkpointsase_firewall_policy.policy_rules": {mayBeEmpty, "networkPolicyGranularUpdate.model.ts, [] clears rules on destroy"},
	// applicationCreateBase.dto.ts: neither list has a min-size of its own. UsersMinSize is a
	// cross-field rule (users >= 1 only while groups is empty), so `users = []` alongside a non-empty
	// groups is accepted and vice versa. MinItems on either would refuse a legal configuration; the
	// both-empty case is caught by resourceApplicationCustomizeDiff instead.
	"resource.checkpointsase_application.users":  {mayBeEmpty, "applicationCreateBase.dto.ts cross-field UsersMinSize"},
	"resource.checkpointsase_application.groups": {mayBeEmpty, "applicationCreateBase.dto.ts cross-field UsersMinSize"},
	// enhancedRouteTable.dto.ts has no tunnelIds on the update DTO at all, and the endpoint's pipe
	// sets forbidNonWhitelisted, so the provider never sends this — it is read-side and used only to
	// re-identify a route entry locally. Nothing to constrain.
	"resource.checkpointsase_enhanced_route_table.tunnel_ids": {mayBeEmpty, "never sent; local matching only"},

	// --- mayBeEmpty by construction: object-element lists the provider iterates ------------------
	// These carry no array of their own to the wire in a way an empty list could break: each is
	// either a MaxItems-1 wrapper block, or a collection the provider loops over one request at a
	// time. Recorded rather than skipped so the test's "unclassified" check stays meaningful.
	"resource.checkpointsase_network.network":                           {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_network.region":                            {mayBeEmpty, "iterated; one request per region"},
	"resource.checkpointsase_enhanced_network.region":                   {mayBeEmpty, "iterated; one request per region"},
	"resource.checkpointsase_gateway.gateways":                          {mayBeEmpty, "iterated; one request per gateway"},
	"resource.checkpointsase_enhanced_dynamic_tunnel.tunnel":            {mayBeEmpty, "create sends tunnels; update diffs into addTunnels"},
	"resource.checkpointsase_enhanced_dynamic_tunnel.phase1":            {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_enhanced_dynamic_tunnel.phase2":            {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_enhanced_static_tunnel.phase1":             {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_enhanced_static_tunnel.phase2":             {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_ipsec_single.phase1":                       {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_ipsec_single.phase2":                       {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_ipsec_redundant.shared_settings":           {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_ipsec_redundant.advanced_settings":         {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_ipsec_redundant.advanced_settings.phase1":  {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_ipsec_redundant.advanced_settings.phase2":  {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_ipsec_redundant.tunnel1":                   {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_ipsec_redundant.tunnel2":                   {mayBeEmpty, "MaxItems 1 wrapper block"},
	"resource.checkpointsase_firewall_policy.policy_rules.sources":      {mayBeEmpty, "MaxItems 1 wrapper block; absent means unrestricted"},
	"resource.checkpointsase_firewall_policy.policy_rules.destinations": {mayBeEmpty, "MaxItems 1 wrapper block; absent means unrestricted"},
	// createUser.dto.ts: @IsString({each:true}) @IsOptional() accessGroups?: string[] = []
	// -- @IsOptional with NO @ArrayMinSize, and the DTO's own default is []. An
	// empty list is legal and is the only way to express "no access groups".
	"resource.checkpointsase_user.access_groups": {mayBeEmpty, "createUser.dto.ts @IsOptional, no @ArrayMinSize, defaults to []"},
	"resource.checkpointsase_user.profile_data":  {mayBeEmpty, "MaxItems 1 wrapper block"},

	// --- enhanced network private DNS ----------------------------------------------------------
	// EIGHT entries, not the four the dispatch predicted or the six the task brief did. Both
	// counted the arrays that carry DATA (servers, search_domains, and the two domains lists) and
	// missed that every MaxItems-1 BLOCK in privateDNSSchema is a TypeList too, so walkSchema
	// reports `attributes`, `dns_policy`, `dns_policy.public` and `dns_policy.private` as well.
	// Recorded here because the count is a trap for Task 3, which needs the identical eight under
	// its own resource name -- this map is keyed by resource, so nothing about these carries over.
	//
	// EVERY ONE IS mayBeEmpty, and the reasoning below is why none of them can be mustReject:
	// a mustReject verdict FORCES MinItems: 1 (the test above asserts exactly that), and MinItems
	// on any of these would refuse a body the server accepts.
	//
	// The whole family's verdict rests on one measurement, API-FINDINGS.md 1.31, 2026-08-26:
	//   PUT {"enabled":false,"attributes":{"servers":[],"searchDomains":[]}}  -> 202
	// Two empty arrays in the only supported way to turn private DNS off.
	//
	// servers deserves the longest note because the brief called it "mustReject when enabled is
	// true". That is a true statement about the API (swagger.yaml:4492: "must contain at least one
	// entry when enabled is true") and it is NOT the verdict this map can record: the condition is
	// on a sibling attribute, MinItems has no access to one, and setting MinItems: 1 to express it
	// would make the 202 above unwritable -- i.e. would remove the only way to turn the feature
	// off. The conditional is enforced in validatePrivateDNSDiff (private_dns.go) instead, which is
	// where a cross-field rule can see both fields.
	"resource.checkpointsase_enhanced_network_private_dns.attributes":                    {mayBeEmpty, "MaxItems 1 wrapper block: ZERO blocks is the legal 'off' CONFIGURATION. It is not a legal BODY -- a PUT with no `attributes` object is a 422 -- and mayBeEmpty holds only because expandCustomDnsUpdate synthesises the two required empty arrays. Also Optional+Computed, so MinItems must be 0 regardless"},
	"resource.checkpointsase_enhanced_network_private_dns.attributes.servers":            {mayBeEmpty, "measured: {\"enabled\":false,...\"servers\":[]} is a 202 (API-FINDINGS.md 1.31). The 'at least one when enabled is true' minimum (swagger.yaml:4492) is CONDITIONAL on a sibling, so it lives in validatePrivateDNSDiff -- MinItems here would make the 'off' body unwritable"},
	"resource.checkpointsase_enhanced_network_private_dns.attributes.search_domains":     {mayBeEmpty, "swagger.yaml:4500 says so in words: \"Required — send an empty array if you have none\""},
	"resource.checkpointsase_enhanced_network_private_dns.attributes.dns_policy":         {mayBeEmpty, "MaxItems 1 wrapper block; dnsPolicy is absent from CustomDnsUpdateAttributes' required list (swagger.yaml:4482-4484, which names only servers and searchDomains) and is an `omitempty` pointer in the model, so ZERO blocks omits the key entirely rather than sending null"},
	"resource.checkpointsase_enhanced_network_private_dns.attributes.dns_policy.public":  {mayBeEmpty, "MaxItems 1 wrapper block; DnsPolicy (swagger.yaml:4589) requires neither half and Public is an `omitempty` pointer, so zero blocks omits the key"},
	"resource.checkpointsase_enhanced_network_private_dns.attributes.dns_policy.private": {mayBeEmpty, "MaxItems 1 wrapper block; DnsPolicy (swagger.yaml:4589) requires neither half and Private is an `omitempty` pointer, so zero blocks omits the key"},
	// Both domains lists are Required INSIDE their blocks (swagger.yaml:4595, :4609) and carry
	// maxItems 100 with no minItems -- so once you write the block you must write the key, and []
	// is a legal value for it. Required-and-empty is not a contradiction here.
	"resource.checkpointsase_enhanced_network_private_dns.attributes.dns_policy.public.domains":  {mayBeEmpty, "swagger.yaml:4600 uniqueItems + maxItems 100, no minItems; Required inside `public`, which is about presence not length"},
	"resource.checkpointsase_enhanced_network_private_dns.attributes.dns_policy.private.domains": {mayBeEmpty, "swagger.yaml:4625 uniqueItems + maxItems 100, no minItems; Required inside `private`, which is about presence not length"},

	// --- checkpointsase_enhanced_region_private_dns: THE SAME EIGHT, AND THE SAME COUNT ---------
	// This map is keyed by RESOURCE NAME, so the shared privateDNSSchema cannot supply these and
	// the region resource needs its own eight. Eight, not four: the four leaf lists plus the four
	// MaxItems-1 wrapper BLOCKS, which are TypeList too and which walkSchema reports as attributes.
	// Counting the leaves and forgetting the blocks is the mistake the Phase 5 plan and both task
	// briefs made; adding the resource without them fails the test above with all eight named.
	//
	// EVERY VERDICT BELOW IS SOURCED FROM THE SPEC, AND NONE OF IT FROM A MEASUREMENT OF THIS
	// ENDPOINT. That distinction is the point of writing them out again rather than aliasing the
	// network entries. API-FINDINGS.md 1.31's 202 for {"enabled":false,"attributes":{"servers":[],
	// "searchDomains":[]}} was measured against /v3/networks/enhanced/{networkId}/privateDNS; no
	// probe has ever touched /regions/{regionId}/privateDNS. What carries over is that both
	// operations take the SAME request model -- CustomDnsUpdate, hence the same
	// CustomDnsUpdateAttributes and the same DnsPolicy (openapi.yaml:1121 vs :633) -- so the
	// schema-level facts below apply verbatim while the live 202 does not.
	//
	// `attributes` is the one worth reading twice. mayBeEmpty here is a statement about the HCL
	// ONLY: zero blocks is a legal configuration. On the WIRE an absent `attributes` object is a
	// 422 (API-FINDINGS.md 1.31, network path), and the verdict is legal solely because
	// expandCustomDnsUpdate synthesises {"servers":[],"searchDomains":[]} for a config that names
	// neither. If that synthesis were ever removed, this entry would become a lie without changing.
	"resource.checkpointsase_enhanced_region_private_dns.attributes": {mayBeEmpty, "MaxItems 1 wrapper block: ZERO blocks is the legal 'off' CONFIGURATION. It is not a legal BODY -- a PUT with no `attributes` object is a 422 -- and mayBeEmpty holds only because expandCustomDnsUpdate synthesises the two required empty arrays. Also Optional+Computed, so MinItems must be 0 regardless"},
	// servers: swagger.yaml:4486-4492 (CustomDnsUpdateAttributes.servers) declares uniqueItems and
	// maxItems 4 and NO minItems. The "must contain at least one entry when enabled is true" in the
	// description at :4492 is conditional on a SIBLING attribute, which MinItems cannot see, and
	// MinItems: 1 here would make the only supported way to turn private DNS off unwritable. The
	// conditional lives in validatePrivateDNSDiff, reached from this resource's own CustomizeDiff.
	"resource.checkpointsase_enhanced_region_private_dns.attributes.servers": {mayBeEmpty, "swagger.yaml:4489 maxItems 4, uniqueItems, NO minItems. The 'at least one when enabled is true' minimum (swagger.yaml:4492) is CONDITIONAL on a sibling, so it lives in validatePrivateDNSDiff -- MinItems here would make the 'off' body unwritable. The matching 202 was measured on the NETWORK path, not this one"},
	// search_domains: swagger.yaml:4500's description settles it in words rather than by
	// decorator -- "Required — send an empty array if you have none. Omitting it on update is
	// rejected with 400". So [] is not merely tolerated, it is the prescribed way to have none.
	"resource.checkpointsase_enhanced_region_private_dns.attributes.search_domains": {mayBeEmpty, "swagger.yaml:4500 says so in words: \"Required — send an empty array if you have none\", and omitting the key is a 400. [] is the prescribed empty value, not a tolerated one"},
	// dns_policy and its two halves: CustomDnsUpdateAttributes.dnsPolicy is not in the required
	// list (swagger.yaml:4483-4484 names only servers and searchDomains), and the generated model
	// carries `json:"dnsPolicy,omitempty"` on a pointer -- so zero blocks omits the key rather than
	// sending null. Same for public/private: DnsPolicy (swagger.yaml:4589) requires neither, and
	// both are `omitempty` pointers. expandDnsPolicy returns nil when neither half is written,
	// which is what makes "no blocks" reach the wire as "no key".
	"resource.checkpointsase_enhanced_region_private_dns.attributes.dns_policy":         {mayBeEmpty, "MaxItems 1 wrapper block; dnsPolicy is absent from CustomDnsUpdateAttributes' required list (swagger.yaml:4482-4484, which names only servers and searchDomains) and is an `omitempty` pointer in the model, so ZERO blocks omits the key entirely rather than sending null"},
	"resource.checkpointsase_enhanced_region_private_dns.attributes.dns_policy.public":  {mayBeEmpty, "MaxItems 1 wrapper block; DnsPolicy (swagger.yaml:4589) requires neither half and Public is an `omitempty` pointer, so zero blocks omits the key"},
	"resource.checkpointsase_enhanced_region_private_dns.attributes.dns_policy.private": {mayBeEmpty, "MaxItems 1 wrapper block; DnsPolicy (swagger.yaml:4589) requires neither half and Private is an `omitempty` pointer, so zero blocks omits the key"},
	// Both domains lists are Required INSIDE their blocks (swagger.yaml:4595, :4609) and carry
	// maxItems 100 with no minItems -- so once you write the block you must write the key, and []
	// is a legal value for it. Required-and-empty is not a contradiction. Note the 100: it is NOT
	// the 4 the two lists above carry, and a MaxItems: 4 copied across would refuse valid config.
	"resource.checkpointsase_enhanced_region_private_dns.attributes.dns_policy.public.domains":  {mayBeEmpty, "swagger.yaml:4600 uniqueItems + maxItems 100, no minItems; Required inside `public` (swagger.yaml:4595), which is about presence not length -- and the model marshals `domains` without omitempty, so [] satisfies that presence"},
	"resource.checkpointsase_enhanced_region_private_dns.attributes.dns_policy.private.domains": {mayBeEmpty, "swagger.yaml:4625 uniqueItems + maxItems 100, no minItems; Required inside `private` (swagger.yaml:4609), which is about presence not length -- and the model marshals `domains` without omitempty, so [] satisfies that presence"},

	// --- checkpointsase_split_tunneling: FOUR, and the fourth is the wrapper block ---------------
	// Count them from the schema rather than from the request body, which is the mistake this
	// phase has now made three times. The BODY has three arrays; the SCHEMA has four TypeLists,
	// because `except_data` is a MaxItems-1 wrapper block and walkSchema reports it as an
	// attribute like any other.
	//
	// There is a FIFTH TypeList in this resource -- except_data.exceptions -- and it is absent
	// from this map ON PURPOSE, not by oversight. The test above skips `s.Computed && !s.Optional`,
	// and `exceptions` is Computed-only (decision D5, API-FINDINGS.md 1.29): it is never sent, so
	// it has no empty-array verdict to record. If anyone ever makes it Optional, this test starts
	// failing with `...except_data.exceptions is a list or set attribute with no entry`, which is
	// the right way to find out that D5 has been reopened.
	//
	// `except_data` itself: mayBeEmpty is a statement about the HCL. Zero blocks cannot occur --
	// the attribute is Required, so Terraform refuses a configuration without it before any
	// verdict here applies -- and MinItems: 1 would be redundant rather than protective. On the
	// wire `exceptData` is an OBJECT and not an array at all (swagger.yaml:7118), named in
	// SplitTunnelingBase's required list (swagger.yaml:7120-7122) and marked @IsNotEmptyObject()
	// in the backend DTO, which is about PRESENCE and not about length.
	"resource.checkpointsase_split_tunneling.except_data": {mayBeEmpty, "MaxItems 1 wrapper block, and Required -- so Terraform already refuses zero blocks and MinItems would add nothing. On the wire exceptData is an object, not an array (swagger.yaml:7118), required by SplitTunnelingBase (swagger.yaml:7120-7122)"},
	// The three arrays. swagger.yaml:7127-7147 declares each of them with NO minItems, NO maxItems
	// and NO uniqueItems, and each carries `default: []`.
	//
	// AND THE DEFAULT IS A TRAP, WHICH IS WHY THE MEASUREMENT IS QUOTED ON EVERY ONE OF THEM.
	// `default: []` reads as "you may omit this". Measured 2026-08-26: omitting an array returns
	// a 400, and the 400 names EXACTLY THE ARRAYS THAT WERE LEFT OUT -- all three when all three
	// are omitted (API-FINDINGS.md 1.31), only updatableObjectIds when only that one is omitted
	// (API-FINDINGS.md 1.37). These `why` strings used to say "omitting it is a 400 naming all
	// three arrays"; that generalised 1.31's probe, which omitted all three at once, and 1.37
	// measured it false. The verdict is unaffected either way: [] is not merely tolerated here,
	// it is the only legal way to have none -- which is the strongest possible form of
	// mayBeEmpty, and makes MinItems: 1 a bug that would remove the ability to clear a list the
	// server insists on receiving. expandSplitTunneling sends all three as [] for a
	// configuration that names none, which is what makes Optional-in-HCL and required-on-the-wire
	// consistent rather than contradictory.
	"resource.checkpointsase_split_tunneling.except_data.cidr":                 {mayBeEmpty, "swagger.yaml:7127-7133: no minItems, no maxItems, no uniqueItems, `default: []`. MEASURED 2026-08-26 (API-FINDINGS.md 1.31, 1.37): the key is required on the wire even when empty -- omitting it is a 400 that names it (\"exceptData.cidr must be an array\") -- so [] is the prescribed empty value, not a tolerated one"},
	"resource.checkpointsase_split_tunneling.except_data.address_object_ids":   {mayBeEmpty, "swagger.yaml:7134-7140: no minItems, no maxItems, no uniqueItems, `default: []`. MEASURED 2026-08-26 (API-FINDINGS.md 1.31, 1.37): omitting it is a 400 that names it (\"exceptData.addressObjectIds must be an array\", plus four more complaints about the same array), so [] is the prescribed empty value"},
	"resource.checkpointsase_split_tunneling.except_data.updatable_object_ids": {mayBeEmpty, "swagger.yaml:7141-7147: no minItems, no maxItems, no uniqueItems, `default: []`. MEASURED 2026-08-26 (API-FINDINGS.md 1.37, which omitted THIS ARRAY ALONE): omitting it is a 400 naming only it (\"exceptData.updatableObjectIds must be an array\", and two more about the same array), so [] is the prescribed empty value"},
}

/*
TestSchemaListAttributesMatchTheirEmptyArrayVerdict enforces listAttributeEmptyPolicy in both
directions, and fails on any list or set attribute missing from it.

The "unclassified" failure is the point. A new list attribute that reaches a request body is exactly
the situation that produced three blockers, so the suite refuses to pass until someone has read the
field's validator and written the answer down.
*/
func TestSchemaListAttributesMatchTheirEmptyArrayVerdict(t *testing.T) {
	for res, m := range allRegistered() {
		if !strings.HasPrefix(res, "resource.") {
			continue // data sources have no request body
		}
		walkSchema("", m, func(path string, s *schema.Schema) {
			// TypeSet as well as TypeList. Both reach a request body as a JSON
			// array, so both can be sent as `[]`, and a sweep that looked only at
			// TypeList would have a hole exactly the size of the next attribute
			// somebody makes a set. checkpointsase_access_policy was the first
			// resource in this provider to use TypeSet at all, which is how the
			// hole was found; widening it here cost nothing elsewhere.
			if (s.Type != schema.TypeList && s.Type != schema.TypeSet) ||
				(s.Computed && !s.Optional) {
				return
			}
			full := res + "." + path
			policy, ok := listAttributeEmptyPolicy[full]
			if !ok {
				t.Errorf("%s is a list or set attribute with no entry in listAttributeEmptyPolicy. Read the "+
					"field's validator in perimeter81-public-api and record whether the server accepts "+
					"an empty array for it — guessing is what this map exists to stop", full)
				return
			}
			switch policy.verdict {
			case mustReject:
				if s.MinItems != 1 {
					t.Errorf("%s MinItems = %d, want 1: the server rejects an empty array (%s), so an "+
						"empty list must fail at plan time rather than 15 minutes into an apply",
						full, s.MinItems, policy.why)
				}
			case mayBeEmpty:
				if s.MinItems != 0 {
					t.Errorf("%s has MinItems = %d, but the server accepts an empty array (%s). Refusing "+
						"[] here removes the only way to clear the list", full, s.MinItems, policy.why)
				}
			}
		})
	}
}
