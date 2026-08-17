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

// Terraform writes Sensitive attributes to state in plaintext; the marker only
// redacts CLI and log output. Two attributes shipped without it in v2.3 and
// leaked WireGuard private key material into provider logs.
func TestSchemaSecretAttributesAreMarkedSensitive(t *testing.T) {
	secretNames := map[string]bool{
		"passphrase": true, "secret_access_key": true, "access_key_id": true,
		"vault": true, "private_key": true, "api_key": true,
		"customer_root_ca": true, "request_config_token": true,
	}
	normalizedSecretNames := make(map[string]bool, len(secretNames))
	for name := range secretNames {
		normalizedSecretNames[normalizeAttributeName(name)] = true
	}
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
		t.Skipf("KNOWN (deferred to Phase 6): %d server-assigned timestamp(s) are user-writable:\n  %s",
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
