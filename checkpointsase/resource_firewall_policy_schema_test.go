package checkpointsase

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// schemaResource aliases schema.Resource for use in table-driven schema tests.
type schemaResource = schema.Resource

// v3's GranularFirewallPolicy requires policyLoggingEnabled at the policy level
// and logEnabled per rule. policyLoggingEnabled is already carried by the
// existing `trace` attribute; logEnabled is new. It MUST be Optional with a
// default — if it were Required, every existing policy_rules block would fail
// with "Missing required argument" on upgrade.
func TestFirewallPolicyLogEnabledIsOptionalWithDefault(t *testing.T) {
	r := resourceFirewallPolicy()
	rules, ok := r.Schema["policy_rules"]
	if !ok {
		t.Fatal("schema has no policy_rules attribute")
	}
	elem, ok := rules.Elem.(*schemaResource)
	if !ok {
		t.Fatalf("policy_rules Elem is %T, want *schema.Resource", rules.Elem)
	}
	logEnabled, ok := elem.Schema["log_enabled"]
	if !ok {
		t.Fatal("policy_rules has no log_enabled attribute")
	}
	if logEnabled.Required {
		t.Error("log_enabled must not be Required — it would break existing configs on upgrade")
	}
	if !logEnabled.Optional {
		t.Error("log_enabled must be Optional")
	}
	if logEnabled.Default != false {
		t.Errorf("log_enabled Default = %v, want false", logEnabled.Default)
	}
	if logEnabled.Description == "" {
		t.Error("log_enabled needs a Description — tfplugindocs depends on it")
	}
}

func TestFirewallPolicyTraceStillExists(t *testing.T) {
	r := resourceFirewallPolicy()
	trace, ok := r.Schema["trace"]
	if !ok {
		t.Fatal("trace attribute was removed; it carries policyLoggingEnabled and removing it is a breaking change")
	}
	if trace.Description == "" {
		t.Error("trace needs a Description")
	}
}
