package checkpointsase

import (
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

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("CHECKPOINT_SASE_API_KEY"); v == "" {
		t.Fatal("CHECKPOINT_SASE_API_KEY must be set for acceptance tests")
	}
}
