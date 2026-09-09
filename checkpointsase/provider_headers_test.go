package checkpointsase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
configureAgainst runs the provider's real ConfigureContextFunc against a stub
server and returns the headers the SDK actually put on the wire.

IT DRIVES THE REGISTERED ConfigureContextFunc, not a copy of its body. The
defect this file exists to catch is the headers being computed correctly and
then never reaching the client -- asserting on a locally-built Configuration
would pass just as well with providerConfigure wired to nothing.

The request is a real one: the returned client is asked for something, the stub
records what arrived. Nothing is stubbed between the SDK and net/http.

@return http.Header - the headers the server received
*/
func configureAgainst(t *testing.T, terraformVersion string) http.Header {
	t.Helper()

	var got http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	p := Provider()
	// What the plugin SDK does from the Configure request in a real run
	// (helper/schema/grpc_provider.go:540). Setting it by hand is the only way
	// to exercise the branch, since no Terraform process is involved here.
	p.TerraformVersion = terraformVersion

	data := schema.TestResourceDataRaw(t, p.Schema, map[string]interface{}{
		"api_key":  "not-a-real-key",
		"base_url": server.URL,
	})

	meta, diags := p.ConfigureContextFunc(context.Background(), data)
	if diags.HasError() {
		t.Fatalf("configure reported errors: %v", diags)
	}
	client, ok := meta.(*perimeter81Sdk.APIClient)
	if !ok {
		t.Fatalf("configure returned %T, want *perimeter81Sdk.APIClient", meta)
	}

	// Any call will do -- the assertion is about headers, not about the body.
	// GetStatus is chosen because it takes no path parameters, so nothing about
	// this test depends on a resource existing. The error is ignored on purpose:
	// a decode failure against a stub response says nothing about what was sent,
	// and `got` is populated either way.
	_, _, _ = client.NetworksAPI.GetStatus(context.Background()).Execute()

	if got == nil {
		t.Fatal("the stub server was never called, so no headers were captured")
	}
	return got
}

/*
TestClientIdentityHeadersAreSentOnEveryRequest covers the two headers the API
team asked for. Exact values, not prefixes: the point of a client header is that
somebody can filter on it, and a filter does not tolerate a near miss.
*/
func TestClientIdentityHeadersAreSentOnEveryRequest(t *testing.T) {
	headers := configureAgainst(t, "1.9.5")

	for header, want := range map[string]string{
		"X-Cp-Client":         "terraform-provider-checkpointsase",
		"X-Cp-Client-Version": ProviderVersion,
	} {
		if got := headers.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

/*
TestUserAgentReportsTerraformAndTheProvider asserts the parts rather than the
whole string. Two of the four segments are owned by other people -- the plugin
SDK's version comes from its own build metadata -- so pinning the full value
would make this test fail on a dependency bump that broke nothing.

What must hold: Terraform's version is real, and the provider identifies itself.
*/
func TestUserAgentReportsTerraformAndTheProvider(t *testing.T) {
	userAgent := configureAgainst(t, "1.9.5").Get("User-Agent")

	for _, want := range []string{
		"Terraform/1.9.5",
		"terraform-provider-checkpointsase/" + ProviderVersion,
	} {
		if !strings.Contains(userAgent, want) {
			t.Errorf("User-Agent %q does not contain %q", userAgent, want)
		}
	}

	// The SDK's own hardcoded default (configuration.go). Seeing it means
	// cfg.UserAgent was never applied, so the API learns neither Terraform's
	// version nor the provider's real one -- the whole point of this change.
	// Both spellings are checked because the default differs between the v2.3
	// SDK ("Swagger-Codegen/...") and the v3 one.
	for _, stale := range []string{"Swagger-Codegen", "CheckPointSW-terraform-provider-checkpointsase"} {
		if strings.Contains(userAgent, stale) {
			t.Errorf("User-Agent is still the SDK's own default (%s): %q", stale, userAgent)
		}
	}
}

/*
TestUserAgentSurvivesAnUnknownTerraformVersion is the guard on the empty case.

p.UserAgent does not check TerraformVersion, so without the fallback in
Provider's closure this emits "Terraform/ (+https://www.terraform.io)" -- a
malformed product token that some proxies drop. Empty is not exotic: it is what
`go test` sees, and what Terraform 0.11 sends.
*/
func TestUserAgentSurvivesAnUnknownTerraformVersion(t *testing.T) {
	userAgent := configureAgainst(t, "").Get("User-Agent")

	if strings.Contains(userAgent, "Terraform/ ") {
		t.Errorf("empty TerraformVersion produced a bare product token: %q", userAgent)
	}
	if !strings.Contains(userAgent, "Terraform/0.11+compatible") {
		t.Errorf("User-Agent %q does not carry the 0.11+compatible fallback", userAgent)
	}
}
