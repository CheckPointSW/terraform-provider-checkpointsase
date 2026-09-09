package checkpointsase

import (
	"context"
	"log"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
ProviderVersion is the provider's own version, reported to the API in the
User-Agent and in the X-CP-Client-Version header.

Overwritten from main() at startup, where goreleaser's `-X main.version` lands.
The default here matters anyway: `go test` and `go build` never run main(), so
this value is what those builds report.

SINGLE SOURCE ON PURPOSE. Before this, the version existed as a literal in the
Makefile, another in the SDK's own User-Agent, and a third that goreleaser tried
to inject into a symbol nobody had declared. A fourth copy inside the header
strings would have been one more thing to miss at tag time.
*/
var ProviderVersion = "3.0.0"

/*
providerClientName is the value of the X-CP-Client header and the last segment
of the User-Agent.

SPELLED WITH THE HYPHEN BEFORE "sase" AT THE OPERATOR'S REQUEST, which is not
how the provider is named anywhere else: the registry address, the binary and
the resource prefix are all `checkpointsase`, unhyphenated. Anyone grepping API
logs for the provider needs to know both spellings exist.
*/
const providerClientName = "terraform-provider-checkpointsase"

/*
Provider Set up the provider schema

@return &schema.Provider
*/
func Provider() *schema.Provider {
	p := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("CHECKPOINT_SASE_API_KEY", nil),
				Description: descriptions["api_key"],
			},
			"base_url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("BASE_URL", perimeter81Sdk.BaseURLUS),
				Description: descriptions["base_url"],
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"checkpointsase_network":                 resourceNetwork(),
			"checkpointsase_wireguard":               resourceWireguard(),
			"checkpointsase_openvpn":                 resourceOpenvpn(),
			"checkpointsase_ipsec_single":            resourceIpsecSingle(),
			"checkpointsase_ipsec_redundant":         resourceIpsecRedundant(),
			"checkpointsase_gateway":                 resourceGateway(),
			"checkpointsase_object_services":         resourceObjectServices(),
			"checkpointsase_object_addresses":        resourceObjectAddresses(),
			"checkpointsase_enhanced_network":        resourceEnhancedNetwork(),
			"checkpointsase_enhanced_region":         resourceEnhancedRegion(),
			"checkpointsase_enhanced_static_tunnel":  resourceEnhancedStaticTunnel(),
			"checkpointsase_enhanced_dynamic_tunnel": resourceEnhancedDynamicTunnel(),
			"checkpointsase_enhanced_route_table":    resourceEnhancedRouteTable(),
			"checkpointsase_application":             resourceApplication(),
			"checkpointsase_firewall_policy":         resourceFirewallPolicy(),
			"checkpointsase_support_options":         resourceSupportOptions(),
			"checkpointsase_user":                    resourceUser(),
			"checkpointsase_group":                   resourceGroup(),
			"checkpointsase_group_membership":        resourceGroupMembership(),
			"checkpointsase_access_policy":           resourceAccessPolicy(),
			"checkpointsase_https_inspection_policy": resourceHttpsInspectionPolicy(),
			"checkpointsase_internet_access_status":  resourceInternetAccessStatus(),

			"checkpointsase_enhanced_network_private_dns": resourceEnhancedNetworkPrivateDNS(),
			"checkpointsase_enhanced_region_private_dns":  resourceEnhancedRegionPrivateDNS(),
			"checkpointsase_split_tunneling":              resourceSplitTunneling(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"checkpointsase_networks":                         dataSourceNetworks(),
			"checkpointsase_standard_networks":                dataSourceStandardNetworks(),
			"checkpointsase_all_networks":                     dataSourceAllNetworks(),
			"checkpointsase_regions":                          dataSourceRegions(),
			"checkpointsase_object_services":                  dataSourceObjectServices(),
			"checkpointsase_object_addresses":                 dataSourceObjectAddresses(),
			"checkpointsase_enhanced_networks":                dataSourceEnhancedNetworks(),
			"checkpointsase_enhanced_regions":                 dataSourceEnhancedRegions(),
			"checkpointsase_applications":                     dataSourceApplications(),
			"checkpointsase_route_table":                      dataSourceRouteTable(),
			"checkpointsase_enhanced_route_table":             dataSourceEnhancedRouteTable(),
			"checkpointsase_network_health":                   dataSourceNetworkHealth(),
			"checkpointsase_enhanced_network_health":          dataSourceEnhancedNetworkHealth(),
			"checkpointsase_enhanced_tunnels":                 dataSourceEnhancedTunnels(),
			"checkpointsase_customer_certificates":            dataSourceCustomerCertificates(),
			"checkpointsase_status":                           dataSourceStatus(),
			"checkpointsase_web_categories":                   dataSourceWebCategories(),
			"checkpointsase_application_control_applications": dataSourceApplicationControlApplications(),
			"checkpointsase_updatable_objects":                dataSourceUpdatableObjects(),
			"checkpointsase_users":                            dataSourceUsers(),
			"checkpointsase_groups":                           dataSourceGroups(),
			"checkpointsase_access_policy":                    dataSourceAccessPolicy(),
			"checkpointsase_https_inspection_policy":          dataSourceHttpsInspectionPolicy(),
			// Read-only because the API is: the standard family declares `get`
			// and nothing else on both privateDNS paths. The enhanced family's
			// equivalents are RESOURCES, above.
			"checkpointsase_standard_network_private_dns": dataSourceStandardNetworkPrivateDNS(),
			"checkpointsase_standard_region_private_dns":  dataSourceStandardRegionPrivateDNS(),
		},
	}

	/*
		A CLOSURE RATHER THAN `ConfigureContextFunc: providerConfigure`, because
		the User-Agent needs p itself.

		p.TerraformVersion is filled in by the plugin SDK from the Configure
		request (helper/schema/grpc_provider.go:540) immediately before this
		runs, so it is only readable from here -- not at the time Provider()
		builds the struct.
	*/
	p.ConfigureContextFunc = func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		// p.UserAgent does NOT guard an empty TerraformVersion, and it is empty
		// under `go test` and under Terraform 0.11, which would put a bare
		// "Terraform/ (+..." on the wire. "0.11+compatible" is the spelling the
		// HashiCorp-maintained providers use for the same gap.
		if p.TerraformVersion == "" {
			p.TerraformVersion = "0.11+compatible"
		}
		return providerConfigure(ctx, d, p.UserAgent(providerClientName, ProviderVersion))
	}

	return p
}

/*
providerConfigure Intialize the provider client SDK configuration
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param d *schema.ResourceData - the terraform resource data

@return interface{} - the terraform meta data that contains the client, and diag.Diagnostics
*/
func providerConfigure(con context.Context, d *schema.ResourceData,
	userAgent string) (interface{}, diag.Diagnostics) {

	// Get the api key and base url from the provider schema
	apiKey := d.Get("api_key").(string)
	baseUrl := d.Get("base_url").(string)

	// Initialize the Check Point Check Point SASE client SDK
	var client interface{}
	if apiKey != "" {
		cfg := perimeter81Sdk.NewConfiguration(apiKey, baseUrl)

		// OVERRIDES THE SDK's OWN DEFAULT, which is the code generator's
		// boilerplate "Swagger-Codegen/2.3.0/go" -- a string that identifies
		// neither Check Point nor this provider to whoever reads the API logs.
		// The SDK is a published module here (no replace directive in go.mod),
		// so this is the only place it can be corrected.
		cfg.UserAgent = userAgent

		// Sent on every request: Configuration.DefaultHeader is applied to each
		// outgoing request by the SDK's prepareRequest.
		//
		// Neither value is a credential, so both are literals rather than
		// environment reads -- they identify the client, they do not
		// authenticate it. The API key remains the only secret, and it still
		// arrives from CHECKPOINT_SASE_API_KEY.
		cfg.AddDefaultHeader("X-CP-Client", providerClientName)
		cfg.AddDefaultHeader("X-CP-Client-Version", ProviderVersion)

		client = perimeter81Sdk.NewAPIClient(cfg)
	}

	// check if the client is initialized correctly
	if client == nil {
		log.Println("[ERROR] Initializing Check Point SASE client is not completed")
		return nil, nil
	}
	log.Println("[INFO] Initializing Check Point SASE client")

	return client, nil
}

var descriptions map[string]string

func init() {
	descriptions = map[string]string{
		"api_key":  "The API key for the Check Point SASE Public API.",
		"base_url": "The base URL for the Check Point SASE REST API. Defaults to the US endpoint. Valid values: https://api.perimeter81.com/api/rest (US), https://api.eu.sase.checkpoint.com/api/rest (EU), https://api.au.sase.checkpoint.com/api/rest (AU), https://api.in.sase.checkpoint.com/api/rest (IN), https://api.ca.sase.checkpoint.com/api/rest (CA, added in v3).",
	}
}
