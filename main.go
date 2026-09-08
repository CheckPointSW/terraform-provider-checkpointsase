package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"

	"terraform-provider-checkpointsase/checkpointsase"
)

// Generate the Check Point SASE Terraform provider documentation using `tfplugindocs`:
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name checkpointsase

/*
version and commit are injected at release time by goreleaser, whose ldflags
already name them: `-X main.version={{.Version}} -X main.commit={{.Commit}}`
(.goreleaser.yml:19).

THEY HAD TO BE DECLARED HERE FOR THAT TO DO ANYTHING. The Go linker silently
ignores -X against a symbol that does not exist -- no error, no warning -- so
until this block existed the release pipeline injected nothing at all and every
build reported the same version.

The default is the shipped version rather than "dev" so that a `go build`
straight from the tree still reports something truthful in the User-Agent and
the X-CP-Client-Version header. Bump it with the release.
*/
var (
	version = "3.0.0"
	commit  = "none"
)

func main() {
	// Read by providerConfigure for the User-Agent and X-CP-Client-Version.
	// Assigned before Serve so it is set long before Terraform calls Configure.
	checkpointsase.ProviderVersion = version

	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return checkpointsase.Provider()
		},
	})
}
