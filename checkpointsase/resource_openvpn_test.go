package checkpointsase

import (
	"context"
	"fmt"
	"testing"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var randNameOpenVpn string = randStringBytesRmndr()

// TestAccOpenvpn_basic covers the credential-rotation contract: creating the
// tunnel yields a secret_access_key, and bumping `version` replaces it.
//
// The assertions read Terraform STATE, not the API. secretAccessKey is returned
// exactly once, in the create/update response — the subsequent GET does not
// carry it, even though the spec declares it on OpenVPNTunnel. So state is the
// only place the value can be observed, which is precisely what the resource's
// description promises. An earlier version of this test asked the API for it and
// therefore could never pass.
func TestAccOpenvpn_basic(t *testing.T) {
	t.Parallel()
	// Captured by pointer on purpose: the check closures must read this when
	// they run, not when the Steps slice is built. Passing it by value is how
	// the previous version of this test ended up comparing against "".
	var createdSecret string
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t); testAccPreCheckRegion(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccOpenvpnConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckOpenvpnExists("checkpointsase_openvpn.ovpn2"),
					testAccCaptureOpenvpnSecret("checkpointsase_openvpn.ovpn2", &createdSecret),
				),
			},
			{
				Config: testAccOpenvpnUpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckOpenvpnExists("checkpointsase_openvpn.ovpn2"),
					testAccCheckOpenvpnSecretRotated("checkpointsase_openvpn.ovpn2", &createdSecret),
				),
			},
		},
	})
}

// testAccCheckOpenvpnExists confirms the tunnel really exists server-side, so a
// state-only assertion cannot pass against a tunnel that was never created.
func testAccCheckOpenvpnExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}
		tunnelId := rs.Primary.ID
		if tunnelId == "" {
			return fmt.Errorf("No tunnel id is set")
		}
		conn := testAccProvider.Meta().(*perimeter81Sdk.APIClient)
		networkId := rs.Primary.Attributes["network_id"]
		if _, _, err := conn.StandardTunnelsAPI.StandardGetOpenVPNTunnel(context.Background(), networkId, tunnelId).Execute(); err != nil {
			return err
		}
		return nil
	}
}

// testAccCaptureOpenvpnSecret records the create-time secret from state.
func testAccCaptureOpenvpnSecret(n string, out *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}
		secret := rs.Primary.Attributes["secret_access_key"]
		if secret == "" {
			return fmt.Errorf("secret_access_key is empty in state after create; " +
				"the create response is the only place the API ever returns it, so it " +
				"must be persisted there or the credential is lost")
		}
		*out = secret
		return nil
	}
}

// testAccCheckOpenvpnSecretRotated asserts the version bump replaced the
// credential. The values themselves are never printed — the attribute is
// Sensitive and test output is not a safe place for it.
func testAccCheckOpenvpnSecretRotated(n string, previous *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not Found: %s", n)
		}
		current := rs.Primary.Attributes["secret_access_key"]
		if current == "" {
			return fmt.Errorf("secret_access_key is empty in state after the version bump; " +
				"the rotated secret from the update response was not persisted")
		}
		if current == *previous {
			return fmt.Errorf("secret_access_key is unchanged after the version bump; " +
				"the server rotated the credential but Terraform kept the stale value")
		}
		return nil
	}
}

func testAccOpenvpnConfig() string {
	config := `
resource "checkpointsase_network" "n2" {
  network {
    name = "%s"
    tags = ["test"]
  }
  region {
    cpregion_id = "%s"
    idle = true
  }
}

data "checkpointsase_networks" "all2" {
	depends_on = [
    	checkpointsase_network.n2
  	]
}

resource "checkpointsase_openvpn" "ovpn2" {
  network_id = checkpointsase_network.n2.id
  region_id = {
    for network in data.checkpointsase_networks.all2.networks :
    network.id => network.regions[0].id
    if network.id == checkpointsase_network.n2.id
  }[checkpointsase_network.n2.id]
  gateway_id = {
    for network in data.checkpointsase_networks.all2.networks :
    network.id => network.regions[0].instances[0].id
    if network.id == checkpointsase_network.n2.id
  }[checkpointsase_network.n2.id]
  tunnel_name = "OpenVPNTunnel"
  version = 1
}
  `
	return fmt.Sprintf(config, randNameOpenVpn, testAccRegionID())
}

func testAccOpenvpnUpdateConfig() string {
	config := `
resource "checkpointsase_network" "n2" {
  network {
    name = "%s"
    tags = ["test"]
  }
  region {
    cpregion_id = "%s"
    idle = true
  }
}

data "checkpointsase_networks" "all2" {
	depends_on = [
    	checkpointsase_network.n2
  	]
}

resource "checkpointsase_openvpn" "ovpn2" {
  network_id = checkpointsase_network.n2.id
  region_id = {
    for network in data.checkpointsase_networks.all2.networks :
    network.id => network.regions[0].id
    if network.id == checkpointsase_network.n2.id
  }[checkpointsase_network.n2.id]
  gateway_id = {
    for network in data.checkpointsase_networks.all2.networks :
    network.id => network.regions[0].instances[0].id
    if network.id == checkpointsase_network.n2.id
  }[checkpointsase_network.n2.id]
  tunnel_name = "OpenVPNTunnel"
  version = 2
}
  `
	return fmt.Sprintf(config, randNameOpenVpn, testAccRegionID())
}

/*
diffOpenvpnVersionBump runs the SDK's real diff machinery -- including
CustomizeDiff -- over a `version` change on an already-created tunnel, the way
`terraform plan` does for an update.

Going through r.Diff rather than calling resourceOpenvpnCustomizeDiff directly is
deliberate: it covers the WIRING (the function being registered on the resource at
all) as well as the rule. A CustomizeDiff nobody calls is exactly the defect a
direct call would miss.

The prior state carries an ID because the rule is update-only -- on create every
computed attribute is already unknown and d.Id() is empty.

  - @param t *testing.T
  - @param oldVersion, newVersion string - the version values either side of the plan

@return *terraform.InstanceDiff - what `terraform plan` would produce
*/
func diffOpenvpnVersionBump(t *testing.T, oldVersion, newVersion string) *terraform.InstanceDiff {
	t.Helper()

	r := resourceOpenvpn()
	prior := &terraform.InstanceState{
		ID: "9E00LwOQVD",
		Attributes: map[string]string{
			"id":                "9E00LwOQVD",
			"version":           oldVersion,
			"network_id":        "SbrV9IZhgq",
			"region_id":         "fksPscPIX2",
			"gateway_id":        "enaLicxLwX",
			"tunnel_name":       "qaovpnprobe",
			"access_key_id":     "d5626591cf58aaaa",
			"secret_access_key": "an-existing-32-character-secret!",
		},
	}
	cfg := terraform.NewResourceConfigRaw(map[string]interface{}{
		"version":     newVersion,
		"network_id":  "SbrV9IZhgq",
		"region_id":   "fksPscPIX2",
		"gateway_id":  "enaLicxLwX",
		"tunnel_name": "qaovpnprobe",
	})

	diff, err := r.Diff(context.Background(), prior, cfg, nil)
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	return diff
}

/*
TestOpenvpnCustomizeDiffMarksSecretComputedOnVersionBump pins the plan-honesty
rule behind P81-145415.

A `version` bump rotates the tunnel's credentials server-side. Both credential
attributes are Computed, so without the CustomizeDiff the plan shows only the
version integer moving and says nothing about the live secret being replaced.
That silence is what made the rotation look like a no-op.

The negative half matters as much as the positive: `access_key_id` is verified NOT
to rotate (the API returns a byte-identical 16-character id before and after), so
marking it known-after-apply would promise a change that never arrives.
*/
func TestOpenvpnCustomizeDiffMarksSecretComputedOnVersionBump(t *testing.T) {
	diff := diffOpenvpnVersionBump(t, "1", "2")

	secret, ok := diff.Attributes["secret_access_key"]
	if !ok {
		t.Fatalf("secret_access_key absent from the diff; a rotation plan must surface it.\ndiff: %#v", diff.Attributes)
	}
	if !secret.NewComputed {
		t.Errorf("secret_access_key is not NewComputed, so the plan would not show "+
			"'(known after apply)' for a credential that is about to be replaced. got: %#v", secret)
	}

	if key, ok := diff.Attributes["access_key_id"]; ok && key.NewComputed {
		t.Errorf("access_key_id was marked NewComputed, promising a rotation the server "+
			"never performs -- it is a stable identifier. got: %#v", key)
	}
}

/*
TestOpenvpnCustomizeDiffLeavesSecretAloneWithoutAVersionChange is the other half of
the rule: a plan that does not touch `version` is not a rotation, so the stored
secret must not be advertised as changing.

Without this, any unrelated plan would claim the credential is about to move, and
since the API discloses the secret only once there would be no way for a user to
tell a real rotation from noise.
*/
func TestOpenvpnCustomizeDiffLeavesSecretAloneWithoutAVersionChange(t *testing.T) {
	diff := diffOpenvpnVersionBump(t, "2", "2")

	if diff == nil {
		return // no diff at all is the ideal outcome
	}
	if secret, ok := diff.Attributes["secret_access_key"]; ok && secret.NewComputed {
		t.Errorf("secret_access_key marked NewComputed without a version change; "+
			"an unrelated plan must not claim a credential rotation. got: %#v", secret)
	}
}
