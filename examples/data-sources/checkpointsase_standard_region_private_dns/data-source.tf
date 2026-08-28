# Read the private DNS configuration of one region inside a standard network.
#
# Read-only for the same reason as the network-level data source: the standard
# family exposes GET and nothing else on this path. The enhanced family's
# equivalent is the checkpointsase_enhanced_region_private_dns resource.
data "checkpointsase_regions" "all" {}

resource "checkpointsase_network" "example" {
  network {
    name = "example-network"
  }
  region {
    # cpregion_id names a CATALOGUE entry and is an opaque server id, not an
    # AWS-style region name. Reading it from checkpointsase_regions is what every
    # other example in this repo does, and it keeps this file applyable — which
    # matters more here than elsewhere, because the whole point of the file is the
    # cpregion_id / region_id distinction spelled out below.
    cpregion_id = data.checkpointsase_regions.all.regions[0].id
  }
}

# region_id is the region's OWN server-assigned id — region[*].region_id — and
# NOT the cpregion_id catalogue entry the region was created from. The two are
# different values and the catalogue id is not a valid path segment here.
data "checkpointsase_standard_region_private_dns" "example" {
  network_id = checkpointsase_network.example.id
  region_id  = one(checkpointsase_network.example.region[*].region_id)
}

output "example_region_dns_enabled" {
  value = data.checkpointsase_standard_region_private_dns.example.enabled
}
