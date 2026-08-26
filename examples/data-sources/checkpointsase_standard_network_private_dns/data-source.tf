# Read the private DNS configuration of a standard network.
#
# This data source is read-only because the API is: the standard network family
# exposes GET and nothing else on this path. To MANAGE private DNS, use the
# checkpointsase_enhanced_network_private_dns resource, which is the enhanced
# family's equivalent.
data "checkpointsase_standard_networks" "all" {}

data "checkpointsase_standard_network_private_dns" "first" {
  network_id = data.checkpointsase_standard_networks.all.networks[0].id
}

# `attributes` holds either one element or none. The API omits it entirely for a
# network nothing has ever configured, so guard any reference to it.
output "first_network_dns_servers" {
  value = try(data.checkpointsase_standard_network_private_dns.first.attributes[0].servers, [])
}
