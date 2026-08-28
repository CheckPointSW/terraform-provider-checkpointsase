# The import id is the ENHANCED NETWORK ID and the REGION ID, joined by a COLON:
#
#     <network_id>:<region_id>
#
# THE SEPARATOR IS ":", NOT "-", AND THAT MATTERS. Nothing in the API rules a
# hyphen out of either id -- both are typed as bare strings with no pattern -- so a
# hyphen-separated id could not be split unambiguously: a network id containing one
# would be cut short and the import would go looking for a network that never
# existed. Only the FIRST colon separates, so a region id containing one is still
# fine. Real ids to date are 10 alphanumeric characters, which contain neither.
#
# `region_id` IS THE REGION'S OWN ID, NOT the `harmony_sase_region_id` from the
# enhanced_regions catalogue that the region was created from. The two are
# different values. If you have the network in Terraform already, read it with
#
#     terraform show -json | jq -r '..|objects|select(.type=="checkpointsase_enhanced_network")|.values.region[].id'
#
# Passing the catalogue id instead gets a 404, and the provider says so.
#
# A malformed id -- no colon, or an empty half -- is refused with a usage string
# before any request is made, because an empty path segment is a different route
# rather than a 404 on this one.
#
# Import only reads. It records the region's CURRENT private DNS configuration in
# state and changes nothing. The first apply afterwards writes your configuration
# over it, and that write is a FULL REPLACEMENT: anything your HCL omits from
# `attributes` is cleared. Run `terraform plan` and read it before applying.
terraform import checkpointsase_enhanced_region_private_dns.example sG14j5VPLM:eKBn3Xxdxj
