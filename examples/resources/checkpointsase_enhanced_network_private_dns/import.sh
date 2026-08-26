# The import id is the ENHANCED NETWORK ID and nothing else. Private DNS is
# addressed entirely by the network it belongs to -- there is no separate id to
# look up -- so the resource id and `network_id` are always the same value.
#
# Import only reads. It records the network's CURRENT private DNS configuration in
# state and changes nothing. The first apply afterwards writes your configuration
# over it, and that write is a FULL REPLACEMENT: anything your HCL omits from
# `attributes` is cleared. Run `terraform plan` and read it before applying.
#
# A network id the API does not know is refused with "no such enhanced network"
# rather than silently importing an empty resource.
terraform import checkpointsase_enhanced_network_private_dns.example net-01234567-89ab-cdef-0123-456789abcdef
