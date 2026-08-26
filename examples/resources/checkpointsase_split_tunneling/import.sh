# The import id is the NETWORK ID and nothing else. Split tunnelling is addressed
# entirely by the network it belongs to -- there is no separate id to look up and
# no separator to get right -- so the resource id and `network_id` are always the
# same value. Either family: a standard or an enhanced network id both work.
#
# Import only reads. It records the network's CURRENT split tunnelling in state and
# changes nothing. The first apply afterwards writes your configuration over it,
# and the mode plus the three destination lists are a FULL REPLACEMENT: anything
# your HCL omits is cleared. Run `terraform plan` and read it before applying.
#
# TWO THINGS THE IMPORTED STATE WILL NOT TELL YOU, both about
# `except_data.exceptions`. It is read-only, so it never appears in your HCL and
# never plans a change. And if the network is in `via_tunnel` mode it imports as
# EMPTY even when the network still holds exceptions -- exceptions are not
# supported in that mode, so the API does not return them. Switching such a network
# to `out_of_tunnel` brings them back. Check the console before assuming a network
# has none.
#
# A network id the API does not know is refused with "no such network" rather than
# silently importing an empty resource.
terraform import checkpointsase_split_tunneling.example net-01234567-89ab-cdef-0123-456789abcdef
