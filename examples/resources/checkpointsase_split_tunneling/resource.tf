# checkpointsase_split_tunneling configures split tunnelling on ONE network:
# GET /v3/networks/{networkId}/split-tunneling and
# PUT /v3/networks/{networkId}/split-tunneling/async.
#
# `network_id` TAKES EITHER FAMILY. This path has no enhanced/standard segment,
# and both were verified returning identical bodies and accepting writes. The
# example below uses a standard network; an enhanced one works the same way.
#
# It is a SETTING on a network that already exists, not an object of its own. The
# API has no create and no delete for it -- every network has a tunnelling mode as
# soon as it exists -- so `terraform apply` adopts whatever the network currently
# holds and replaces it with yours. Only one Terraform resource in one
# configuration should own a given network's split tunnelling; a second would
# fight the first on every apply.
#
# THE THREE DESTINATION LISTS ARE A FULL REPLACEMENT. What you write is what the
# network gets: dropping an entry removes it, and writing the block empty
# (`except_data {}`) clears all three. All three arrays are sent on every write
# even when empty, because the API requires the keys.
#
# THE WRITE IS ASYNCHRONOUS. The API answers `202 Accepted` and the provider polls
# the operation to completion before reporting the apply as done. Raise the budget
# with a `timeouts { create = "1h" }` block if a tenant needs longer than the
# 30-minute default.

data "checkpointsase_regions" "all" {}

resource "checkpointsase_network" "example" {
  network {
    name = "tfExampleSplitTunnel"
    tags = ["terraform", "example"]
  }

  region {
    cpregion_id = data.checkpointsase_regions.all.regions[0].id
    idle        = true
  }
}

resource "checkpointsase_object_addresses" "datacentre" {
  name        = "exampleDatacentre"
  description = "Datacentre range reachable through the tunnel"
  value_type  = "cidr"
  value       = ["10.60.0.0/24"]
}

resource "checkpointsase_split_tunneling" "example" {
  network_id = checkpointsase_network.example.id

  # `out_of_tunnel`: internet traffic does NOT go through the cloud gateway,
  # EXCEPT the destinations named below -- only those are tunnelled.
  # `via_tunnel`:    everything goes through the gateway EXCEPT those
  # destinations. Flipping this value inverts what `except_data` means, so read
  # the plan carefully before changing it. Case-sensitive.
  default_tunneling_mode = "out_of_tunnel"

  except_data {
    # CIDR blocks. Checked for FORMAT at plan time; whether a given range is
    # acceptable to the network is the server's decision.
    cidr = ["10.50.0.0/16", "10.51.0.0/16"]

    # Shared address objects, by id.
    address_object_ids = [checkpointsase_object_addresses.datacentre.id]

    # Updatable objects, by UUID -- see the checkpointsase_updatable_objects data
    # source. A `409` on apply means the API could not reconcile these.
    updatable_object_ids = []

    # `exceptions` IS NOT WRITABLE, so it is not in this example. See the note at
    # the bottom of this file -- it is a limitation of the v3 API, not of the
    # provider, and it cuts both ways.
  }
}

# Turning split tunnelling "off" is not a thing: every network has a tunnelling
# mode. To send everything through the tunnel, set `via_tunnel` and empty the
# destinations:
#
#   resource "checkpointsase_split_tunneling" "example" {
#     network_id             = checkpointsase_network.example.id
#     default_tunneling_mode = "via_tunnel"
#
#     # Required, and the empty block is what CLEARS the three lists. It sends
#     # three empty arrays, which is what the API demands.
#     except_data {}
#   }
#
# `except_data.exceptions` IS READ-ONLY, AND THAT COSTS YOU BOTH DIRECTIONS. An
# exception is a destination INSIDE an excepted range that bypasses the tunnel
# anyway. The v3 endpoint MERGES this field rather than replacing it, so nothing
# the provider could send would ever remove a saved exception: an empty array, an
# omitted key and shrinking the covering `cidr` were all measured leaving the
# exception in place, and switching to `via_tunnel` only HIDES it -- exceptions
# are not supported in that mode, so the read stops returning them while the
# server keeps them. Switch back and the exception reappears. Rather than let a
# resource resurrect bypass rules its operator never wrote and Terraform never
# displayed, the provider surfaces exceptions for inspection and never sends them.
# So you can read them here:
#
#   output "split_tunneling_exceptions" {
#     value = checkpointsase_split_tunneling.example.except_data[0].exceptions
#   }
#
# -- and you must add or remove them in the console.
#
# `terraform destroy` on this resource makes NO API CALL. It releases Terraform's
# claim and leaves the network routing traffic exactly as the last apply
# configured it. Destroying deliberately does not write a different mode, because
# changing which of a live network's traffic bypasses the tunnel as a side effect
# of removing a Terraform resource is not something a destroy should do. If you
# want a different mode, apply it first, then destroy.
output "split_tunneling_mode" {
  value = checkpointsase_split_tunneling.example.default_tunneling_mode
}
