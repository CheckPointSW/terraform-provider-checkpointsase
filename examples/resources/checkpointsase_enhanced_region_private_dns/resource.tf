# checkpointsase_enhanced_region_private_dns configures private DNS on ONE REGION
# of an enhanced network: GET and PUT
# /v3/networks/enhanced/{networkId}/regions/{regionId}/privateDNS.
#
# It is a SETTING on a region that already exists, not an object of its own. The
# API has no create and no delete for it -- the configuration is there as soon as
# the region is, with `enabled = false` and nothing else -- so `terraform apply`
# adopts whatever the region currently holds and replaces it with yours. Only one
# Terraform resource in one configuration should own a given region's private DNS;
# a second would fight the first on every apply.
#
# `region_id` IS THE REGION'S OWN ID, NOT THE CATALOGUE ID IT WAS CREATED FROM.
# You pick a `harmony_sase_region_id` out of the enhanced_regions catalogue when
# you create the network; the server then assigns that region its own id, and that
# is what this endpoint's path wants. `one(...region[*].id)` below is how to read
# it. Passing the catalogue id gets a 404.
#
# EVERY WRITE IS A FULL REPLACEMENT. Anything you leave out of `attributes` is
# CLEARED, not preserved -- including `search_domains` and the whole `dns_policy`
# block. To keep a value, write it. This is the API's own behaviour, not a
# provider choice.
#
# ONE EXCEPTION, AND IT IS THE `attributes` BLOCK ITSELF. The API returns the
# object on every read once anything has been written, so `attributes` is computed
# as well as optional and REMOVING THE WHOLE BLOCK leaves the region holding
# whatever it already has. There is nothing it could clear to -- a write with no
# `attributes` object is rejected outright. The blocks nested INSIDE it are
# ordinary optional blocks, so dropping `dns_policy` or `search_domains` does clear
# those. To turn private DNS off, set `enabled = false`.
#
# HOW A REGION'S PRIVATE DNS COMBINES WITH ITS NETWORK'S IS NOT DOCUMENTED, and
# this provider does not model any relationship between the two. Using this
# alongside checkpointsase_enhanced_network_private_dns on the same network is
# supported; what the API does with both is the API's business.

data "checkpointsase_enhanced_regions" "catalog" {}

resource "checkpointsase_enhanced_network" "example" {
  name   = "example-enhanced-network"
  subnet = "10.121.0.0/22"

  region {
    harmony_sase_region_id = data.checkpointsase_enhanced_regions.catalog.regions[0].id
    scale_units            = 1
    idle                   = true
  }
}

resource "checkpointsase_enhanced_region_private_dns" "example" {
  network_id = checkpointsase_enhanced_network.example.id

  # `one(...)` rather than `[0]`: it fails loudly if the network ever carries more
  # than one region, where an index would silently pick whichever came back first.
  region_id = one(checkpointsase_enhanced_network.example.region[*].id)

  enabled = true

  attributes {
    # ORDER MATTERS AND IS PRESERVED on the enhanced-network endpoint, which takes
    # the identical body: `servers` is a priority-ordered list, and the API returns
    # both lists in exactly the order you send them -- it does not sort, deduplicate
    # or normalise. Reordering these blocks is a real change.
    #
    # At most four servers, and at least one whenever `enabled = true`. Addresses
    # must be unique; the provider refuses a duplicate during `plan` rather than
    # letting the apply fail.
    servers {
      address = "10.121.0.53"
      is_tls  = false
    }
    servers {
      address = "10.121.1.53"
      is_tls  = true # DNS over TLS for this server only
    }

    # At most four, unique, order preserved. Write `search_domains = []` or omit
    # the argument to have none -- both send an empty array, which is what the API
    # requires.
    search_domains = ["corp.example.com", "internal.example.com"]

    # Optional. DELETING THIS BLOCK CLEARS THE POLICY, because the write replaces
    # the whole object. Both `domains` lists take up to 100 entries -- not 4 like
    # the two lists above.
    dns_policy {
      public {
        domains = ["www.example.com"]
      }
      private {
        # `matchPattern` or `resolveAllViaPrivate`, CASE-SENSITIVE: the API does
        # not fold case on this enum, so "matchpattern" is refused.
        mode            = "matchPattern"
        public_fallback = true
        domains         = ["db.corp.example.com", "*.svc.corp.example.com"]
      }
    }
  }
}

# Turning private DNS off is a configuration change, not a destroy. Setting
# `enabled = false` is the supported way to do it, and the provider still sends
# the empty `servers` and `search_domains` arrays the API demands on every write
# -- so you can omit the `attributes` block entirely:
#
#   resource "checkpointsase_enhanced_region_private_dns" "example" {
#     network_id = checkpointsase_enhanced_network.example.id
#     region_id  = one(checkpointsase_enhanced_network.example.region[*].id)
#     enabled    = false
#   }
#
# `terraform destroy` on this resource makes NO API CALL. It releases Terraform's
# claim and leaves the region resolving names exactly as the last apply
# configured it. Destroying deliberately does not write `enabled = false`,
# because changing how a live region resolves names as a side effect of removing
# a Terraform resource is not something a destroy should do. If you want private
# DNS off, apply `enabled = false` first, then destroy.
output "enhanced_region_private_dns_enabled" {
  value = checkpointsase_enhanced_region_private_dns.example.enabled
}
