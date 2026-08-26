# checkpointsase_enhanced_network_private_dns configures private DNS on ONE
# enhanced network: GET and PUT /v3/networks/enhanced/{networkId}/privateDNS.
#
# It is a SETTING on a network that already exists, not an object of its own. The
# API has no create and no delete for it -- the configuration is there as soon as
# the network is, with `enabled = false` and nothing else -- so `terraform apply`
# adopts whatever the network currently holds and replaces it with yours. Only one
# Terraform resource in one configuration should own a given network's private
# DNS; a second would fight the first on every apply.
#
# EVERY WRITE IS A FULL REPLACEMENT. Anything you leave out of `attributes` is
# CLEARED, not preserved -- including `search_domains` and the whole `dns_policy`
# block. To keep a value, write it. This is the API's own behaviour, not a
# provider choice.
#
# ONE EXCEPTION, AND IT IS THE `attributes` BLOCK ITSELF. The API returns the
# object on every read once anything has been written, so `attributes` is computed
# as well as optional and REMOVING THE WHOLE BLOCK leaves the network holding
# whatever it already has. There is nothing it could clear to -- a write with no
# `attributes` object is rejected outright. The blocks nested INSIDE it are
# ordinary optional blocks, so dropping `dns_policy` or `search_domains` does clear
# those. To turn private DNS off, set `enabled = false`.

data "checkpointsase_enhanced_regions" "catalog" {}

resource "checkpointsase_enhanced_network" "example" {
  name   = "example-enhanced-network"
  subnet = "10.120.0.0/22"

  region {
    harmony_sase_region_id = data.checkpointsase_enhanced_regions.catalog.regions[0].id
    scale_units            = 1
    idle                   = true
  }
}

resource "checkpointsase_enhanced_network_private_dns" "example" {
  network_id = checkpointsase_enhanced_network.example.id
  enabled    = true

  attributes {
    # ORDER MATTERS AND IS PRESERVED. `servers` is a priority-ordered list, and
    # the API returns both lists in exactly the order you send them -- it does not
    # sort, deduplicate or normalise. Reordering these blocks is a real change.
    #
    # At most four servers, and at least one whenever `enabled = true`. Addresses
    # must be unique; the provider refuses a duplicate during `plan` rather than
    # letting the apply fail.
    servers {
      address = "10.120.0.53"
      is_tls  = false
    }
    servers {
      address = "10.120.1.53"
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
#   resource "checkpointsase_enhanced_network_private_dns" "example" {
#     network_id = checkpointsase_enhanced_network.example.id
#     enabled    = false
#   }
#
# `terraform destroy` on this resource makes NO API CALL. It releases Terraform's
# claim and leaves the network resolving names exactly as the last apply
# configured it. Destroying deliberately does not write `enabled = false`,
# because changing how a live network resolves names as a side effect of removing
# a Terraform resource is not something a destroy should do. If you want private
# DNS off, apply `enabled = false` first, then destroy.
output "enhanced_network_private_dns_enabled" {
  value = checkpointsase_enhanced_network_private_dns.example.enabled
}
