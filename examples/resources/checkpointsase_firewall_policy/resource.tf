data "checkpointsase_regions" "all" {}

resource "checkpointsase_network" "example" {
  network {
    name   = "tfExampleNet"
    subnet = "10.0.0.0/16"
  }
  region {
    cpregion_id = data.checkpointsase_regions.all.regions[0].id
  }
}

# sources.addresses, destinations.addresses and services all take the IDs of
# shared objects — never CIDRs, IPs or port numbers.
resource "checkpointsase_object_addresses" "branch" {
  name       = "tfExampleBranchLan"
  value_type = "cidr"
  value      = ["192.0.2.0/24"]
}

resource "checkpointsase_object_addresses" "database" {
  name       = "tfExampleDatabase"
  value_type = "ip"
  value      = ["10.0.5.10"]
}

resource "checkpointsase_object_services" "postgres" {
  name = "tfExamplePostgres"

  protocols {
    protocol   = "tcp"
    value_type = "single"
    value      = [5432]
  }
}

# Adopt-style: a firewall policy is auto-created with the network, so this
# resource applies your configuration to the policy that already exists.
resource "checkpointsase_firewall_policy" "example" {
  network_id = checkpointsase_network.example.id
  enabled    = true
  # The default action, applied to traffic no rule below matches.
  allowed = false
  trace   = true

  # Rule order is evaluation order: the first matching rule wins.
  policy_rules {
    name        = "branch-to-database"
    enabled     = true
    allowed     = true
    log_enabled = true

    sources {
      addresses = [checkpointsase_object_addresses.branch.id]
    }
    destinations {
      addresses = [checkpointsase_object_addresses.database.id]
    }
    services = [checkpointsase_object_services.postgres.id]
  }

  # users and groups may be combined with each other, but never with
  # addresses in the same block. Omitting `destinations` entirely means
  # "any destination".
  policy_rules {
    name        = "contractors-blocked"
    enabled     = true
    allowed     = false
    log_enabled = true

    sources {
      groups = ["gRoUpId1234"]
    }
  }
}
