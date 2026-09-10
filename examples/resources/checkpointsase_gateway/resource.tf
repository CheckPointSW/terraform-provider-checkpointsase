# One resource per gateway. There is no `name`: the API neither accepts nor
# returns one, so the Terraform address is the identity.
#
# region_id is the network-region ID (checkpointsase_network.region.region_id),
# not the cloud region ID (cpregion_id).
resource "checkpointsase_gateway" "primary" {
  network_id = "ZwAeo5wqiF"
  region_id  = "K7tEfRm9vQ"
  idle       = false
}

# A second gateway in the same region is a second resource. Creates take about
# 14 minutes each and the backend builds them one at a time, so this apply is
# roughly 28 minutes.
resource "checkpointsase_gateway" "standby" {
  network_id = "ZwAeo5wqiF"
  region_id  = "K7tEfRm9vQ"
  idle       = true

  # The default is 2 hours; raise it if you declare many gateways at once.
  timeouts {
    create = "4h"
  }
}
