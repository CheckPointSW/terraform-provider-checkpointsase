# A route attached to one or more dynamic (BGP) tunnels.
# `propagated` is a computed attribute and must not be set in configuration.
resource "checkpointsase_enhanced_route_table" "example" {
  network_id = "ZwAeo5wqiF"
  type       = "dynamic"
  tunnel_ids = ["tun-abc12345"]
  subnets    = ["10.50.0.0/16"]
}

# Read every route on the network — including the ones the API creates by
# itself — through the data source of the same name.
data "checkpointsase_enhanced_route_table" "example" {
  network_id = "ZwAeo5wqiF"
}

# `type = "static"` is rejected during `terraform plan`. A static tunnel's route
# is created together with the tunnel and its subnets are the tunnel's own
# `remote_gateway_subnets` — one value, two views — so there is no separate
# object here for Terraform to manage. Set the subnets on the tunnel instead:
#
#   resource "checkpointsase_enhanced_static_tunnel" "example" {
#     # ... the rest of the tunnel's configuration ...
#     remote_gateway_subnets = ["10.60.0.0/16"]
#   }
#
# and read the route back with the data source above.
