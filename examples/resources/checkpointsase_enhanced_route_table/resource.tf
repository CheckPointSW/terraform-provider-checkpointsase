# There is no working example of this resource, because there is no working
# configuration of it. Every use is rejected during `terraform plan`, for
# `type = "static"` and `type = "dynamic"` alike.
#
# A route is not a separate object — it belongs to its tunnel. Harmony SASE
# creates the route when the tunnel is created, and the route's subnets are the
# tunnel's own `remote_gateway_subnets`: one value, two views. So there is
# never a tunnel without a route, and nothing here for Terraform to create.
#
# Set the routed subnets on the tunnel, whichever kind you have.

resource "checkpointsase_enhanced_static_tunnel" "example" {
  # ... the rest of the tunnel's configuration ...
  remote_gateway_subnets = ["10.50.0.0/16"]
}

resource "checkpointsase_enhanced_dynamic_tunnel" "example" {
  # ... the rest of the tunnel's configuration ...
  remote_gateway_subnets = ["10.60.0.0/16"]
}

# Read every route on the network — all of them are created by the API itself —
# through the data source of the same name.
data "checkpointsase_enhanced_route_table" "example" {
  network_id = "ZwAeo5wqiF"
}
