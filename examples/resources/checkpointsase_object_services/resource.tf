resource "checkpointsase_object_services" "web_ports" {
  name        = "webPorts"
  description = "Common HTTP/HTTPS ports"

  protocols {
    protocol   = "tcp"
    value      = [80, 443]
    value_type = "list"
  }
}

# One object may mix port entries with ICMP entries. An icmp entry carries a
# protocol_options code and no ports; a tcp/udp entry carries value_type + value
# and no protocol_options. Use -1 for "any ICMP type" — there is no default,
# because the server would silently pick -1 for you.
resource "checkpointsase_object_services" "ping_and_ssh" {
  name        = "pingAndSsh"
  description = "ICMP echo plus SSH"

  protocols {
    protocol         = "icmp"
    protocol_options = 8 # Echo (ping request)
  }

  protocols {
    protocol   = "tcp"
    value      = [22]
    value_type = "single"
  }
}
