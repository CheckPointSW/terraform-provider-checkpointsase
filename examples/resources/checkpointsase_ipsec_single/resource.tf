# A single-tunnel IPsec attachment to one gateway of a standard network.
# Timing fields use duration-string syntax ("30s", "60m", "8h"). `dh` values
# are integer Diffie-Hellman group numbers (e.g. 14 = MODP2048).
resource "checkpointsase_ipsec_single" "example" {
  network_id             = "ZwAeo5wqiF"
  region_id              = "K7tEfRm9vQ"
  gateway_id             = "abc12345DE"
  tunnel_name            = "ipsecSingle01"
  remote_public_ip       = "203.0.113.20"
  p81_gateway_subnets    = ["10.99.0.0/24"]
  remote_gateway_subnets = ["192.168.20.0/24"]
  # No hyphens: the server's passphrase regex allows letters, digits, "." and
  # "_" only, 8-64 characters. The provider enforces it at plan time, so the
  # previous value here would have failed `terraform plan` for anyone who
  # copied this example.
  passphrase = "ChangeMe.shared.secret"

  key_exchange  = "ikev2"
  ike_life_time = "28800s"
  lifetime      = "3600s"
  dpd_delay     = "30s"
  dpd_timeout   = "60s"

  phase1 {
    auth       = ["sha256"]
    encryption = ["aes-cbc-256"]
    dh         = [14]
  }

  phase2 {
    auth       = ["sha256"]
    encryption = ["aes-cbc-256"]
    dh         = [14]
  }
}
