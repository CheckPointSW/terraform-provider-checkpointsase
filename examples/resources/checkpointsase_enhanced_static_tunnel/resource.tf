# A static IPsec tunnel attached to a region of an enhanced network.
# Timing fields use duration-string syntax ("30s", "60m", "8h"), not raw integers.
# Encryption values must match the public-api enum (PhaseEncryptionV2_1) — use
# "aes256", "aes128", etc. Passphrases must satisfy the IsPassphrase regex
# (letters/digits/`.`/`_`, 8-64 chars — no hyphens).
# `p81_gateway_subnets` must equal the parent enhanced network's own subnet
# (or `0.0.0.0/0` for a default route); arbitrary CIDRs are rejected.
#
# `remote_gateway_subnets` IS THE OPPOSITE CASE AND THE TWO ARE EASY TO CONFUSE.
# Never write `0.0.0.0/0` there. A static tunnel created with
# `remote_gateway_subnets = ["0.0.0.0/0"]` applies cleanly and can then NEVER be
# updated -- every later change comes back
#   404 {"message":"Remote gateway subnets not found"}
# even for a change that touches neither subnet list. Measured 2026-08-17
# (API-FINDINGS.md 1.2); the same tunnel with a real CIDR updates fine. The only
# way out is destroy and re-create.
resource "checkpointsase_enhanced_static_tunnel" "example" {
  network_id             = "ZwAeo5wqiF"
  region_id              = "K7tEfRm9vQ"
  tunnel_name            = "staticTunnel01"
  description            = "Static tunnel — managed by Terraform"
  remote_public_ip       = "203.0.113.40"
  p81_gateway_subnets    = ["10.99.0.0/24"]
  remote_gateway_subnets = ["192.168.40.0/24"]
  peak_bandwidth         = 1000
  auth_type              = "psk"
  passphrase             = "ChangeMeSharedSecret"

  key_exchange  = "ikev2"
  ike_life_time = "28800s"
  lifetime      = "3600s"
  dpd_delay     = "30s"
  dpd_timeout   = "60s"

  phase1 {
    auth                = ["sha256"]
    encryption          = ["aes256"]
    key_exchange_method = ["modp2048"]
  }

  phase2 {
    auth                = ["sha256"]
    encryption          = ["aes256"]
    key_exchange_method = ["modp2048"]
  }
}
