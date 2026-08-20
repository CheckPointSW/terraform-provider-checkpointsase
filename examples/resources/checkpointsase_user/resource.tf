# Every attribute of checkpointsase_user forces replacement: /v3/users has no
# update endpoint, so changing any value here deletes the account and invites
# the new one. Editing `email` in particular is a destroy-and-invite, not a
# rename.
resource "checkpointsase_user" "engineer" {
  # example.com, and NOT the RFC 2606 .invalid you might expect in an example:
  # the server validates the TLD against the IANA registry, and .invalid is a
  # reserved special-use TLD rather than a delegated one, so an @example.invalid
  # address is refused at apply with `"data.email" must be a valid email`.
  # Measured against a live tenant; see testAccUserEmailDomain in
  # checkpointsase/resource_user_test.go.
  email          = "ada.lovelace@example.com"
  invite_message = "Welcome aboard — this invitation enrols you in the corporate VPN."
  idp_type       = "database"

  # A create-time instruction, not a fact about the account: false means "send
  # the invitation and let her verify her own address". It is never read back
  # from the server, so her verifying that address does NOT show up here as
  # drift — which is what stops a later apply from deleting and re-inviting
  # her. Read the account's real verification state from the
  # checkpointsase_users data source instead.
  email_verified = false

  profile_data {
    first_name = "Ada"
    last_name  = "Lovelace"
    phone      = "+15550100200"
  }
}
