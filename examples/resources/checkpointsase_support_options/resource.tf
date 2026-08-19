# checkpointsase_support_options is an ACCOUNT-WIDE singleton: there is one
# support-options object per tenant, so declare this resource ONCE per
# configuration. There is no network_id, and applying it overwrites the support
# options every end user of the account sees in the Harmony SASE agent.
#
# The API has only GET and PUT on this object, so Terraform adopts whatever the
# account already has. The PUT is a whole-object replace: every field below is set
# on every apply, including the ones you leave out. And `terraform destroy` only
# releases the resource from state — it does NOT put the account's previous
# support options back, because the API never reported what they were.
resource "checkpointsase_support_options" "support" {
  # Each type is one of "harmonySaseDefault" (Check Point's own support details),
  # "custom", or "hidden" (offer nothing). "custom" is the only one that takes a
  # companion field.
  phone_support_type = "custom"
  live_chat_type     = "custom"

  user_guides_enabled = true

  # Required by phone_support_type = "custom", and rejected for the other two
  # types. One to three entries, shown in the order written.
  support_phone_numbers {
    description  = "US Support"
    phone_number = "+1 555 0100"
  }

  support_phone_numbers {
    description  = "EU Support"
    phone_number = "+44 20 7000 0000"
  }

  # Required by live_chat_type = "custom", and rejected for the other two types.
  live_chat_custom_url = "https://support.example.com/chat"
}

# To offer nothing but the user guides, drop both companion fields:
#
#   resource "checkpointsase_support_options" "support" {
#     phone_support_type  = "hidden"
#     live_chat_type      = "hidden"
#     user_guides_enabled = true
#   }
