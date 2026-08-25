# checkpointsase_access_policy owns the tenant's ENTIRE web access policy.
#
# The API has no per-rule endpoint: GET, POST over the whole webRules array and
# DELETE are all it offers, and a rule's priority comes from its position in
# that array. So one resource owns the whole list, the order of the `rule`
# blocks below IS the order the policy is stored in, and every apply is a single
# POST that replaces the array.
#
# Two consequences worth reading before you apply this:
#
#   * Any rule that is NOT in this configuration is removed on the next apply,
#     including rules somebody added in the Harmony SASE console.
#   * `terraform destroy` deletes every web access rule in the tenant. The API
#     documents the result as "all internet traffic will be allowed after
#     deletion".

data "checkpointsase_web_categories" "all" {}

resource "checkpointsase_group" "contractors" {
  name = "tfExampleContractors"
}

resource "checkpointsase_access_policy" "example" {
  # A rule that restricts nothing matches all traffic from every source to
  # every destination. Omit `sources`, `destinations` and `conditions` rather
  # than writing empty blocks: an absent block is how the API spells "any", and
  # `sources {}` is refused at plan time because it could never converge -- the
  # server returns an unrestricted rule as empty buckets, which read back as no
  # block at all.
  rule {
    name       = "allow-everything-by-default"
    applied_on = "both"
    action     = "allow"
    status     = "active"
  }

  # sources and destinations take object IDs, never names, URLs or CIDRs. Every
  # id attribute is a SET: order is not significant and Terraform will not
  # propose a change just because the server returned them in another order.
  rule {
    name       = "block-gambling-for-contractors"
    applied_on = "both"
    action     = "block"
    status     = "active"

    sources {
      groups = [checkpointsase_group.contractors.id]
    }

    destinations {
      categories = [data.checkpointsase_web_categories.all.web_categories[0].id]
    }
  }

  # `conditions` is one or more time windows. The rule is in force only inside
  # them; a rule with no conditions block has no time constraint.
  rule {
    name       = "warn-outside-office-hours"
    applied_on = "agents"
    action     = "warning"
    status     = "active"

    conditions {
      weekdays     = ["Mon", "Tue", "Wed", "Thu", "Fri"]
      start_hour   = 18
      start_minute = 0
      end_hour     = 23
      end_minute   = 59
    }
  }
}

# `id` and `priority` are assigned by the server. Note that priority DESCENDS
# with position -- the first block above gets 2 and the last gets 0 -- and that
# which end of that range the policy engine consults first is not documented by
# the API and has not been measured. Do not rely on either reading.
output "access_policy_rule_priorities" {
  value = {
    for rule in checkpointsase_access_policy.example.rule : rule.name => rule.priority
  }
}
