# checkpointsase_https_inspection_policy owns the tenant's ENTIRE HTTPS
# inspection policy -- the whole ordered bypassRules list.
#
# The API has no per-rule endpoint: GET, POST over the whole bypassRules array
# and DELETE are all it offers, and a rule's priority comes from its position in
# that array. So one resource owns the whole list, the order of the `rule`
# blocks below IS the order the policy is stored in, and every apply is a single
# POST that replaces the array.
#
# Two consequences worth reading before you apply this:
#
#   * Any rule that is NOT in this configuration is removed on the next apply,
#     including rules somebody added in the Harmony SASE console.
#   * `terraform destroy` removes every bypass rule in the tenant. Traffic those
#     rules were excluding from HTTPS inspection stops being excluded.
#
# The tenant-wide cleanup-rule default action is NOT managed here and is left
# untouched by every write.

data "checkpointsase_web_categories" "all" {}

resource "checkpointsase_group" "finance" {
  name = "tfExampleFinance"
}

resource "checkpointsase_https_inspection_policy" "example" {
  # A rule that restricts nothing matches all traffic from every source to
  # every destination. Omit `sources` and `destinations` rather than writing
  # empty blocks: an absent block is how the API spells "any", and `sources {}`
  # is refused at plan time because it could never converge -- the server
  # returns an unrestricted rule as empty buckets, which read back as no block
  # at all.
  rule {
    name       = "bypass-everything-by-default"
    applied_on = "both"
    action     = "bypass"
    status     = "active"
  }

  # sources and destinations take object IDs, never names or CIDRs. Every id
  # attribute is a SET: order is not significant and Terraform will not propose
  # a change just because the server returned them in another order.
  #
  # `applications` is a source type the web access policy does not have, and
  # `domains` is a destination type it does not have. `addresses` is legal on
  # BOTH sides here, which it is on neither there.
  rule {
    name       = "bypass-banking-for-finance"
    applied_on = "both"
    action     = "bypass"
    status     = "active"

    sources {
      groups = [checkpointsase_group.finance.id]
    }

    destinations {
      categories = [data.checkpointsase_web_categories.all.web_categories[0].id]
    }
  }

  # action and applied_on are validated TOGETHER by the server, and most of that
  # rule depends on whether your tenant has the Inspection Policy feature, which
  # the provider cannot see:
  #
  #   * `inspect` with `sites` is accepted by every tenant.
  #   * `inspect` with `agents` or `both` needs the feature. The provider does
  #     NOT refuse it at plan time -- refusing would make a feature-enabled
  #     tenant unable to write a configuration its own server accepts -- so on a
  #     tenant without the feature it fails on apply with
  #     422 VALIDATION_ACTION_INSPECT_NOT_ALLOWED.
  #   * `inspectNoDecrypt` is valid ONLY with `agents`. With `sites` or `both`
  #     no tenant accepts it, so that combination is refused at plan time.
  rule {
    name       = "inspect-site-traffic"
    applied_on = "sites"
    action     = "inspect"
    status     = "active"
  }
}

# `id` and `priority` are assigned by the server. Note that priority DESCENDS
# with position -- the first block above gets 2 and the last gets 0 -- and that
# which end of that range the policy engine consults first is not documented by
# the API and has not been measured. Do not rely on either reading.
#
# Keyed by index rather than by name: nothing in the API is documented to make
# rule names unique, and a duplicate would make a name-keyed map fail to build.
output "https_inspection_rule_priorities" {
  value = {
    for index, rule in checkpointsase_https_inspection_policy.example.rule :
    index => "${rule.name} = ${rule.priority}"
  }
}
