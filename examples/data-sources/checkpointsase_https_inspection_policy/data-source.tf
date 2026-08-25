# Reads the tenant's whole HTTPS-inspection policy without owning it.
#
# This is the READ-ONLY half of a name that is also a resource. Use it when the
# policy belongs to somebody else -- a tenant maintained in the Harmony SASE
# console, or another Terraform configuration -- because the resource of the same
# name deletes every rule its own configuration does not contain.
#
# It takes no arguments. There is one policy per tenant, addressed by path.

data "checkpointsase_https_inspection_policy" "current" {}

# Which traffic is currently skipping inspection, in the order the server stores
# the rules. `action` is always present: the API declares it optional with a
# default of `bypass`, and a rule stored without one reads back as `bypass`.
output "bypassed_rules" {
  value = [
    for rule in data.checkpointsase_https_inspection_policy.current.rule :
    rule.name if rule.action == "bypass" && rule.status == "active"
  ]
}

# This policy's source and destination vocabulary is NOT the web access policy's.
# `applications` is a source type here and nowhere in that one, `domains` is a
# destination type here only, and `addresses` is legal on BOTH sides of a rule
# here and on neither side there -- so an attribute name alone does not tell you
# which side it belongs to.
output "rules_restricted_by_address" {
  value = [
    for rule in data.checkpointsase_https_inspection_policy.current.rule : rule.name
    if length(rule.sources) > 0 && length(rule.sources[0].addresses) > 0
  ]
}

# See the checkpointsase_access_policy data-source example for what controlled_by
# is and why nothing acts on it.
output "https_inspection_controlled_by" {
  value = data.checkpointsase_https_inspection_policy.current.controlled_by
}
