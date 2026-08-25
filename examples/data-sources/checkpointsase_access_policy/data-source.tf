# Reads the tenant's whole web access policy without owning it.
#
# This is the READ-ONLY half of a name that is also a resource. Terraform allows
# a data source and a resource to share a name, and the convention is exactly
# this: `data` reads what is there, `resource` owns it. Use the data source when
# the policy belongs to somebody else -- a tenant maintained in the Harmony SASE
# console, or another Terraform configuration -- because the resource deletes
# every rule its own configuration does not contain.
#
# It takes no arguments. There is one policy per tenant and the API addresses it
# by path, so there is nothing to filter or paginate.

data "checkpointsase_access_policy" "current" {}

# The rules come back in the order the server stores them, which is the order
# that determines precedence. Note that `priority` DESCENDS with position -- the
# first rule has the highest number and the last has 0 -- and that which end the
# policy engine consults first is not documented by the API and has not been
# measured. Do not build on either reading.
output "access_policy_rule_names" {
  value = [for rule in data.checkpointsase_access_policy.current.rule : rule.name]
}

# `sources` and `destinations` are ABSENT on a rule that restricts nothing. The
# server returns an unrestricted rule as one empty bucket per legal type; those
# carry no information and are dropped, so "any source" reads as no block rather
# than as a block of empty lists.
output "unrestricted_rules" {
  value = [
    for rule in data.checkpointsase_access_policy.current.rule :
    rule.name if length(rule.sources) == 0 && length(rule.destinations) == 0
  ]
}

# controlled_by is `quantum` or `hsase` and says which product owns the policy.
# It is surfaced WITHOUT being interpreted: the API documents nothing beyond the
# two values and what they imply for a client has not been investigated, so
# nothing in this provider branches on it and neither should you until you have
# confirmed what it means for your tenant.
output "access_policy_controlled_by" {
  value = data.checkpointsase_access_policy.current.controlled_by
}
