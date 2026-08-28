# Every attribute of checkpointsase_group forces replacement: /v3/groups has no
# update endpoint. A replacement is NOT a rename -- the old group is deleted, and
# deleting a group drops every membership in it. Use one
# checkpointsase_group_membership resource per member so that Terraform recreates
# the memberships after a replacement.
resource "checkpointsase_group" "engineering" {
  # 1-64 CHARACTERS, not bytes: the server counts characters, so a 64-character
  # name in any script fits. Letters in any script are accepted, because the
  # server's own pattern is Unicode-aware -- "Engineering", "Ingénierie" and
  # "研究開発" are all valid -- and so is Unicode whitespace, including the
  # ideographic space U+3000 and a non-breaking space.
  #
  # The provider's plan-time check is a faithful port of the server's rule with
  # one deliberate difference: its whitespace class is the wider one, so nothing
  # the server accepts is refused at plan time. What the server rejects it still
  # rejects -- notably ; " < > ` = + and ?.
  name = "Engineering"

  # Optional, and write-only: the Group read model carries no description field,
  # so the server never reports this back and an imported group has no value for
  # it in state. Omit the argument entirely rather than setting it to "" -- the
  # API validates description as optional AND non-empty, so an explicit empty
  # string is rejected with a 400.
  description = "Owns the platform services. Managed by Terraform."
}

# applications, networks, vpn_locations and users are projections of other
# objects' grants, not settings on the group, so they are read-only here.
output "engineering_members" {
  value = checkpointsase_group.engineering.users
}
