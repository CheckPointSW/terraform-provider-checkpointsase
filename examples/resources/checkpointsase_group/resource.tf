# Every attribute of checkpointsase_group forces replacement: /v3/groups has no
# update endpoint. A replacement is NOT a rename -- the old group is deleted, and
# deleting a group drops every membership in it. Use one
# checkpointsase_group_membership resource per member so that Terraform recreates
# the memberships after a replacement.
resource "checkpointsase_group" "engineering" {
  # 1-64 characters. Letters in ANY script are accepted, because the server's own
  # pattern is Unicode-aware: "Engineering", "Ingénierie" and "研究開発" are all
  # valid names.
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
