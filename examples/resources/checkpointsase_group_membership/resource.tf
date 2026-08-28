# A join resource: the API models group membership as a pairing on
# /v3/groups/{groupId}/member/{userId} rather than as an object, so this resource
# has no attributes of its own beyond the two ids and no update path. Its
# Terraform id is "<group_id>:<user_id>".
#
# One resource per member. Destroying it removes ONLY the membership -- the user
# and the group both survive, which is what makes it safe to add and remove
# people without touching their accounts.
resource "checkpointsase_group_membership" "ada_in_engineering" {
  # REFERENCE THE PARENTS, DO NOT HARDCODE THEIR IDS. The references are what put
  # edges in Terraform's dependency graph, and the edges are what order the
  # membership's DELETE before either parent's on a destroy. With literal ids
  # Terraform sees three unrelated resources and may delete the group first,
  # leaving the membership's delete to 404 against a group that no longer exists.
  group_id = checkpointsase_group.engineering.id
  user_id  = checkpointsase_user.engineer.id
}

# Changing either id is a different membership, so both attributes force
# replacement: Terraform removes the old pairing and creates the new one.
resource "checkpointsase_group_membership" "ada_in_platform" {
  group_id = checkpointsase_group.platform.id
  user_id  = checkpointsase_user.engineer.id
}

# The group's own `users` attribute reads the resulting list back. It is a
# read-only projection -- membership is written here, never there.
output "engineering_members" {
  value = checkpointsase_group.engineering.users
}

# An existing membership is imported by its composite id, group first:
#
#   terraform import checkpointsase_group_membership.ada_in_engineering \
#     "5f8d0d55b54764421b7156c3:5f8d0d55b54764421b7156c9"
#
# The separator is a colon because both ids are restricted to
# [a-zA-Z0-9_-] by the API, so a colon cannot occur inside either half. A
# hyphen would have been ambiguous.
