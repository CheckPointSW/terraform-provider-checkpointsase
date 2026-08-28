# A membership has no ID of its own -- the API models it as a pairing, not an
# object -- so the import ID is the group ID and the user ID joined by a colon:
#
#     <group_id>:<user_id>
#
# A colon is unambiguous here: both halves are constrained to letters, digits,
# underscore and hyphen, so neither can contain one. A hyphen separator would
# have been ambiguous, since hyphens are legal inside each ID.
terraform import checkpointsase_group_membership.example MrawzXWSFg:ktewV1wJBI
