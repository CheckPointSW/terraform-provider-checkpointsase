# A group is imported by its own ID, which you can list with the
# checkpointsase_groups data source or GET /v3/groups.
#
# `description` cannot be recovered by an import: the Group object the API
# returns carries no description field at all, so the value is write-only. It
# stays empty in state until you supply it in configuration, and the resource's
# DiffSuppressFunc stops that transition from replacing the group -- which would
# otherwise drop every membership in it.
terraform import checkpointsase_group.example MrawzXWSFg
