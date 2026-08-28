# The first page of the tenant's access groups.
data "checkpointsase_groups" "first_page" {}

# Paginated and sorted. `sort` is a PLAIN STRING here, not a map: GET /v3/groups
# documents the parameter as a bare "Sort order" with no grammar, so the value is
# passed through verbatim and is not validated locally -- guessing at a syntax
# would refuse spellings the server accepts.
data "checkpointsase_groups" "sorted" {
  page  = 1
  limit = 10
  sort  = "name"
}

output "group_count_on_this_page" {
  value = length(data.checkpointsase_groups.first_page.data)
}

output "groups_in_tenant" {
  value = data.checkpointsase_groups.first_page.items_total
}

# Every group exposes its four projections as lists, empty rather than null when
# the group has none of that kind.
output "first_group" {
  value = try({
    id            = data.checkpointsase_groups.sorted.data[0].id
    name          = data.checkpointsase_groups.sorted.data[0].name
    is_default    = data.checkpointsase_groups.sorted.data[0].is_default
    member_count  = length(data.checkpointsase_groups.sorted.data[0].users)
    network_count = length(data.checkpointsase_groups.sorted.data[0].networks)
  }, null)
}

# There is no `description` attribute, and that is not an omission: the API's
# group read model carries no such field. checkpointsase_group accepts one on
# create and the server never reports it back.
