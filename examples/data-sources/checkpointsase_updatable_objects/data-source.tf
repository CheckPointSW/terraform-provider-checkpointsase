# The whole catalog. This data source pages through to exhaustion, so there is
# no page or limit argument: updatable_objects always holds the complete set.
data "checkpointsase_updatable_objects" "all" {}

# Filtered. Every argument is optional and is passed straight to the API.
data "checkpointsase_updatable_objects" "aws" {
  name = "AWS"
  sort = "name"
}

# items_total is the server's own count. After an exhaustive read it must equal
# the number of rows returned, which is what makes a truncated read visible.
output "updatable_object_count" {
  value = length(data.checkpointsase_updatable_objects.all.updatable_objects)
}

output "updatable_object_total_reported_by_server" {
  value = data.checkpointsase_updatable_objects.all.items_total
}
