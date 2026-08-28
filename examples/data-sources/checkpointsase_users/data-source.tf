# The first page of the tenant's users. limit defaults to 500, the API's own
# default, and page defaults to 1 -- both are sent explicitly, so state always
# records which page was read.
data "checkpointsase_users" "first_page" {}

# Paginated and sorted. `sort` is a field-to-direction map here, because
# GET /v3/users declares the parameter as an object and it reaches the wire as
# sort[email]=asc. checkpointsase_groups takes a plain string for the same
# argument; the two endpoints are genuinely different and the provider does not
# pretend otherwise.
data "checkpointsase_users" "by_email" {
  page  = 1
  limit = 50

  sort = {
    email = "asc"
  }
}

# `where` is passed through to the API verbatim. The API documents no grammar
# for it, so the provider does not validate it: an unrecognised expression is
# rejected by the server on the read.
data "checkpointsase_users" "filtered" {
  where = "terminated=false"
}

# Compare items_total with the number of rows returned to see whether the read
# was complete. This is the metadata the three data sources in LEFTOVERS.md L15
# do not expose, which is why a truncated read there is invisible.
output "user_count_on_this_page" {
  value = length(data.checkpointsase_users.first_page.data)
}

output "users_in_tenant" {
  value = data.checkpointsase_users.first_page.items_total
}

output "user_pages" {
  value = data.checkpointsase_users.first_page.total_page
}

# There is deliberately no invitation_token in `data`. A read over every user in
# the tenant would write one pending user's enrolment token per row into state
# in plaintext. Read it from the checkpointsase_user resource instead, where the
# scope is a single account you are managing on purpose.
output "first_user_email" {
  value = try(data.checkpointsase_users.by_email.data[0].email, null)
}
