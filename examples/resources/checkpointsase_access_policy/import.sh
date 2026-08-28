# The web access policy is a tenant-wide singleton addressed by path, so there
# is no id to look up and the id you type is ignored -- the resource always
# stores "access-policy".
#
# Importing does NOT merge with what is already there. It records the tenant's
# current policy in state; the first apply after that REPLACES it with your
# configuration, deleting any rule your configuration does not contain. Run
# `terraform plan` and read it before applying.
terraform import checkpointsase_access_policy.example access-policy
