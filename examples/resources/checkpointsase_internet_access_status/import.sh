# There is one Internet Access status per tenant, addressed by path rather than
# by id, so the import id is always the constant below -- and any other value
# behaves identically.
#
# Import only reads. It records the tenant's CURRENT value in state and changes
# nothing; the first apply after that writes your configuration's value, which
# may switch Internet Access, Threat Prevention and DLP on or off for the whole
# tenant. Run `terraform plan` and read it before applying.
terraform import checkpointsase_internet_access_status.this internet-access-status
