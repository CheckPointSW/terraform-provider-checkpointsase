# checkpointsase_internet_access_status is the tenant-wide Internet Access
# security enforcement switch: GET and POST /v3/ia/status, one field.
#
# READ THIS BEFORE SETTING IT TO "inactive". The API describes the field as
# indicating "whether Internet Access, Threat Prevention, and DLP are enabled or
# disabled". One value, three features -- two of which are not in the name of
# either the resource or the attribute. Setting "inactive" does not just stop web
# filtering; it disables Threat Prevention and DLP for the whole tenant.
#
# It is a SETTING, not an object. It exists before Terraform manages it and
# cannot be deleted, so only one resource in one configuration should own it.

resource "checkpointsase_internet_access_status" "this" {
  ia_status = "active"
}

# Rules can be created and changed while this is "inactive" -- they are simply
# not enforced -- so neither policy resource needs to depend on this one. The
# dependency below is therefore deliberate ORDERING, not a requirement: it makes
# an apply that both writes rules and turns enforcement on put the rules in
# place first.
#
# WARNING, BECAUSE THIS BLOCK IS HERE ONLY TO DEMONSTRATE depends_on: a
# checkpointsase_access_policy resource owns the tenant's ENTIRE web access
# policy and REMOVES EVERY RULE NOT LISTED IN IT. Applied as written against a
# tenant that already has rules -- from the console or from another
# configuration -- it deletes all of them and leaves the single rule below. If
# you only want to order this example's apply, read the policy instead:
# `data "checkpointsase_access_policy" "existing" {}` takes no arguments and
# changes nothing.
resource "checkpointsase_access_policy" "example" {
  depends_on = [checkpointsase_internet_access_status.this]

  rule {
    name       = "allow-everything-by-default"
    applied_on = "both"
    action     = "allow"
    status     = "active"
  }
}

# `terraform destroy` on this resource makes NO API call. It releases Terraform's
# claim and leaves the tenant exactly as it is -- whatever value was last applied
# stays in force. Destroying does not set "inactive", because switching off three
# security features as a side effect of removing a Terraform resource is not
# something a destroy should do. If you want enforcement off, apply
# ia_status = "inactive" first, then destroy.
output "internet_access_enforcement" {
  value = checkpointsase_internet_access_status.this.ia_status
}
