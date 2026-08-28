# A user is imported by its own ID, which you can list with the
# checkpointsase_users data source or GET /v3/users.
#
# Three attributes cannot be recovered by an import, because the API does not
# return them: invite_message, idp_type and email_verified. They stay empty in
# state until you supply them in configuration. The resource carries a
# DiffSuppressFunc for exactly this case, so the first plan after an import does
# NOT propose replacing the user -- without it, the empty-to-configured
# transition on a ForceNew attribute would delete the account and re-invite it.
terraform import checkpointsase_user.example ktewV1wJBI
