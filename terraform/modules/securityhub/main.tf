# Findings-only Security Hub: the account was not subscribed, so this
# module owns enablement. No standards are subscribed, which keeps the
# cost at effectively zero; findings arrive via BatchImportFindings
# from the analyzer. Destroy disables the hub.

resource "aws_securityhub_account" "main" {
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = false
}
