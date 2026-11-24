terraform {
  required_version = "= 1.16.2"
}

output "demonstration" {
  value = local.not_declared
}
