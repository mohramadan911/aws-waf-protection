output "web_acl_id" {
  description = "The ID of the WAF web ACL"
  value       = try(aws_wafv2_web_acl.main[0].id, "")
}

output "web_acl_arn" {
  description = "The ARN of the WAF web ACL"
  value       = try(aws_wafv2_web_acl.main[0].arn, "")
}

output "whitelist_ipv4_id" {
  description = "The ID of the IPv4 whitelist IP set"
  value       = try(aws_wafv2_ip_set.whitelist_ipv4[0].id, "")
}

output "whitelist_ipv6_id" {
  description = "The ID of the IPv6 whitelist IP set"
  value       = try(aws_wafv2_ip_set.whitelist_ipv6[0].id, "")
}