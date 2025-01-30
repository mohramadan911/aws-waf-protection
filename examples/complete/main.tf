provider "aws" {
  region = "us-east-1"
  alias  = "waf-provider"
}

# Optional: If you're testing with a specific AWS profile
# provider "aws" {
#   region  = "us-east-1"
#   profile = "your-profile-name"
#   alias   = "waf-provider"
# }

module "waf" {
  source = "../../"

  providers = {
    aws.waf-provider = aws.waf-provider
  }

  # Core Configuration
  enabled      = true
  name_prefix  = "my-app"
  environment  = "prod"
  name         = "my-waf-acl"
  description  = "WAF ACL for my application"
  
  # WAF Scope
  for_cloudfront = true
  
  # Rate Limiting Configuration
  rate_limit_enabled = true
  rate_limit_block   = true
  rate_limit_global  = 2000
  rate_limit_domestic = 5000
  
  # WordPress Protection
  wordpress_protection_enabled              = true
  wordpress_rules_override_action_to_count  = false
  wordpress_excluded_rules                  = []
  
  # PHP Protection
  php_protection_enabled              = true
  php_rules_override_action_to_count  = false
  php_excluded_rules                  = []
  
  # Bot Protection
  bot_protection_enabled              = true
  bot_rules_override_action_to_count  = false
  bot_excluded_rules                  = []

  # AWS Managed Rules
  aws_managed_waf_groups = [
    {
      name                     = "AWSManagedRulesCommonRuleSet"
      priority                 = 10
      override_action_to_count = false
      excluded_rules          = []
    },
    {
      name                     = "AWSManagedRulesKnownBadInputsRuleSet"
      priority                 = 20
      override_action_to_count = false
      excluded_rules          = []
    }
  ]

  # Rule Exceptions
  aws_managed_waf_groups_exceptions = [
    {
      name            = "CommonRuleSet"
      priority        = 1
      enabled         = true
      label           = "awswaf:managed:aws:core-rule-set"
      exception_paths = ["/api/health", "/api/status"]
    }
  ]

  # IP Sets (these ARNs need to be created first or imported)
  global_blacklist_ipv4_ip_set_arn = "arn:aws:wafv2:us-east-1:123456789012:global/ipset/example-ipv4/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
  global_blacklist_ipv6_ip_set_arn = "arn:aws:wafv2:us-east-1:123456789012:global/ipset/example-ipv6/a1b2c3d4-5678-90ab-cdef-EXAMPLE22222"
}

# Optional: Output the WAF ACL ID and ARN
output "waf_web_acl_id" {
  description = "The ID of the WAF web ACL"
  value       = module.waf.web_acl_id
}

output "waf_web_acl_arn" {
  description = "The ARN of the WAF web ACL"
  value       = module.waf.web_acl_arn
}