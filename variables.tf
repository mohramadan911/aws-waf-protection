# Core Variables
variable "enabled" {
  description = "Enable or disable WAF protection"
  type        = bool
  default     = true
}

variable "name_prefix" {
  description = "Name prefix for all resources"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "name" {
  description = "Name for the WAF ACL"
  type        = string
}

variable "description" {
  description = "Description for the WAF ACL"
  type        = string
  default     = "WAF ACL with managed rules and IP rate limiting"
}

variable "for_cloudfront" {
  description = "If true, WAF will be created for CloudFront (global), if false for regional"
  type        = bool
  default     = true
}

# WordPress Protection Variables
variable "wordpress_protection_enabled" {
  description = "Enable WordPress protection rules"
  type        = bool
  default     = false
}

variable "wordpress_rules_override_action_to_count" {
  description = "Override WordPress rules to count instead of block"
  type        = bool
  default     = false
}

variable "wordpress_excluded_rules" {
  description = "List of WordPress rules to exclude"
  type        = list(string)
  default     = []
}

# PHP Protection Variables
variable "php_protection_enabled" {
  description = "Enable PHP protection rules"
  type        = bool
  default     = false
}

variable "php_rules_override_action_to_count" {
  description = "Override PHP rules to count instead of block"
  type        = bool
  default     = false
}

variable "php_excluded_rules" {
  description = "List of PHP rules to exclude"
  type        = list(string)
  default     = []
}

# Rate Limiting Variables
variable "rate_limit_enabled" {
  description = "Enable rate limiting"
  type        = bool
  default     = false
}

variable "rate_limit_block" {
  description = "Block requests that exceed rate limit (if false, only count)"
  type        = bool
  default     = true
}

variable "rate_limit_global" {
  description = "Number of requests allowed per IP for global rate limit"
  type        = number
  default     = 2000
}

variable "rate_limit_domestic" {
  description = "Number of requests allowed per IP for domestic rate limit"
  type        = number
  default     = 5000
}

# AWS Managed Rules Variables
variable "aws_managed_waf_groups" {
  description = "List of AWS managed WAF rule groups to enable"
  type = list(object({
    name                     = string
    priority                 = number
    override_action_to_count = bool
    excluded_rules          = list(string)
  }))
  default = []
}

variable "aws_managed_waf_groups_exceptions" {
  description = "List of exceptions for AWS managed WAF rule groups"
  type = list(object({
    name            = string
    priority        = number
    enabled         = bool
    label           = string
    exception_paths = list(string)
  }))
  default = []
}

# Bot Control Variables
variable "enabled_bot_control_rules" {
  description = "List of bot control rules to enable"
  type = list(object({
    name                     = string
    priority                 = number
    override_action_to_count = bool
    excluded_rules          = list(string)
  }))
  default = []
}

# Blacklist Variables
variable "global_blacklist_ipv4_ip_set_arn" {
  description = "ARN of the IPv4 IP set used for global blacklisting"
  type        = string
}

variable "global_blacklist_ipv6_ip_set_arn" {
  description = "ARN of the IPv6 IP set used for global blacklisting"
  type        = string
}

# Provider Variable
variable "waf_provider_region" {
  description = "Region for the WAF provider"
  type        = string
  default     = "us-east-1"  # Default region for CloudFront WAF
}

# Bot Protection Variables
variable "bot_protection_enabled" {
  description = "Enable AWS Bot Control protection rules"
  type        = bool
  default     = false
}

variable "bot_rules_override_action_to_count" {
  description = "Override Bot Control rules to count instead of block"
  type        = bool
  default     = false
}

variable "bot_excluded_rules" {
  description = "List of Bot Control rules to exclude"
  type        = list(string)
  default     = []
}