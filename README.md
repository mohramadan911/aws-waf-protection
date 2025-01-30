# AWS WAF Protection Terraform Module

This module provides a comprehensive WAF (Web Application Firewall) setup for AWS applications, supporting both CloudFront distributions and regional resources.

## Features

- AWS Managed Rule Groups integration
- IP-based rate limiting (global and domestic)
- IP whitelist and blacklist management
- Support for both IPv4 and IPv6
- WordPress and PHP specific protections
- Bot control integration
- CloudWatch metrics integration

## Usage

```hcl
module "waf" {
  source = "github.com/yourusername/aws-waf-protection"
  
  enabled      = true
  name_prefix  = "my-app"
  environment  = "prod"
  
  for_cloudfront = true
  
  rate_limit_enabled = true
  rate_limit_global  = 2000
}