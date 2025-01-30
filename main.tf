locals {
  web_acl_name = "${var.name_prefix}-${var.environment}"
  
  enabled_wordpress_rules = var.wordpress_protection_enabled ? [
    {
      name                     = "AWSManagedRulesWordPressRuleSet"
      priority                 = 20
      override_action_to_count = var.wordpress_rules_override_action_to_count
      excluded_rules          = var.wordpress_excluded_rules
    }
  ] : []

  enabled_php_rules = var.php_protection_enabled ? [
    {
      name                     = "AWSManagedRulesPHPRuleSet"
      priority                 = 25
      override_action_to_count = var.php_rules_override_action_to_count
      excluded_rules          = var.php_excluded_rules
    }
  ] : []

  # Bot Control Rules
  enabled_bot_control_rules = var.bot_protection_enabled ? [
    {
      name                     = "AWSManagedRulesBotControlRuleSet"
      priority                 = 15
      override_action_to_count = var.bot_rules_override_action_to_count
      excluded_rules          = var.bot_excluded_rules
    }
  ] : []
}

# IP Sets for Whitelist and Blacklist
resource "aws_wafv2_ip_set" "whitelist_ipv4" {
  count              = var.enabled ? 1 : 0
  provider           = aws.waf-provider
  name               = "${local.web_acl_name}-whitelist-ipv4"
  description        = "Whitelist IPv4 addresses"
  scope              = var.for_cloudfront ? "CLOUDFRONT" : "REGIONAL"
  ip_address_version = "IPV4"

  lifecycle {
    ignore_changes = [addresses]
  }
}

resource "aws_wafv2_ip_set" "whitelist_ipv6" {
  count              = var.enabled ? 1 : 0
  provider           = aws.waf-provider
  name               = "${local.web_acl_name}-whitelist-ipv6"
  description        = "Whitelist IPv6 addresses"
  scope              = var.for_cloudfront ? "CLOUDFRONT" : "REGIONAL"
  ip_address_version = "IPV6"

  lifecycle {
    ignore_changes = [addresses]
  }
}

# WAF ACL Resource
resource "aws_wafv2_web_acl" "main" {
  count       = var.enabled ? 1 : 0
  provider    = aws.waf-provider
  
  name        = local.web_acl_name
  description = var.description
  scope       = var.for_cloudfront ? "CLOUDFRONT" : "REGIONAL"

  default_action {
    allow {}
  }


  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.name
    sampled_requests_enabled   = true
  }
  ### AWS Baseline managed rule groups provide general protection against a wide variety of common threats. 
  ### Choose one or more of these rule groups to establish baseline protection for your resources.
  ### https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html 
  dynamic "rule" {
    for_each = var.aws_managed_waf_groups

    content {
      name = rule.value.name

      priority = rule.value.priority + 30

      # Always in count mode. The exception will block traffic
      override_action {
        dynamic "count" {
          for_each = rule.value.override_action_to_count ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = rule.value.override_action_to_count ? [] : [1]
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = "AWS"
          dynamic "rule_action_override" {
            for_each = rule.value.excluded_rules
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }

        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  # --------------------------------------------------------------------------------------------------------------------
  # -------------------------------------------       Rules & Exception       ------------------------------------------
  # --------------------------------------------------------------------------------------------------------------------

  dynamic "rule" {
    for_each = var.aws_managed_waf_groups_exceptions

    content {
      name     = "${rule.value.name}_Exception"
      priority = rule.value.priority + 110

      action {
        dynamic "block" {
          for_each = rule.value.enabled ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.enabled ? [] : [1]
          content {}
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }

      statement {
        # Statement for the Rule/Label to block if empty `exception_paths`
        dynamic "label_match_statement" {
          for_each = length(rule.value.exception_paths) == 0 ? [1] : []
          content {
            key   = rule.value.label
            scope = "LABEL"
          }
        }

        # And statement if any exception_paths exists
        dynamic "and_statement" {
          for_each = length(rule.value.exception_paths) >= 1 ? [1] : []
          content {
            # Right member of AND statement
            statement {
              label_match_statement {
                key   = rule.value.label
                scope = "LABEL"
              }
            }

            # Left member of AND statement
            statement {
              not_statement {
                # Start  -- dynamic statement for single path exception
                dynamic "statement" {
                  for_each = length(rule.value.exception_paths) == 1 ? rule.value.exception_paths : []
                  content {
                    byte_match_statement {
                      text_transformation {
                        priority = "1"
                        type     = "NONE"
                      }
                      positional_constraint = "STARTS_WITH"
                      search_string         = statement.value
                      field_to_match {
                        uri_path {}
                      }
                    }
                  }
                }
                # End  -- dynamic statement for single path exception

                # Start  -- dynamic statement for multiple paths exception
                dynamic "statement" {
                  for_each = length(rule.value.exception_paths) > 1 ? [1] : []
                  content {
                    or_statement {
                      # Start  -- dynamic `or_statement` -- multiple paths exception
                      dynamic "statement" {
                        for_each = rule.value.exception_paths
                        content {
                          byte_match_statement {
                            text_transformation {
                              priority = "1"
                              type     = "NONE"
                            }
                            positional_constraint = "STARTS_WITH"
                            search_string         = statement.value
                            field_to_match {
                              uri_path {}
                            }
                          }
                        }
                      }
                      # End  -- dynamic `or_statement` -- multiple paths exception
                    }
                  }
                }
                # End  -- dynamic statement for multiple paths exception
              }
            }
          }
        }
      }
    }
  }
  ### Wordpress rules
  dynamic "rule" {
    for_each = local.enabled_wordpress_rules
    content {
      name     = rule.value.name
      priority = rule.value.priority
      override_action {
        dynamic "count" {
          for_each = rule.value.override_action_to_count ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = rule.value.override_action_to_count ? [] : [1]
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = "AWS"
          dynamic "rule_action_override" {
            for_each = rule.value.excluded_rules
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }


  ### PHP rules
  dynamic "rule" {
    for_each = local.enabled_php_rules
    content {
      name     = rule.value.name
      priority = rule.value.priority
      override_action {
        dynamic "count" {
          for_each = rule.value.override_action_to_count ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = rule.value.override_action_to_count ? [] : [1]
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = "AWS"
          dynamic "rule_action_override" {
            for_each = rule.value.excluded_rules
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  ### Global Rate limit
  dynamic "rule" {
    for_each = var.rate_limit_enabled ? [1] : []

    content {
      name     = "IP-global-rate-limit-ipv4"
      priority = 8

      action {
        dynamic "block" {
          for_each = var.rate_limit_block ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = var.rate_limit_block ? [] : [1]
          content {}
        }
      }

      statement {
        rate_based_statement {
          limit              = var.rate_limit_global
          aggregate_key_type = "IP"

          scope_down_statement {
            not_statement {
              statement {
                geo_match_statement {
                  country_codes = ["DE", "AT", "CH", "PT", "ES"]
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "IP-global-rate-limit-ipv4"
        sampled_requests_enabled   = true
      }
    }
  }

  dynamic "rule" {
    for_each = var.rate_limit_enabled ? [1] : []

    content {
      name     = "IP-global-rate-limit-ipv6"
      priority = 9

      action {
        dynamic "block" {
          for_each = var.rate_limit_block ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = var.rate_limit_block ? [] : [1]
          content {}
        }
      }

      statement {
        rate_based_statement {
          limit              = var.rate_limit_global
          aggregate_key_type = "IP"

          scope_down_statement {
            not_statement {
              statement {
                geo_match_statement {
                  country_codes = ["DE", "AT", "CH", "PT", "ES"]
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "IP-global-rate-limit-ipv6"
        sampled_requests_enabled   = true
      }
    }
  }

  ### Domestic Rate limit
  dynamic "rule" {
    for_each = var.rate_limit_enabled ? [1] : []
    content {
      name     = "IP-domestic-rate-limit-ipv4"
      priority = 10

      action {
        dynamic "block" {
          for_each = var.rate_limit_block ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = var.rate_limit_block ? [] : [1]
          content {}
        }
      }

      statement {
        rate_based_statement {
          limit              = var.rate_limit_domestic
          aggregate_key_type = "IP"

          scope_down_statement {
            geo_match_statement {
              country_codes = ["DE", "AT", "CH", "PT", "ES"]
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "IP-domestic-rate-limit-ipv4"
        sampled_requests_enabled   = true
      }
    }
  }

  dynamic "rule" {
    for_each = var.rate_limit_enabled ? [1] : []
    content {
      name     = "IP-domestic-rate-limit-ipv6"
      priority = 11

      action {
        dynamic "block" {
          for_each = var.rate_limit_block ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = var.rate_limit_block ? [] : [1]
          content {}
        }
      }

      statement {
        rate_based_statement {
          limit              = var.rate_limit_domestic
          aggregate_key_type = "IP"

          scope_down_statement {
            geo_match_statement {
              country_codes = ["DE", "AT", "CH", "PT", "ES"]
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "IP-domestic-rate-limit-ipv6"
        sampled_requests_enabled   = true
      }
    }
  }

  ### Global Blacklist
  rule {
    name     = "IP-global-blacklist-ipv4"
    priority = 12

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = var.global_blacklist_ipv4_ip_set_arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IP-global-blacklist-ipv4"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "IP-global-blacklist-ipv6"
    priority = 13

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = var.global_blacklist_ipv6_ip_set_arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IP-global-blacklist-ipv6"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = local.enabled_bot_control_rules

    content {
      name = rule.value.name

      priority = rule.value.priority

      # Always in count mode. The exception will block traffic
      override_action {
        dynamic "count" {
          for_each = rule.value.override_action_to_count ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = rule.value.override_action_to_count ? [] : [1]
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = "AWS"
          dynamic "rule_action_override" {
            for_each = rule.value.excluded_rules
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }

        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }


}