variable "region" {
  type        = string
  default     = "il-central-1"
  description = "AWS region"
}

variable "tag_name" {
  type        = string
  default     = "DDoS NW Monitor IP  in AWS"
  description = "Name tag value"
}

variable "tag_owner_email" {
  type        = string
  default     = "danny.milshtein@thalesgroup.com"
  description = "Owner email tag value"
}

variable "tag_manager_email" {
  type        = string
  default     = "gabriele.buratti@thalesgroup.com"
  description = "Manager email tag value"
}

variable "tag_team_email" {
  type        = string
  default     = "ww.dis.imperva.sales_all_se@thalesgroup.com"
  description = "Team email tag value"
}

variable "tag_description" {
  type        = string
  default     = "Demo Lab for DDoS NW IP monitoring tool in AWS"
  description = "Description tag value"
}

variable "tag_environment" {
  type        = string
  default     = "Demo"
  description = "Environment tag value"
}

variable "tag_dataclassification" {
  type        = string
  default     = "THALES GROUP LIMITED DISTRIBUTION"
  description = "Data classification tag value"
}

variable "app_name" {
  description = "Application name identifier"
  type        = string
  default     = "ddos-monitor"
}

variable "container_port" {
  description = "Port exposed by the application container"
  type        = number
  default     = 5001
}

variable "origin_custom_header_secret" {
  description = "Secret key value for CloudFront to ALB origin header validation"
  type        = string
  sensitive   = true
  default     = "ImpervaDDoSMonitorOriginSecret2026!"
}
