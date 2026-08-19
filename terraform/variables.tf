variable "region" {
  type        = string
  default     = "il-central-1"
  description = "AWS region"
}

variable "tag_name" {
  type        = string
  default     = ""
  description = "Name tag value"
}

variable "tag_owner_email" {
  type        = string
  default     = ""
  description = "Owner email tag value"
}

variable "tag_manager_email" {
  type        = string
  default     = ""
  description = "Manager email tag value"
}

variable "tag_team_email" {
  type        = string
  default     = ""
  description = "Team email tag value"
}

variable "tag_description" {
  type        = string
  default     = ""
  description = "Description tag value"
}

variable "tag_environment" {
  type        = string
  default     = ""
  description = "Environment tag value"
}

variable "tag_dataclassification" {
  type        = string
  default     = ""
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
