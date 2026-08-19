variable "aws_region" {
  description = "AWS Region for deployment"
  type        = string
  default     = "il-central-1"
}

variable "app_name" {
  description = "Application name identifier"
  type        = string
  default     = "ddos-monitor"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
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
