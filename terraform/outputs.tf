output "cloudfront_domain_name" {
  description = "The domain name of the CloudFront distribution"
  value       = "https://${aws_cloudfront_distribution.cdn.domain_name}"
}

output "alb_dns_name" {
  description = "The DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "ecr_repository_url" {
  description = "The URL of the ECR repository"
  value       = aws_ecr_repository.app.repository_url
}

output "aws_region" {
  description = "The AWS Region deployed to"
  value       = var.region
}
