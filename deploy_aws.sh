#!/usr/bin/env bash
set -e

REGION="il-central-1"
APP_NAME="ddos-monitor"

echo "=================================================="
echo "🚀 AWS Deployment Script for DDoS Monitoring Tool"
echo "Region: ${REGION}"
echo "=================================================="

# 1. Provision Infrastructure with Terraform
cd terraform
echo "📦 Initializing and applying Terraform infrastructure..."
terraform init
terraform apply -auto-approve

# Extract outputs
ECR_URL=$(terraform output -raw ecr_repository_url)
CLOUDFRONT_URL=$(terraform output -raw cloudfront_domain_name)
cd ..

echo "✅ Infrastructure provisioned!"
echo "ECR URL: ${ECR_URL}"
echo "CloudFront URL: ${CLOUDFRONT_URL}"

# 2. Authenticate Docker with AWS ECR in il-central-1
echo "🔐 Authenticating Docker with ECR in ${REGION}..."
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ECR_URL}"

# 3. Build & Push Docker Image
echo "🐳 Building Docker image..."
docker build -t "${APP_NAME}:latest" .

echo "🏷️ Tagging image for ECR..."
docker tag "${APP_NAME}:latest" "${ECR_URL}:latest"

echo "⬆️ Pushing image to ECR..."
docker push "${ECR_URL}:latest"

# 4. Force new deployment on ECS Fargate
echo "🔄 Updating ECS Fargate service to deploy new container..."
aws ecs update-service \
  --region "${REGION}" \
  --cluster "${APP_NAME}-cluster" \
  --service "${APP_NAME}-service" \
  --force-new-deployment > /dev/null

echo "=================================================="
echo "🎉 Deployment successful!"
echo "Your app is accessible via CloudFront at:"
echo "👉 ${CLOUDFRONT_URL}"
echo "=================================================="
